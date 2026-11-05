import { AcmeEnv, CONFIG, getTermsOfServiceUrl } from "../config";
import { generateNonceString } from "../crypto/nonce";
import { verifyAcmeJws } from "../crypto/jws";
import { issueCertificateFromCsr, parseAndVerifyCsr } from "../crypto/x509";
import { selectIntermediateCa } from "../crypto/ca";
import { validateCaaForOrder } from "../dns/caa";
import { Database } from "../db/queries";
import { AuthorizationRow, OrderRow } from "../db/types";
import { AcmeError } from "../errors";
import { checkAriRenewalEligibility } from "../ari/window";
import { RateLimiter } from "../ratelimit/limiter";

interface NewOrderPayload {
  identifiers: Array<{ type: string; value: string }>;
  notBefore?: string;
  notAfter?: string;
  replaces?: string; // RFC 9773 Predecessor certID
}

const DOMAIN_REGEX =
  /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

export async function handleNewOrder(
  request: Request,
  database: Database,
  baseUrl: string,
  env: AcmeEnv
): Promise<Response> {
  const verified = await verifyAcmeJws<NewOrderPayload>(request, database, "/new-order");
  if (!verified.account) {
    throw AcmeError.unauthorized("Account required for newOrder");
  }

  // RFC 8555 § 7.3.3: userActionRequired when terms of service have changed
  const termsOfServiceUrl = getTermsOfServiceUrl(env);
  if (termsOfServiceUrl && verified.account.terms_of_service !== termsOfServiceUrl) {
    throw AcmeError.userActionRequired(
      "Terms of service have changed",
      termsOfServiceUrl
    );
  }

  const payload = verified.payload;
  if (!Array.isArray(payload.identifiers) || payload.identifiers.length === 0) {
    throw AcmeError.malformed("newOrder must specify at least one identifier");
  }

  const domainList: string[] = [];
  for (const ident of payload.identifiers) {
    if (ident.type !== "dns") {
      throw AcmeError.rejectedIdentifier(
        `Unsupported identifier type '${ident.type}'. Only 'dns' is supported.`
      );
    }
    const domain = ident.value.trim().toLowerCase();
    if (!DOMAIN_REGEX.test(domain)) {
      throw AcmeError.rejectedIdentifier(`Invalid domain syntax: '${ident.value}'`);
    }
    domainList.push(domain);
  }

  // Evaluate ARI Renewal & Exemption
  let isAriRenewal = false;
  let replacesCertId: string | null = null;

  if (payload.replaces) {
    const predecessor = await database.getCertificateByCertId(payload.replaces);
    if (!predecessor) {
      throw AcmeError.malformed(
        `Certificate specified in 'replaces' (${payload.replaces}) does not exist`
      );
    }

    const eligibility = checkAriRenewalEligibility(predecessor, domainList);
    if (!eligibility.eligible) {
      throw AcmeError.malformed(
        `ARI renewal rejected: ${eligibility.reason || "Certificate not eligible for ARI renewal"}`
      );
    }

    isAriRenewal = true;
    replacesCertId = payload.replaces;
  }

  // Check Rate Limits (exempts duplicate & domain caps if isAriRenewal == true)
  const rateLimiter = new RateLimiter(database);
  await rateLimiter.checkNewOrderLimits(verified.account.id, domainList, isAriRenewal);

  const orderId = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + CONFIG.ORDER_EXPIRATION_SECONDS;

  const order: OrderRow = {
    id: orderId,
    account_id: verified.account.id,
    status: "pending",
    identifiers: JSON.stringify(domainList),
    not_before: payload.notBefore ? Math.floor(new Date(payload.notBefore).getTime() / 1000) : null,
    not_after: payload.notAfter ? Math.floor(new Date(payload.notAfter).getTime() / 1000) : null,
    replaces_cert_id: replacesCertId,
    is_ari_renewal: isAriRenewal ? 1 : 0,
    created_at: now,
    expires_at: expiresAt,
    certificate_id: null,
  };

  await database.saveOrder(order);

  // Per user requirement: "续期证书时，必须重新验证所有权。"
  // All authorizations are issued fresh in 'pending' status, requiring DNS-01 re-verification.
  const authzIds: string[] = [];
  const uniqueDomains = Array.from(new Set(domainList));

  for (const domain of uniqueDomains) {
    const authzId = crypto.randomUUID();
    const token = generateNonceString();
    const authz: AuthorizationRow = {
      id: authzId,
      order_id: orderId,
      identifier_value: domain,
      status: "pending",
      token,
      expires_at: now + CONFIG.AUTHZ_EXPIRATION_SECONDS,
      created_at: now,
    };
    await database.saveAuthorization(authz);
    authzIds.push(authzId);
  }

  return formatOrderResponse(order, authzIds, baseUrl, 201);
}

export async function handleGetOrder(
  request: Request,
  database: Database,
  baseUrl: string,
  orderId: string
): Promise<Response> {
  const verified = await verifyAcmeJws(request, database);
  if (!verified.account) {
    throw AcmeError.unauthorized();
  }

  const order = await database.getOrderById(orderId);
  if (!order) {
    throw AcmeError.notFound("Order not found");
  }

  if (order.account_id !== verified.account.id) {
    throw AcmeError.unauthorized("Order does not belong to account");
  }

  const authzs = await database.getAuthorizationsByOrderId(orderId);

  // If currently pending, verify if all authorizations have transitioned to valid
  if (order.status === "pending" && authzs.length > 0) {
    const allValid = authzs.every((a) => a.status === "valid");
    const anyInvalid = authzs.some((a) => a.status === "invalid");
    if (anyInvalid) {
      await database.updateOrderStatus(orderId, "invalid");
      order.status = "invalid";
    } else if (allValid) {
      await database.updateOrderStatus(orderId, "ready");
      order.status = "ready";
    }
  }

  return formatOrderResponse(
    order,
    authzs.map((a) => a.id),
    baseUrl,
    200
  );
}

export async function handleFinalizeOrder(
  request: Request,
  database: Database,
  baseUrl: string,
  orderId: string,
  env: AcmeEnv
): Promise<Response> {
  const verified = await verifyAcmeJws<{ csr: string }>(request, database);
  if (!verified.account) {
    throw AcmeError.unauthorized();
  }

  const order = await database.getOrderById(orderId);
  if (!order) {
    throw AcmeError.notFound("Order not found");
  }

  if (order.account_id !== verified.account.id) {
    throw AcmeError.unauthorized("Order does not belong to account");
  }

  const authzs = await database.getAuthorizationsByOrderId(orderId);
  const allValid = authzs.length > 0 && authzs.every((a) => a.status === "valid");

  if (!allValid && order.status !== "ready") {
    throw AcmeError.orderNotReady("All authorizations must be valid before finalizing");
  }

  if (!verified.payload.csr) {
    throw AcmeError.badCSR("Finalize payload must contain 'csr'");
  }

  // Parse & verify CSR
  const parsedCsr = await parseAndVerifyCsr(verified.payload.csr);
  const orderDomains: string[] = JSON.parse(order.identifiers);

  // Validate CSR domains match order identifiers
  const orderSet = new Set(orderDomains.map((d) => d.toLowerCase()));
  const csrSet = new Set(parsedCsr.domains.map((d) => d.toLowerCase()));

  if (orderSet.size !== csrSet.size || !orderDomains.every((d) => csrSet.has(d.toLowerCase()))) {
    throw AcmeError.badCSR(
      `CSR domains [${parsedCsr.domains.join(", ")}] do not match order domains [${orderDomains.join(", ")}]`
    );
  }

  // Pre-issuance CAA Verification (RFC 8659)
  // All intermediate CAs share the unified CAA Identity: CAA_ISSUER_DOMAIN_NAME ("cfms-pki.crpteam.club")
  const accountUri = `${baseUrl}/account/${verified.account.id}`;
  await validateCaaForOrder(orderDomains, accountUri, env);

  // After CAA validation and other pre-issuance checks pass,
  // select an Intermediate CA from the eligible pool
  const selectedCa = await selectIntermediateCa(env);

  // Issue Certificate with selected intermediate CA
  const issued = await issueCertificateFromCsr(
    parsedCsr.csr,
    orderDomains,
    env,
    undefined,
    selectedCa
  );

  const certIdInDb = crypto.randomUUID();
  await database.saveCertificate({
    id: certIdInDb,
    cert_id: issued.certId,
    serial_number: issued.serialNumber,
    aki: issued.aki,
    subject: issued.subject,
    san: JSON.stringify(issued.san),
    pem: issued.chainPem,
    not_before: issued.notBefore,
    not_after: issued.notAfter,
    account_id: order.account_id,
    created_at: Math.floor(Date.now() / 1000),
    revoked_at: null,
    revocation_reason: null,
    replaced_by_cert_id: null,
  });

  // If this was an ARI renewal, link replacement on predecessor cert
  if (order.is_ari_renewal && order.replaces_cert_id) {
    await database.markCertificateReplaced(order.replaces_cert_id, issued.certId);
  }

  // Update order status to valid
  await database.updateOrderStatus(orderId, "valid", certIdInDb);
  order.status = "valid";
  order.certificate_id = certIdInDb;

  return formatOrderResponse(
    order,
    authzs.map((a) => a.id),
    baseUrl,
    200
  );
}

function formatOrderResponse(
  order: OrderRow,
  authzIds: string[],
  baseUrl: string,
  status: number
): Response {
  const identifiers: Array<{ type: string; value: string }> = JSON.parse(
    order.identifiers
  ).map((val: string) => ({ type: "dns", value: val }));

  const body: Record<string, unknown> = {
    status: order.status,
    expires: new Date(order.expires_at * 1000).toISOString(),
    identifiers,
    authorizations: authzIds.map((id) => `${baseUrl}/authz/${id}`),
    finalize: `${baseUrl}/order/${order.id}/finalize`,
  };

  if (order.not_before) {
    body.notBefore = new Date(order.not_before * 1000).toISOString();
  }
  if (order.not_after) {
    body.notAfter = new Date(order.not_after * 1000).toISOString();
  }

  // Echo replaces if present per RFC 9773 § 4.2
  if (order.replaces_cert_id) {
    body.replaces = order.replaces_cert_id;
  }

  if (order.status === "valid" && order.certificate_id) {
    body.certificate = `${baseUrl}/cert/${order.certificate_id}`;
  }

  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      Location: `${baseUrl}/order/${order.id}`,
    },
  });
}
