import { AcmeEnv, CONFIG, getTermsOfServiceUrl } from "../config";
import { generateNonceString } from "../crypto/nonce";
import { verifyAcmeJws, exportPublicJwkSpki } from "../crypto/jws";
import {
  issueCertificateFromCsr,
  parseAndVerifyCsr,
  ParsedCsr,
} from "../crypto/x509";
import { selectIntermediateCa } from "../crypto/ca";
import { validateCaaForOrder } from "../dns/caa";
import { Database } from "../db/queries";
import { AuthorizationRow, OrderRow } from "../db/types";
import { AcmeError } from "../errors";
import { checkAriRenewalEligibility } from "../ari/window";
import { RateLimiter } from "../ratelimit/limiter";
import { buildChallengesForAuthorization } from "../acme/challenges";
import { validateDnsIdentifier } from "../acme/identifiers";
import { syncOrderState } from "../acme/state";

interface NewOrderPayload {
  identifiers: Array<{ type: string; value: string }>;
  notBefore?: string;
  notAfter?: string;
  replaces?: string; // RFC 9773 Predecessor certID
}

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
    if (
      !ident ||
      typeof ident !== "object" ||
      typeof ident.type !== "string" ||
      typeof ident.value !== "string"
    ) {
      throw AcmeError.malformed(
        "Each identifier must include a string 'type' and 'value'"
      );
    }

    if (ident.type !== "dns") {
      // RFC 8555 § 6.7 unsupportedIdentifier. This server intentionally does
      // not implement RFC 8738 IP validation: Workers fetch() cannot target IP
      // literals and the documented TCP-socket path is not a supported HTTP
      // validation transport. Rejecting the identifier prevents orders that
      // could never be validated from being created.
      throw AcmeError.unsupportedIdentifier(
        `Identifier type '${ident.type}' is not supported. Only 'dns' identifiers can be validated by this ACME server.`
      );
    }

    // A DNS identifier must be a DNS name, not an IP address literal. The
    // shared validator also rejects legacy numeric IPv4 notations that the URL
    // parser would turn into an IP address. Nothing is persisted before every
    // identifier has been validated.
    const validated = validateDnsIdentifier(ident.value);
    if (!validated.ok) {
      throw validated.errorType === "malformed"
        ? AcmeError.malformed(validated.detail)
        : AcmeError.rejectedIdentifier(validated.detail);
    }
    domainList.push(validated.value);
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
  // All authorizations are issued fresh in 'pending' status, requiring
  // re-verification through dns-01 or http-01.
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

    for (const challenge of buildChallengesForAuthorization(authz)) {
      await database.saveChallenge(challenge);
    }

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

  let order = await database.getOrderById(orderId);
  if (!order) {
    throw AcmeError.notFound("Order not found");
  }

  if (order.account_id !== verified.account.id) {
    throw AcmeError.unauthorized("Order does not belong to account");
  }

  const now = Math.floor(Date.now() / 1000);
  const synced = await syncOrderState(database, order, now);
  order = synced.order;

  return formatOrderResponse(
    order,
    synced.authorizations.map((a) => a.id),
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

  let order = await database.getOrderById(orderId);
  if (!order) {
    throw AcmeError.notFound("Order not found");
  }

  if (order.account_id !== verified.account.id) {
    throw AcmeError.unauthorized("Order does not belong to account");
  }

  const now = Math.floor(Date.now() / 1000);
  const synced = await syncOrderState(database, order, now);
  order = synced.order;
  const authzs = synced.authorizations;

  // Idempotent finalize of an already-issued order.
  if (order.status === "valid" && order.certificate_id) {
    return formatOrderResponse(
      order,
      authzs.map((authz) => authz.id),
      baseUrl,
      200
    );
  }

  if (order.status !== "ready") {
    throw AcmeError.orderNotReady(
      `Order is '${order.status}'; only a ready order can be finalized`
    );
  }

  if (order.expires_at <= now) {
    await database.updateOrderStatus(orderId, "invalid");
    order.status = "invalid";
    throw AcmeError.orderNotReady("Order has expired");
  }

  const allValid =
    authzs.length > 0 &&
    authzs.every(
      (authz) => authz.status === "valid" && authz.expires_at > now
    );
  if (!allValid) {
    throw AcmeError.orderNotReady(
      "All authorizations must be valid and unexpired before finalizing"
    );
  }

  if (!verified.payload.csr) {
    throw AcmeError.badCSR("Finalize payload must contain 'csr'");
  }

  // Parse & verify CSR before claiming the order so malformed requests do not
  // move the order into `processing`.
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

  // RFC 8555 § 11.1 Key Selection: the CSR public key must differ from the
  // account key authenticating this request, and must not reuse a key already
  // registered to another account. This runs before the order is claimed and
  // before any intermediate CA is invoked, so no non-compliant certificate
  // can be issued.
  await assertCsrKeyIsNotAnAccountKey(
    parsedCsr,
    verified.jwk,
    verified.header.alg,
    database
  );

  // Serialize finalization: only one request may move a ready order to
  // processing and issue a certificate.
  const claimed = await database.claimOrderForFinalize(orderId);
  if (!claimed) {
    const latest = await database.getOrderById(orderId);
    if (latest?.status === "valid" && latest.certificate_id) {
      return formatOrderResponse(
        latest,
        authzs.map((authz) => authz.id),
        baseUrl,
        200
      );
    }
    throw AcmeError.orderNotReady("Order is already being finalized");
  }
  order.status = "processing";

  try {
    const nowBeforeIssue = Math.floor(Date.now() / 1000);
    const authzsBeforeIssue = await database.getAuthorizationsByOrderId(orderId);
    if (
      authzsBeforeIssue.length === 0 ||
      authzsBeforeIssue.some(
        (authz) => authz.status !== "valid" || authz.expires_at <= nowBeforeIssue
      )
    ) {
      await database.updateOrderStatus(orderId, "invalid");
      throw AcmeError.orderNotReady(
        "All authorizations must be valid and unexpired before issuance"
      );
    }

    // Pre-issuance CAA Verification (RFC 8659). Pass the validation methods
    // actually used so a CAA `validationmethods` property is evaluated against
    // the correct method rather than assuming dns-01.
    const accountUri = `${baseUrl}/account/${verified.account.id}`;
    const validationRows = await database.getValidChallengeTypesByOrderId(orderId);
    const methodsByDomain = new Map<string, string[]>();
    for (const row of validationRows) {
      const domain = row.identifier_value.toLowerCase();
      const methods = methodsByDomain.get(domain) ?? [];
      if (!methods.includes(row.type)) {
        methods.push(row.type);
      }
      methodsByDomain.set(domain, methods);
    }
    await validateCaaForOrder(
      orderDomains,
      accountUri,
      env,
      undefined,
      methodsByDomain
    );

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

    // Re-check authorization validity and order state immediately before
    // persisting the certificate. This closes the window between the first
    // check and a slow CAA lookup/issuance.
    const finalCheckTime = Math.floor(Date.now() / 1000);
    const [authzsBeforePersist, orderBeforePersist] = await Promise.all([
      database.getAuthorizationsByOrderId(orderId),
      database.getOrderById(orderId),
    ]);
    if (
      !orderBeforePersist ||
      orderBeforePersist.status !== "processing" ||
      orderBeforePersist.expires_at <= finalCheckTime ||
      authzsBeforePersist.length === 0 ||
      authzsBeforePersist.some(
        (authz) =>
          authz.status !== "valid" || authz.expires_at <= finalCheckTime
      )
    ) {
      await database.updateOrderStatus(orderId, "invalid");
      throw AcmeError.orderNotReady(
        "Order or authorization expired before the certificate could be issued"
      );
    }

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
      authzs.map((authz) => authz.id),
      baseUrl,
      200
    );
  } catch (err) {
    // Issuance did not complete. Return the order to `ready` (unless it was
    // deliberately marked invalid above) so the client can retry.
    await database.releaseOrderFromProcessing(orderId);
    throw err;
  }
}

function equalPublicKeyBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }
  return difference === 0;
}

/**
 * RFC 8555 § 11.1: the CSR must not use the account key that authenticates the
 * request, and the server also rejects a key that is already registered to
 * another account.
 *
 * Account keys are compared through their canonical SPKI DER encoding rather
 * than the stored JWK JSON, whose field order and encoding are not canonical.
 * The cross-account check uses the accounts table's UNIQUE thumbprint index
 * (the RFC 7638 thumbprint of the account key), so it is a point lookup rather
 * than a table scan.
 */
async function assertCsrKeyIsNotAnAccountKey(
  parsedCsr: ParsedCsr,
  accountJwk: JsonWebKey,
  accountAlgorithm: string,
  database: Database
): Promise<void> {
  let accountSpki: Uint8Array;
  try {
    accountSpki = await exportPublicJwkSpki(accountJwk, accountAlgorithm);
  } catch {
    // A comparison that cannot be performed must never be treated as a pass.
    // The account key was just used to verify the request signature, so this
    // signals a server-side problem rather than a bad CSR.
    throw AcmeError.serverInternal(
      "Unable to compare the CSR public key with the account public key"
    );
  }

  if (equalPublicKeyBytes(accountSpki, parsedCsr.publicKeySpki)) {
    throw AcmeError.badCSR(
      "The CSR public key must not be the ACME account key used to authenticate this request"
    );
  }

  const existingAccount = await database.getAccountByThumbprint(
    parsedCsr.publicKeyThumbprint
  );
  if (existingAccount) {
    throw AcmeError.badCSR(
      "The CSR public key is already registered to an ACME account; a distinct certificate key is required"
    );
  }
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
