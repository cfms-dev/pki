import { verifyAcmeJws } from "../crypto/jws";
import { Database } from "../db/queries";
import { AcmeError } from "../errors";
import { validateDns01Challenge } from "../dns/validator";
import { RateLimiter } from "../ratelimit/limiter";

export async function handleChallenge(
  request: Request,
  database: Database,
  baseUrl: string,
  authzId: string,
  fetchImpl: typeof fetch = fetch
): Promise<Response> {
  const verified = await verifyAcmeJws(request, database);
  if (!verified.account) {
    throw AcmeError.unauthorized();
  }

  const authz = await database.getAuthorizationById(authzId);
  if (!authz) {
    throw AcmeError.notFound("Authorization not found");
  }

  const order = await database.getOrderById(authz.order_id);
  if (!order || order.account_id !== verified.account.id) {
    throw AcmeError.unauthorized("Authorization does not belong to your account");
  }

  if (authz.status === "valid") {
    // Already valid
    return formatChallengeResponse(authz, baseUrl, "valid");
  }

  // Check rate limit for failed attempts
  const rateLimiter = new RateLimiter(database);
  await rateLimiter.checkFailedValidationLimit(
    verified.account.id,
    authz.identifier_value
  );

  // Validate DNS-01 challenge via DoH
  const result = await validateDns01Challenge(
    authz.identifier_value,
    authz.token,
    verified.thumbprint,
    fetchImpl
  );

  if (result.valid) {
    await database.updateAuthorizationStatus(authz.id, "valid");
    authz.status = "valid";

    // Check if all authorizations for this order are now valid
    const allAuthzs = await database.getAuthorizationsByOrderId(order.id);
    const allValid = allAuthzs.every(
      (a) => (a.id === authz.id ? "valid" : a.status) === "valid"
    );
    if (allValid) {
      await database.updateOrderStatus(order.id, "ready");
    }

    return formatChallengeResponse(authz, baseUrl, "valid");
  } else {
    await database.updateAuthorizationStatus(authz.id, "invalid");
    await database.updateOrderStatus(order.id, "invalid");
    authz.status = "invalid";

    const errorDetails = {
      type: "urn:ietf:params:acme:error:dns",
      detail: result.error || "DNS validation failed",
      status: 400,
    };

    return formatChallengeResponse(authz, baseUrl, "invalid", errorDetails);
  }
}

function formatChallengeResponse(
  authz: { id: string; token: string; status: string },
  baseUrl: string,
  status: string,
  error?: { type: string; detail: string; status: number }
): Response {
  const body: Record<string, unknown> = {
    type: "dns-01",
    url: `${baseUrl}/challenge/${authz.id}`,
    token: authz.token,
    status,
  };
  if (error) {
    body.error = error;
  }

  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      Link: `<${baseUrl}/authz/${authz.id}>;rel="up"`,
    },
  });
}
