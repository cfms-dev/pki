import { verifyAcmeJws } from "../crypto/jws";
import { Database } from "../db/queries";
import { ChallengeRow } from "../db/types";
import { AcmeError } from "../errors";
import { ensureChallengesForAuthorization } from "../acme/challenges";
import { isWildcardDnsName } from "../acme/identifiers";
import { syncAuthorizationState } from "../acme/state";

export async function handleGetAuthz(
  request: Request,
  database: Database,
  baseUrl: string,
  authzId: string
): Promise<Response> {
  const verified = await verifyAcmeJws(request, database);
  if (!verified.account) {
    throw AcmeError.unauthorized();
  }

  let authz = await database.getAuthorizationById(authzId);
  if (!authz) {
    throw AcmeError.notFound("Authorization not found");
  }

  const order = await database.getOrderById(authz.order_id);
  if (!order || order.account_id !== verified.account.id) {
    throw AcmeError.unauthorized("Authorization does not belong to your account");
  }

  const now = Math.floor(Date.now() / 1000);
  await ensureChallengesForAuthorization(database, authz);
  authz = await syncAuthorizationState(database, authz, now);

  if (authz.status === "invalid") {
    await database.invalidatePendingChallengesForAuthorization(
      authz.id,
      JSON.stringify({
        type: "urn:ietf:params:acme:error:unauthorized",
        detail: "Authorization is invalid",
        status: 403,
      })
    );
    await database.invalidateOpenOrder(order.id);
  } else if (authz.status === "valid") {
    await database.markOrderReadyIfAllAuthorizationsValid(order.id);
  }

  const challenges = await database.getChallengesByAuthorizationId(authz.id);

  // RFC 8555 § 7.1.4: a wildcard authorization MUST NOT include the "*." prefix
  // in identifier.value. The base domain is returned and "wildcard" is true.
  const isWildcard = isWildcardDnsName(authz.identifier_value);
  const body: Record<string, unknown> = {
    status: authz.status,
    expires: new Date(authz.expires_at * 1000).toISOString(),
    identifier: {
      type: "dns",
      value: isWildcard ? authz.identifier_value.slice(2) : authz.identifier_value,
    },
    challenges: challenges.map((challenge) => formatChallenge(challenge, baseUrl)),
  };

  if (isWildcard) {
    body.wildcard = true;
  }

  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
    },
  });
}

function formatChallenge(
  challenge: ChallengeRow,
  baseUrl: string
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    type: challenge.type,
    url: `${baseUrl}/challenge/${challenge.id}`,
    status: challenge.status,
    token: challenge.token,
  };

  if (challenge.validated_at) {
    body.validated = new Date(challenge.validated_at * 1000).toISOString();
  }
  if (challenge.error) {
    try {
      body.error = JSON.parse(challenge.error);
    } catch {
      // Ignore a malformed persisted error document.
    }
  }

  return body;
}
