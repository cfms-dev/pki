import { CONFIG } from "../config";
import { generateNonceString } from "../crypto/nonce";
import { Database } from "../db/queries";
import { AuthorizationRow, ChallengeRow } from "../db/types";
import { isWildcardDnsName } from "./identifiers";

/**
 * Builds the challenges offered for an authorization.
 *
 * The dns-01 challenge deliberately reuses the authorization ID as its
 * challenge ID. This keeps the historical `/challenge/{authzId}` URLs working
 * for clients and tests created before HTTP-01 support existed.
 */
export function buildChallengesForAuthorization(
  authz: AuthorizationRow
): ChallengeRow[] {
  const base = {
    authorization_id: authz.id,
    status: "pending" as const,
    error: null,
    validated_at: null,
    processing_started_at: null,
    validation_generation: 0,
    created_at: authz.created_at,
  };

  const challenges: ChallengeRow[] = authz.identifier_type === "ip" ? [] : [
    {
      ...base,
      id: authz.id,
      type: "dns-01",
      token: authz.token,
    },
  ];

  // RFC 8555 § 8.3 / § 7.1.3: wildcard identifiers can only use dns-01.
  if (!isWildcardDnsName(authz.identifier_value)) {
    challenges.push({
      ...base,
      id: crypto.randomUUID(),
      type: "http-01",
      token: generateNonceString(),
    });
  }

  return challenges;
}

/**
 * Loads the challenges for an authorization, creating the default set when
 * they do not exist yet (legacy rows) or when a pending legacy authorization
 * predates HTTP-01 support.
 */
export async function ensureChallengesForAuthorization(
  database: Database,
  authz: AuthorizationRow
): Promise<ChallengeRow[]> {
  let challenges = await database.getChallengesByAuthorizationId(authz.id);

  if (challenges.length === 0) {
    const desired = buildChallengesForAuthorization(authz);
    let rows: ChallengeRow[];

    if (authz.status === "pending") {
      rows = desired;
    } else if (authz.status === "valid") {
      // The legacy authorization was already validated. Preserve its dns-01
      // challenge URL rather than offering a new pending HTTP-01 challenge.
      rows = [
        {
          ...desired[0],
          status: "valid",
          validated_at: authz.created_at,
        },
      ];
    } else {
      rows = [
        {
          ...desired[0],
          status: "invalid",
          error: JSON.stringify({
            type: "urn:ietf:params:acme:error:unauthorized",
            detail: "Authorization is invalid",
            status: 403,
          }),
        },
      ];
    }

    for (const challenge of rows) {
      await database.saveChallengeIfAbsent(challenge);
    }
    challenges = await database.getChallengesByAuthorizationId(authz.id);
  } else if (
    authz.status === "pending" &&
    !challenges.some((challenge) => challenge.type === "http-01") &&
    !isWildcardDnsName(authz.identifier_value)
  ) {
    // Upgrade a pending legacy authorization created before HTTP-01 support.
    const httpChallenge = buildChallengesForAuthorization(authz).find(
      (challenge) => challenge.type === "http-01"
    );
    if (httpChallenge) {
      await database.saveChallengeIfAbsent(httpChallenge);
      challenges = await database.getChallengesByAuthorizationId(authz.id);
    }
  }

  return challenges;
}

/**
 * Finds a challenge by its URL ID. For backwards compatibility, a challenge
 * ID that equals an authorization ID resolves to that authorization's dns-01
 * challenge.
 */
export async function findChallengeById(
  database: Database,
  challengeId: string
): Promise<{ challenge: ChallengeRow; authorization: AuthorizationRow } | null> {
  const challenge = await database.getChallengeById(challengeId);
  if (challenge) {
    const authorization = await database.getAuthorizationById(challenge.authorization_id);
    if (!authorization) return null;
    return { challenge, authorization };
  }

  const authorization = await database.getAuthorizationById(challengeId);
  if (!authorization) return null;

  const challenges = await ensureChallengesForAuthorization(database, authorization);
  const dnsChallenge = challenges.find((candidate) => candidate.type === "dns-01");
  if (!dnsChallenge) return null;

  return { challenge: dnsChallenge, authorization };
}

/** Maximum age of a `processing` claim before another request may retry it. */
export const CHALLENGE_PROCESSING_STALE_SECONDS =
  CONFIG.CHALLENGE_PROCESSING_STALE_SECONDS;
