import { verifyAcmeJws } from "../crypto/jws";
import { Database } from "../db/queries";
import { ChallengeRow } from "../db/types";
import { AcmeError } from "../errors";
import { validateDns01Challenge } from "../dns/validator";
import { RateLimiter } from "../ratelimit/limiter";
import {
  CHALLENGE_PROCESSING_STALE_SECONDS,
  findChallengeById,
} from "../acme/challenges";
import { isWildcardDnsName } from "../acme/identifiers";
import {
  Http01ErrorType,
  validateHttp01Challenge,
} from "../http01/validator";

interface ChallengeProblem {
  type: string;
  detail: string;
  status: number;
}

function buildProblem(errorType: string, detail: string): ChallengeProblem {
  const type = errorType.startsWith("urn:")
    ? errorType
    : `urn:ietf:params:acme:error:${errorType}`;
  const status =
    errorType === "unauthorized" || errorType === "caa"
      ? 403
      : errorType === "serverInternal"
        ? 500
        : 400;
  return { type, detail, status };
}

function problemJson(problem: ChallengeProblem): string {
  return JSON.stringify(problem);
}

export async function handleChallenge(
  request: Request,
  database: Database,
  baseUrl: string,
  challengeId: string,
  fetchImpl: typeof fetch = fetch
): Promise<Response> {
  const verified = await verifyAcmeJws(request, database);
  if (!verified.account) {
    throw AcmeError.unauthorized();
  }

  const found = await findChallengeById(database, challengeId);
  if (!found) {
    throw AcmeError.notFound("Challenge not found");
  }

  const { challenge, authorization } = found;
  const order = await database.getOrderById(authorization.order_id);
  if (!order || order.account_id !== verified.account.id) {
    throw AcmeError.unauthorized("Challenge does not belong to your account");
  }

  const now = Math.floor(Date.now() / 1000);

  // Expired authorizations can never validate or issue.
  if (authorization.expires_at <= now) {
    const problem = buildProblem("unauthorized", "Authorization has expired");
    await database.updateAuthorizationStatus(authorization.id, "invalid");
    await database.invalidatePendingChallengesForAuthorization(
      authorization.id,
      problemJson(problem)
    );
    await database.invalidateOpenOrder(order.id);
    return formatChallengeResponse(
      { ...challenge, status: "invalid" },
      baseUrl,
      problem
    );
  }

  // A challenge that already validated is simply returned. A different
  // challenge on the same authorization may still be pending (for example when
  // a client triggered dns-01 and http-01 concurrently); allow it to validate
  // independently so the stored challenge state stays truthful.
  if (authorization.status === "valid" && challenge.status === "valid") {
    return formatChallengeResponse(challenge, baseUrl);
  }

  if (authorization.status === "invalid") {
    const problem = buildProblem("unauthorized", "Authorization is invalid");
    await database.invalidateChallenge(challenge.id, problemJson(problem));
    await database.invalidateOpenOrder(order.id);
    challenge.status = "invalid";
    challenge.error = problemJson(problem);
    return formatChallengeResponse(challenge, baseUrl, problem);
  }

  if (challenge.status === "valid") {
    return formatChallengeResponse(challenge, baseUrl);
  }

  if (challenge.status === "invalid") {
    return formatChallengeResponse(challenge, baseUrl);
  }

  if (order.status === "invalid") {
    const problem = buildProblem("unauthorized", "Order is no longer valid");
    await database.invalidateChallenge(challenge.id, problemJson(problem));
    challenge.status = "invalid";
    challenge.error = problemJson(problem);
    return formatChallengeResponse(challenge, baseUrl, problem);
  }

  // A concurrent validation that is still fresh must not be duplicated.
  const staleBefore = now - CHALLENGE_PROCESSING_STALE_SECONDS;
  if (
    challenge.status === "processing" &&
    (challenge.processing_started_at ?? 0) >= staleBefore
  ) {
    return formatChallengeResponse(challenge, baseUrl);
  }

  if (
    (challenge.type === "http-01" && isWildcardDnsName(authorization.identifier_value)) ||
    (challenge.type === "dns-01" && authorization.identifier_type === "ip")
  ) {
    const invalidMethodAttempt = await database.claimChallengeForValidation(
      challenge.id,
      now,
      staleBefore
    );
    if (invalidMethodAttempt !== null) {
      const problem = buildProblem(
        "malformed",
        "Challenge method is not allowed for this identifier"
      );
      await database.completeChallengeValidationFailure(
        challenge.id,
        invalidMethodAttempt,
        authorization.id,
        order.id,
        problemJson(problem)
      );
      challenge.status = "invalid";
      challenge.error = problemJson(problem);
      return formatChallengeResponse(challenge, baseUrl, problem);
    }
    const fresh = await database.getChallengeById(challenge.id);
    return formatChallengeResponse(fresh ?? challenge, baseUrl);
  }

  if (challenge.type !== "http-01" && challenge.type !== "dns-01") {
    throw AcmeError.malformed(`Unsupported challenge type '${challenge.type}'`);
  }

  const rateLimiter = new RateLimiter(database);
  await rateLimiter.checkFailedValidationLimit(
    verified.account.id,
    { type: authorization.identifier_type ?? "dns", value: authorization.identifier_value }
  );

  const validationGeneration = await database.claimChallengeForValidation(
    challenge.id,
    now,
    staleBefore
  );
  if (validationGeneration === null) {
    const fresh = await database.getChallengeById(challenge.id);
    return formatChallengeResponse(fresh ?? challenge, baseUrl);
  }

  let validation:
    | { valid: true }
    | { valid: false; errorType: Http01ErrorType | "dns"; error: string };

  try {
    if (challenge.type === "http-01") {
      const result = await validateHttp01Challenge(
        { type: authorization.identifier_type ?? "dns", value: authorization.identifier_value },
        challenge.token,
        verified.thumbprint,
        { fetchImpl, signal: request.signal }
      );
      validation = result.valid
        ? { valid: true }
        : {
            valid: false,
            errorType: result.errorType ?? "serverInternal",
            error: result.error ?? "HTTP-01 validation failed",
          };
    } else {
      const result = await validateDns01Challenge(
        authorization.identifier_value,
        challenge.token,
        verified.thumbprint,
        fetchImpl
      );
      validation = result.valid
        ? { valid: true }
        : {
            valid: false,
            errorType: "dns",
            error: result.error || "DNS validation failed",
          };
    }
  } catch {
    // Never let an unexpected validator failure leave the challenge stuck in
    // `processing`, and never leak internal error details to the client.
    validation = {
      valid: false,
      errorType: "serverInternal",
      error: "Validation could not be completed due to an internal error",
    };
  }

  if (validation.valid) {
    const completed = await database.completeChallengeValidationSuccess(
      challenge.id,
      validationGeneration,
      authorization.id,
      order.id,
      now
    );
    if (!completed) {
      const [fresh, freshAuthz] = await Promise.all([
        database.getChallengeById(challenge.id),
        database.getAuthorizationById(authorization.id),
      ]);
      if (fresh?.status === "processing" && freshAuthz?.status === "invalid") {
        const problem = buildProblem("unauthorized", "Authorization is invalid");
        await database.invalidateChallenge(challenge.id, problemJson(problem));
        return formatChallengeResponse(
          { ...fresh, status: "invalid", error: problemJson(problem) },
          baseUrl,
          problem
        );
      }
      return formatChallengeResponse(fresh ?? challenge, baseUrl);
    }
    challenge.status = "valid";
    challenge.validated_at = now;
    challenge.error = null;
    return formatChallengeResponse(challenge, baseUrl);
  }

  const problem = buildProblem(validation.errorType, validation.error);
  const completed = await database.completeChallengeValidationFailure(
    challenge.id,
    validationGeneration,
    authorization.id,
    order.id,
    problemJson(problem)
  );
  if (!completed) {
    const fresh = await database.getChallengeById(challenge.id);
    return formatChallengeResponse(fresh ?? challenge, baseUrl);
  }

  // Only actual validation failures consume the failed-attempt budget.
  try {
    await rateLimiter.recordFailedValidation(
      verified.account.id,
      { type: authorization.identifier_type ?? "dns", value: authorization.identifier_value }
    );
  } catch {
    // State is already persisted; do not turn a validation failure into a 500.
  }

  challenge.status = "invalid";
  challenge.error = problemJson(problem);
  return formatChallengeResponse(challenge, baseUrl, problem);
}

function formatChallengeResponse(
  challenge: ChallengeRow,
  baseUrl: string,
  overrideProblem?: ChallengeProblem
): Response {
  const body: Record<string, unknown> = {
    type: challenge.type,
    url: `${baseUrl}/challenge/${challenge.id}`,
    status: challenge.status,
    token: challenge.token,
  };

  if (challenge.validated_at) {
    body.validated = new Date(challenge.validated_at * 1000).toISOString();
  }

  let problem: ChallengeProblem | undefined = overrideProblem;
  if (!problem && challenge.error) {
    try {
      problem = JSON.parse(challenge.error) as ChallengeProblem;
    } catch {
      problem = undefined;
    }
  }
  if (problem) {
    body.error = problem;
  }

  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      Link: `<${baseUrl}/authz/${challenge.authorization_id}>;rel="up"`,
    },
  });
}
