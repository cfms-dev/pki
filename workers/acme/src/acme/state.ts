import { Database } from "../db/queries";
import { AuthorizationRow, OrderRow } from "../db/types";

const EXPIRED_AUTHORIZATION_ERROR = JSON.stringify({
  type: "urn:ietf:params:acme:error:unauthorized",
  detail: "Authorization has expired",
  status: 403,
});

/**
 * Reconciles an authorization's status with its challenges and expiry. This
 * makes state recoverable if an isolate dies between updating the challenge and
 * updating the authorization/order.
 */
export async function syncAuthorizationState(
  database: Database,
  authz: AuthorizationRow,
  now: number
): Promise<AuthorizationRow> {
  if (authz.status !== "invalid" && authz.expires_at <= now) {
    await database.updateAuthorizationStatus(authz.id, "invalid");
    await database.invalidatePendingChallengesForAuthorization(
      authz.id,
      EXPIRED_AUTHORIZATION_ERROR
    );
    authz.status = "invalid";
    return authz;
  }

  if (authz.status !== "pending") {
    return authz;
  }

  const challenges = await database.getChallengesByAuthorizationId(authz.id);
  if (challenges.some((challenge) => challenge.status === "valid")) {
    await database.updateAuthorizationStatusIfPending(authz.id, "valid");
    authz.status = "valid";
  } else if (challenges.some((challenge) => challenge.status === "invalid")) {
    // A failed challenge invalidates the whole authorization. This also
    // recovers state if an isolate died after invalidating the challenge but
    // before updating the authorization/order.
    await database.updateAuthorizationStatusIfPending(authz.id, "invalid");
    authz.status = "invalid";
  }

  return authz;
}

/**
 * Reconciles an order with its authorizations. A `processing` order is left
 * alone because finalize owns that transition and performs its own checks.
 */
export async function syncOrderState(
  database: Database,
  order: OrderRow,
  now: number
): Promise<{ order: OrderRow; authorizations: AuthorizationRow[] }> {
  const authorizations = await database.getAuthorizationsByOrderId(order.id);
  for (const authz of authorizations) {
    await syncAuthorizationState(database, authz, now);
  }

  if (order.status === "valid" || order.status === "invalid") {
    return { order, authorizations };
  }

  if (order.status === "processing") {
    // Finalize owns the processing transition, but an authorization that
    // became invalid or expired while a finalize was in flight must still stop
    // issuance.
    if (authorizations.some((authz) => authz.status === "invalid")) {
      await database.updateOrderStatus(order.id, "invalid");
      order.status = "invalid";
    }
    return { order, authorizations };
  }

  if (order.expires_at <= now) {
    await database.updateOrderStatus(order.id, "invalid");
    order.status = "invalid";
    return { order, authorizations };
  }

  if (authorizations.some((authz) => authz.status === "invalid")) {
    await database.updateOrderStatus(order.id, "invalid");
    order.status = "invalid";
    return { order, authorizations };
  }

  if (
    authorizations.length > 0 &&
    authorizations.every((authz) => authz.status === "valid")
  ) {
    if (order.status === "pending") {
      await database.updateOrderStatus(order.id, "ready");
    }
    order.status = "ready";
  }

  return { order, authorizations };
}
