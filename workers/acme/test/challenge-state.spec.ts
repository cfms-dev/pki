import { describe, it, expect, beforeEach } from "vitest";
import { createMockD1Database } from "./mock-d1";
import { Database } from "../src/db/queries";
import { AuthorizationRow, ChallengeRow, OrderRow } from "../src/db/types";

const now = 1_700_000_000;

async function createFixture() {
  const database = new Database(createMockD1Database());

  const order: OrderRow = {
    id: "order-1",
    account_id: "account-1",
    status: "pending",
    identifiers: JSON.stringify(["example.com"]),
    not_before: null,
    not_after: null,
    replaces_cert_id: null,
    is_ari_renewal: 0,
    created_at: now,
    expires_at: now + 3600,
    certificate_id: null, processing_started_at: null, finalize_generation: 0,
  };
  const authz: AuthorizationRow = {
    id: "authz-1",
    order_id: order.id,
    identifier_value: "example.com",
    identifier_type: "dns",
    status: "pending",
    token: "a".repeat(22),
    expires_at: now + 3600,
    created_at: now,
  };
  const challenge: ChallengeRow = {
    id: "challenge-1",
    authorization_id: authz.id,
    type: "http-01",
    token: "b".repeat(22),
    status: "pending",
    error: null,
    validated_at: null,
    processing_started_at: null,
    validation_generation: 0,
    created_at: now,
  };

  await database.saveOrder(order);
  await database.saveAuthorization(authz);
  await database.saveChallenge(challenge);

  return { database, order, authz, challenge };
}

describe("Challenge processing generations", () => {
  let fixture: Awaited<ReturnType<typeof createFixture>>;

  beforeEach(async () => {
    fixture = await createFixture();
  });

  it("fences a stale attempt after its processing claim was reclaimed", async () => {
    const { database, order, authz, challenge } = fixture;

    const first = await database.claimChallengeForValidation(
      challenge.id,
      now,
      now - 60
    );
    expect(first).toBe(1);

    // A new request reclaims the stale processing row. The generation must
    // advance so the original attempt can no longer commit.
    const second = await database.claimChallengeForValidation(
      challenge.id,
      now + 61,
      now + 1
    );
    expect(second).toBe(2);

    const staleFailure = await database.completeChallengeValidationFailure(
      challenge.id,
      first!,
      authz.id,
      order.id,
      JSON.stringify({ type: "urn:ietf:params:acme:error:incorrectResponse" })
    );
    expect(staleFailure).toBe(false);

    const afterStale = await database.getChallengeById(challenge.id);
    expect(afterStale?.status).toBe("processing");
    expect(afterStale?.validation_generation).toBe(2);
    expect((await database.getAuthorizationById(authz.id))?.status).toBe(
      "pending"
    );
    expect((await database.getOrderById(order.id))?.status).toBe("pending");

    const currentSuccess = await database.completeChallengeValidationSuccess(
      challenge.id,
      second!,
      authz.id,
      order.id,
      now + 61
    );
    expect(currentSuccess).toBe(true);

    const completed = await database.getChallengeById(challenge.id);
    expect(completed?.status).toBe("valid");
    expect((await database.getAuthorizationById(authz.id))?.status).toBe(
      "valid"
    );
    expect((await database.getOrderById(order.id))?.status).toBe("ready");
  });

  it("does not let a stale success resurrect a challenge that a newer attempt failed", async () => {
    const { database, order, authz, challenge } = fixture;

    const first = await database.claimChallengeForValidation(
      challenge.id,
      now,
      now - 60
    );
    const second = await database.claimChallengeForValidation(
      challenge.id,
      now + 61,
      now + 1
    );
    expect(first).toBe(1);
    expect(second).toBe(2);

    const currentFailure = await database.completeChallengeValidationFailure(
      challenge.id,
      second!,
      authz.id,
      order.id,
      JSON.stringify({ type: "urn:ietf:params:acme:error:connection" })
    );
    expect(currentFailure).toBe(true);

    const staleSuccess = await database.completeChallengeValidationSuccess(
      challenge.id,
      first!,
      authz.id,
      order.id,
      now + 62
    );
    expect(staleSuccess).toBe(false);

    expect((await database.getChallengeById(challenge.id))?.status).toBe(
      "invalid"
    );
    expect((await database.getAuthorizationById(authz.id))?.status).toBe(
      "invalid"
    );
    expect((await database.getOrderById(order.id))?.status).toBe("invalid");
  });

  it("rejects a completion whose generation does not match the current claim", async () => {
    const { database, order, authz, challenge } = fixture;

    const generation = await database.claimChallengeForValidation(
      challenge.id,
      now,
      now - 60
    );
    expect(generation).toBe(1);

    expect(
      await database.completeChallengeValidationSuccess(
        challenge.id,
        99,
        authz.id,
        order.id,
        now
      )
    ).toBe(false);
    expect(
      await database.completeChallengeValidationFailure(
        challenge.id,
        99,
        authz.id,
        order.id,
        JSON.stringify({ type: "urn:ietf:params:acme:error:connection" })
      )
    ).toBe(false);

    expect((await database.getChallengeById(challenge.id))?.status).toBe(
      "processing"
    );
  });

  it("does not allow a second fresh claim to run concurrently", async () => {
    const { database, challenge } = fixture;

    expect(
      await database.claimChallengeForValidation(challenge.id, now, now - 60)
    ).toBe(1);
    expect(
      await database.claimChallengeForValidation(challenge.id, now + 1, now)
    ).toBeNull();
  });
});
