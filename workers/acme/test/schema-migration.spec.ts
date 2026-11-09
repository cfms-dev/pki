import { describe, it, expect } from "vitest";
import { createMockD1Database } from "./mock-d1";
import { Database } from "../src/db/queries";
import { AuthorizationRow, OrderRow } from "../src/db/types";
import { ensureChallengesForAuthorization } from "../src/acme/challenges";

const now = 1_700_000_000;

function makeOrder(id: string, domain: string, status: OrderRow["status"]): OrderRow {
  return {
    id,
    account_id: "account-1",
    status,
    identifiers: JSON.stringify([domain]),
    not_before: null,
    not_after: null,
    replaces_cert_id: null,
    is_ari_renewal: 0,
    created_at: now,
    expires_at: now + 3600,
    certificate_id: null, processing_started_at: null, finalize_generation: 0,
  };
}

function makeAuthz(
  id: string,
  orderId: string,
  domain: string,
  status: AuthorizationRow["status"]
): AuthorizationRow {
  return {
    id,
    order_id: orderId,
    identifier_value: domain,
    identifier_type: "dns",
    status,
    token: "t".repeat(22),
    expires_at: now + 3600,
    created_at: now,
  };
}

describe("legacy order compatibility", () => {
  it("lazily creates both challenges for a pending legacy authorization", async () => {
    const database = new Database(createMockD1Database());

    const order = makeOrder("legacy-order", "legacy.example.com", "pending");
    const authz = makeAuthz(
      "legacy-authz",
      order.id,
      "legacy.example.com",
      "pending"
    );
    await database.saveOrder(order);
    await database.saveAuthorization(authz);

    const first = await ensureChallengesForAuthorization(database, authz);
    expect(first.map((challenge) => challenge.type)).toEqual([
      "dns-01",
      "http-01",
    ]);
    expect(first.every((challenge) => challenge.validation_generation === 0)).toBe(
      true
    );

    // Re-reading must not duplicate or replace the rows.
    const second = await ensureChallengesForAuthorization(database, authz);
    expect(second.map((challenge) => challenge.id).sort()).toEqual(
      first.map((challenge) => challenge.id).sort()
    );
  });

  it("offers only dns-01 for a pending legacy wildcard authorization", async () => {
    const database = new Database(createMockD1Database());

    const order = makeOrder("wildcard-order", "*.example.com", "pending");
    const authz = makeAuthz(
      "wildcard-authz",
      order.id,
      "*.example.com",
      "pending"
    );
    await database.saveOrder(order);
    await database.saveAuthorization(authz);

    const challenges = await ensureChallengesForAuthorization(database, authz);
    expect(challenges.map((challenge) => challenge.type)).toEqual(["dns-01"]);
  });

  it("preserves a valid legacy authorization as a valid dns-01 challenge", async () => {
    const database = new Database(createMockD1Database());

    const order = makeOrder("valid-order", "valid.example.com", "ready");
    const authz = makeAuthz("valid-authz", order.id, "valid.example.com", "valid");
    await database.saveOrder(order);
    await database.saveAuthorization(authz);

    const challenges = await ensureChallengesForAuthorization(database, authz);
    expect(challenges).toHaveLength(1);
    expect(challenges[0].type).toBe("dns-01");
    expect(challenges[0].status).toBe("valid");

    // Finalize's CAA check must fall back to the only method that existed for
    // legacy authorizations.
    expect(await database.getValidChallengeTypesByOrderId(order.id)).toEqual([
      { identifier_value: "valid.example.com", type: "dns-01" },
    ]);
  });

  it("records an invalid legacy authorization as an invalid dns-01 challenge", async () => {
    const database = new Database(createMockD1Database());

    const order = makeOrder("invalid-order", "invalid.example.com", "invalid");
    const authz = makeAuthz(
      "invalid-authz",
      order.id,
      "invalid.example.com",
      "invalid"
    );
    await database.saveOrder(order);
    await database.saveAuthorization(authz);

    const challenges = await ensureChallengesForAuthorization(database, authz);
    expect(challenges).toHaveLength(1);
    expect(challenges[0].type).toBe("dns-01");
    expect(challenges[0].status).toBe("invalid");
  });
});
