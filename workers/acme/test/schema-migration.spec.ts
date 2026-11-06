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
    certificate_id: null,
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
    status,
    token: "t".repeat(22),
    expires_at: now + 3600,
    created_at: now,
  };
}

async function challengeColumns(d1: D1Database): Promise<string[]> {
  const result = await d1
    .prepare("PRAGMA table_info(challenges)")
    .all<{ name: string }>();
  return (result.results || []).map((row) => row.name);
}

describe("challenges table deployment migration", () => {
  it("creates the challenges table with a generation column for a pre-HTTP-01 database", async () => {
    const d1 = createMockD1Database();
    // Minimal pre-existing schema: no challenges table and no
    // accounts.terms_of_service column.
    await d1.exec(`
      CREATE TABLE accounts (
        id TEXT PRIMARY KEY,
        jwk TEXT NOT NULL,
        thumbprint TEXT UNIQUE NOT NULL,
        contact TEXT,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
    `);

    const database = new Database(d1);
    await database.initSchema();

    expect(await challengeColumns(d1)).toContain("validation_generation");

    // The new column must be usable through the normal insert path.
    await database.saveChallenge({
      id: "challenge-1",
      authorization_id: "authz-1",
      type: "http-01",
      token: "t".repeat(22),
      status: "pending",
      error: null,
      validated_at: null,
      processing_started_at: null,
      validation_generation: 0,
      created_at: now,
    });
    expect((await database.getChallengeById("challenge-1"))?.validation_generation).toBe(
      0
    );
  });

  it("adds the generation column to a challenges table created by an earlier deployment", async () => {
    const d1 = createMockD1Database();
    await d1.exec(`
      CREATE TABLE challenges (
        id TEXT PRIMARY KEY,
        authorization_id TEXT NOT NULL,
        type TEXT NOT NULL,
        token TEXT NOT NULL,
        status TEXT NOT NULL,
        error TEXT,
        validated_at INTEGER,
        processing_started_at INTEGER,
        created_at INTEGER NOT NULL,
        UNIQUE (authorization_id, type)
      );
      INSERT INTO challenges (id, authorization_id, type, token, status, created_at)
      VALUES ('old-challenge', 'old-authz', 'dns-01', '${"t".repeat(22)}', 'pending', ${now});
    `);

    const database = new Database(d1);
    await database.initSchema();
    expect(await challengeColumns(d1)).toContain("validation_generation");

    // Rows that predate the column are backfilled by the DEFAULT 0 and can be
    // claimed normally.
    expect((await database.getChallengeById("old-challenge"))?.validation_generation).toBe(
      0
    );
    expect(
      await database.claimChallengeForValidation("old-challenge", now, now - 60)
    ).toBe(1);

    // initSchema must be idempotent, including the ALTER TABLE migration.
    await database.initSchema();
    expect(await challengeColumns(d1)).toContain("validation_generation");
  });
});

describe("legacy order compatibility", () => {
  it("lazily creates both challenges for a pending legacy authorization", async () => {
    const database = new Database(createMockD1Database());
    await database.initSchema();

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
    await database.initSchema();

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
    await database.initSchema();

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
    await database.initSchema();

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
