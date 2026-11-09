import { isUniqueConstraintError } from "../src/db/errors";
import { describe, it, expect, beforeEach } from "vitest";
import { createMockD1Database } from "./mock-d1";
import { Database } from "../src/db/queries";
import {
  ensureAccountPublicKeyIndex,
  migrateAccountPublicKeyFingerprints,
} from "../src/db/account-keys";
import { calculateJwkThumbprint, normalizePublicKey } from "../src/crypto/jws";
import { AcmeEnv } from "../src/config";
import {
  ACME_BASE_URL,
  createTestEnvironment,
  getNonce,
  makeJwsRequest,
  TestEnvironment,
} from "./acme-test-helpers";
import {
  exportPublicJwk,
  generateAccountKeys,
  padBase64Url,
} from "./account-key-test-helpers";

const NOW = 1_700_000_000;

interface LegacyAccountInput {
  id: string;
  jwk: JsonWebKey | string;
  thumbprint: string;
  createdAt?: number;
  contact?: string | null;
  status?: "valid" | "deactivated" | "revoked";
}

async function createLegacyDatabase(
  accounts: LegacyAccountInput[]
): Promise<{ d1: D1Database; database: Database }> {
  const d1 = createMockD1Database();
  for (const account of accounts) {
    await d1
      .prepare(
        "INSERT INTO accounts (id, jwk, thumbprint, contact, status, created_at) VALUES (?, ?, ?, ?, ?, ?)"
      )
      .bind(
        account.id,
        typeof account.jwk === "string"
          ? account.jwk
          : JSON.stringify(account.jwk),
        account.thumbprint,
        account.contact ?? null,
        account.status ?? "valid",
        account.createdAt ?? NOW
      )
      .run();
  }
  const database = new Database(d1);
  return { d1, database };
}

async function tableColumns(d1: D1Database, table: string): Promise<string[]> {
  const result = await d1
    .prepare(`PRAGMA table_info(${table})`)
    .all<{ name: string }>();
  return (result.results || []).map((row) => row.name);
}

async function countRows(d1: D1Database, table: string): Promise<number> {
  const row = await d1
    .prepare(`SELECT COUNT(*) AS count FROM ${table}`)
    .first<{ count: number }>();
  return row?.count ?? 0;
}

describe("account public key fingerprint schema and migration", () => {
  it("creates the identity column, UNIQUE index, and conflict table on an empty database", async () => {
    const d1 = createMockD1Database();
    const database = new Database(d1);

    expect(await tableColumns(d1, "accounts")).toContain(
      "public_key_fingerprint"
    );
    const index = await database.accountFingerprintIndexInfo();
    expect(index?.sql?.toUpperCase()).toContain("UNIQUE");
    expect(await tableColumns(d1, "account_key_conflicts")).toEqual(
      expect.arrayContaining([
        "account_id",
        "reason",
        "public_key_fingerprint",
        "conflicting_account_id",
        "detected_at",
      ])
    );
    await migrateAccountPublicKeyFingerprints(database);
    await expect(ensureAccountPublicKeyIndex(database)).resolves.toBeUndefined();

    // The data migration remains idempotent.
    expect(await tableColumns(d1, "accounts")).toContain(
      "public_key_fingerprint"
    );
    await migrateAccountPublicKeyFingerprints(database);
    await expect(ensureAccountPublicKeyIndex(database)).resolves.toBeUndefined();
  });

  it("backfills legacy account data in the current schema without changing identity", async () => {
    const firstKeys = await generateAccountKeys("ES256");
    const firstJwk = await exportPublicJwk(firstKeys);
    const secondKeys = await generateAccountKeys("RS256");
    const secondJwk = await exportPublicJwk(secondKeys);
    const paddedRsa = {
      ...secondJwk,
      n: padBase64Url(secondJwk.n as string, 2),
      e: padBase64Url(secondJwk.e as string, 1),
    };

    const legacyInputs: LegacyAccountInput[] = [
      {
        id: "legacy-ec",
        jwk: firstJwk,
        thumbprint: await calculateJwkThumbprint(firstJwk),
        contact: JSON.stringify(["mailto:legacy@example.com"]),
      },
      {
        id: "legacy-rsa",
        jwk: paddedRsa,
        thumbprint: await calculateJwkThumbprint(paddedRsa),
        createdAt: NOW + 1,
      },
    ];
    const { d1, database } = await createLegacyDatabase(legacyInputs);

    expect(await tableColumns(d1, "accounts")).toContain(
      "public_key_fingerprint"
    );
    for (const input of legacyInputs) {
      const row = await database.getAccountById(input.id);
      // A nullable fingerprint is backfilled only by the explicit data migration.
      expect(row?.public_key_fingerprint ?? null).toBeNull();
    }

    const before = await Promise.all(
      legacyInputs.map((input) => database.getAccountById(input.id))
    );
    await migrateAccountPublicKeyFingerprints(database);
    await ensureAccountPublicKeyIndex(database);

    const expected = [
      {
        jwk: firstJwk,
        fingerprint: (await normalizePublicKey(firstJwk)).fingerprint,
      },
      {
        jwk: paddedRsa,
        fingerprint: (await normalizePublicKey(paddedRsa)).fingerprint,
      },
    ];

    for (let i = 0; i < legacyInputs.length; i++) {
      const after = await database.getAccountById(legacyInputs[i].id);
      expect(after?.public_key_fingerprint).toBe(expected[i].fingerprint);
      // Identity, stored protocol JWK, and RFC 7638 thumbprint are preserved.
      expect(after?.id).toBe(before[i]?.id);
      expect(after?.jwk).toBe(before[i]?.jwk);
      expect(after?.thumbprint).toBe(before[i]?.thumbprint);
      expect(after?.contact).toBe(before[i]?.contact);
      expect(after?.status).toBe(before[i]?.status);
      expect(after?.created_at).toBe(before[i]?.created_at);
    }
    expect(await countRows(d1, "accounts")).toBe(legacyInputs.length);

    // Re-running is idempotent and does not recompute/rewrite rows.
    const secondRun = await migrateAccountPublicKeyFingerprints(database);
    expect(secondRun).toMatchObject({
      scanned: 0,
      updated: 0,
      conflicts: 0,
      remaining: 0,
    });
    await migrateAccountPublicKeyFingerprints(database);
    await expect(ensureAccountPublicKeyIndex(database)).resolves.toBeUndefined();
  });

  it("detects historical duplicate actual public keys without deleting or rewriting accounts", async () => {
    const keys = await generateAccountKeys("ES256");
    const canonical = await exportPublicJwk(keys);
    const padded = {
      ...canonical,
      x: padBase64Url(canonical.x as string),
      y: padBase64Url(canonical.y as string),
    };

    const { d1, database } = await createLegacyDatabase([
      {
        id: "a-older-account",
        jwk: canonical,
        thumbprint: await calculateJwkThumbprint(canonical),
        createdAt: NOW,
      },
      {
        id: "b-newer-account",
        jwk: padded,
        thumbprint: await calculateJwkThumbprint(padded),
        createdAt: NOW,
      },
    ]);

    await migrateAccountPublicKeyFingerprints(database);
    await expect(ensureAccountPublicKeyIndex(database)).rejects.toMatchObject({
      type: "urn:ietf:params:acme:error:serverInternal",
    });

    expect(await countRows(d1, "accounts")).toBe(2);
    const older = await database.getAccountById("a-older-account");
    const newer = await database.getAccountById("b-newer-account");
    const expectedFingerprint = (await normalizePublicKey(canonical)).fingerprint;

    // Deterministic selection by created_at, id: the older row is indexed,
    // the newer duplicate is left unindexed and reported for review.
    expect(older?.public_key_fingerprint).toBe(expectedFingerprint);
    expect(newer?.public_key_fingerprint ?? null).toBeNull();
    expect(older?.thumbprint).toBe(await calculateJwkThumbprint(canonical));
    expect(newer?.thumbprint).toBe(await calculateJwkThumbprint(padded));

    const conflicts = await database.listAccountKeyConflicts();
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0]).toMatchObject({
      account_id: "b-newer-account",
      reason: "duplicate_public_key",
      public_key_fingerprint: expectedFingerprint,
      conflicting_account_id: "a-older-account",
    });
    // No JWK/private material is stored in the conflict row.
    expect(JSON.stringify(conflicts[0])).not.toContain("\"x\"");
    expect(JSON.stringify(conflicts[0])).not.toContain("\"n\"");

    // Repeated migration must not create duplicate conflict rows.
    const rerun = await migrateAccountPublicKeyFingerprints(database);
    expect(rerun.scanned).toBe(0);
    expect(await database.listAccountKeyConflicts()).toHaveLength(1);
    await migrateAccountPublicKeyFingerprints(database);
    await expect(ensureAccountPublicKeyIndex(database)).rejects.toMatchObject({
      type: "urn:ietf:params:acme:error:serverInternal",
    });

    // The UNIQUE index is real: the duplicate cannot be silently assigned the
    // same identity fingerprint.
    await expect(
      database.setAccountPublicKeyFingerprint(
        "b-newer-account",
        expectedFingerprint
      )
    ).rejects.toSatisfy(isUniqueConstraintError);

    // Simulate an administrator resolving the duplicate by removing the
    // duplicative account (production requires manual review, never automatic
    // deletion). Migration then completes.
    await d1.prepare("DELETE FROM accounts WHERE id = ?").bind("b-newer-account").run();
    await database.clearAccountKeyConflict("b-newer-account");
    await migrateAccountPublicKeyFingerprints(database);
    await expect(ensureAccountPublicKeyIndex(database)).resolves.toBeUndefined();
  });

  it("records invalid legacy JWKs and blocks unsafe operations until resolved", async () => {
    const { d1, database } = await createLegacyDatabase([
      {
        id: "broken-account",
        jwk: "{not-json",
        thumbprint: "B".repeat(43),
      },
    ]);

    await migrateAccountPublicKeyFingerprints(database);
    await expect(ensureAccountPublicKeyIndex(database)).rejects.toMatchObject({
      type: "urn:ietf:params:acme:error:serverInternal",
    });
    expect(await countRows(d1, "accounts")).toBe(1);

    const conflicts = await database.listAccountKeyConflicts();
    expect(conflicts).toEqual([
      expect.objectContaining({
        account_id: "broken-account",
        reason: "invalid_public_key",
        public_key_fingerprint: null,
      }),
    ]);
    expect((await database.getAccountById("broken-account"))?.public_key_fingerprint ?? null).toBeNull();

    // Administrator repairs the JWK, clears the stale conflict, and reruns.
    const repairedKeys = await generateAccountKeys("ES256");
    const repairedJwk = await exportPublicJwk(repairedKeys);
    await d1
      .prepare("UPDATE accounts SET jwk = ?, thumbprint = ? WHERE id = ?")
      .bind(
        JSON.stringify(repairedJwk),
        await calculateJwkThumbprint(repairedJwk),
        "broken-account"
      )
      .run();
    await database.clearAccountKeyConflict("broken-account");
    await migrateAccountPublicKeyFingerprints(database);
    await expect(ensureAccountPublicKeyIndex(database)).resolves.toBeUndefined();
    expect(
      (await database.getAccountById("broken-account"))?.public_key_fingerprint
    ).toBe((await normalizePublicKey(repairedJwk)).fingerprint);
  });

  it("preserves legacy authentication and key authorization material across migration", async () => {
    const testEnv: TestEnvironment = await createTestEnvironment();
    const env: AcmeEnv = testEnv.env;
    const database = testEnv.database;
    const keys = await generateAccountKeys("ES256");
    const canonical = await exportPublicJwk(keys);
    const padded = {
      ...canonical,
      x: padBase64Url(canonical.x as string),
      y: padBase64Url(canonical.y as string),
    };
    const legacyThumbprint = await calculateJwkThumbprint(padded);
    const accountId = crypto.randomUUID();
    const kid = `${ACME_BASE_URL}/account/${accountId}`;
    await database.saveAccount({
      id: accountId,
      jwk: JSON.stringify(padded),
      thumbprint: legacyThumbprint,
      contact: null,
      status: "valid",
      created_at: Math.floor(Date.now() / 1000),
    });

    // A legacy account with a NULL fingerprint can still authenticate, because
    // JWS verification uses the stored JWK/thumbprint rather than the index.
    const nonce = await getNonce(env);
    const auth = await makeJwsRequest(
      env,
      kid,
      "",
      { keys, jwk: padded, kid, alg: "ES256" },
      nonce
    );
    expect(auth.response.status).toBe(200);

    const keyAuthorizationBefore = `challenge-token.${legacyThumbprint}`;
    await migrateAccountPublicKeyFingerprints(database);
    await ensureAccountPublicKeyIndex(database);
    const migrated = await database.getAccountById(accountId);
    expect(migrated?.thumbprint).toBe(legacyThumbprint);
    expect(migrated?.jwk).toBe(JSON.stringify(padded));
    expect(`challenge-token.${migrated?.thumbprint}`).toBe(keyAuthorizationBefore);
    expect(migrated?.public_key_fingerprint).toBe(
      (await normalizePublicKey(canonical)).fingerprint
    );
  });

  it("fails closed when the named index is not a UNIQUE index on the fingerprint column", async () => {
    const d1 = createMockD1Database();
    const database = new Database(d1);

    await d1.exec(`
      DROP INDEX idx_accounts_public_key_fingerprint;
      CREATE UNIQUE INDEX idx_accounts_public_key_fingerprint ON accounts (id);
    `);

    await expect(ensureAccountPublicKeyIndex(database)).rejects.toMatchObject({
      type: "urn:ietf:params:acme:error:serverInternal",
    });
  });

  it("enforces the UNIQUE fingerprint index for direct duplicate writes", async () => {
    const d1 = createMockD1Database();
    const database = new Database(d1);

    const firstKeys = await generateAccountKeys("ES256");
    const secondKeys = await generateAccountKeys("ES256");
    const firstJwk = await exportPublicJwk(firstKeys);
    const secondJwk = await exportPublicJwk(secondKeys);
    const fingerprint = (await normalizePublicKey(firstJwk)).fingerprint;

    await database.saveAccount({
      id: "first",
      jwk: JSON.stringify(firstJwk),
      thumbprint: await calculateJwkThumbprint(firstJwk),
      public_key_fingerprint: fingerprint,
      contact: null,
      status: "valid",
      created_at: NOW,
    });
    await database.saveAccount({
      id: "second",
      jwk: JSON.stringify(secondJwk),
      thumbprint: await calculateJwkThumbprint(secondJwk),
      public_key_fingerprint: null,
      contact: null,
      status: "valid",
      created_at: NOW,
    });

    await expect(
      d1
        .prepare("UPDATE accounts SET public_key_fingerprint = ? WHERE id = ?")
        .bind(fingerprint, "second")
        .run()
    ).rejects.toSatisfy(isUniqueConstraintError);

    await expect(
      database.saveAccount({
        id: "third",
        jwk: JSON.stringify(secondJwk),
        thumbprint: "C".repeat(43),
        public_key_fingerprint: fingerprint,
        contact: null,
        status: "valid",
        created_at: NOW,
      })
    ).rejects.toSatisfy(isUniqueConstraintError);
  });
});
