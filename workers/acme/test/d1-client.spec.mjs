import { readMigrations } from "../scripts/migrations.mjs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { d1Client } from "../scripts/d1-client.mjs";
import { Database } from "../src/db/queries";
import { migrateAccountPublicKeyFingerprints } from "../src/db/account-keys";
import { isUniqueConstraintError } from "../src/db/errors";

afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); });

describe("D1 management API adapter", () => {
  it("maps Drizzle results, batches and errors and resumes an account data backfill", async () => {
    vi.stubEnv("CLOUDFLARE_ACCOUNT_ID", "account");
    vi.stubEnv("CLOUDFLARE_D1_DATABASE_ID", "database");
    vi.stubEnv("CLOUDFLARE_API_TOKEN", "test-token");
    const sqlite = new DatabaseSync(":memory:");
    for (const migration of readMigrations()) sqlite.exec(migration.sql);
    const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    sqlite.prepare("INSERT INTO accounts (id, jwk, thumbprint, status, created_at) VALUES (?, ?, ?, 'valid', 1)").run("legacy", JSON.stringify(await crypto.subtle.exportKey("jwk", keys.publicKey)), "legacy-thumbprint");

    vi.stubGlobal("fetch", vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      expect(Array.isArray(body)).toBe(false);
      const statements = body.batch ?? [body];

      sqlite.exec("BEGIN");
      try {
        const result = statements.map(({ sql, params }) => {
          const statement = sqlite.prepare(sql);
          const before = sqlite.prepare("SELECT total_changes() AS n").get().n;
          const results = statement.all(...params);
          const changes = sqlite.prepare("SELECT total_changes() AS n").get().n - before;
          return { success: true, results, meta: { changes } };
        });
        sqlite.exec("COMMIT");
        return Response.json({ success: true, result });
      } catch (error) {
        sqlite.exec("ROLLBACK");
        return Response.json({ success: false, errors: [{ message: error.message }] });
      }
    }));
    try {
      const database = new Database(d1Client());
      const adapter = d1Client();
      expect(await adapter.prepare("SELECT 2 AS second, 1 AS first").raw()).toEqual([[2, 1]]);
      expect(await adapter.prepare("SELECT id FROM accounts WHERE id = ?").bind("missing").raw()).toEqual([]);
      expect(await adapter.prepare("UPDATE accounts SET contact = ? WHERE id = ? RETURNING contact")
        .bind("contact", "legacy").raw()).toEqual([["contact"]]);
      const batch = await adapter.batch([
        adapter.prepare("INSERT INTO nonces VALUES (?, ?)").bind("rest-nonce", 2),
        adapter.prepare("SELECT nonce FROM nonces"),
      ]);
      expect(batch[0].meta.changes).toBe(1);
      expect(batch[1].results).toEqual([{ nonce: "rest-nonce" }]);
      await expect(adapter.batch([
        adapter.prepare("DELETE FROM nonces"),
        adapter.prepare("INSERT INTO accounts (id, jwk, thumbprint, status, created_at) VALUES ('legacy', '{}', 'duplicate', 'valid', 1)"),
      ])).rejects.toThrow("UNIQUE constraint failed");
      expect(await adapter.prepare("SELECT nonce FROM nonces").first("nonce")).toBe("rest-nonce");
      const summary = await migrateAccountPublicKeyFingerprints(database);
      expect(summary).toMatchObject({ updated: 1, remaining: 0 });
      expect(await migrateAccountPublicKeyFingerprints(database)).toMatchObject({ scanned: 0, remaining: 0 });
      expect((await database.getAccountById("legacy")).thumbprint).toBe("legacy-thumbprint");
      expect(await database.getAccountById("missing")).toBeNull();
      await expect(database.saveAccount({ id: "legacy", jwk: "{}", thumbprint: "duplicate", status: "valid", created_at: 1 }))
        .rejects.toSatisfy(isUniqueConstraintError);
      vi.stubGlobal("fetch", async () => new Response("private remote error", { status: 503 }));
      await expect(adapter.prepare("SELECT 1").raw()).rejects.toThrow("D1 query failed (HTTP 503)");
    } finally { sqlite.close(); }
  });
});
