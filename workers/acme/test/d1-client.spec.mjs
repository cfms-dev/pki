import { afterEach, describe, expect, it, vi } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { d1Client } from "../scripts/d1-client.mjs";
import { Database } from "../src/db/queries";
import { migrateAccountPublicKeyFingerprints } from "../src/db/account-keys";

afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); });

describe("D1 management API adapter", () => {
  it("uses the documented batch envelope and resumes a legacy key migration", async () => {
    vi.stubEnv("CLOUDFLARE_ACCOUNT_ID", "account");
    vi.stubEnv("CLOUDFLARE_D1_DATABASE_ID", "database");
    vi.stubEnv("CLOUDFLARE_API_TOKEN", "test-token");
    const sqlite = new DatabaseSync(":memory:");
    sqlite.exec("CREATE TABLE accounts (id TEXT PRIMARY KEY, jwk TEXT NOT NULL, thumbprint TEXT UNIQUE NOT NULL, contact TEXT, status TEXT NOT NULL, created_at INTEGER NOT NULL)");
    const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    sqlite.prepare("INSERT INTO accounts VALUES (?, ?, ?, NULL, 'valid', 1)").run("legacy", JSON.stringify(await crypto.subtle.exportKey("jwk", keys.publicKey)), "legacy-thumbprint");
    let batches = 0;
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      expect(Array.isArray(body)).toBe(false);
      const statements = body.batch ?? [body];
      if (body.batch) batches++;
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
      await database.initSchema();
      expect(batches).toBeGreaterThan(0);
      const summary = await migrateAccountPublicKeyFingerprints(database);
      expect(summary).toMatchObject({ updated: 1, remaining: 0 });
      expect(await migrateAccountPublicKeyFingerprints(database)).toMatchObject({ scanned: 0, remaining: 0 });
      expect((await database.getAccountById("legacy")).thumbprint).toBe("legacy-thumbprint");
    } finally { sqlite.close(); }
  });
});
