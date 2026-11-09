import { beforeEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import type { AcmeEnv } from "../src/config";
import { Database } from "../src/db/queries";
import { createMockD1Database } from "./mock-d1";
import { testAssets, testRateLimits } from "./website-test-helpers";
import { testContext } from "./acme-test-helpers";

function protectedEnv(api: () => Promise<{ success: boolean }>, accounts = api): AcmeEnv {
  return {
    ASSETS: testAssets,
    API_RATE_LIMITER: { limit: vi.fn(api) }, ACCOUNT_REGISTRATION_LIMITER: { limit: vi.fn(accounts) },
    get DB(): D1Database { throw new Error("Rejected request accessed D1"); },
  };
}

describe("pre-D1 ingress admission", () => {
  it.each([
    ["HEAD", "/new-nonce"], ["POST", "/new-account"], ["POST", "/new-order"], ["GET", "/missing"], ["DELETE", "/new-nonce"],
  ])("rejects limited %s %s before reading its body or database", async (method, path) => {
    const env = protectedEnv(async () => ({ success: false }));
    const body = new ReadableStream({ pull() { throw new Error("Read rejected JWS body"); } });
    const request = new Request(`https://acme.test${path}`, {
      method, headers: { "CF-Connecting-IP": "203.0.113.1", "Content-Type": "application/jose+json" },
      ...(method === "POST" ? { body, duplex: "half" as const } : {}),
    });
    const response = await worker.fetch(request, env, testContext);
    expect(response.status).toBe(429); expect(response.headers.get("Retry-After")).toBe("60");
    expect(response.headers.get("Replay-Nonce")).toBeNull();
    expect(env.API_RATE_LIMITER.limit).toHaveBeenCalledWith({ key: "203.0.113.1" });
  });

  it("limits account registration independently before parsing an invalid JWS", async () => {
    const env = protectedEnv(async () => ({ success: true }), async () => ({ success: false }));
    const response = await worker.fetch(new Request("https://acme.test/new-account", { method: "POST", body: "invalid" }), env, testContext);
    expect(response.status).toBe(429); expect(env.ACCOUNT_REGISTRATION_LIMITER.limit).toHaveBeenCalledOnce();
  });

  it.each(["missing", "failure"])("fails closed on %s bindings without reflecting their errors", async (mode) => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const env = protectedEnv(async () => { throw new Error("private internal binding data"); });
    if (mode === "missing") delete (env as Partial<AcmeEnv>).API_RATE_LIMITER;
    const response = await worker.fetch(new Request("https://acme.test/new-nonce"), env, testContext);
    expect(response.status).toBe(503); expect(response.headers.get("Replay-Nonce")).toBeNull();
    expect(await response.text()).not.toContain("private internal");
  });

  it("ignores client forwarded addresses and shares the fallback bucket when platform metadata is absent", async () => {
    const env = protectedEnv(async () => ({ success: false }));
    for (const address of ["1.1.1.1", "8.8.8.8"]) await worker.fetch(new Request("https://acme.test/missing", {
      headers: { "X-Forwarded-For": address, Forwarded: `for=${address}` },
    }), env, testContext);
    expect(vi.mocked(env.API_RATE_LIMITER.limit).mock.calls).toEqual([[{ key: "unknown-source" }], [{ key: "unknown-source" }]]);
  });

  it.each([["GET", "/directory"], ["HEAD", "/directory"], ["OPTIONS", "/new-account"]])(
    "keeps %s %s independent of admission and D1", async (method, path) => {
      const env = protectedEnv(async () => { throw new Error("Must bypass admission"); });
      const response = await worker.fetch(new Request(`https://acme.test${path}`, { method }), env, testContext);
      expect(response.status).toBeLessThan(300); expect(env.API_RATE_LIMITER.limit).not.toHaveBeenCalled();
    });
});

describe("expired nonce lifecycle", () => {
  let d1: D1Database; let db: Database;
  beforeEach(async () => { d1 = createMockD1Database(); db = new Database(d1); });

  it("runs scheduled cleanup using only the nonce table without schema initialization", async () => {
    const binding = createMockD1Database(false);
    await binding.exec("CREATE TABLE nonces (nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)");
    const database = new Database(binding);
    const now = Math.floor(Date.now() / 1000);
    await database.saveNonce("expired", now - 1);
    await database.saveNonce("live", now + 300);
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await worker.scheduled({} as ScheduledController, { ...testRateLimits, ASSETS: testAssets, DB: binding }, testContext);

    expect(log).toHaveBeenCalledWith(JSON.stringify({ event: "acme_nonce_cleanup", deleted: 1, backlog: false }));
    expect((await binding.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all()).results).toEqual([{ name: "nonces" }]);
    expect(await binding.prepare("SELECT nonce FROM nonces").all()).toMatchObject({ results: [{ nonce: "live" }] });
  });

  it("reports a missing schema with safe diagnostic context and still fails the scheduled invocation", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const event = { cron: "*/5 * * * *", scheduledTime: Date.now() } as ScheduledController;
    const binding = createMockD1Database(false);

    await expect(worker.scheduled(event, { ...testRateLimits, ASSETS: testAssets, DB: binding }, testContext))
      .rejects.toThrow(/Nonce cleanup failed \(schema; [a-f0-9-]+\)/);

    expect(JSON.parse(log.mock.calls[0][0])).toEqual({
      event: "acme_nonce_cleanup_failed", category: "schema", errorId: expect.any(String),
      cron: event.cron, scheduledTime: event.scheduledTime,
    });
  });

  it("does not expose raw database exceptions or their causes in logs or the thrown error", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(Database.prototype, "cleanupExpiredNonces").mockRejectedValue(
      new Error("private SQL and parameters", { cause: new Error("D1_ERROR: Network connection lost. private token") }),
    );

    const error = await worker.scheduled({} as ScheduledController, { ...testRateLimits, ASSETS: testAssets, DB: d1 }, testContext)
      .catch((error: Error) => error);

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toMatch(/Nonce cleanup failed \(unavailable; [a-f0-9-]+\)/);
    expect((error as Error).cause).toBeUndefined();
    expect(JSON.stringify(log.mock.calls)).not.toContain("private");
    expect(JSON.parse(log.mock.calls[0][0]).category).toBe("unavailable");
  });

  it("bounds each pass, reports backlog, and never removes live nonces", async () => {
    const now = Math.floor(Date.now() / 1000);
    await d1.prepare(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 1005)
      INSERT INTO nonces SELECT 'expired-' || i, ? FROM n`).bind(now).run();
    await db.saveNonce("live", now + 300);
    expect(await db.cleanupExpiredNonces(now, 1)).toEqual({ deleted: 1000, backlog: true });
    expect(await db.cleanupExpiredNonces(now, 1)).toEqual({ deleted: 5, backlog: false });
    expect(await db.cleanupExpiredNonces(now)).toEqual({ deleted: 0, backlog: false });
    expect(await db.consumeNonce("expired-1", now)).toBe(false);
    expect(await db.consumeNonce("live", now)).toBe(true);
    expect(await db.consumeNonce("live", now)).toBe(false);
  });

  it("enforces the scheduled 100-batch cap and logs remaining backlog", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const now = Math.floor(Date.now() / 1000);
    await d1.prepare(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 100001)
      INSERT INTO nonces SELECT 'expired-' || i, ? FROM n`).bind(now - 1).run();
    await db.saveNonce("live", now + 300);
    await worker.scheduled({} as ScheduledController, { ...testRateLimits, ASSETS: testAssets, DB: d1 }, testContext);
    expect(log).toHaveBeenCalledWith(JSON.stringify({ event: "acme_nonce_cleanup_backlog", deleted: 100000, backlog: true }));
    expect(await db.consumeNonce("live", now)).toBe(true);
    expect(await db.cleanupExpiredNonces(now)).toEqual({ deleted: 1, backlog: false });
  });
});
