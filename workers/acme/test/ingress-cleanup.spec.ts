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
  beforeEach(async () => { d1 = createMockD1Database(); db = new Database(d1); await db.initSchema(); });

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
