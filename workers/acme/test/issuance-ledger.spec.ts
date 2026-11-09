import { beforeEach, describe, expect, it } from "vitest";
import { CONFIG } from "../src/config";
import { Database } from "../src/db/queries";
import type { CertificateRow, OrderRow } from "../src/db/types";
import { issuanceBuckets } from "../src/ratelimit/issuance";
import { createMockD1Database } from "./mock-d1";
import { ACME_BASE_URL, createOrder, createTestEnvironment, getNonce, makeCsr, makeJwsRequest, registerAccount } from "./acme-test-helpers";

const now = 1800000000;
let d1: D1Database;
let db: Database;

beforeEach(async () => {
  d1 = createMockD1Database(); db = new Database(d1);
  await db.saveAccount({ id: "owner", jwk: "{}", thumbprint: "owner", contact: null, status: "valid", created_at: now });
});

async function ready(names = ["victim.example.com"], predecessor: string | null = null) {
  const id = crypto.randomUUID();
  const cert: CertificateRow = {
      ca_id: null,
    id: crypto.randomUUID(), cert_id: crypto.randomUUID(), serial_number: "01", aki: "01", subject: "CN=test",
    san: JSON.stringify(names), pem: "test-public-certificate", not_before: now, not_after: now + 86400,
    account_id: "owner", created_at: now, revoked_at: null, revocation_reason: null, replaced_by_cert_id: null,
  };
  const order: OrderRow = { id, account_id: "owner", status: "ready", identifiers: cert.san,
    not_before: null, not_after: null, replaces_cert_id: predecessor, is_ari_renewal: predecessor ? 1 : 0,
    created_at: now, expires_at: now + 3600, certificate_id: null, processing_started_at: null, finalize_generation: 0 };
  await db.saveOrder(order);
  for (const name of names) await db.saveAuthorization({ id: crypto.randomUUID(), order_id: id,
    identifier_value: name, identifier_type: "dns", status: "valid", token: "test", expires_at: now + 3600, created_at: now });
  const generation = (await db.claimOrderForFinalize(id, now))!;
  return { id, cert, generation, complete: () => db.completeOrder(id, generation, cert, predecessor, now) };
}

async function count() {
  return (await d1.prepare("SELECT COUNT(*) AS n FROM issuance_ledger").first<{ n: number }>())!.n;
}

describe("atomic successful-issuance accounting", () => {
  it("does not let unverified or invalid attacker orders consume another account's budget", async () => {
    const context = await createTestEnvironment();
    const attacker = await registerAccount(context.env); const victim = await registerAccount(context.env);
    for (let i = 0; i < 51; i++) {
      const order = await createOrder(context.env, attacker, [{ type: "dns", value: "victim.example.com" }]);
      expect(order.response.status).toBe(201);
      if (i % 2 === 0) await context.database.updateOrderStatus(order.response.headers.get("Location")!.split("/").pop()!, "invalid");
    }
    const victimOrder = await createOrder(context.env, victim, [{ type: "dns", value: "victim.example.com" }]);
    expect(victimOrder.response.status).toBe(201);
    expect((await context.d1.prepare("SELECT COUNT(*) AS n FROM issuance_ledger").first<{ n: number }>())!.n).toBe(0);
    const id = victimOrder.response.headers.get("Location")!.split("/").pop()!;
    await context.d1.prepare("UPDATE authorizations SET status = 'valid' WHERE order_id = ?").bind(id).run();
    context.env.fetch = async () => Response.json({ Status: 0, Answer: [] });
    const issued = await makeJwsRequest(context.env, `${ACME_BASE_URL}/order/${id}/finalize`,
      { csr: await makeCsr(["victim.example.com"]) }, victim, await getNonce(context.env));
    expect(issued.response.status).toBe(200);
    expect((await context.d1.prepare("SELECT COUNT(*) AS n FROM issuance_ledger").first<{ n: number }>())!.n).toBe(2);
  });

  it("returns HTTP 429 with Retry-After and leaves the blocked order retryable", async () => {
    CONFIG.RATE_LIMIT_DUPLICATE_CERTS = 1;
    const context = await createTestEnvironment(); const owner = await registerAccount(context.env);
    context.env.fetch = async () => Response.json({ Status: 0, Answer: [] });
    for (const status of [200, 429]) {
      const order = await createOrder(context.env, owner, [{ type: "dns", value: "victim.example.com" }]);
      expect(order.response.status).toBe(201);
      const id = order.response.headers.get("Location")!.split("/").pop()!;
      await context.d1.prepare("UPDATE authorizations SET status = 'valid' WHERE order_id = ?").bind(id).run();
      const finalized = await makeJwsRequest(context.env, `${ACME_BASE_URL}/order/${id}/finalize`,
        { csr: await makeCsr(["victim.example.com"]) }, owner, await getNonce(context.env));
      expect(finalized.response.status).toBe(status);
      if (status === 429) {
        expect(Number(finalized.response.headers.get("Retry-After"))).toBeGreaterThan(0);
        expect((await context.database.getOrderById(id))?.status).toBe("ready");
        expect(finalized.response.headers.get("Replay-Nonce")).not.toBeNull();
      }
    }
  });

  it("charges a successful certificate once and retains the charge after revocation", async () => {
    const order = await ready(["a.example.com", "b.example.com"]);
    expect(await order.complete()).toBe(true);
    expect(await count()).toBe(2); // one group and one exact set
    await db.revokeCertificate(order.cert.cert_id, now, "keyCompromise");
    expect(await order.complete()).toBe(false);
    expect(await count()).toBe(2);
  });

  it("enforces duplicate limits on commit and returns the rolling-window retry time", async () => {
    CONFIG.RATE_LIMIT_DUPLICATE_CERTS = 2;
    expect(await (await ready()).complete()).toBe(true);
    expect(await (await ready()).complete()).toBe(true);
    const blocked = await ready();
    await expect(blocked.complete()).rejects.toMatchObject({ status: 429, extraHeaders: { "Retry-After": "604800" } });
    expect(await db.getCertificateById(blocked.cert.id)).toBeNull();
    expect(await count()).toBe(4);
    await expect(db.assertIssuanceCapacity(issuanceBuckets(["victim.example.com"]), now + 604800)).resolves.toBeUndefined();
  });

  it("serializes concurrent commits competing for the last registered-domain slot", async () => {
    CONFIG.RATE_LIMIT_CERTS_PER_DOMAIN = 1;
    const first = await ready(["a.example.com"]); const second = await ready(["b.example.com"]);
    const results = await Promise.allSettled([first.complete(), second.complete()]);
    expect(results.filter((r) => r.status === "fulfilled" && r.value === true)).toHaveLength(1);
    expect(results.filter((r) => r.status === "rejected" && r.reason.status === 429)).toHaveLength(1);
    expect(await count()).toBe(2);
  });

  it("rolls back every bucket if a later write fails and charges only on retry success", async () => {
    const order = await ready(["a.example.com", "b.example.net"]);
    await d1.exec("CREATE TRIGGER fail_order BEFORE UPDATE OF certificate_id ON orders WHEN NEW.certificate_id IS NOT NULL BEGIN SELECT RAISE(ABORT, 'test rollback'); END");
    await expect(order.complete()).rejects.toThrow("test rollback");
    expect(await count()).toBe(0); expect(await db.getCertificateById(order.cert.id)).toBeNull();
    await d1.exec("DROP TRIGGER fail_order");
    expect(await order.complete()).toBe(true); expect(await count()).toBe(3);
  });

  it("does not charge expired orders or stale finalize generations", async () => {
    const order = await ready();
    expect(await db.completeOrder(order.id, order.generation + 1, order.cert, null, now)).toBe(false);
    expect(await db.completeOrder(order.id, order.generation, order.cert, null, now + 3600)).toBe(false);
    expect(await count()).toBe(0);
  });

  it("exempts ARI replacements but allows only one replacement", async () => {
    CONFIG.RATE_LIMIT_CERTS_PER_DOMAIN = 1;
    const original = await ready(); expect(await original.complete()).toBe(true);
    const first = await ready(undefined, original.cert.cert_id); const second = await ready(undefined, original.cert.cert_id);
    expect(await first.complete()).toBe(true); expect(await second.complete()).toBe(false);
    expect(await count()).toBe(2);
  });
});

describe("issuance accounting readiness", () => {
  it("fails closed if its ledger initialization marker is missing", async () => {
    const order = await ready();
    await d1.exec("DELETE FROM security_migrations");
    await expect(db.ensureIssuanceLedgerReady()).rejects.toMatchObject({ status: 503 });
    await expect(order.complete()).rejects.toMatchObject({ status: 503 });
    expect(await count()).toBe(0);
    expect(await db.getCertificateById(order.cert.id)).toBeNull();
  });
});
