import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as x509 from "@peculiar/x509";
import { CONFIG } from "../src/config";
import worker from "../src/index";
import { normalizePublicKey } from "../src/crypto/jws";
import { importCaPrivateKey } from "../src/crypto/ca";
import { generateRandomSerialNumberHex, issueCertificateFromCsr, parseAndVerifyCsr } from "../src/crypto/x509";
import { base64UrlEncode } from "../src/crypto/nonce";
import { validateCaa } from "../src/dns/caa";
import { validateDns01Challenge } from "../src/dns/validator";
import { ensureAccountPublicKeyIndex, migrateAccountPublicKeyFingerprints } from "../src/db/account-keys";
import { CertificateRow } from "../src/db/types";
import {
  ACME_BASE_URL as BASE, createTestEnvironment, getNonce, makeJwsRequest,
  registerAccount, makeCsr, TestAccount, TestEnvironment, testContext,
} from "./acme-test-helpers";

let context: TestEnvironment;
let owner: TestAccount;
const keys = () => crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;

beforeEach(async () => { context = await createTestEnvironment(); owner = await registerAccount(context.env); });
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

async function certificate(domains = ["victim.example.com"]) {
  const pair = await keys();
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: `CN=${domains[0]}`, keys: pair, signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: [new x509.SubjectAlternativeNameExtension(domains.map((value) => ({ type: "dns" as const, value })))],
  });
  const issued = await issueCertificateFromCsr((await parseAndVerifyCsr(base64UrlEncode(csr.rawData))).csr, domains, context.env);
  const row: CertificateRow = {
    id: crypto.randomUUID(), cert_id: issued.certId, serial_number: issued.serialNumber, aki: issued.aki,
    subject: issued.subject, san: JSON.stringify(domains), pem: issued.chainPem, not_before: issued.notBefore,
    not_after: issued.notAfter, account_id: owner.kid.split("/").pop()!, created_at: issued.notBefore,
    revoked_at: null, revocation_reason: null, replaced_by_cert_id: null, ca_id: issued.caId,
  };
  const leaf = new x509.X509Certificate(issued.leafPem);
  const signer: TestAccount = { keys: pair, jwk: await crypto.subtle.exportKey("jwk", pair.publicKey) as JsonWebKey, kid: "", thumbprint: "" };
  return { row, leaf, signer, der: base64UrlEncode(leaf.rawData) };
}

async function revoke(der: string, account: TestAccount, mode: "kid" | "jwk" = "kid", reason?: unknown) {
  return (await makeJwsRequest(context.env, `${BASE}/revoke-cert`, { certificate: der, ...(reason === undefined ? {} : { reason }) },
    account, await getNonce(context.env), mode)).response;
}

async function readyOrder(id = crypto.randomUUID(), predecessor: string | null = null, domains = ["victim.example.com"]) {
  const now = Math.floor(Date.now() / 1000);
  await context.database.saveOrder({ id, account_id: owner.kid.split("/").pop()!, status: "ready", identifiers: JSON.stringify(domains),
    not_before: null, not_after: null, replaces_cert_id: predecessor, is_ari_renewal: predecessor ? 1 : 0,
    created_at: now, expires_at: now + 3600, certificate_id: null });
  for (const domain of domains) await context.database.saveAuthorization({ id: crypto.randomUUID(), order_id: id,
    identifier_value: domain, status: "valid", token: "token", created_at: now, expires_at: now + 3600 });
  return id;
}

describe("certificate revocation authorization", () => {
  it("rejects unrelated accounts and unrelated public keys without changing the certificate", async () => {
    const cert = await certificate(); await context.database.saveCertificate(cert.row);
    const attacker = await registerAccount(context.env);
    expect((await revoke(cert.der, attacker)).status).toBe(403);
    expect((await revoke(cert.der, attacker, "jwk")).status).toBe(403);
    expect((await context.database.getCertificateById(cert.row.id))?.revoked_at).toBeNull();
  });
  it.each(["kid", "jwk"] as const)("accepts the legitimate %s signer and serializes duplicate revocations", async (mode) => {
    const cert = await certificate(); await context.database.saveCertificate(cert.row);
    const results = await Promise.all([revoke(cert.der, mode === "kid" ? owner : cert.signer, mode), revoke(cert.der, mode === "kid" ? owner : cert.signer, mode)]);
    expect(results.map((result) => result.status).sort()).toEqual([200, 400]);
    const row = await context.database.getCertificateById(cert.row.id);
    expect(row?.revoked_at).not.toBeNull(); expect(row?.revocation_reason).toBe("unspecified");
  });
  it("requires valid authorizations for every certificate name", async () => {
    const cert = await certificate(["one.example.com", "two.example.com"]); await context.database.saveCertificate(cert.row);
    const attacker = await registerAccount(context.env);
    const orderId = await readyOrder(undefined, null, ["one.example.com"]);
    await context.d1.prepare("UPDATE orders SET account_id = ? WHERE id = ?").bind(attacker.kid.split("/").pop(), orderId).run();
    expect((await revoke(cert.der, attacker)).status).toBe(403);
    const now = Math.floor(Date.now() / 1000);
    await context.database.saveAuthorization({ id: crypto.randomUUID(), order_id: orderId, identifier_value: "two.example.com", status: "valid", token: "token", created_at: now, expires_at: now + 300 });
    expect((await revoke(cert.der, attacker)).status).toBe(200);
  });
  it("rejects a forged certificate with the original AKI and serial", async () => {
    const cert = await certificate(); await context.database.saveCertificate(cert.row);
    const pair = await keys();
    const forged = await x509.X509CertificateGenerator.create({ serialNumber: cert.leaf.serialNumber,
      subject: cert.leaf.subject, issuer: cert.leaf.issuer, notBefore: cert.leaf.notBefore, notAfter: cert.leaf.notAfter,
      publicKey: pair.publicKey, signingKey: pair.privateKey, signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [cert.leaf.getExtension(x509.AuthorityKeyIdentifierExtension)!] });
    expect((await revoke(base64UrlEncode(forged.rawData), owner)).status).toBe(404);
  });
  it.each(["1", -1, 7, 8, 1.5, null])("rejects invalid revocation reason %j", async (reason) => {
    const cert = await certificate(); await context.database.saveCertificate(cert.row);
    const response = await revoke(cert.der, owner, "kid", reason);
    expect(response.status).toBe(400); expect((await response.json() as { type: string }).type).toContain("badRevocationReason");
  });
});

describe("JWS request boundaries", () => {
  async function signed(path: string, overrides: Record<string, unknown> = {}, payload: unknown = {}, contentType = "application/jose+json") {
    const url = `${BASE}${path}`;
    const header = { alg: "ES256", nonce: await getNonce(context.env), url, ...(path === "/new-account" ? { jwk: owner.jwk } : { kid: owner.kid }), ...overrides };
    const protectedB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify(header)));
    const payloadB64 = payload === "" ? "" : base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
    const signature = base64UrlEncode(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, owner.keys.privateKey,
      new TextEncoder().encode(`${protectedB64}.${payloadB64}`)));
    return worker.fetch(new Request(url, { method: "POST", headers: { "Content-Type": contentType }, body: JSON.stringify({ protected: protectedB64, payload: payloadB64, signature }) }), context.env, testContext);
  }
  it.each(["https://foreign.example/new-account", `${BASE}/prefix/new-account`, `${BASE}/new-account?x=1`, "http://acme.test/new-account", "https://acme.test:8443/new-account"])("rejects mismatched signed URL %s", async (url) => {
    expect((await signed("/new-account", { url })).status).toBe(400);
  });
  it("rejects a foreign kid even when its last path segment identifies a real account", async () => {
    expect((await signed("/new-order", { kid: owner.kid.replace(BASE, "https://foreign.example") }, { identifiers: [{ type: "dns", value: "example.com" }] })).status).toBe(400);
  });
  it.each([{ crit: ["custom"] }, { b64: false }])("rejects unsupported protected extensions %j", async (headers) => {
    expect((await signed("/new-account", headers)).status).toBe(400);
  });
  it.each([null, [], 42, "payload"])("rejects a non-object payload %j", async (payload) => {
    expect((await signed("/new-account", {}, payload)).status).toBe(400);
  });
  it("rejects non-empty POST-as-GET and oversized input", async () => {
    expect((await signed("/order/nonexistent")).status).toBe(400);
    expect((await signed("/new-account", {}, { data: "x".repeat(65536) })).status).toBe(413);
    expect((await signed("/new-account", {}, {}, "application/json")).status).toBe(415);
  });
  it("rejects 1024-bit RSA account keys", async () => {
    const pair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
    await expect(normalizePublicKey(await crypto.subtle.exportKey("jwk", pair.publicKey))).rejects.toThrow("2048");
  });
});

describe("DNS failures never authorize issuance", () => {
  it.each([{ Status: 2 }, { Status: 3 }, {}, { Status: 0, Answer: {} }, { Status: 0, Answer: [{ type: 257, data: "malformed" }] }])("fails closed for %j", async (body) => {
    const fetcher = vi.fn(async () => Response.json(body));
    await expect(validateCaa("example.com", undefined, fetcher)).rejects.toMatchObject({ type: "urn:ietf:params:acme:error:dns" });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it("allows successful empty answers and recovers only transport failures", async () => {
    const fetcher = vi.fn(async (input) => {
      if (String(input).startsWith("https://cloudflare")) throw new Error("offline");
      return Response.json({ Status: 0 });
    });
    expect((await validateCaa("example.com", undefined, fetcher)).valid).toBe(true);
  });
  it("rejects total resolver failure, alias cycles and oversized answers", async () => {
    await expect(validateCaa("example.com", undefined, async () => { throw new Error("offline"); })).rejects.toThrow();
    await expect(validateCaa("example.com", undefined, async () => Response.json({ Status: 0, Answer: [{ type: 5, data: "example.com." }] }))).rejects.toThrow("cycle");
    await expect(validateDns01Challenge("example.com", "token", "thumbprint", async () => new Response("x".repeat(65537)))).rejects.toThrow("64 KiB");
  });
  it("bounds a resolver that ignores cancellation", async () => {
    vi.useFakeTimers();
    const pending = validateCaa("example.com", undefined, () => new Promise(() => {}));
    const rejected = expect(pending).rejects.toThrow();
    await vi.advanceTimersByTimeAsync(20001);
    await rejected;
  });
});

describe("migration and issuance fencing", () => {
  it("never backfills legacy keys in a public request", async () => {
    const pair = await keys(); const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    await context.database.saveAccount({ id: "legacy", jwk: JSON.stringify(jwk), thumbprint: "legacy", contact: null, status: "valid", created_at: 1 });
    await expect(ensureAccountPublicKeyIndex(context.database)).rejects.toMatchObject({ status: 503 });
    expect((await context.database.getAccountById("legacy"))?.public_key_fingerprint).toBeNull();
    await migrateAccountPublicKeyFingerprints(context.database);
    await expect(ensureAccountPublicKeyIndex(context.database)).resolves.toBeUndefined();
  });
  it("rejects a composite unique index that does not enforce public key uniqueness", async () => {
    await context.d1.exec("DROP INDEX idx_accounts_public_key_fingerprint; CREATE UNIQUE INDEX idx_accounts_public_key_fingerprint ON accounts (public_key_fingerprint, id)");
    await expect(ensureAccountPublicKeyIndex(context.database)).rejects.toMatchObject({ status: 500 });
  });
  it("reclaims stale issuance and prevents the old attempt from persisting or releasing the new one", async () => {
    const cert = await certificate(); const id = await readyOrder(); const now = Math.floor(Date.now() / 1000);
    const first = await context.database.claimOrderForFinalize(id, now - 61);
    const second = await context.database.claimOrderForFinalize(id, now);
    expect(second).toBe(first! + 1);
    expect(await context.database.completeOrder(id, first!, cert.row, null, now)).toBe(false);
    await context.database.releaseOrderFromProcessing(id, first!);
    await context.database.invalidateFinalizeClaim(id, first!);
    expect((await context.database.getOrderById(id))?.status).toBe("processing");
    expect(await context.database.completeOrder(id, second!, cert.row, null, now)).toBe(true);
  });
  it("allows only one ARI replacement across competing orders", async () => {
    const predecessor = await certificate(); await context.database.saveCertificate(predecessor.row);
    const first = await certificate(); const second = await certificate();
    const one = await readyOrder(undefined, predecessor.row.cert_id); const two = await readyOrder(undefined, predecessor.row.cert_id);
    const now = Math.floor(Date.now() / 1000);
    const g1 = await context.database.claimOrderForFinalize(one); const g2 = await context.database.claimOrderForFinalize(two);
    expect(await context.database.completeOrder(one, g1!, first.row, predecessor.row.cert_id, now)).toBe(true);
    expect(await context.database.completeOrder(two, g2!, second.row, predecessor.row.cert_id, now)).toBe(false);
    expect(await context.database.getCertificateById(second.row.id)).toBeNull();
    expect((await context.database.getCertificateById(predecessor.row.id))?.replaced_by_cert_id).toBe(first.row.cert_id);
  });
  it("rolls back the entire issuance batch if its last write fails", async () => {
    const cert = await certificate(); const id = await readyOrder(); const generation = await context.database.claimOrderForFinalize(id);
    await context.d1.exec("CREATE TRIGGER fail_completion BEFORE UPDATE OF certificate_id ON orders WHEN NEW.certificate_id IS NOT NULL BEGIN SELECT RAISE(ABORT, 'simulated failure'); END");
    await expect(context.database.completeOrder(id, generation!, cert.row, null, Math.floor(Date.now() / 1000))).rejects.toThrow("simulated failure");
    expect(await context.database.getCertificateById(cert.row.id)).toBeNull();
    expect((await context.database.getOrderById(id))?.status).toBe("processing");
  });
});

describe("CA and certificate policy", () => {
  it("caps leaf validity at issuer expiry and preserves the issuer SKI in AKI", async () => {
    const existing = new x509.X509Certificate(context.caFixture.pem);
    const privateKey = await importCaPrivateKey(context.env.PK_GENERIC_INTERMEDIATE as string);
    const ca = await x509.X509CertificateGenerator.create({
      subject: existing.subject, issuer: existing.subject, serialNumber: "1234",
      publicKey: existing.publicKey, signingKey: privateKey, signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      notBefore: new Date(Date.now() - 10000), notAfter: new Date(Date.now() + 3600000),
      extensions: [new x509.BasicConstraintsExtension(true, 0, true), new x509.SubjectKeyIdentifierExtension("aabbccdd")],
    });
    context.caFixture.pem = ca.toString("pem");
    const issued = await certificate();
    expect(issued.leaf.notAfter.getTime()).toBe(ca.notAfter.getTime());
    expect(issued.leaf.getExtension(x509.AuthorityKeyIdentifierExtension)?.keyId).toBe("aabbccdd");
  });
  it("rejects a CSR with a 1024-bit RSA key", async () => {
    const pair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 1024,
      publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({ name: "CN=example.com", keys: pair,
      signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } });
    await expect(parseAndVerifyCsr(base64UrlEncode(csr.rawData))).rejects.toMatchObject({ type: "urn:ietf:params:acme:error:badCSR" });
  });
  it("rejects mismatched CA private keys", async () => {
    const encoded = Buffer.from(await crypto.subtle.exportKey("pkcs8", owner.keys.privateKey) as ArrayBuffer).toString("base64");
    context.env.PK_GENERIC_INTERMEDIATE = `-----BEGIN PRIVATE KEY-----\n${encoded}\n-----END PRIVATE KEY-----`;
    await expect(certificate()).rejects.toThrow("does not match");
  });
  it("generates positive serials whose DER contents fit 20 bytes", () => {
    for (let i = 0; i < 100; i++) {
      const serial = generateRandomSerialNumberHex();
      expect(serial).toHaveLength(40);
      expect(parseInt(serial.slice(0, 2), 16)).toBeLessThan(128);
      expect(BigInt(`0x${serial}`)).toBeGreaterThan(0n);
    }
  });
  it("honors configured validity and ARI renewal windows", async () => {
    CONFIG.CERT_VALIDITY_DAYS = 7;
    CONFIG.RENEWAL_WINDOW_DAYS = 2;
    CONFIG.CRL_BASE_URL = "  https://configured.example/crl/  ";
    context.env.fetch = async () => Response.json({ Status: 0 });
    const id = await readyOrder();
    const { response } = await makeJwsRequest(context.env, `${BASE}/order/${id}/finalize`, { csr: await makeCsr(["victim.example.com"]) }, owner, await getNonce(context.env));
    expect(response.status).toBe(200);
    const order = await context.database.getOrderById(id);
    const cert = await context.database.getCertificateById(order!.certificate_id!);
    expect(cert!.not_after - cert!.not_before).toBe(7 * 86400);
    const leaf = new x509.X509Certificate(cert!.pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)![0]);
    const crl = leaf.getExtension(x509.CRLDistributionPointsExtension);
    expect(crl?.distributionPoints[0].distributionPoint?.fullName?.[0].uniformResourceIdentifier)
      .toBe("https://configured.example/crl/generic-intermediate.crl");
    const info = await worker.fetch(new Request(`${BASE}/renewal-info/${cert!.cert_id}`), context.env, testContext);
    const body = await info.json() as { suggestedWindow: { start: string; end: string }; explanationURL: string };
    expect(body.explanationURL).toBe(CONFIG.ARI_EXPLANATION_URL);
    expect(Date.parse(body.suggestedWindow.end) - Date.parse(body.suggestedWindow.start)).toBe(2 * 86400000);
  });
  it.each([0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])(
    "fails closed for invalid code-configured validity %s", async (days) => {
      CONFIG.CERT_VALIDITY_DAYS = days;
      const result = await makeJwsRequest(context.env, `${BASE}/new-order`,
        { identifiers: [{ type: "dns", value: "example.com" }] }, owner, await getNonce(context.env));
      expect(result.response.status).toBe(500);
      expect(await context.d1.prepare("SELECT COUNT(*) AS count FROM orders").first<{ count: number }>())
        .toEqual({ count: 0 });
    }
  );
  it.each([0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])(
    "fails closed for invalid code-configured renewal window %s", async (days) => {
      const issued = await certificate();
      await context.database.saveCertificate(issued.row);
      CONFIG.RENEWAL_WINDOW_DAYS = days;
      const response = await worker.fetch(new Request(`${BASE}/renewal-info/${issued.row.cert_id}`), context.env, testContext);
      expect(response.status).toBe(500);
    }
  );
  it.each(["2026-02-30T00:00:00Z", "2027-01-01T25:00:00Z", "not-a-date"])("rejects invalid validity timestamp %s", async (notBefore) => {
    const result = await makeJwsRequest(context.env, `${BASE}/new-order`, { identifiers: [{ type: "dns", value: "example.com" }], notBefore }, owner, await getNonce(context.env));
    expect(result.response.status).toBe(400);
  });
});
