import { beforeEach, describe, expect, it, vi } from "vitest";
import * as x509 from "@peculiar/x509";
import * as transport from "../src/http01/socket";
import { AcmeIdentifier, normalizeIpAddress, readIdentifiers, validateIpIdentifier } from "../src/acme/identifiers";
import { computeSuggestedWindow, checkAriRenewalEligibility } from "../src/ari/window";
import { issuanceGroup, RateLimiter } from "../src/ratelimit/limiter";
import { base64UrlEncode } from "../src/crypto/nonce";
import { CONFIG } from "../src/config";
import { createTestEnvironment, registerAccount, createOrder, getAuthorization, makeJwsRequest, getNonce, triggerChallenge, dohAnswer } from "./acme-test-helpers";
import { issuanceBuckets } from "../src/ratelimit/issuance";

const ipv4: AcmeIdentifier = { type: "ip", value: "93.184.216.34" };
const ipv6: AcmeIdentifier = { type: "ip", value: "2606:4700:4700::1111" };
const dns: AcmeIdentifier = { type: "dns", value: "example.com" };

async function makeTypedCsr(identifiers: AcmeIdentifier[]) {
  const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: "", keys, signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: [new x509.SubjectAlternativeNameExtension(identifiers)],
  });
  return base64UrlEncode(csr.rawData);
}

describe("IP ACME issuance and lifecycle", () => {
  let context: Awaited<ReturnType<typeof createTestEnvironment>>;
  let account: Awaited<ReturnType<typeof registerAccount>>;
  beforeEach(async () => {
    context = await createTestEnvironment();
    account = await registerAccount(context.env);
    vi.spyOn(transport, "requestIpHttp01").mockImplementation(async (url) => new Response(`${url.pathname.split("/").pop()}.${account.thumbprint}`));
    vi.stubGlobal("fetch", vi.fn(async (input) => {
      const url = new URL(String(input));
      if (url.pathname.includes("acme-challenge")) return new Response(`${url.pathname.split("/").pop()}.${account.thumbprint}`);
      const type = url.searchParams.get("type");
      return dohAnswer(type === "A" ? [{ type: 1, data: ipv4.value }] : []);
    }));
  });

  async function ready(identifiers: AcmeIdentifier[]) {
    const order = await createOrder(context.env, account, identifiers);
    expect(order.response.status).toBe(201);
    expect(order.body.identifiers).toEqual(identifiers);
    let nonce = order.nonce;
    for (const url of order.body.authorizations as string[]) {
      const authz = await getAuthorization(context.env, account, url, nonce);
      const identifier = authz.body.identifier as AcmeIdentifier;
      const challenges = authz.body.challenges as { type: string; url: string }[];
      if (identifier.type === "ip") expect(challenges.map((c) => c.type)).toEqual(["http-01"]);
      const result = await triggerChallenge(context.env, account, challenges.find((c) => c.type === "http-01")!.url, authz.nonce);
      expect(result.body.status).toBe("valid");
      nonce = result.nonce;
    }
    return { order, nonce };
  }

  it.each([[ipv4], [ipv6], [dns, ipv4, ipv6]])("signs correctly typed SANs and short-lived certificates for %j", async (...args) => {
    const identifiers = args as AcmeIdentifier[];
    const { order, nonce } = await ready(identifiers);
    const result = await makeJwsRequest(context.env, `${order.url}/finalize`, { csr: await makeTypedCsr(identifiers) }, account, nonce);
    expect(result.response.status, await result.response.clone().text()).toBe(200);
    const row = (await context.d1.prepare("SELECT * FROM certificates").first())!;
    const leaf = new x509.X509Certificate((row.pem as string).match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)![0]);
    const san = leaf.getExtension(x509.SubjectAlternativeNameExtension)!;
    expect(san.names.items.map((item) => ({ type: item.type, value: item.type === "ip" ? normalizeIpAddress(item.value) : item.value }))).toEqual(identifiers);
    expect(san.critical).toBe(!identifiers.some((item) => item.type === "dns"));
    if (!identifiers.some((item) => item.type === "dns")) expect(leaf.subject).toBe("");
    expect(leaf.notAfter.getTime() - leaf.notBefore.getTime()).toBe(160 * 3600000);
    expect(readIdentifiers(row.san as string)).toEqual(identifiers);
    const cert = await context.database.getCertificateByCertId(row.cert_id as string);
    const window = computeSuggestedWindow(cert!);
    expect(Date.parse(window.start)).toBe((cert!.not_before + Math.floor(160 * 3600 * 2 / 3)) * 1000);
    expect(Date.parse(window.end)).toBe((cert!.not_before + Math.floor(160 * 3600 * 5 / 6)) * 1000);
    expect(checkAriRenewalEligibility(cert!, identifiers, cert!.not_before).eligible).toBe(false);
    expect(checkAriRenewalEligibility(cert!, identifiers, Date.parse(window.start) / 1000).eligible).toBe(true);
    // Revocation uses the issued typed metadata and the issuing account.
    const revoked = await makeJwsRequest(context.env, "https://acme.test/revoke-cert", { certificate: base64UrlEncode(leaf.rawData) }, account, result.nextNonce);
    expect(revoked.response.status).toBe(200);
    expect(await context.database.accountHasValidAuthorizations(account.kid.split("/").pop()!, identifiers, Math.floor(Date.now() / 1000))).toBe(true);
    expect(await context.database.accountHasValidAuthorizations(account.kid.split("/").pop()!, [{ type: "dns", value: ipv4.value }], Math.floor(Date.now() / 1000))).toBe(false);
    const caaQueries = vi.mocked(fetch).mock.calls.filter(([input]) => String(input).includes("type=CAA"));
    expect(caaQueries.length > 0).toBe(identifiers.some((item) => item.type === "dns"));
    expect(caaQueries.every(([input]) => !String(input).includes(ipv4.value) && !String(input).includes("2606"))).toBe(true);
  });

  it("normalizes and deduplicates equivalent IPv6 identifiers", async () => {
    const result = await createOrder(context.env, account, [ipv6, { type: "ip", value: "2606:4700:4700:0:0:0:0:1111" }]);
    expect(result.body.identifiers).toEqual([ipv6]);
    expect(result.body.authorizations).toHaveLength(1);
  });

  it("creates fresh pending authorizations for an ARI IP renewal", async () => {
    const { order, nonce } = await ready([ipv4]);
    const result = await makeJwsRequest(context.env, `${order.url}/finalize`, { csr: await makeTypedCsr([ipv4]) }, account, nonce);
    expect(result.response.status).toBe(200);
    const row = (await context.d1.prepare("SELECT cert_id FROM certificates").first<{ cert_id: string }>())!;
    const now = Math.floor(Date.now() / 1000);
    // Move only the predecessor's ARI metadata into its suggested window.
    await context.d1.prepare("UPDATE certificates SET not_before = ?, not_after = ? WHERE cert_id = ?").bind(now - 120 * 3600, now + 40 * 3600, row.cert_id).run();
    const renewal = await makeJwsRequest(context.env, "https://acme.test/new-order", { identifiers: [ipv4], replaces: row.cert_id }, account, result.nextNonce);
    expect(renewal.response.status).toBe(201);
    const renewalBody = await renewal.response.json() as { authorizations: string[]; finalize: string };
    const authz = await getAuthorization(context.env, account, renewalBody.authorizations[0], renewal.nextNonce);
    expect(authz.body).toMatchObject({ status: "pending", identifier: ipv4 });
    expect((authz.body.challenges as { status: string }[]).every((item) => item.status === "pending")).toBe(true);
    const earlyFinalize = await makeJwsRequest(context.env, renewalBody.finalize, { csr: await makeTypedCsr([ipv4]) }, account, authz.nonce);
    expect(earlyFinalize.response.status).toBe(403);
  });

  it("allows another account to revoke only after obtaining a matching typed IP authorization", async () => {
    const { order, nonce } = await ready([ipv4]);
    const issued = await makeJwsRequest(context.env, `${order.url}/finalize`, { csr: await makeTypedCsr([ipv4]) }, account, nonce);
    expect(issued.response.status).toBe(200);
    const row = (await context.d1.prepare("SELECT pem FROM certificates").first<{ pem: string }>())!;
    const certificate = base64UrlEncode(new x509.X509Certificate(row.pem).rawData);
    account = await registerAccount(context.env);
    const denied = await makeJwsRequest(context.env, "https://acme.test/revoke-cert", { certificate }, account, await getNonce(context.env));
    expect(denied.response.status).toBe(403);
    const verified = await ready([ipv4]);
    const revoked = await makeJwsRequest(context.env, "https://acme.test/revoke-cert", { certificate }, account, verified.nonce);
    expect(revoked.response.status).toBe(200);
  });

  it("rejects mismatched CSR types, missing IP SANs and extra identifiers before claiming", async () => {
    const { order, nonce } = await ready([ipv4]);
    let next = nonce;
    for (const names of [[dns], [ipv6], [ipv4, ipv6], [{ type: "dns" as const, value: ipv4.value }]]) {
      const result = await makeJwsRequest(context.env, `${order.url}/finalize`, { csr: await makeTypedCsr(names) }, account, next);
      expect(result.response.status).toBe(400);
      expect(await result.response.json()).toMatchObject({ type: "urn:ietf:params:acme:error:badCSR" });
      expect((await context.database.getOrderById(order.url.split("/").pop()!))!.status).toBe("ready");
      next = result.nextNonce;
    }
  });

  it("rejects injected DNS-01 for IP without doing DNS validation", async () => {
    const order = await createOrder(context.env, account, [ipv4]);
    const authzId = (order.body.authorizations as string[])[0].split("/").pop()!;
    const authz = (await context.database.getAuthorizationById(authzId))!;
    await context.database.saveChallenge({ id: authzId, authorization_id: authzId, type: "dns-01", token: authz.token, status: "pending", error: null, validated_at: null, processing_started_at: null, validation_generation: 0, created_at: authz.created_at });
    const result = await triggerChallenge(context.env, account, `https://acme.test/challenge/${authzId}`, order.nonce);
    expect(result.body.status).toBe("invalid");
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("enforces 160-hour policy at new-order and caps issuance by global validity", async () => {
    const nonce = await getNonce(context.env);
    const result = await makeJwsRequest(context.env, "https://acme.test/new-order", { identifiers: [ipv4], notAfter: new Date(Date.now() + 161 * 3600000).toISOString() }, account, nonce);
    expect(result.response.status).toBe(400);
    expect(await context.d1.prepare("SELECT COUNT(*) AS count FROM orders").first("count")).toBe(0);
    CONFIG.CERT_VALIDITY_DAYS = 1;
    const prepared = await ready([ipv4]);
    const issued = await makeJwsRequest(context.env, `${prepared.order.url}/finalize`, { csr: await makeTypedCsr([ipv4]) }, account, prepared.nonce);
    expect(issued.response.status).toBe(200);
    const row = await context.d1.prepare("SELECT not_before, not_after FROM certificates").first<{ not_before: number; not_after: number }>();
    expect(row!.not_after - row!.not_before).toBe(86400);
  });

  it("reads legacy DNS metadata with the current authorization schema", async () => {
    expect((await context.d1.prepare("PRAGMA table_info(authorizations)").all<{ name: string }>()).results.filter((item) => item.name === "identifier_type")).toHaveLength(1);
    expect(readIdentifiers('["EXAMPLE.COM"]')).toEqual([dns]);
  });

  it("groups IPv4 per address and IPv6 per /64, preserving DNS limits", async () => {
    expect(issuanceGroup(ipv4)).not.toBe(issuanceGroup({ type: "ip", value: "93.184.216.35" }));
    expect(issuanceGroup(ipv6)).toBe(issuanceGroup({ type: "ip", value: "2606:4700:4700::2222" }));
    expect(issuanceGroup(dns)).toBe("example.com");
    CONFIG.RATE_LIMIT_CERTS_PER_DOMAIN = 1;
    const limiter = new RateLimiter(context.database);
    const group = issuanceBuckets([ipv6])[0];
    await context.d1.prepare("INSERT INTO issuance_ledger VALUES (?, ?, ?)").bind("issued", group.key, Math.floor(Date.now() / 1000)).run();
    await expect(context.database.assertIssuanceCapacity(issuanceBuckets([{ type: "ip", value: "2606:4700:4700::2222" }]), Math.floor(Date.now() / 1000))).rejects.toThrow("rate limit");
    CONFIG.RATE_LIMIT_FAILED_VALIDATIONS = 1;
    await limiter.recordFailedValidation("one", ipv4);
    await expect(limiter.checkFailedValidationLimit("one", ipv4)).rejects.toThrow(ipv4.value);
    await expect(limiter.checkFailedValidationLimit("two", ipv4)).resolves.toBeUndefined();
  });

  it.each(["127.1", "2130706433", "0177.0.0.1", "0x7f000001", "1.2.3.04", "[2606:4700:4700::1111]", "fe80::1%eth0", "10.0.0.1", "192.0.2.1", "::ffff:127.0.0.1", "2606:4700:4700::1111:80/path"])("rejects unsafe or nonstandard IP identifier %s", (value) => {
    expect(validateIpIdentifier(value).ok).toBe(false);
  });
});
