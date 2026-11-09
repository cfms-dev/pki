import { migrateAccountPublicKeyFingerprints } from "../src/db/account-keys";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as x509 from "@peculiar/x509";
import { AcmeEnv } from "../src/config";
import { calculateJwkThumbprint, normalizePublicKey } from "../src/crypto/jws";
import { base64UrlEncode } from "../src/crypto/nonce";
import { Database } from "../src/db/queries";
import {
  TestAccount,
  createOrder,
  createTestEnvironment,
  dohAnswer,
  getAuthorization,
  installFetchMock,
  makeJwsRequest,
  TestEnvironment,
  triggerChallenge,
} from "./acme-test-helpers";
import {
  exportPublicJwk,
  generateAccountKeys,
  padBase64Url,
  registerAccountJwk,
  registerFreshAccount,
} from "./account-key-test-helpers";

const PUBLIC_A = "93.184.216.34";
const DOMAIN = "finalize-identity.example.com";

interface AuthzChallenge {
  type: string;
  url: string;
  token: string;
  status: string;
}

function isDohUrl(url: string): boolean {
  return (
    url.startsWith("https://cloudflare-dns.com/dns-query") ||
    url.startsWith("https://dns.google/resolve")
  );
}

async function makeCsrFromKeys(
  domains: string[],
  keys: CryptoKeyPair,
  alg: "ES256" | "RS256"
): Promise<string> {
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: `CN=${domains[0]}`,
    keys,
    signingAlgorithm:
      alg === "ES256"
        ? { name: "ECDSA", hash: "SHA-256" }
        : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    extensions: [
      new x509.SubjectAlternativeNameExtension(
        domains.map((domain) => ({ type: "dns" as const, value: domain }))
      ),
    ],
  });
  return base64UrlEncode(csr.rawData);
}

describe("finalize cross-account public key reuse checks", () => {
  let env: AcmeEnv;
  let database: Database;
  let testEnv: TestEnvironment;
  let restoreFetch: (() => void) | null = null;

  beforeEach(async () => {
    testEnv = await createTestEnvironment();
    env = testEnv.env;
    database = testEnv.database;
    restoreFetch = null;
  });

  afterEach(() => {
    restoreFetch?.();
    restoreFetch = null;
  });

  async function createReadyOrder(account: TestAccount) {
    const order = await createOrder(env, account, [{ type: "dns", value: DOMAIN }]);
    expect(order.response.status).toBe(201);

    const authzUrl = (order.body.authorizations as string[])[0];
    const authz = await getAuthorization(env, account, authzUrl, order.nonce);
    const http = (authz.body.challenges as AuthzChallenge[]).find(
      (challenge) => challenge.type === "http-01"
    );
    if (!http) throw new Error("http-01 challenge not offered");

    const keyAuthorization = `${http.token}.${account.thumbprint}`;
    restoreFetch = installFetchMock(async (input) => {
      const url = String(input);
      if (isDohUrl(url)) {
        return new URL(url).searchParams.get("type") === "A"
          ? dohAnswer([{ type: 1, data: PUBLIC_A }])
          : dohAnswer([]);
      }
      return new Response(keyAuthorization, { status: 200 });
    });

    const triggered = await triggerChallenge(env, account, http.url, authz.nonce);
    expect(triggered.body.status).toBe("valid");
    return { order, nonce: triggered.nonce };
  }

  async function finalize(
    account: TestAccount,
    orderUrl: string,
    csr: string,
    nonce: string
  ) {
    const result = await makeJwsRequest(
      env,
      `${orderUrl}/finalize`,
      { csr },
      account,
      nonce
    );
    return {
      response: result.response,
      body: (await result.response.json()) as Record<string, unknown>,
      nonce: result.nextNonce,
    };
  }

  async function getOrder(account: TestAccount, orderUrl: string, nonce: string) {
    const result = await makeJwsRequest(env, orderUrl, "", account, nonce);
    return {
      body: (await result.response.json()) as Record<string, unknown>,
      nonce: result.nextNonce,
    };
  }

  async function countCertificates(): Promise<number> {
    const row = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM certificates"
    ).first<{ count: number }>();
    return row?.count ?? 0;
  }

  it("rejects an attacker CSR that reuses a victim account key stored in a non-canonical encoding", async () => {
    const victim = await registerFreshAccount(env, "ES256", (jwk) => ({
      ...jwk,
      x: padBase64Url(jwk.x as string),
      y: padBase64Url(jwk.y as string),
    }));
    const attacker = await registerFreshAccount(env, "ES256");
    const { order, nonce } = await createReadyOrder(attacker);

    // The CSR's canonical SPKI is the same actual key as the victim account's
    // non-canonically encoded JWK. The RFC 7638 thumbprints differ, so only a
    // canonical SPKI fingerprint can catch this.
    const rejected = await finalize(
      attacker,
      order.url,
      await makeCsrFromKeys([DOMAIN], victim.keys, "ES256"),
      nonce
    );
    expect(rejected.response.status).toBe(400);
    expect(rejected.body.type).toBe("urn:ietf:params:acme:error:badCSR");
    expect(String(rejected.body.detail)).toContain("already registered");

    const afterRejection = await getOrder(attacker, order.url, rejected.nonce);
    expect(afterRejection.body.status).toBe("ready");
    expect(await countCertificates()).toBe(0);
  });

  it("rejects a CSR reusing an RSA account key with padded integer encodings", async () => {
    const victimKeys = await generateAccountKeys("RS256");
    const canonical = await exportPublicJwk(victimKeys);
    const padded = {
      ...canonical,
      n: padBase64Url(canonical.n as string, 3),
      e: padBase64Url(canonical.e as string, 1),
    };
    const victim = await registerAccountJwk(env, victimKeys, padded, "RS256");
    expect(victim.status).toBe(201);

    await migrateAccountPublicKeyFingerprints(database);
    const attacker = await registerFreshAccount(env, "ES256");
    const { order, nonce } = await createReadyOrder(attacker);

    const rejected = await finalize(
      attacker,
      order.url,
      await makeCsrFromKeys([DOMAIN], victimKeys, "RS256"),
      nonce
    );
    expect(rejected.response.status).toBe(400);
    expect(rejected.body.type).toBe("urn:ietf:params:acme:error:badCSR");
    expect(await countCertificates()).toBe(0);
  });

  it("still rejects the current account key directly", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const { order, nonce } = await createReadyOrder(account);

    const rejected = await finalize(
      account,
      order.url,
      await makeCsrFromKeys([DOMAIN], account.keys, "ES256"),
      nonce
    );
    expect(rejected.response.status).toBe(400);
    expect(rejected.body.type).toBe("urn:ietf:params:acme:error:badCSR");
    expect(String(rejected.body.detail)).toContain("account key");
    expect(await countCertificates()).toBe(0);
  });

  it("rejects the request signing key even when rollover changes the stored key during verification", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const { order, nonce } = await createReadyOrder(account);
    const csr = await makeCsrFromKeys([DOMAIN], account.keys, "ES256");
    const nextKeys = await generateAccountKeys("ES256");
    const nextJwk = await exportPublicJwk(nextKeys);
    const nextIdentity = await normalizePublicKey(nextJwk);
    const original = Database.prototype.getAccountById;
    let changed = false;
    const spy = vi.spyOn(Database.prototype, "getAccountById").mockImplementation(async function (this: Database, id) {
      const snapshot = await original.call(this, id);
      if (!changed && id === account.kid.split("/").pop()) {
        changed = true;
        await env.DB.prepare("UPDATE accounts SET jwk = ?, thumbprint = ?, public_key_fingerprint = ? WHERE id = ?")
          .bind(JSON.stringify(nextJwk), await calculateJwkThumbprint(nextJwk), nextIdentity.fingerprint, id).run();
      }
      return snapshot;
    });
    try {
      const rejected = await finalize(account, order.url, csr, nonce);
      expect(changed).toBe(true);
      expect(rejected.response.status).toBe(400);
      expect(rejected.body.type).toContain("badCSR");
      expect(await countCertificates()).toBe(0);
      expect((await database.getOrderById(order.url.split("/").pop()!))?.status).toBe("ready");
    } finally { spy.mockRestore(); }
  });

  it("accepts a CSR with a fresh non-account key and issues a certificate", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const { order, nonce } = await createReadyOrder(account);
    const certificateKeys = await generateAccountKeys("ES256");

    const accepted = await finalize(
      account,
      order.url,
      await makeCsrFromKeys([DOMAIN], certificateKeys, "ES256"),
      nonce
    );
    expect(accepted.response.status).toBe(200);
    expect(accepted.body.status).toBe("valid");
    expect(await countCertificates()).toBe(1);
  });

  it("backfills a valid legacy account and still rejects its key in a CSR", async () => {
    const legacyKeys = await generateAccountKeys("ES256");
    const legacyJwk = await exportPublicJwk(legacyKeys);
    const legacyId = crypto.randomUUID();
    await database.saveAccount({
      id: legacyId,
      jwk: JSON.stringify(legacyJwk),
      thumbprint: await calculateJwkThumbprint(legacyJwk),
      contact: null,
      status: "valid",
      created_at: Math.floor(Date.now() / 1000),
    });
    expect(
      (await database.getAccountById(legacyId))?.public_key_fingerprint ?? null
    ).toBeNull();

    await migrateAccountPublicKeyFingerprints(database);
    const attacker = await registerFreshAccount(env, "ES256");
    const { order, nonce } = await createReadyOrder(attacker);

    const rejected = await finalize(
      attacker,
      order.url,
      await makeCsrFromKeys([DOMAIN], legacyKeys, "ES256"),
      nonce
    );
    expect(rejected.response.status).toBe(400);
    expect(rejected.body.type).toBe("urn:ietf:params:acme:error:badCSR");
    expect(await countCertificates()).toBe(0);

    const legacyRow = await database.getAccountById(legacyId);
    expect(legacyRow?.public_key_fingerprint).toBe(
      (await normalizePublicKey(legacyJwk)).fingerprint
    );
  });

  it("fails closed when a legacy account key cannot be normalized", async () => {
    const attacker = await registerFreshAccount(env, "ES256");
    const { order, nonce } = await createReadyOrder(attacker);

    await database.saveAccount({
      id: crypto.randomUUID(),
      jwk: "{this is not valid JSON",
      thumbprint: "A".repeat(43),
      contact: null,
      status: "valid",
      created_at: Math.floor(Date.now() / 1000),
    });

    const certificateKeys = await generateAccountKeys("ES256");
    const rejected = await finalize(
      attacker,
      order.url,
      await makeCsrFromKeys([DOMAIN], certificateKeys, "ES256"),
      nonce
    );
    expect(rejected.response.status).toBe(503);
    expect(rejected.body.type).toBe("urn:ietf:params:acme:error:serverInternal");
    expect(await countCertificates()).toBe(0);

    const afterRejection = await getOrder(attacker, order.url, rejected.nonce);
    expect(afterRejection.body.status).toBe("ready");
  });

  it("fails closed when the account fingerprint index is unavailable", async () => {
    const attacker = await registerFreshAccount(env, "ES256");
    const { order, nonce } = await createReadyOrder(attacker);
    await env.DB.prepare(
      "DROP INDEX idx_accounts_public_key_fingerprint"
    ).run();

    const certificateKeys = await generateAccountKeys("ES256");
    const rejected = await finalize(
      attacker,
      order.url,
      await makeCsrFromKeys([DOMAIN], certificateKeys, "ES256"),
      nonce
    );
    expect(rejected.response.status).toBe(500);
    expect(rejected.body.type).toBe("urn:ietf:params:acme:error:serverInternal");
    expect(await countCertificates()).toBe(0);

    // The direct current-account-key comparison runs before the index check,
    // so the most important defense still reports badCSR rather than 500.
    const direct = await finalize(
      attacker,
      order.url,
      await makeCsrFromKeys([DOMAIN], attacker.keys, "ES256"),
      rejected.nonce
    );
    expect(direct.response.status).toBe(400);
    expect(direct.body.type).toBe("urn:ietf:params:acme:error:badCSR");

    const afterRejection = await getOrder(attacker, order.url, direct.nonce);
    expect(afterRejection.body.status).toBe("ready");
    expect(await countCertificates()).toBe(0);
  });

  it("rejects a reused key whose account was registered with a different field order", async () => {
    const victim = await registerFreshAccount(env, "ES256", (jwk) => ({
      y: jwk.y,
      crv: jwk.crv,
      x: jwk.x,
      kty: jwk.kty,
      kid: "ignored",
    }));
    await migrateAccountPublicKeyFingerprints(database);
    const attacker = await registerFreshAccount(env, "ES256");
    const { order, nonce } = await createReadyOrder(attacker);

    const rejected = await finalize(
      attacker,
      order.url,
      await makeCsrFromKeys([DOMAIN], victim.keys, "ES256"),
      nonce
    );
    expect(rejected.response.status).toBe(400);
    expect(rejected.body.type).toBe("urn:ietf:params:acme:error:badCSR");
    expect(await countCertificates()).toBe(0);
  });
});
