import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as x509 from "@peculiar/x509";
import { AcmeEnv } from "../src/config";
import { base64UrlDecode, base64UrlEncode } from "../src/crypto/nonce";
import { calculateJwkThumbprint } from "../src/crypto/jws";
import {
  ACME_BASE_URL,
  AccountKeyAlgorithm,
  TestAccount,
  createOrder,
  createTestEnvironment,
  dohAnswer,
  getAuthorization,
  getNonce,
  installFetchMock,
  makeJwsRequest,
  registerAccount,
  testContext,
  triggerChallenge,
} from "./acme-test-helpers";
import worker from "../src/index";

const PUBLIC_A = "93.184.216.34";
const DOMAIN = "example.com";

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

async function generateEcKeys(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
}

async function generateRsaKeys(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;
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

describe("finalize CSR key selection (RFC 8555 § 11.1)", () => {
  let env: AcmeEnv;
  let restoreFetch: (() => void) | null = null;

  beforeEach(async () => {
    ({ env } = await createTestEnvironment());
    restoreFetch = null;
  });

  afterEach(() => {
    restoreFetch?.();
    restoreFetch = null;
  });

  async function registerAccountWithAlgorithm(
    alg: AccountKeyAlgorithm,
    transformJwk?: (jwk: JsonWebKey) => JsonWebKey
  ): Promise<TestAccount> {
    const keys = alg === "RS256" ? await generateRsaKeys() : await generateEcKeys();
    const exported = (await crypto.subtle.exportKey("jwk", keys.publicKey)) as JsonWebKey;
    const jwk = transformJwk ? transformJwk(exported) : exported;
    const thumbprint = await calculateJwkThumbprint(jwk);

    const nonce = await getNonce(env);
    const result = await makeJwsRequest(
      env,
      `${ACME_BASE_URL}/new-account`,
      { contact: ["mailto:admin@example.com"], termsOfServiceAgreed: true },
      { keys, jwk, kid: "", alg },
      nonce,
      "jwk"
    );
    expect(result.response.status).toBe(201);
    const kid = result.response.headers.get("Location");
    if (!kid) throw new Error("Account response did not include Location");

    return { keys, jwk, thumbprint, kid, alg };
  }

  /**
   * Creates an order and validates its http-01 challenge so finalize is
   * reachable. The fetch mock also answers CAA queries with an empty answer,
   * which permits issuance.
   */
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

  it("rejects a CSR reusing the current account's EC key and keeps the order ready", async () => {
    const account = await registerAccountWithAlgorithm("ES256");
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

    const afterRejection = await getOrder(account, order.url, rejected.nonce);
    expect(afterRejection.body.status).toBe("ready");
    expect(await countCertificates()).toBe(0);

    // A distinct certificate key must still be able to finalize the order.
    const certificateKeys = await generateEcKeys();
    const accepted = await finalize(
      account,
      order.url,
      await makeCsrFromKeys([DOMAIN], certificateKeys, "ES256"),
      afterRejection.nonce
    );
    expect(accepted.response.status).toBe(200);
    expect(accepted.body.status).toBe("valid");
    expect(await countCertificates()).toBe(1);
  });

  it("rejects a CSR reusing the current account's RSA key and keeps the order ready", async () => {
    const account = await registerAccountWithAlgorithm("RS256");
    const { order, nonce } = await createReadyOrder(account);

    const rejected = await finalize(
      account,
      order.url,
      await makeCsrFromKeys([DOMAIN], account.keys, "RS256"),
      nonce
    );
    expect(rejected.response.status).toBe(400);
    expect(rejected.body.type).toBe("urn:ietf:params:acme:error:badCSR");
    expect(String(rejected.body.detail)).toContain("account key");

    const afterRejection = await getOrder(account, order.url, rejected.nonce);
    expect(afterRejection.body.status).toBe("ready");
    expect(await countCertificates()).toBe(0);

    // A different RSA key is a perfectly valid certificate key.
    const certificateKeys = await generateRsaKeys();
    const accepted = await finalize(
      account,
      order.url,
      await makeCsrFromKeys([DOMAIN], certificateKeys, "RS256"),
      afterRejection.nonce
    );
    expect(accepted.response.status).toBe(200);
    expect(accepted.body.status).toBe("valid");
    expect(await countCertificates()).toBe(1);
  });

  it("compares public keys independently of JWK field order", async () => {
    // The account is registered with a JWK whose field order differs from the
    // canonical RFC 7638 ordering. The stored JSON is not used for comparison:
    // both keys are normalized to SPKI DER before they are compared.
    const account = await registerAccountWithAlgorithm("ES256", (jwk) => ({
      y: jwk.y,
      crv: jwk.crv,
      x: jwk.x,
      kty: jwk.kty,
    }));
    const { order, nonce } = await createReadyOrder(account);

    const rejected = await finalize(
      account,
      order.url,
      await makeCsrFromKeys([DOMAIN], account.keys, "ES256"),
      nonce
    );
    expect(rejected.response.status).toBe(400);
    expect(rejected.body.type).toBe("urn:ietf:params:acme:error:badCSR");
    expect(await countCertificates()).toBe(0);
  });

  it("compares public keys independently of JWK encoding", async () => {
    // WebCrypto tolerates redundant leading zero bytes in EC coordinates and
    // normalizes them on import. A non-canonical JWK encoding must not hide the
    // fact that the CSR reuses the account key.
    const padCoordinate = (value: string): string => {
      const bytes = base64UrlDecode(value);
      const padded = new Uint8Array(bytes.length + 1);
      padded.set(bytes, 1);
      return base64UrlEncode(padded);
    };
    const account = await registerAccountWithAlgorithm("ES256", (jwk) => ({
      ...jwk,
      x: padCoordinate(jwk.x as string),
      y: padCoordinate(jwk.y as string),
    }));
    const { order, nonce } = await createReadyOrder(account);

    const rejected = await finalize(
      account,
      order.url,
      await makeCsrFromKeys([DOMAIN], account.keys, "ES256"),
      nonce
    );
    expect(rejected.response.status).toBe(400);
    expect(rejected.body.type).toBe("urn:ietf:params:acme:error:badCSR");
    expect(await countCertificates()).toBe(0);
  });

  it("rejects a CSR that reuses another account's public key", async () => {
    const account = await registerAccountWithAlgorithm("ES256");
    const otherAccount = await registerAccount(env);
    const { order, nonce } = await createReadyOrder(account);

    const rejected = await finalize(
      account,
      order.url,
      await makeCsrFromKeys([DOMAIN], otherAccount.keys, "ES256"),
      nonce
    );
    expect(rejected.response.status).toBe(400);
    expect(rejected.body.type).toBe("urn:ietf:params:acme:error:badCSR");
    expect(String(rejected.body.detail)).toContain("already registered");

    const afterRejection = await getOrder(account, order.url, rejected.nonce);
    expect(afterRejection.body.status).toBe("ready");
    expect(await countCertificates()).toBe(0);
  });

  it("accepts a CSR whose key differs from the account key regardless of key type", async () => {
    const account = await registerAccountWithAlgorithm("ES256");
    const { order, nonce } = await createReadyOrder(account);

    const certificateKeys = await generateRsaKeys();
    const accepted = await finalize(
      account,
      order.url,
      await makeCsrFromKeys([DOMAIN], certificateKeys, "RS256"),
      nonce
    );
    expect(accepted.response.status).toBe(200);
    expect(accepted.body.status).toBe("valid");

    const certificateUrl = String(accepted.body.certificate);
    const certificateResponse = await worker.fetch(
      new Request(certificateUrl),
      env,
      testContext
    );
    const chain = await certificateResponse.text();
    const leaf = new x509.X509Certificate(chain);
    const leafKey = await leaf.publicKey.export();
    const leafSpki = new Uint8Array(
      (await crypto.subtle.exportKey("spki", leafKey)) as ArrayBuffer
    );
    const csrKeySpki = new Uint8Array(
      (await crypto.subtle.exportKey("spki", certificateKeys.publicKey)) as ArrayBuffer
    );
    expect(Array.from(leafSpki)).toEqual(Array.from(csrKeySpki));
  });

  it("rejects a CSR with an unparsable public key and leaves the order ready", async () => {
    const account = await registerAccountWithAlgorithm("ES256");
    const { order, nonce } = await createReadyOrder(account);

    const rejected = await finalize(
      account,
      order.url,
      base64UrlEncode(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00])),
      nonce
    );
    expect(rejected.response.status).toBe(400);
    expect(rejected.body.type).toBe("urn:ietf:params:acme:error:badCSR");

    const afterRejection = await getOrder(account, order.url, rejected.nonce);
    expect(afterRejection.body.status).toBe("ready");
    expect(await countCertificates()).toBe(0);
  });
});
