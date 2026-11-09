import { testAssets } from "./website-test-helpers";
import { mockCaCertificate } from "./ca-test-helpers";
import { describe, it, expect, beforeEach } from "vitest";
import worker from "../src/index";
import { AcmeEnv, CONFIG } from "../src/config";
import { handleDirectory } from "../src/routes/directory";
import { createMockD1Database } from "./mock-d1";
import { base64UrlEncode } from "../src/crypto/nonce";
import { calculateJwkThumbprint } from "../src/crypto/jws";
import * as x509 from "@peculiar/x509";

import { Database } from "../src/db/queries";

describe("RFC 8555 termsOfService and Optional Directory Fields", () => {
  let env: AcmeEnv;
  let caCertPem: string;
  let caKeyPem: string;

  beforeEach(async () => {
    const caKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;

    const caCert = await x509.X509CertificateGenerator.create({
      serialNumber: "0102030405060708090a",
      subject: "CN=Test Intermediate CA, O=Test",
      issuer: "CN=Test Root CA",
      notBefore: new Date(),
      notAfter: new Date(Date.now() + 365 * 86400 * 1000),
      publicKey: caKeys.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new x509.BasicConstraintsExtension(true, undefined, true),
        await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey),
      ],
    });

    caCertPem = caCert.toString("pem");
    const pkcs8Der = await crypto.subtle.exportKey("pkcs8", caKeys.privateKey);
    caKeyPem = `-----BEGIN PRIVATE KEY-----\n${Buffer.from(pkcs8Der as ArrayBuffer).toString("base64")}\n-----END PRIVATE KEY-----`;

    const d1 = createMockD1Database();
    const database = new Database(d1);
    await database.initSchema();

    mockCaCertificate(caCertPem);
    env = {
      ASSETS: testAssets,
      DB: d1,
      PK_GENERIC_INTERMEDIATE: caKeyPem,
    };
  });

  const ctx = {
    waitUntil: () => {},
    passThroughOnException: () => {},
  } as unknown as ExecutionContext;

  async function getNonce(customEnv = env): Promise<string> {
    const resp = await worker.fetch(
      new Request("https://acme.test/new-nonce", { method: "HEAD" }),
      customEnv,
      ctx
    );
    return resp.headers.get("Replay-Nonce")!;
  }

  async function makeJwsRequest(
    url: string,
    payload: Record<string, unknown> | "",
    accountKey: CryptoKeyPair,
    keyMode: { jwk?: JsonWebKey; kid?: string },
    nonce: string,
    customEnv = env
  ): Promise<{ response: Response; nextNonce: string }> {
    const protectedHeader: Record<string, unknown> = {
      alg: "ES256",
      nonce,
      url,
    };
    if (keyMode.jwk) protectedHeader.jwk = keyMode.jwk;
    if (keyMode.kid) protectedHeader.kid = keyMode.kid;

    const protectedB64 = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(protectedHeader))
    );
    const payloadB64 =
      payload === ""
        ? ""
        : base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));

    const signingInput = new TextEncoder().encode(`${protectedB64}.${payloadB64}`);
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      accountKey.privateKey,
      signingInput
    );
    const signatureB64 = base64UrlEncode(signature);

    const body = JSON.stringify({
      protected: protectedB64,
      payload: payloadB64,
      signature: signatureB64,
    });

    const response = await worker.fetch(
      new Request(url, {
        method: "POST",
        headers: { "Content-Type": "application/jose+json" },
        body,
      }),
      customEnv,
      ctx
    );

    const nextNonce = response.headers.get("Replay-Nonce") || "";
    return { response, nextNonce };
  }

  describe("1. Directory Metadata Optional Fields (RFC 8555 § 7.1.1)", () => {
    it("should omit termsOfService by default when unspecified", async () => {
      const resp = handleDirectory(
        new Request("https://acme.test/directory"),
        { ASSETS: testAssets, DB: createMockD1Database() },
        "https://acme.test"
      );
      expect(resp.status).toBe(200);
      const data = (await resp.json()) as { meta?: Record<string, unknown> };
      expect(data.meta).toBeDefined();
      expect(data.meta!.termsOfService).toBeUndefined();
    });

    it("should include termsOfService when specified in CONFIG", async () => {
      CONFIG.TERMS_OF_SERVICE_URL = "  https://example.com/tos-2026  ";
      const resp = handleDirectory(
        new Request("https://acme.test/directory"),
        { ASSETS: testAssets, DB: createMockD1Database() },
        "https://acme.test"
      );
      expect(resp.status).toBe(200);
      const data = (await resp.json()) as { meta: { termsOfService?: string } };
      expect(data.meta.termsOfService).toBe("https://example.com/tos-2026");
    });

    it("should omit website when specified as whitespace", async () => {
      CONFIG.WEBSITE_URL = "  ";
      const resp = handleDirectory(
        new Request("https://acme.test/directory"),
        { ASSETS: testAssets, DB: createMockD1Database() },
        "https://acme.test"
      );
      expect(resp.status).toBe(200);
      const data = (await resp.json()) as { meta?: Record<string, unknown> };
      expect(data.meta?.website).toBeUndefined();
    });

    it("should omit caaIdentities when specified as an empty array", async () => {
      CONFIG.CAA_IDENTITIES = [];
      const resp = handleDirectory(
        new Request("https://acme.test/directory"),
        { ASSETS: testAssets, DB: createMockD1Database() },
        "https://acme.test"
      );
      expect(resp.status).toBe(200);
      const data = (await resp.json()) as { meta?: Record<string, unknown> };
      expect(data.meta?.caaIdentities).toBeUndefined();
    });

    it("should omit externalAccountRequired by default and include true when set", async () => {
      const respDefault = handleDirectory(
        new Request("https://acme.test/directory"),
        { ASSETS: testAssets, DB: createMockD1Database() },
        "https://acme.test"
      );
      const dataDefault = (await respDefault.json()) as { meta?: Record<string, unknown> };
      expect(dataDefault.meta?.externalAccountRequired).toBeUndefined();

      CONFIG.EXTERNAL_ACCOUNT_REQUIRED = true;
      const respTrue = handleDirectory(
        new Request("https://acme.test/directory"),
        { ASSETS: testAssets, DB: createMockD1Database() },
        "https://acme.test"
      );
      const dataTrue = (await respTrue.json()) as { meta: { externalAccountRequired?: boolean } };
      expect(dataTrue.meta.externalAccountRequired).toBe(true);
    });

    it("should omit meta completely if all optional fields are disabled", async () => {
      CONFIG.WEBSITE_URL = "";
      CONFIG.CAA_IDENTITIES = [];
      CONFIG.TERMS_OF_SERVICE_URL = "  ";
      const resp = handleDirectory(
        new Request("https://acme.test/directory"),
        {
          ASSETS: testAssets,
          DB: createMockD1Database(),
        },
        "https://acme.test"
      );
      expect(resp.status).toBe(200);
      const data = (await resp.json()) as { meta?: Record<string, unknown> };
      expect(data.meta).toBeUndefined();
    });
  });

  describe("2. Account Creation without Terms of Service Requirement", () => {
    it("should create account successfully when termsOfService is not configured, whether agreed or omitted", async () => {
      const accountKeys = (await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      )) as CryptoKeyPair;
      const accountJwk = (await crypto.subtle.exportKey("jwk", accountKeys.publicKey)) as JsonWebKey;

      let nonce = await getNonce();
      // Case A: termsOfServiceAgreed omitted
      const resWithoutAgreed = await makeJwsRequest(
        "https://acme.test/new-account",
        { contact: ["mailto:dev@example.org"] },
        accountKeys,
        { jwk: accountJwk },
        nonce
      );
      expect(resWithoutAgreed.response.status).toBe(201);
      const bodyA = (await resWithoutAgreed.response.json()) as Record<string, unknown>;
      expect(bodyA.status).toBe("valid");
      expect(bodyA.termsOfServiceAgreed).toBeUndefined();
      expect(bodyA.contact).toEqual(["mailto:dev@example.org"]);
    });

    it("should omit contact in account response if not specified by client", async () => {
      const accountKeys = (await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      )) as CryptoKeyPair;
      const accountJwk = (await crypto.subtle.exportKey("jwk", accountKeys.publicKey)) as JsonWebKey;

      const nonce = await getNonce();
      const res = await makeJwsRequest(
        "https://acme.test/new-account",
        {},
        accountKeys,
        { jwk: accountJwk },
        nonce
      );
      expect(res.response.status).toBe(201);
      const body = (await res.response.json()) as Record<string, unknown>;
      expect(body.status).toBe("valid");
      expect(body.contact).toBeUndefined();
    });

    it("should include termsOfServiceAgreed: true in response if client explicitly agreed", async () => {
      const accountKeys = (await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      )) as CryptoKeyPair;
      const accountJwk = (await crypto.subtle.exportKey("jwk", accountKeys.publicKey)) as JsonWebKey;

      const nonce = await getNonce();
      const res = await makeJwsRequest(
        "https://acme.test/new-account",
        { termsOfServiceAgreed: true },
        accountKeys,
        { jwk: accountJwk },
        nonce
      );
      expect(res.response.status).toBe(201);
      const body = (await res.response.json()) as Record<string, unknown>;
      expect(body.termsOfServiceAgreed).toBe(true);
    });
  });

  describe("3. Account Creation with Terms of Service Requirement (§ 7.3)", () => {
    it("should reject account creation with 403 userActionRequired if termsOfService is set and termsOfServiceAgreed is not true", async () => {
      CONFIG.TERMS_OF_SERVICE_URL = "https://example.com/terms-current";

      const accountKeys = (await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      )) as CryptoKeyPair;
      const accountJwk = (await crypto.subtle.exportKey("jwk", accountKeys.publicKey)) as JsonWebKey;

      let nonce = await getNonce(env);

      // Attempt without termsOfServiceAgreed
      const resMissing = await makeJwsRequest(
        "https://acme.test/new-account",
        { contact: ["mailto:admin@example.org"] },
        accountKeys,
        { jwk: accountJwk },
        nonce,
        env
      );
      expect(resMissing.response.status).toBe(403);
      const linkHeader = resMissing.response.headers.get("Link");
      expect(linkHeader).toContain('<https://example.com/terms-current>;rel="terms-of-service"');
      const errBody = (await resMissing.response.json()) as Record<string, unknown>;
      expect(errBody.type).toBe("urn:ietf:params:acme:error:userActionRequired");
      expect(errBody.instance).toBe("https://example.com/terms-current");
      expect(errBody.termsOfService).toBe("https://example.com/terms-current");

      // Attempt with termsOfServiceAgreed: false
      nonce = resMissing.nextNonce;
      const resFalse = await makeJwsRequest(
        "https://acme.test/new-account",
        { termsOfServiceAgreed: false },
        accountKeys,
        { jwk: accountJwk },
        nonce,
        env
      );
      expect(resFalse.response.status).toBe(403);

      // Successful attempt with termsOfServiceAgreed: true
      nonce = resFalse.nextNonce;
      const resSuccess = await makeJwsRequest(
        "https://acme.test/new-account",
        { termsOfServiceAgreed: true },
        accountKeys,
        { jwk: accountJwk },
        nonce,
        env
      );
      expect(resSuccess.response.status).toBe(201);
      const body = (await resSuccess.response.json()) as Record<string, unknown>;
      expect(body.termsOfServiceAgreed).toBe(true);
    });
  });

  describe("4. Terms of Service Changes & RFC 8555 § 7.3.3 Flow", () => {
    it("should handle terms change, userActionRequired on newOrder, and agreement via account update", async () => {
      CONFIG.TERMS_OF_SERVICE_URL = "https://example.com/terms-v1";

      const accountKeys = (await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      )) as CryptoKeyPair;
      const accountJwk = (await crypto.subtle.exportKey("jwk", accountKeys.publicKey)) as JsonWebKey;

      // 1. Create account under terms-v1
      let nonce = await getNonce(env);
      const createRes = await makeJwsRequest(
        "https://acme.test/new-account",
        { contact: ["mailto:admin@example.org"], termsOfServiceAgreed: true },
        accountKeys,
        { jwk: accountJwk },
        nonce,
        env
      );
      expect(createRes.response.status).toBe(201);
      const kid = createRes.response.headers.get("Location")!;
      expect(kid).toBeTruthy();
      nonce = createRes.nextNonce;

      // 2. Server updates terms to terms-v2
      CONFIG.TERMS_OF_SERVICE_URL = "https://example.com/terms-v2";

      // 3. Client calls newOrder without having agreed to terms-v2 -> returns 403 userActionRequired
      const orderFail = await makeJwsRequest(
        "https://acme.test/new-order",
        { identifiers: [{ type: "dns", value: "test.example.org" }] },
        accountKeys,
        { kid },
        nonce,
        env
      );
      expect(orderFail.response.status).toBe(403);
      expect(orderFail.response.headers.get("Link")).toContain(
        '<https://example.com/terms-v2>;rel="terms-of-service"'
      );
      const orderErr = (await orderFail.response.json()) as Record<string, unknown>;
      expect(orderErr.type).toBe("urn:ietf:params:acme:error:userActionRequired");
      nonce = orderFail.nextNonce;

      // 4. Client attempts to set termsOfServiceAgreed: false on existing account -> 400 malformed (RFC 8555 § 7.1.2)
      const updateFalse = await makeJwsRequest(
        kid,
        { termsOfServiceAgreed: false },
        accountKeys,
        { kid },
        nonce,
        env
      );
      expect(updateFalse.response.status).toBe(400);
      nonce = updateFalse.nextNonce;

      // 5. Client agrees to terms-v2 by updating account with termsOfServiceAgreed: true (RFC 8555 § 7.3.3)
      const updateTrue = await makeJwsRequest(
        kid,
        { termsOfServiceAgreed: true },
        accountKeys,
        { kid },
        nonce,
        env
      );
      expect(updateTrue.response.status).toBe(200);
      const updatedBody = (await updateTrue.response.json()) as Record<string, unknown>;
      expect(updatedBody.termsOfServiceAgreed).toBe(true);
      nonce = updateTrue.nextNonce;

      // 6. Client retries newOrder -> now succeeds!
      const orderSuccess = await makeJwsRequest(
        "https://acme.test/new-order",
        { identifiers: [{ type: "dns", value: "test.example.org" }] },
        accountKeys,
        { kid },
        nonce,
        env
      );
      expect(orderSuccess.response.status).toBe(201);
    });

    it("should allow onlyReturnExisting query even if terms changed, but require agreement on newAccount without onlyReturnExisting", async () => {
      CONFIG.TERMS_OF_SERVICE_URL = "https://example.com/terms-v1";

      const accountKeys = (await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      )) as CryptoKeyPair;
      const accountJwk = (await crypto.subtle.exportKey("jwk", accountKeys.publicKey)) as JsonWebKey;

      let nonce = await getNonce(env);
      const createRes = await makeJwsRequest(
        "https://acme.test/new-account",
        { termsOfServiceAgreed: true },
        accountKeys,
        { jwk: accountJwk },
        nonce,
        env
      );
      expect(createRes.response.status).toBe(201);
      nonce = createRes.nextNonce;

      CONFIG.TERMS_OF_SERVICE_URL = "https://example.com/terms-v2";

      // onlyReturnExisting: true should succeed with 200 (RFC 8555 § 7.3.1)
      const existingRes = await makeJwsRequest(
        "https://acme.test/new-account",
        { onlyReturnExisting: true },
        accountKeys,
        { jwk: accountJwk },
        nonce,
        env
      );
      expect(existingRes.response.status).toBe(200);
      nonce = existingRes.nextNonce;

      // newAccount without onlyReturnExisting and without termsOfServiceAgreed should return 403
      const newAccWithoutAgreed = await makeJwsRequest(
        "https://acme.test/new-account",
        {},
        accountKeys,
        { jwk: accountJwk },
        nonce,
        env
      );
      expect(newAccWithoutAgreed.response.status).toBe(403);
      nonce = newAccWithoutAgreed.nextNonce;

      // newAccount with termsOfServiceAgreed: true should update and return 200
      const newAccWithAgreed = await makeJwsRequest(
        "https://acme.test/new-account",
        { termsOfServiceAgreed: true },
        accountKeys,
        { jwk: accountJwk },
        nonce,
        env
      );
      expect(newAccWithAgreed.response.status).toBe(200);
      const body = (await newAccWithAgreed.response.json()) as Record<string, unknown>;
      expect(body.termsOfServiceAgreed).toBe(true);
    });
  });
});
