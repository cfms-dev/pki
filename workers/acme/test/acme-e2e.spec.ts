import { testAssets, testRateLimits } from "./website-test-helpers";
import { mockCaCertificate } from "./ca-test-helpers";
import { describe, it, expect, beforeEach } from "vitest";
import * as x509 from "@peculiar/x509";
import worker from "../src/index";
import { AcmeEnv, CONFIG } from "../src/config";
import { createMockD1Database } from "./mock-d1";
import { base64UrlEncode } from "../src/crypto/nonce";
import { calculateJwkThumbprint } from "../src/crypto/jws";
import { computeExpectedDnsDigest } from "../src/dns/validator";
import { computeCertId } from "../src/ari/cert-id";

describe("ACME RFC 8555 & RFC 9773 ARI End-to-End Suite", () => {
  let env: AcmeEnv;
  let caKeyPem: string;
  let caCertPem: string;
  let caKeys: CryptoKeyPair;

  beforeEach(async () => {
    // Generate CA key pair and cert
    caKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;

    const caCert = await x509.X509CertificateGenerator.create({
      serialNumber: "0102030405060708090a",
      subject: "CN=CFMS Intermediate CA, O=CFMS",
      issuer: "CN=CFMS Root CA",
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

    mockCaCertificate(caCertPem);
    env = {
      ...testRateLimits, ASSETS: testAssets,
      DB: createMockD1Database(),
      PK_GENERIC_INTERMEDIATE: caKeyPem,
      fetch: async (input: RequestInfo | URL) => {
        if (!String(input).includes("type=CAA")) return globalThis.fetch(input);
        return new Response(JSON.stringify({ Status: 0 }), { headers: { "Content-Type": "application/dns-json" } });
      },
    };
  });

  const ctx = {
    waitUntil: () => {},
    passThroughOnException: () => {},
  } as unknown as ExecutionContext;

  async function makeJwsRequest(
    url: string,
    payload: Record<string, unknown> | "",
    accountKey: CryptoKeyPair,
    keyMode: { jwk?: JsonWebKey; kid?: string },
    nonce: string
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
      env,
      ctx
    );

    const nextNonce = response.headers.get("Replay-Nonce") || "";
    return { response, nextNonce };
  }

  it("should complete full ACME lifecycle: order, DNS-01 validation, 90-day cert issuance, and ARI renewal with re-validation & rate limit exemption", async () => {
    // -------------------------------------------------------------
    // 1. Directory & Nonce
    // -------------------------------------------------------------
    const dirResp = await worker.fetch(
      new Request("https://acme.test/directory"),
      env,
      ctx
    );
    expect(dirResp.status).toBe(200);
    const directory = (await dirResp.json()) as Record<string, string>;
    expect(directory.newAccount).toBe("https://acme.test/new-account");
    expect(directory.newOrder).toBe("https://acme.test/new-order");
    expect(directory.renewalInfo).toBe("https://acme.test/renewal-info");

    const nonceResp = await worker.fetch(
      new Request("https://acme.test/new-nonce", { method: "HEAD" }),
      env,
      ctx
    );
    expect(nonceResp.status).toBe(200);
    let nonce = nonceResp.headers.get("Replay-Nonce")!;
    expect(nonce).toBeDefined();

    // -------------------------------------------------------------
    // 2. Create Account
    // -------------------------------------------------------------
    const accountKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const accountJwk = (await crypto.subtle.exportKey("jwk", accountKeys.publicKey)) as JsonWebKey;
    const accountThumbprint = await calculateJwkThumbprint(accountJwk);

    const accRes = await makeJwsRequest(
      "https://acme.test/new-account",
      { contact: ["mailto:admin@example.com"], termsOfServiceAgreed: true },
      accountKeys,
      { jwk: accountJwk },
      nonce
    );
    expect(accRes.response.status).toBe(201);
    const kid = accRes.response.headers.get("Location")!;
    expect(kid).toContain("https://acme.test/account/");
    nonce = accRes.nextNonce;

    // -------------------------------------------------------------
    // 3. Create Order
    // -------------------------------------------------------------
    const orderRes = await makeJwsRequest(
      "https://acme.test/new-order",
      { identifiers: [{ type: "dns", value: "example.com" }] },
      accountKeys,
      { kid },
      nonce
    );
    expect(orderRes.response.status).toBe(201);
    const order = (await orderRes.response.json()) as Record<string, unknown>;
    expect(order.status).toBe("pending");
    const orderUrl = orderRes.response.headers.get("Location")!;
    const authzUrl = (order.authorizations as string[])[0];
    nonce = orderRes.nextNonce;

    // -------------------------------------------------------------
    // 4. Fetch Authorization & Challenge
    // -------------------------------------------------------------
    const authzRes = await makeJwsRequest(authzUrl, "", accountKeys, { kid }, nonce);
    expect(authzRes.response.status).toBe(200);
    const authz = (await authzRes.response.json()) as {
      challenges: Array<{ type: string; url: string; token: string; status: string }>;
    };
    const dnsChallenge = authz.challenges.find((c) => c.type === "dns-01")!;
    expect(dnsChallenge.status).toBe("pending");
    nonce = authzRes.nextNonce;

    // -------------------------------------------------------------
    // 5. Trigger DNS-01 Challenge Validation
    // Mock globalThis.fetch for DoH resolution during challenge
    // -------------------------------------------------------------
    const expectedDnsDigest = await computeExpectedDnsDigest(
      dnsChallenge.token,
      accountThumbprint
    );

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const urlStr = String(input);
      if (urlStr.includes("_acme-challenge.example.com")) {
        return new Response(
          JSON.stringify({
            Status: 0,
            Answer: [{ type: 16, data: `"${expectedDnsDigest}"` }],
          }),
          { status: 200, headers: { "Content-Type": "application/dns-json" } }
        );
      }
      throw new Error("Unexpected external request: " + urlStr);
    }) as typeof fetch;

    try {
      const chalRes = await makeJwsRequest(
        dnsChallenge.url,
        {},
        accountKeys,
        { kid },
        nonce
      );
      expect(chalRes.response.status).toBe(200);
      const chalBody = (await chalRes.response.json()) as { status: string };
      expect(chalBody.status).toBe("valid");
      nonce = chalRes.nextNonce;
    } finally {
      globalThis.fetch = originalFetch;
    }

    // -------------------------------------------------------------
    // 6. Check Order Ready & Finalize with CSR
    // -------------------------------------------------------------
    const getOrderRes = await makeJwsRequest(orderUrl, "", accountKeys, { kid }, nonce);
    const readyOrder = (await getOrderRes.response.json()) as { status: string };
    expect(readyOrder.status).toBe("ready");
    nonce = getOrderRes.nextNonce;

    const certKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=example.com",
      keys: certKeys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new x509.SubjectAlternativeNameExtension([
          { type: "dns", value: "example.com" },
        ]),
      ],
    });
    const csrB64 = base64UrlEncode(csr.rawData);

    const finalizeRes = await makeJwsRequest(
      `${orderUrl}/finalize`,
      { csr: csrB64 },
      accountKeys,
      { kid },
      nonce
    );
    expect(finalizeRes.response.status).toBe(200);
    const validOrder = (await finalizeRes.response.json()) as {
      status: string;
      certificate: string;
    };
    expect(validOrder.status).toBe("valid");
    expect(validOrder.certificate).toBeDefined();
    nonce = finalizeRes.nextNonce;

    // -------------------------------------------------------------
    // 7. Download Certificate Chain
    // -------------------------------------------------------------
    const certResp = await worker.fetch(new Request(validOrder.certificate), env, ctx);
    expect(certResp.status).toBe(200);
    expect(certResp.headers.get("Content-Type")).toBe("application/pem-certificate-chain");
    const certChain = await certResp.text();
    expect(certChain).toContain("-----BEGIN CERTIFICATE-----");

    const leafCert = new x509.X509Certificate(certChain);
    expect(leafCert.subject).toBe("CN=example.com");

    // Verify 90-day validity
    const validityDays =
      (leafCert.notAfter.getTime() - leafCert.notBefore.getTime()) / (86400 * 1000);
    expect(Math.round(validityDays)).toBe(90);

    // -------------------------------------------------------------
    // 8. RFC 9773 ACME Renewal Information (ARI) Query
    // -------------------------------------------------------------
    const akiExt = leafCert.extensions.find((e) => e.type === "2.5.29.35");
    const akiHex = (akiExt as { keyId?: string })?.keyId || "";
    const certId = computeCertId(akiHex, leafCert.serialNumber);

    const ariResp = await worker.fetch(
      new Request(`https://acme.test/renewal-info/${certId}`),
      env,
      ctx
    );
    expect(ariResp.status).toBe(200);
    expect(ariResp.headers.get("Retry-After")).toBe(
      CONFIG.ARI_RETRY_AFTER_SECONDS.toString()
    );
    const ariBody = (await ariResp.json()) as {
      suggestedWindow: { start: string; end: string };
    };

    const winStart = Math.floor(new Date(ariBody.suggestedWindow.start).getTime() / 1000);
    const winEnd = Math.floor(new Date(ariBody.suggestedWindow.end).getTime() / 1000);
    // Window length must be 30 days
    expect((winEnd - winStart) / 86400).toBe(30);

    // -------------------------------------------------------------
    // 9. ARI Renewal with Re-verification & Rate Limit Exemption
    // -------------------------------------------------------------
    // Fast forward database certificate created_at / not_before to 65 days ago
    // so current time falls inside the 30-day renewal window
    const sixtyFiveDaysAgo = Math.floor(Date.now() / 1000) - 65 * 86400;
    await env.DB.prepare(
      "UPDATE certificates SET not_before = ?, not_after = ? WHERE cert_id = ?"
    )
      .bind(sixtyFiveDaysAgo, sixtyFiveDaysAgo + 90 * 86400, certId)
      .run();

    // Set duplicate certificate rate limit to max (5)
    await env.DB.prepare(
      "INSERT OR REPLACE INTO rate_limits (key, counter, window_start) VALUES (?, 5, ?)"
    )
      .bind("issuance:duplicate:example.com", Math.floor(Date.now() / 1000))
      .run();

    // Now submit an ARI renewal order with "replaces": certId
    const renewOrderRes = await makeJwsRequest(
      "https://acme.test/new-order",
      {
        identifiers: [{ type: "dns", value: "example.com" }],
        replaces: certId,
      },
      accountKeys,
      { kid },
      nonce
    );

    // Verify rate limit exemption granted!
    expect(renewOrderRes.response.status).toBe(201);
    const renewalOrder = (await renewOrderRes.response.json()) as {
      status: string;
      replaces: string;
      authorizations: string[];
      finalize: string;
    };
    expect(renewalOrder.replaces).toBe(certId);
    expect(renewalOrder.status).toBe("pending");
    nonce = renewOrderRes.nextNonce;

    // Verify user requirement: "续期证书时，必须重新验证所有权"
    // Authorization must be pending, requiring DNS-01 re-verification!
    const renewalAuthzUrl = renewalOrder.authorizations[0];
    const renewAuthzRes = await makeJwsRequest(
      renewalAuthzUrl,
      "",
      accountKeys,
      { kid },
      nonce
    );
    const renewAuthz = (await renewAuthzRes.response.json()) as {
      status: string;
      challenges: Array<{ status: string; url: string; token: string }>;
    };
    expect(renewAuthz.status).toBe("pending");
    expect(renewAuthz.challenges[0].status).toBe("pending");
    nonce = renewAuthzRes.nextNonce;

    // Re-verify challenge for renewal
    const renewDigest = await computeExpectedDnsDigest(
      renewAuthz.challenges[0].token,
      accountThumbprint
    );

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const urlStr = String(input);
      if (urlStr.includes("_acme-challenge.example.com")) {
        return new Response(
          JSON.stringify({
            Status: 0,
            Answer: [{ type: 16, data: `"${renewDigest}"` }],
          }),
          { status: 200, headers: { "Content-Type": "application/dns-json" } }
        );
      }
      throw new Error("Unexpected external request: " + urlStr);
    }) as typeof fetch;

    try {
      const chalRes = await makeJwsRequest(
        renewAuthz.challenges[0].url,
        {},
        accountKeys,
        { kid },
        nonce
      );
      expect(chalRes.response.status).toBe(200);
      nonce = chalRes.nextNonce;
    } finally {
      globalThis.fetch = originalFetch;
    }

    // Finalize renewed order
    const renewFinalizeRes = await makeJwsRequest(
      renewalOrder.finalize,
      { csr: csrB64 },
      accountKeys,
      { kid },
      nonce
    );
    expect(renewFinalizeRes.response.status).toBe(200);
    const renewedValidOrder = (await renewFinalizeRes.response.json()) as {
      status: string;
      certificate: string;
    };
    expect(renewedValidOrder.status).toBe("valid");

    // Verify predecessor certificate is marked replaced
    const predecessorCertInDb = await env.DB.prepare(
      "SELECT * FROM certificates WHERE cert_id = ?"
    )
      .bind(certId)
      .first<{ replaced_by_cert_id: string }>();
    expect(predecessorCertInDb?.replaced_by_cert_id).toBeDefined();

    // Verify ARI on predecessor certificate now reports immediate past window
    const ariReplacedResp = await worker.fetch(
      new Request(`https://acme.test/renewal-info/${certId}`),
      env,
      ctx
    );
    const ariReplacedBody = (await ariReplacedResp.json()) as {
      suggestedWindow: { start: string; end: string };
    };
    const repEnd = Math.floor(
      new Date(ariReplacedBody.suggestedWindow.end).getTime() / 1000
    );
    expect(repEnd).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
  }, 15_000);
});
