import { describe, it, expect, beforeEach } from "vitest";
import { createMockD1Database } from "./mock-d1";
import { Database } from "../src/db/queries";
import {
  base64UrlDecode,
  base64UrlEncode,
  createAndSaveNonce,
  verifyAndConsumeNonce,
} from "../src/crypto/nonce";
import {
  calculateJwkThumbprint,
  verifyAcmeJws,
} from "../src/crypto/jws";

describe("JWS & Nonce Cryptography", () => {
  let db: Database;

  beforeEach(async () => {
    db = new Database(createMockD1Database());
    await db.initSchema();
  });

  it("should generate and consume single-use nonces", async () => {
    const nonce = await createAndSaveNonce(db);
    expect(nonce).toBeDefined();
    expect(typeof nonce).toBe("string");

    // First consumption succeeds
    const consumed = await verifyAndConsumeNonce(db, nonce);
    expect(consumed).toBe(true);

    // Second consumption fails (anti-replay)
    const consumedAgain = await verifyAndConsumeNonce(db, nonce);
    expect(consumedAgain).toBe(false);
  });

  it("should correctly compute RFC 7638 SHA-256 JWK thumbprint", async () => {
    // Example test vector from RFC 7638 Section 3.1
    const testJwk: JsonWebKey = {
      kty: "RSA",
      n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      e: "AQAB",
    };

    const thumbprint = await calculateJwkThumbprint(testJwk);
    expect(thumbprint).toBe("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
  });

  it("should sign and verify ACME JWS payload with ES256", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

    const nonce = await createAndSaveNonce(db);
    const url = "https://acme.example.com/new-account";

    const protectedHeader = {
      alg: "ES256",
      nonce,
      url,
      jwk,
    };
    const protectedB64 = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(protectedHeader))
    );

    const payloadObj = { contact: ["mailto:admin@example.com"], termsOfServiceAgreed: true };
    const payloadB64 = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(payloadObj))
    );

    const signingInput = new TextEncoder().encode(`${protectedB64}.${payloadB64}`);
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      keyPair.privateKey,
      signingInput
    );
    const signatureB64 = base64UrlEncode(signature);

    const jwsBody = JSON.stringify({
      protected: protectedB64,
      payload: payloadB64,
      signature: signatureB64,
    });

    const request = new Request(url, {
      method: "POST",
      headers: { "Content-Type": "application/jose+json" },
      body: jwsBody,
    });

    const verified = await verifyAcmeJws(request, db);
    expect(verified.header.alg).toBe("ES256");
    expect(verified.payload).toEqual(payloadObj);
    expect(verified.thumbprint).toBeDefined();
  });
});
