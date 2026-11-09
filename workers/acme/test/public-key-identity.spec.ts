import { describe, it, expect } from "vitest";
import {
  calculateJwkThumbprint,
  normalizePublicKey,
  publicKeyFingerprintFromSpki,
  PublicKeyIdentityError,
} from "../src/crypto/jws";
import { base64UrlEncode } from "../src/crypto/nonce";
import {
  exportPublicJwk,
  generateAccountKeys,
  padBase64Url,
} from "./account-key-test-helpers";

const BASE64URL_43 = /^[A-Za-z0-9_-]{43}$/;

describe("canonical public key identity", () => {
  it("normalizes the same EC key independently of JWK field order", async () => {
    const keys = await generateAccountKeys("ES256");
    const jwk = await exportPublicJwk(keys);
    const reordered = {
      y: jwk.y,
      crv: jwk.crv,
      x: jwk.x,
      kty: jwk.kty,
    } as JsonWebKey;

    const first = await normalizePublicKey(jwk);
    const second = await normalizePublicKey(reordered);

    expect(second.fingerprint).toBe(first.fingerprint);
    expect(second.thumbprint).toBe(first.thumbprint);
    expect(first.fingerprint).toMatch(BASE64URL_43);
    expect(first.thumbprint).toMatch(BASE64URL_43);
  });

  it("normalizes EC coordinates with redundant leading zero bytes", async () => {
    const keys = await generateAccountKeys("ES256");
    const jwk = await exportPublicJwk(keys);
    const padded = {
      ...jwk,
      x: padBase64Url(jwk.x as string),
      y: padBase64Url(jwk.y as string),
    };

    const canonical = await normalizePublicKey(jwk);
    const paddedIdentity = await normalizePublicKey(padded);

    expect(paddedIdentity.fingerprint).toBe(canonical.fingerprint);
    expect(paddedIdentity.spki).toEqual(canonical.spki);
    // This demonstrates why RFC 7638 thumbprints cannot be used as the
    // identity index: the padded encoding has a different protocol value.
    expect(await calculateJwkThumbprint(padded)).not.toBe(
      await calculateJwkThumbprint(jwk)
    );
  });

  it("normalizes an RSA key whose modulus and exponent have redundant leading zeroes", async () => {
    const keys = await generateAccountKeys("RS256");
    const jwk = await exportPublicJwk(keys);
    const padded = {
      ...jwk,
      n: padBase64Url(jwk.n as string, 4),
      e: padBase64Url(jwk.e as string, 2),
    };

    const canonical = await normalizePublicKey(jwk);
    const paddedIdentity = await normalizePublicKey(padded);

    expect(paddedIdentity.fingerprint).toBe(canonical.fingerprint);
    expect(paddedIdentity.spki).toEqual(canonical.spki);
    expect(await calculateJwkThumbprint(padded)).not.toBe(
      await calculateJwkThumbprint(jwk)
    );
  });

  it("ignores unrelated optional JWK members", async () => {
    const keys = await generateAccountKeys("ES256");
    const jwk = await exportPublicJwk(keys);
    const decorated = {
      ...jwk,
      kid: "not-part-of-the-key",
      use: "sig",
      key_ops: ["sign"],
      alg: "ES256",
      ext: true,
      x5u: "https://example.invalid/cert.pem",
    } as JsonWebKey;

    const first = await normalizePublicKey(jwk);
    const second = await normalizePublicKey(decorated);

    expect(second.fingerprint).toBe(first.fingerprint);
    expect(second.thumbprint).toBe(first.thumbprint);
  });

  it("produces the canonical SPKI DER and its SHA-256 fingerprint", async () => {
    const keys = await generateAccountKeys("ES256");
    const jwk = await exportPublicJwk(keys);
    const identity = await normalizePublicKey(jwk);
    const expectedSpki = new Uint8Array(
      (await crypto.subtle.exportKey("spki", keys.publicKey)) as ArrayBuffer
    );

    expect(identity.spki).toEqual(expectedSpki);
    expect(identity.fingerprint).toBe(
      await publicKeyFingerprintFromSpki(expectedSpki)
    );
  });

  it("normalizes Ed25519 (EdDSA) account keys", async () => {
    const keys = await generateAccountKeys("EdDSA");
    const jwk = await exportPublicJwk(keys);
    const identity = await normalizePublicKey(jwk, "EdDSA");

    expect(identity.algorithm).toBe("EdDSA");
    expect(identity.fingerprint).toMatch(BASE64URL_43);
    expect(identity.thumbprint).toMatch(BASE64URL_43);
  });

  it("produces different identities for different keys", async () => {
    const firstKeys = await generateAccountKeys("ES256");
    const secondKeys = await generateAccountKeys("ES256");
    const thirdKeys = await generateAccountKeys("RS256");

    const first = await normalizePublicKey(await exportPublicJwk(firstKeys));
    const second = await normalizePublicKey(await exportPublicJwk(secondKeys));
    const third = await normalizePublicKey(await exportPublicJwk(thirdKeys));

    expect(first.fingerprint).not.toBe(second.fingerprint);
    expect(first.fingerprint).not.toBe(third.fingerprint);
    expect(second.fingerprint).not.toBe(third.fingerprint);
  });

  it("rejects private key material instead of accepting an ambiguous key", async () => {
    const keys = await generateAccountKeys("ES256");
    const jwk = await exportPublicJwk(keys);

    await expect(
      normalizePublicKey({ ...jwk, d: "AQAB" })
    ).rejects.toMatchObject({ code: "private_key_material" });

    const rsaKeys = await generateAccountKeys("RS256");
    const rsaJwk = await exportPublicJwk(rsaKeys);
    await expect(
      normalizePublicKey({ ...rsaJwk, p: "AQAB" })
    ).rejects.toMatchObject({ code: "private_key_material" });
  });

  it("rejects invalid, unsupported, and wrong-curve JWKs", async () => {
    const keys = await generateAccountKeys("ES256");
    const jwk = await exportPublicJwk(keys);

    const cases: Array<{ value: unknown; code: string }> = [
      { value: null, code: "invalid_jwk" },
      { value: [], code: "invalid_jwk" },
      { value: "not-a-jwk", code: "invalid_jwk" },
      { value: { kty: "oct", k: "AQAB" }, code: "private_key_material" },
      { value: { kty: "EC", crv: "P-256", y: jwk.y }, code: "invalid_jwk" },
      { value: { ...jwk, crv: "P-384" }, code: "unsupported_curve" },
      { value: { kty: "OKP", crv: "Ed448", x: jwk.x }, code: "unsupported_curve" },
      { value: { ...jwk, x: "!!!not-base64url!!!" }, code: "invalid_jwk" },
    ];

    for (const testCase of cases) {
      await expect(normalizePublicKey(testCase.value)).rejects.toMatchObject({
        code: testCase.code,
      });
    }
  });

  it("rejects a JWK that does not match the JWS algorithm", async () => {
    const rsaKeys = await generateAccountKeys("RS256");
    const rsaJwk = await exportPublicJwk(rsaKeys);

    await expect(normalizePublicKey(rsaJwk, "ES256")).rejects.toBeInstanceOf(
      PublicKeyIdentityError
    );
    await expect(normalizePublicKey(rsaJwk, "HS256")).rejects.toMatchObject({
      code: "unsupported_algorithm",
    });
  });

  it("rejects a point that is not on the declared curve", async () => {
    const zeroCoordinate = base64UrlEncode(new Uint8Array(32));
    const invalidPoint = {
      kty: "EC",
      crv: "P-256",
      x: zeroCoordinate,
      y: zeroCoordinate,
    };

    await expect(normalizePublicKey(invalidPoint)).rejects.toMatchObject({
      code: "key_import_failed",
    });
  });
});
