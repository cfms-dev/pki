import { AcmeEnv } from "../src/config";
import { calculateJwkThumbprint } from "../src/crypto/jws";
import { base64UrlDecode, base64UrlEncode } from "../src/crypto/nonce";
import {
  ACME_BASE_URL,
  AccountKeyAlgorithm,
  getNonce,
  makeJwsRequest,
  TestAccount,
} from "./acme-test-helpers";

export interface RegisteredAccount extends TestAccount {
  status: number;
  body: Record<string, unknown>;
  responseNonce: string;
}

export async function generateAccountKeys(
  alg: AccountKeyAlgorithm
): Promise<CryptoKeyPair> {
  if (alg === "ES256") {
    return (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
  }
  if (alg === "RS256") {
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
  return (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
}

export async function exportPublicJwk(keys: CryptoKeyPair): Promise<JsonWebKey> {
  return (await crypto.subtle.exportKey("jwk", keys.publicKey)) as JsonWebKey;
}

/** Adds redundant leading zero bytes to a base64url-encoded integer/octet string. */
export function padBase64Url(value: string, leadingZeroBytes = 1): string {
  const bytes = base64UrlDecode(value);
  const padded = new Uint8Array(bytes.length + leadingZeroBytes);
  padded.set(bytes, leadingZeroBytes);
  return base64UrlEncode(padded);
}

export async function registerAccountJwk(
  env: AcmeEnv,
  keys: CryptoKeyPair,
  jwk: JsonWebKey,
  alg: AccountKeyAlgorithm = "ES256",
  payload: Record<string, unknown> = {
    contact: ["mailto:admin@example.com"],
    termsOfServiceAgreed: true,
  }
): Promise<RegisteredAccount> {
  const thumbprint = await calculateJwkThumbprint(jwk);
  const nonce = await getNonce(env);
  const result = await makeJwsRequest(
    env,
    `${ACME_BASE_URL}/new-account`,
    payload,
    { keys, jwk, kid: "", alg },
    nonce,
    "jwk"
  );
  const body = (await result.response.json()) as Record<string, unknown>;
  return {
    keys,
    jwk,
    thumbprint,
    kid: result.response.headers.get("Location") || "",
    alg,
    status: result.response.status,
    body,
    responseNonce: result.nextNonce,
  };
}

async function signWithAlgorithm(
  alg: AccountKeyAlgorithm,
  key: CryptoKey,
  data: Uint8Array
): Promise<ArrayBuffer> {
  return crypto.subtle.sign(
    alg === "ES256"
      ? { name: "ECDSA", hash: "SHA-256" }
      : alg === "RS256"
        ? { name: "RSASSA-PKCS1-v1_5" }
        : { name: "Ed25519" },
    key,
    data
  );
}

export interface KeyChangeOverrides {
  /** Protected inner url; defaults to the real key-change URL. */
  innerUrl?: string;
  /** Adds a forbidden nonce member to the inner protected header. */
  includeNonce?: boolean;
  /** Overrides oldKey in the inner payload. */
  oldKey?: JsonWebKey;
  /** Overrides account in the inner payload. */
  account?: string;
  /** Corrupts the inner signature (but keeps the encoding valid). */
  corruptInnerSignature?: boolean;
  /** Overrides the inner protected jwk (signature follows newKeys). */
  innerJwk?: JsonWebKey;
}

/**
 * Builds an RFC 8555 § 7.3.5 keyChange request: outer JWS signed with the
 * current account key, inner JWS (the outer payload) signed with the new key.
 */
export async function makeKeyChangeRequest(
  env: AcmeEnv,
  account: TestAccount,
  newKeys: CryptoKeyPair,
  newJwk: JsonWebKey,
  newAlg: AccountKeyAlgorithm,
  nonce: string,
  overrides: KeyChangeOverrides = {}
): Promise<{ response: Response; nextNonce: string }> {
  const innerHeader: Record<string, unknown> = {
    alg: newAlg,
    jwk: overrides.innerJwk ?? newJwk,
    url: overrides.innerUrl ?? `${ACME_BASE_URL}/key-change`,
  };
  if (overrides.includeNonce) {
    innerHeader.nonce = "must-not-be-present";
  }

  const innerPayload = {
    account: overrides.account ?? account.kid,
    oldKey: overrides.oldKey ?? account.jwk,
  };

  const protectedB64 = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(innerHeader))
  );
  const payloadB64 = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(innerPayload))
  );

  const signature = new Uint8Array(
    await signWithAlgorithm(
      newAlg,
      newKeys.privateKey,
      new TextEncoder().encode(`${protectedB64}.${payloadB64}`)
    )
  );
  if (overrides.corruptInnerSignature) {
    signature[0] ^= 0xff;
  }

  const innerJws = {
    protected: protectedB64,
    payload: payloadB64,
    signature: base64UrlEncode(signature),
  };

  return makeJwsRequest(
    env,
    `${ACME_BASE_URL}/key-change`,
    innerJws,
    account,
    nonce
  );
}

/** Registers an account with a fresh key and returns its identity. */
export async function registerFreshAccount(
  env: AcmeEnv,
  alg: AccountKeyAlgorithm = "ES256",
  transformJwk?: (jwk: JsonWebKey) => JsonWebKey
): Promise<RegisteredAccount> {
  const keys = await generateAccountKeys(alg);
  const exported = await exportPublicJwk(keys);
  const jwk = transformJwk ? transformJwk(exported) : exported;
  return registerAccountJwk(env, keys, jwk, alg);
}
