import { AcmeError } from "../errors";
import { Database } from "../db/queries";
import { AccountRow } from "../db/types";
import { base64UrlDecode, base64UrlEncode, verifyAndConsumeNonce } from "./nonce";

export interface JwsFlattened {
  protected: string;
  payload: string;
  signature: string;
}

export interface JwsProtectedHeader {
  alg: string;
  nonce: string;
  url: string;
  jwk?: JsonWebKey;
  kid?: string;
}

export interface VerifiedJws<T = unknown> {
  header: JwsProtectedHeader;
  payload: T;
  account: AccountRow | null; // null if newAccount before creation
  jwk: JsonWebKey;
  thumbprint: string;
}

/**
 * Calculates RFC 7638 JWK Thumbprint using SHA-256
 */
export async function calculateJwkThumbprint(jwk: JsonWebKey): Promise<string> {
  let canonicalJson = "";
  if (jwk.kty === "EC") {
    if (!jwk.crv || !jwk.x || !jwk.y) {
      throw AcmeError.malformed("Malformed EC JWK: missing required fields");
    }
    canonicalJson = JSON.stringify({
      crv: jwk.crv,
      kty: jwk.kty,
      x: jwk.x,
      y: jwk.y,
    });
  } else if (jwk.kty === "RSA") {
    if (!jwk.e || !jwk.n) {
      throw AcmeError.malformed("Malformed RSA JWK: missing required fields");
    }
    canonicalJson = JSON.stringify({
      e: jwk.e,
      kty: jwk.kty,
      n: jwk.n,
    });
  } else if (jwk.kty === "OKP") {
    if (!jwk.crv || !jwk.x) {
      throw AcmeError.malformed("Malformed OKP JWK: missing required fields");
    }
    canonicalJson = JSON.stringify({
      crv: jwk.crv,
      kty: jwk.kty,
      x: jwk.x,
    });
  } else {
    throw AcmeError.malformed(`Unsupported JWK key type: ${jwk.kty}`);
  }

  const encoded = new TextEncoder().encode(canonicalJson);
  const hash = await crypto.subtle.digest("SHA-256", encoded);
  return base64UrlEncode(hash);
}

/**
 * Imports a public JWK into a CryptoKey for verification
 */
export async function importPublicJwk(jwk: JsonWebKey, alg: string): Promise<CryptoKey> {
  try {
    if (alg === "ES256" && jwk.kty === "EC" && jwk.crv === "P-256") {
      return await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"]
      );
    }
    if (alg === "RS256" && jwk.kty === "RSA") {
      return await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"]
      );
    }
    if (alg === "EdDSA" && jwk.kty === "OKP" && jwk.crv === "Ed25519") {
      return await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, [
        "verify",
      ]);
    }
    throw new Error(`Unsupported algorithm ${alg} or incompatible JWK`);
  } catch (err: unknown) {
    throw AcmeError.malformed(
      `Failed to import public key: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

/**
 * Verifies and parses an incoming ACME JWS request
 */
export async function verifyAcmeJws<T = unknown>(
  request: Request,
  database: Database,
  expectedPath?: string
): Promise<VerifiedJws<T>> {
  let body: JwsFlattened;
  try {
    body = (await request.json()) as JwsFlattened;
  } catch {
    throw AcmeError.malformed("Invalid JSON body");
  }

  if (!body.protected || !body.signature || body.payload === undefined) {
    throw AcmeError.malformed("JWS must include protected, payload, and signature fields");
  }

  let header: JwsProtectedHeader;
  try {
    const headerStr = new TextDecoder().decode(base64UrlDecode(body.protected));
    header = JSON.parse(headerStr) as JwsProtectedHeader;
  } catch {
    throw AcmeError.malformed("Malformed JWS protected header");
  }

  if (!header.alg || !header.nonce || !header.url) {
    throw AcmeError.malformed("JWS protected header missing alg, nonce, or url");
  }

  // 1. Verify and consume Replay-Nonce
  const nonceValid = await verifyAndConsumeNonce(database, header.nonce);
  if (!nonceValid) {
    throw AcmeError.badNonce();
  }

  // 2. Verify URL in protected header matches request URL
  const reqUrl = new URL(request.url);
  const headerUrl = new URL(header.url);
  if (expectedPath) {
    if (headerUrl.pathname !== expectedPath && !headerUrl.pathname.endsWith(expectedPath)) {
      throw AcmeError.malformed(
        `JWS protected url '${header.url}' does not match expected path '${expectedPath}'`
      );
    }
  } else if (headerUrl.pathname !== reqUrl.pathname) {
    throw AcmeError.malformed(
      `JWS protected url '${header.url}' does not match request path '${reqUrl.pathname}'`
    );
  }

  // 3. Resolve key (either jwk or kid)
  let jwk: JsonWebKey;
  let account: AccountRow | null = null;
  let thumbprint = "";

  if (header.jwk) {
    if (header.kid) {
      throw AcmeError.malformed("JWS protected header cannot specify both jwk and kid");
    }
    jwk = header.jwk;
    thumbprint = await calculateJwkThumbprint(jwk);
  } else if (header.kid) {
    const kidUrl = new URL(header.kid);
    const parts = kidUrl.pathname.split("/").filter(Boolean);
    const accountId = parts[parts.length - 1];

    account = await database.getAccountById(accountId);
    if (!account) {
      throw AcmeError.unauthorized("Account does not exist");
    }
    if (account.status !== "valid") {
      throw AcmeError.unauthorized(`Account is ${account.status}`);
    }

    jwk = JSON.parse(account.jwk) as JsonWebKey;
    thumbprint = account.thumbprint;
  } else {
    throw AcmeError.malformed("JWS protected header must include either jwk or kid");
  }

  // 4. Verify signature
  const cryptoKey = await importPublicJwk(jwk, header.alg);
  const signingInput = new TextEncoder().encode(`${body.protected}.${body.payload}`);
  const signatureBytes = base64UrlDecode(body.signature);

  let verifyAlg: { name: string; hash?: string };
  if (header.alg === "ES256") {
    verifyAlg = { name: "ECDSA", hash: "SHA-256" };
  } else if (header.alg === "RS256") {
    verifyAlg = { name: "RSASSA-PKCS1-v1_5" };
  } else if (header.alg === "EdDSA") {
    verifyAlg = { name: "Ed25519" };
  } else {
    throw AcmeError.malformed(`Unsupported alg: ${header.alg}`);
  }

  const isValid = await crypto.subtle.verify(verifyAlg, cryptoKey, signatureBytes, signingInput);
  if (!isValid) {
    throw AcmeError.unauthorized("Invalid JWS signature");
  }

  // 5. Decode payload (empty payload in POST-as-GET is allowed)
  let parsedPayload = {} as T;
  if (body.payload && body.payload.trim() !== "") {
    try {
      const payloadStr = new TextDecoder().decode(base64UrlDecode(body.payload));
      parsedPayload = JSON.parse(payloadStr) as T;
    } catch {
      throw AcmeError.malformed("Malformed JWS payload");
    }
  }

  return {
    header,
    payload: parsedPayload,
    account,
    jwk,
    thumbprint,
  };
}
