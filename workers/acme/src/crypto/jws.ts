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

/** Account key algorithms supported by this ACME server. */
export type AccountKeyAlgorithm = "ES256" | "RS256" | "EdDSA";

export type PublicKeyIdentityErrorCode =
  | "invalid_jwk"
  | "unsupported_algorithm"
  | "unsupported_curve"
  | "private_key_material"
  | "key_import_failed"
  | "key_export_failed";

/**
 * Raised when a JWK cannot be normalized into a stable public-key identity.
 *
 * This is deliberately distinct from RFC 7638 thumbprint failures: a
 * thumbprint is a protocol value derived from the JWK's required members,
 * while the fingerprint below is an identity of the actual key material.
 */
export class PublicKeyIdentityError extends Error {
  constructor(
    public readonly code: PublicKeyIdentityErrorCode,
    message: string
  ) {
    super(message);
    this.name = "PublicKeyIdentityError";
  }
}

export interface CryptoKeyPublicIdentity {
  cryptoKey: CryptoKey;
  /** Canonical public JWK re-exported by WebCrypto. */
  jwk: JsonWebKey;
  /** Canonical SubjectPublicKeyInfo DER. */
  spki: Uint8Array;
  /** RFC 7638 thumbprint of the canonical JWK. */
  thumbprint: string;
  /** base64url(SHA-256(canonical SPKI DER)) — the actual public key identity. */
  fingerprint: string;
}

export interface NormalizedPublicKey extends CryptoKeyPublicIdentity {
  algorithm: AccountKeyAlgorithm;
}

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const publishedUrls = new WeakMap<Request, string>();

export function bindPublishedRequestUrl(request: Request, baseUrl: string): void {
  const actual = new URL(request.url);
  publishedUrls.set(request, `${baseUrl.replace(/\/$/, "")}${actual.pathname}${actual.search}`);
}

async function readJwsBody(request: Request): Promise<unknown> {
  if (request.headers.get("Content-Type")?.split(";")[0].trim().toLowerCase() !== "application/jose+json") {
    throw new AcmeError("malformed", "Content-Type must be application/jose+json", 415);
  }
  if (!request.body) throw AcmeError.malformed("Missing JWS body");
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > 65536) {
        await reader.cancel();
        throw new AcmeError("malformed", "JWS body exceeds 64 KiB", 413);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function assertStrongPublicKey(key: CryptoKey): void {
  if (key.algorithm.name.startsWith("RSA") && (key.algorithm as { modulusLength: number }).modulusLength < 2048) {
    throw new PublicKeyIdentityError("invalid_jwk", "RSA keys must be at least 2048 bits");
  }
}

/**
 * JWK members that carry private key material or symmetric key material.
 * Account keys are public keys only; accepting any of these would make the
 * stored "public" key ambiguous.
 */
const NON_PUBLIC_JWK_MEMBERS = [
  "d",
  "p",
  "q",
  "dp",
  "dq",
  "qi",
  "oth",
  "k",
] as const;

function identityError(
  code: PublicKeyIdentityErrorCode,
  message: string
): never {
  throw new PublicKeyIdentityError(code, message);
}

function asJwkRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    identityError("invalid_jwk", "JWK must be a JSON object");
  }
  return value as Record<string, unknown>;
}

function requireBase64UrlMember(
  jwk: Record<string, unknown>,
  member: string
): string {
  const value = jwk[member];
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !BASE64URL_PATTERN.test(value)
  ) {
    identityError(
      "invalid_jwk",
      `JWK member '${member}' is missing or is not an unpadded base64url string`
    );
  }
  try {
    base64UrlDecode(value);
  } catch {
    identityError("invalid_jwk", `JWK member '${member}' is not valid base64url`);
  }
  return value;
}

function assertNoPrivateMembers(jwk: Record<string, unknown>): void {
  for (const member of NON_PUBLIC_JWK_MEMBERS) {
    if (Object.prototype.hasOwnProperty.call(jwk, member)) {
      identityError(
        "private_key_material",
        `JWK member '${member}' is not allowed in an ACME account public key`
      );
    }
  }
}

function importAlgorithm(algorithm: AccountKeyAlgorithm): {
  name: string;
  namedCurve?: string;
  hash?: string;
} {
  switch (algorithm) {
    case "ES256":
      return { name: "ECDSA", namedCurve: "P-256" };
    case "RS256":
      return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
    case "EdDSA":
      return { name: "Ed25519" };
  }
}

function verificationAlgorithm(algorithm: AccountKeyAlgorithm): {
  name: string;
  hash?: string;
} {
  switch (algorithm) {
    case "ES256":
      return { name: "ECDSA", hash: "SHA-256" };
    case "RS256":
      return { name: "RSASSA-PKCS1-v1_5" };
    case "EdDSA":
      return { name: "Ed25519" };
  }
}

/**
 * Determines the ACME algorithm implied by a public JWK.
 *
 * Only the three account key types supported by this server are accepted. A
 * JWK whose `kty`/`crv` pair does not map to one of them is rejected rather
 * than being guessed at.
 */
export function inferAccountKeyAlgorithm(jwk: unknown): AccountKeyAlgorithm {
  const record = asJwkRecord(jwk);
  const kty = record.kty;

  if (kty === "EC") {
    if (record.crv !== "P-256") {
      identityError(
        "unsupported_curve",
        "Only EC P-256 account keys (ES256) are supported"
      );
    }
    return "ES256";
  }

  if (kty === "RSA") {
    return "RS256";
  }

  if (kty === "OKP") {
    if (record.crv !== "Ed25519") {
      identityError(
        "unsupported_curve",
        "Only OKP Ed25519 account keys (EdDSA) are supported"
      );
    }
    return "EdDSA";
  }

  identityError(
    "unsupported_algorithm",
    `Unsupported JWK key type: ${typeof kty === "string" ? kty : "missing"}`
  );
}

/**
 * Builds the minimal public JWK that WebCrypto should import.
 *
 * Optional members (`kid`, `use`, `key_ops`, `alg`, `x5c`, field ordering, ...)
 * do not contribute to the identity of a key and are intentionally dropped
 * before import so they cannot influence the normalized result. Required
 * members are validated as unpadded base64url strings.
 */
function buildMinimalPublicJwk(
  value: unknown,
  expectedAlgorithm?: AccountKeyAlgorithm
): { jwk: JsonWebKey; algorithm: AccountKeyAlgorithm } {
  const record = asJwkRecord(value);
  assertNoPrivateMembers(record);

  const algorithm = inferAccountKeyAlgorithm(record);
  if (expectedAlgorithm && algorithm !== expectedAlgorithm) {
    identityError(
      "unsupported_algorithm",
      `JWK algorithm ${algorithm} does not match JWS alg ${expectedAlgorithm}`
    );
  }

  if (algorithm === "ES256") {
    return {
      algorithm,
      jwk: {
        kty: "EC",
        crv: "P-256",
        x: requireBase64UrlMember(record, "x"),
        y: requireBase64UrlMember(record, "y"),
      },
    };
  }

  if (algorithm === "RS256") {
    return {
      algorithm,
      jwk: {
        kty: "RSA",
        n: requireBase64UrlMember(record, "n"),
        e: requireBase64UrlMember(record, "e"),
      },
    };
  }

  return {
    algorithm,
    jwk: {
      kty: "OKP",
      crv: "Ed25519",
      x: requireBase64UrlMember(record, "x"),
    },
  };
}

/** base64url(SHA-256(data)) with the standard 43-character output length. */
export async function sha256Base64Url(
  data: Uint8Array | ArrayBuffer
): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(hash);
}

/** SHA-256 fingerprint of a canonical SubjectPublicKeyInfo DER structure. */
export async function publicKeyFingerprintFromSpki(
  spki: Uint8Array
): Promise<string> {
  return sha256Base64Url(spki);
}

/**
 * Derives the canonical identity of a WebCrypto public key.
 *
 * The SPKI DER export is the canonical, algorithm-independent representation
 * of the key material: WebCrypto normalizes leading zeroes in RSA integers
 * and EC coordinates when importing, so the exported DER is stable across
 * legal JWK encodings. The fingerprint is the SHA-256 of that DER, while the
 * RFC 7638 thumbprint is computed over the canonical JWK's required members
 * and remains the value used by ACME key authorizations.
 */
export async function derivePublicKeyIdentityFromCryptoKey(
  cryptoKey: CryptoKey
): Promise<CryptoKeyPublicIdentity> {
  assertStrongPublicKey(cryptoKey);
  let spki: ArrayBuffer;
  try {
    spki = (await crypto.subtle.exportKey("spki", cryptoKey)) as ArrayBuffer;
  } catch (error: unknown) {
    throw new PublicKeyIdentityError(
      "key_export_failed",
      `Failed to export canonical SPKI DER: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }

  let jwk: JsonWebKey;
  try {
    jwk = (await crypto.subtle.exportKey("jwk", cryptoKey)) as JsonWebKey;
  } catch (error: unknown) {
    throw new PublicKeyIdentityError(
      "key_export_failed",
      `Failed to export canonical public JWK: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }

  let thumbprint: string;
  try {
    thumbprint = await calculateJwkThumbprint(jwk);
  } catch (error: unknown) {
    throw new PublicKeyIdentityError(
      "key_export_failed",
      `Failed to compute the canonical JWK thumbprint: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }

  return {
    cryptoKey,
    jwk,
    spki: new Uint8Array(spki),
    thumbprint,
    fingerprint: await publicKeyFingerprintFromSpki(new Uint8Array(spki)),
  };
}

/**
 * Normalizes a public JWK into the server's canonical public-key identity.
 *
 * Returns the imported CryptoKey, canonical SPKI DER, stable SPKI SHA-256
 * fingerprint, and the RFC 7638 thumbprint of the canonical JWK. Any key that
 * cannot be imported/exported/validated fails closed with a
 * PublicKeyIdentityError; callers must not treat that as "different key".
 */
export async function normalizePublicKey(
  value: unknown,
  expectedAlgorithm?: string
): Promise<NormalizedPublicKey> {
  let expected: AccountKeyAlgorithm | undefined;
  if (expectedAlgorithm !== undefined) {
    if (
      expectedAlgorithm !== "ES256" &&
      expectedAlgorithm !== "RS256" &&
      expectedAlgorithm !== "EdDSA"
    ) {
      identityError(
        "unsupported_algorithm",
        `Unsupported JWS algorithm: ${expectedAlgorithm}`
      );
    }
    expected = expectedAlgorithm;
  }

  const { jwk, algorithm } = buildMinimalPublicJwk(value, expected);

  let cryptoKey: CryptoKey;
  try {
    cryptoKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      importAlgorithm(algorithm),
      true,
      ["verify"]
    );
  } catch (error: unknown) {
    throw new PublicKeyIdentityError(
      "key_import_failed",
      `Failed to import public key: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }

  const identity = await derivePublicKeyIdentityFromCryptoKey(cryptoKey);
  const canonicalAlgorithm = inferAccountKeyAlgorithm(identity.jwk);
  if (canonicalAlgorithm !== algorithm) {
    identityError(
      "key_import_failed",
      "Imported public key changed algorithm during canonicalization"
    );
  }

  return { ...identity, algorithm };
}

/**
 * Calculates RFC 7638 JWK Thumbprint using SHA-256.
 *
 * This is the protocol value used by ACME key authorizations. It is computed
 * over the JWK's required members exactly as supplied. It is NOT a stable
 * identity of the actual key: two legal encodings of the same key (for
 * example an RSA modulus with redundant leading zeroes) produce different
 * thumbprints. Use normalizePublicKey().fingerprint for key-identity checks.
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

  return sha256Base64Url(new TextEncoder().encode(canonicalJson));
}

/**
 * Imports a public JWK into a CryptoKey for verification.
 *
 * `extractable` is only set when the caller needs to re-export the key in a
 * canonical form (for example to compare it with a CSR public key). Optional
 * JWK members are dropped and private key material is rejected before
 * WebCrypto sees the key.
 */
export async function importPublicJwk(
  jwk: JsonWebKey,
  alg: string,
  extractable = false
): Promise<CryptoKey> {
  try {
    const algorithm = inferAccountKeyAlgorithm(jwk);
    if (
      alg !== "ES256" &&
      alg !== "RS256" &&
      alg !== "EdDSA"
    ) {
      throw new PublicKeyIdentityError(
        "unsupported_algorithm",
        `Unsupported JWS algorithm: ${alg}`
      );
    }
    if (algorithm !== alg) {
      throw new PublicKeyIdentityError(
        "unsupported_algorithm",
        `JWK algorithm ${algorithm} does not match JWS alg ${alg}`
      );
    }

    const minimal = buildMinimalPublicJwk(jwk, algorithm).jwk;
    const key = await crypto.subtle.importKey(
      "jwk",
      minimal,
      importAlgorithm(algorithm),
      extractable,
      ["verify"]
    );
    assertStrongPublicKey(key);
    return key;
  } catch (err: unknown) {
    if (err instanceof PublicKeyIdentityError) {
      throw AcmeError.malformed(err.message);
    }
    throw AcmeError.malformed(
      `Failed to import public key: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

/**
 * Verifies a flattened JWS signature with a public JWK and its declared alg.
 * Returns false for an invalid signature; malformed inputs throw.
 */
export async function verifyFlattenedJwsSignature(
  jws: JwsFlattened,
  jwk: JsonWebKey,
  alg: string
): Promise<boolean> {
  let algorithm: AccountKeyAlgorithm;
  if (alg === "ES256" || alg === "RS256" || alg === "EdDSA") {
    algorithm = alg;
  } else {
    throw AcmeError.malformed(`Unsupported alg: ${alg}`);
  }

  const cryptoKey = await importPublicJwk(jwk, algorithm);
  const signingInput = new TextEncoder().encode(`${jws.protected}.${jws.payload}`);

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlDecode(jws.signature);
  } catch {
    throw AcmeError.malformed("Malformed JWS signature encoding");
  }

  return crypto.subtle.verify(
    verificationAlgorithm(algorithm),
    cryptoKey,
    signatureBytes,
    signingInput
  );
}

function isFlattenedJws(value: unknown): value is JwsFlattened {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.protected === "string" &&
    typeof candidate.payload === "string" &&
    typeof candidate.signature === "string"
  );
}

/**
 * Verifies and parses an incoming ACME JWS request
 */
export async function verifyAcmeJws<T = unknown>(
  request: Request,
  database: Database,
  expectedPath?: string
): Promise<VerifiedJws<T>> {
  let rawBody: unknown;
  try {
    rawBody = await readJwsBody(request);
  } catch (error) {
    if (error instanceof AcmeError) throw error;
    throw AcmeError.malformed("Invalid JSON body");
  }

  if (!isFlattenedJws(rawBody)) {
    throw AcmeError.malformed(
      "JWS must include protected, payload, and signature fields"
    );
  }
  const body: JwsFlattened = rawBody;
  try {
    for (const value of [body.protected, body.payload, body.signature]) {
      if (base64UrlEncode(base64UrlDecode(value)) !== value) throw new Error("Noncanonical base64url");
    }
  } catch { throw AcmeError.malformed("Invalid JWS base64url encoding"); }
  if (!BASE64URL_PATTERN.test(body.protected) || !BASE64URL_PATTERN.test(body.signature) ||
      (body.payload !== "" && !BASE64URL_PATTERN.test(body.payload)) ||
      Object.keys(rawBody as object).some((key) => !["protected", "payload", "signature"].includes(key))) {
    throw AcmeError.malformed("Invalid flattened JWS encoding or members");
  }

  let header: JwsProtectedHeader;
  try {
    const headerStr = new TextDecoder().decode(base64UrlDecode(body.protected));
    header = JSON.parse(headerStr) as JwsProtectedHeader;
  } catch {
    throw AcmeError.malformed("Malformed JWS protected header");
  }

  if (
    !isRecord(header) ||
    typeof header.alg !== "string" ||
    typeof header.nonce !== "string" ||
    typeof header.url !== "string"
  ) {
    throw AcmeError.malformed("JWS protected header missing alg, nonce, or url");
  }
  if ("crit" in header || "b64" in header) {
    throw AcmeError.malformed("Unsupported JWS protected header extension");
  }
  if (
    header.jwk !== undefined &&
    (typeof header.jwk !== "object" ||
      header.jwk === null ||
      Array.isArray(header.jwk))
  ) {
    throw AcmeError.malformed("JWS protected header contains a malformed jwk");
  }
  if (header.kid !== undefined && typeof header.kid !== "string") {
    throw AcmeError.malformed("JWS protected header contains a malformed kid");
  }

  // 1. Verify and consume Replay-Nonce
  const nonceValid = await verifyAndConsumeNonce(database, header.nonce);
  if (!nonceValid) {
    throw AcmeError.badNonce();
  }

  // 2. Verify URL in protected header matches request URL
  const reqUrl = new URL(request.url);
  try {
    new URL(header.url);
  } catch {
    throw AcmeError.malformed("JWS protected url is not a valid URL");
  }
  const publishedUrl = publishedUrls.get(request) ?? request.url;
  if (header.url !== publishedUrl || (expectedPath && reqUrl.pathname !== expectedPath)) {
    throw AcmeError.malformed("JWS protected url does not match the published request URL");
  }
  const path = reqUrl.pathname;
  const auth = path === "/new-account" ? "jwk" : path === "/revoke-cert" ? "either" : "kid";
  if ((auth === "jwk" && (!header.jwk || header.kid !== undefined)) ||
      (auth === "kid" && (!header.kid || header.jwk !== undefined))) {
    throw AcmeError.malformed(`This endpoint requires ${auth} authentication`);
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
    let kidUrl: URL;
    try {
      kidUrl = new URL(header.kid);
    } catch {
      throw AcmeError.malformed("JWS protected kid is not a valid URL");
    }
    const parts = kidUrl.pathname.split("/").filter(Boolean);
    const accountId = parts[parts.length - 1];
    const serviceOrigin = new URL(publishedUrl).origin;
    if (header.kid !== `${serviceOrigin}/account/${accountId}`) {
      throw AcmeError.malformed("kid must be a published account URL for this service");
    }

    account = await database.getAccountById(accountId);
    if (!account) {
      throw AcmeError.unauthorized("Account does not exist");
    }
    if (account.status !== "valid") {
      throw AcmeError.unauthorized(`Account is ${account.status}`);
    }

    try {
      jwk = JSON.parse(account.jwk) as JsonWebKey;
    } catch {
      throw AcmeError.serverInternal("Stored account key is malformed");
    }
    thumbprint = account.thumbprint;
  } else {
    throw AcmeError.malformed("JWS protected header must include either jwk or kid");
  }

  // 4. Verify signature
  const isValid = await verifyFlattenedJwsSignature(body, jwk, header.alg);
  if (!isValid) {
    throw AcmeError.unauthorized("Invalid JWS signature");
  }

  // 5. Decode payload (empty payload in POST-as-GET is allowed)
  let parsedPayload = {} as T;
  const requiresEmpty = /^\/(?:authz\/[^/]+|order\/[^/]+|cert\/[^/]+)$/.test(path);
  if (requiresEmpty && body.payload !== "") {
    throw AcmeError.malformed("POST-as-GET requires an empty payload");
  }
  if (body.payload && body.payload.trim() !== "") {
    try {
      const payloadStr = new TextDecoder().decode(base64UrlDecode(body.payload));
      parsedPayload = JSON.parse(payloadStr) as T;
      if (!isRecord(parsedPayload)) throw new Error("Payload must be an object");
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
