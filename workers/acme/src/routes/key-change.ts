import {
  calculateJwkThumbprint,
  JwsFlattened,
  normalizePublicKey,
  PublicKeyIdentityError,
  verifyAcmeJws,
  verifyFlattenedJwsSignature,
} from "../crypto/jws";
import { base64UrlDecode } from "../crypto/nonce";
import { ensureAccountPublicKeyIndex } from "../db/account-keys";
import { Database } from "../db/queries";
import { AccountRow } from "../db/types";
import { AcmeError } from "../errors";
import { formatAccountResponse } from "./account";

interface KeyChangeObject {
  account: string;
  oldKey: JsonWebKey;
}

interface InnerProtectedHeader {
  alg: string;
  jwk: JsonWebKey;
  url: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isUniqueConstraintError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return (
    /UNIQUE constraint failed/i.test(message) ||
    /SQLITE_CONSTRAINT_UNIQUE/i.test(message)
  );
}

function decodeBase64UrlJson(value: string, label: string): unknown {
  try {
    const decoded = new TextDecoder().decode(base64UrlDecode(value));
    return JSON.parse(decoded) as unknown;
  } catch {
    throw AcmeError.malformed(`Malformed ${label} JSON`);
  }
}

function parseInnerJws(payload: unknown): JwsFlattened {
  if (!isRecord(payload)) {
    throw AcmeError.malformed("keyChange payload must be a flattened JWS object");
  }
  if (
    typeof payload.protected !== "string" ||
    typeof payload.payload !== "string" ||
    typeof payload.signature !== "string" ||
    payload.payload.length === 0
  ) {
    throw AcmeError.malformed(
      "keyChange inner JWS must include protected, payload, and signature fields"
    );
  }
  if (![payload.protected, payload.payload, payload.signature].every((value) => /^[A-Za-z0-9_-]+$/.test(value as string))) throw AcmeError.malformed("Invalid inner JWS encoding");
  return {
    protected: payload.protected,
    payload: payload.payload,
    signature: payload.signature,
  };
}

function parseInnerHeader(encoded: string): InnerProtectedHeader {
  const raw = decodeBase64UrlJson(encoded, "inner JWS protected header");
  if (!isRecord(raw)) {
    throw AcmeError.malformed("keyChange inner JWS protected header must be an object");
  }

  if ("crit" in raw || "b64" in raw) throw AcmeError.malformed("Unsupported inner JWS extension");
  if (raw.nonce !== undefined) {
    throw AcmeError.malformed("keyChange inner JWS must omit the nonce header parameter");
  }
  if (raw.kid !== undefined) {
    throw AcmeError.malformed("keyChange inner JWS must use jwk, not kid");
  }
  if (typeof raw.alg !== "string" || typeof raw.url !== "string") {
    throw AcmeError.malformed(
      "keyChange inner JWS protected header must include alg, jwk, and url"
    );
  }
  if (!isRecord(raw.jwk)) {
    throw AcmeError.malformed(
      "keyChange inner JWS protected header must include a jwk object"
    );
  }

  return {
    alg: raw.alg,
    jwk: raw.jwk as unknown as JsonWebKey,
    url: raw.url,
  };
}

function parseKeyChangeObject(encoded: string): KeyChangeObject {
  const raw = decodeBase64UrlJson(encoded, "keyChange object");
  if (!isRecord(raw)) {
    throw AcmeError.malformed("keyChange payload must be a JSON object");
  }
  if (typeof raw.account !== "string" || raw.account.length === 0) {
    throw AcmeError.malformed("keyChange payload must include an 'account' string");
  }
  if (!isRecord(raw.oldKey)) {
    throw AcmeError.malformed("keyChange payload must include an 'oldKey' JWK object");
  }

  return {
    account: raw.account,
    oldKey: raw.oldKey as unknown as JsonWebKey,
  };
}

async function normalizeStoredAccountKey(account: AccountRow) {
  let jwk: unknown;
  try {
    jwk = JSON.parse(account.jwk) as unknown;
  } catch {
    throw AcmeError.serverInternal("Stored account key is malformed");
  }
  try {
    return await normalizePublicKey(jwk);
  } catch {
    throw AcmeError.serverInternal(
      "Stored account public key cannot be normalized; refusing key rollover"
    );
  }
}

/**
 * RFC 8555 § 7.3.5 account key rollover.
 *
 * The outer JWS authenticates the current account key (kid); the inner JWS is
 * signed by the requested new key and carries {account, oldKey}. Both the old
 * and new keys are normalized to their actual-public-key fingerprint, so a
 * different encoding of another account's key cannot bypass the reuse check.
 * The database update is a compare-and-swap on the old thumbprint and the
 * UNIQUE public_key_fingerprint index is the final concurrency guard.
 */
export async function handleKeyChange(
  request: Request,
  database: Database,
  baseUrl: string
): Promise<Response> {
  const outer = await verifyAcmeJws<unknown>(request, database, "/key-change");

  // Key rollover must be authenticated by an existing account. A bare jwk
  // request has no account to roll over and is rejected.
  if (!outer.account) {
    throw AcmeError.unauthorized("keyChange requires an account kid");
  }
  if (outer.header.jwk) {
    throw AcmeError.malformed("keyChange request must be authenticated with kid");
  }
  const account = outer.account;

  // Steps 2-6: the inner JWS must be well-formed, use jwk (no nonce), be
  // signed by that jwk, and carry the same URL as the outer JWS.
  const inner = parseInnerJws(outer.payload);
  const innerHeader = parseInnerHeader(inner.protected);
  if (innerHeader.url !== outer.header.url) {
    throw AcmeError.malformed(
      "keyChange inner and outer JWS must use the same url"
    );
  }

  const innerValid = await verifyFlattenedJwsSignature(
    inner,
    innerHeader.jwk,
    innerHeader.alg
  );
  if (!innerValid) {
    throw AcmeError.unauthorized("keyChange inner JWS signature is invalid");
  }

  const keyChange = parseKeyChangeObject(inner.payload);

  // Step 7: the account field must be exactly the account URL from the outer
  // kid (the Location returned by newAccount).
  const expectedAccountUrl = `${baseUrl}/account/${account.id}`;
  if (
    keyChange.account !== outer.header.kid ||
    keyChange.account !== expectedAccountUrl
  ) {
    throw AcmeError.unauthorized(
      "keyChange 'account' does not match the authenticated account URL"
    );
  }

  // Step 8: oldKey must be the account's current key. Compare actual key
  // identities, not JWK JSON or RFC 7638 thumbprints.
  const accountIdentity = await normalizeStoredAccountKey(account);
  let oldIdentity;
  try {
    oldIdentity = await normalizePublicKey(keyChange.oldKey);
  } catch (error: unknown) {
    if (error instanceof PublicKeyIdentityError) {
      throw AcmeError.malformed(
        "keyChange 'oldKey' is not a supported public key"
      );
    }
    throw AcmeError.malformed("keyChange 'oldKey' is not a supported public key");
  }
  if (oldIdentity.fingerprint !== accountIdentity.fingerprint) {
    throw AcmeError.unauthorized(
      "keyChange 'oldKey' does not match the account's current key"
    );
  }

  // Normalize the requested new key with the same function used everywhere
  // else. A key that cannot be normalized fails closed.
  let newIdentity;
  try {
    newIdentity = await normalizePublicKey(
      innerHeader.jwk,
      innerHeader.alg
    );
  } catch (error: unknown) {
    if (error instanceof PublicKeyIdentityError) {
      throw AcmeError.badPublicKey(
        "The requested new account key is malformed or uses an unsupported key type"
      );
    }
    throw AcmeError.badPublicKey("The requested new account key is not acceptable");
  }

  let newThumbprint: string;
  try {
    newThumbprint = await calculateJwkThumbprint(innerHeader.jwk);
  } catch {
    throw AcmeError.badPublicKey("The requested new account key is not acceptable");
  }

  // Do not decide that the new key is unused unless every legacy account key
  // has been indexed.
  await ensureAccountPublicKeyIndex(database);

  // Step 9: no account may already use the new actual public key.
  let existing: AccountRow | null;
  try {
    existing = await database.getAccountByPublicKeyFingerprint(
      newIdentity.fingerprint
    );
  } catch {
    throw AcmeError.serverInternal(
      "Unable to complete the account public key reuse check"
    );
  }

  if (existing) {
    if (existing.id !== account.id) {
      throw AcmeError.keyAlreadyInUse(
        "The requested new account key is already in use by another account",
        `${baseUrl}/account/${existing.id}`
      );
    }

    // The account already holds exactly the requested key and encoding. This
    // is a concurrent identical rollover: report success without rewriting
    // anything.
    if (
      existing.thumbprint === newThumbprint &&
      existing.public_key_fingerprint === newIdentity.fingerprint
    ) {
      return formatAccountResponse(existing, baseUrl, 200);
    }

    // Same actual key: an idempotent no-op. Do not rewrite jwk/thumbprint,
    // because that would change the key authorization used by still-pending
    // http-01/dns-01 challenges for no benefit.
    if (newIdentity.fingerprint === accountIdentity.fingerprint) {
      return formatAccountResponse(account, baseUrl, 200);
    }

    // A concurrent rollover moved the account to the same actual key but a
    // different encoding. The stored protocol thumbprint is the one clients
    // must use for key authorizations, so silently accepting this request
    // would leave the caller with a mismatched thumbprint.
    if (existing.public_key_fingerprint === newIdentity.fingerprint) {
      throw new AcmeError(
        "malformed",
        "The account key was concurrently changed to an equivalent key with a different encoding; retry with the current key",
        409
      );
    }

    throw AcmeError.serverInternal(
      "The account public key identity index is inconsistent; refusing key rollover"
    );
  }

  // Defensive: if the index is unavailable for a lookup that should have
  // matched the current key, do not rewrite the account.
  if (newIdentity.fingerprint === accountIdentity.fingerprint) {
    return formatAccountResponse(account, baseUrl, 200);
  }

  const newJwkJson = JSON.stringify(innerHeader.jwk);
  let changed: boolean;
  try {
    changed = await database.updateAccountKey(account.id, account.thumbprint, {
      jwk: newJwkJson,
      thumbprint: newThumbprint,
      publicKeyFingerprint: newIdentity.fingerprint,
    });
  } catch (error: unknown) {
    if (!isUniqueConstraintError(error)) {
      throw AcmeError.serverInternal("Account key rollover failed");
    }

    // Another account won the race for the same actual key. The failed UPDATE
    // is atomic: the old key is unchanged.
    let holder: AccountRow | null = null;
    try {
      holder = await database.getAccountByPublicKeyFingerprint(
        newIdentity.fingerprint
      );
      // Defensive fallback for a legacy row whose fingerprint has not been
      // indexed yet: the RFC 7638 thumbprint is still UNIQUE in the accounts
      // table. The row is left untouched; the request fails closed.
      if (!holder) {
        holder = await database.getAccountByThumbprint(newThumbprint);
      }
    } catch {
      throw AcmeError.serverInternal("Account key rollover failed");
    }
    if (holder && holder.id !== account.id) {
      throw AcmeError.keyAlreadyInUse(
        "The requested new account key is already in use by another account",
        `${baseUrl}/account/${holder.id}`
      );
    }
    if (holder && holder.id === account.id) {
      if (holder.thumbprint === newThumbprint) {
        return formatAccountResponse(holder, baseUrl, 200);
      }
      throw new AcmeError(
        "malformed",
        "The account key was concurrently changed to an equivalent key with a different encoding; retry with the current key",
        409
      );
    }
    throw AcmeError.serverInternal("Account key rollover failed");
  }

  if (!changed) {
    // A concurrent keyChange (or account deactivation) won. Only report
    // success when the account already holds exactly the requested key.
    let latest: AccountRow | null = null;
    try {
      latest = await database.getAccountById(account.id);
    } catch {
      throw AcmeError.serverInternal("Account key rollover failed");
    }
    if (
      latest &&
      latest.thumbprint === newThumbprint &&
      latest.public_key_fingerprint === newIdentity.fingerprint
    ) {
      return formatAccountResponse(latest, baseUrl, 200);
    }
    throw AcmeError.unauthorized(
      "The account key changed concurrently; retry the keyChange with the current key"
    );
  }

  account.jwk = newJwkJson;
  account.thumbprint = newThumbprint;
  account.public_key_fingerprint = newIdentity.fingerprint;
  return formatAccountResponse(account, baseUrl, 200);
}
