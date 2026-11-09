import { AcmeEnv, getTermsOfServiceUrl } from "../config";
import {
  normalizePublicKey,
  PublicKeyIdentityError,
  verifyAcmeJws,
} from "../crypto/jws";
import { ensureAccountPublicKeyIndex } from "../db/account-keys";
import { Database } from "../db/queries";
import { AccountRow } from "../db/types";
import { AcmeError } from "../errors";

interface NewAccountPayload {
  contact?: string[];
  termsOfServiceAgreed?: boolean;
  onlyReturnExisting?: boolean;
}

function isUniqueConstraintError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return (
    /UNIQUE constraint failed/i.test(message) ||
    /SQLITE_CONSTRAINT_UNIQUE/i.test(message)
  );
}

/**
 * Returns an existing account object and applies the RFC 8555 § 7.3.3 terms
 * handling. Account ID, URL, status, contact, and all related resources are
 * left untouched.
 */
async function respondWithExistingAccount(
  existing: AccountRow,
  payload: NewAccountPayload,
  database: Database,
  baseUrl: string,
  termsOfServiceUrl: string | undefined
): Promise<Response> {
  // RFC 8555 § 7.3 & § 7.3.3:
  // "The server MUST NOT require agreement to the terms of service on this request unless the terms of service have changed."
  if (termsOfServiceUrl && existing.terms_of_service !== termsOfServiceUrl) {
    if (payload.termsOfServiceAgreed === true) {
      await database.updateAccount(existing.id, {
        terms_of_service: termsOfServiceUrl,
      });
      existing.terms_of_service = termsOfServiceUrl;
    } else {
      throw AcmeError.userActionRequired(
        "Terms of service have changed",
        termsOfServiceUrl
      );
    }
  }
  return formatAccountResponse(existing, baseUrl, 200);
}

export async function handleNewAccount(
  request: Request,
  database: Database,
  baseUrl: string,
  env?: AcmeEnv
): Promise<Response> {
  const verified = await verifyAcmeJws<NewAccountPayload>(
    request,
    database,
    "/new-account"
  );

  if (!verified.header.jwk) {
    throw AcmeError.malformed("newAccount request must include jwk in protected header");
  }

  // The JWS signature was verified over the submitted JWK. Normalize the same
  // key into the canonical actual-key identity before any account lookup or
  // insert. Two legal encodings of one key therefore map to one account.
  let publicKeyFingerprint: string;
  try {
    publicKeyFingerprint = (
      await normalizePublicKey(verified.header.jwk, verified.header.alg)
    ).fingerprint;
  } catch (error: unknown) {
    if (error instanceof PublicKeyIdentityError) {
      throw AcmeError.badPublicKey(
        "The account public key is malformed or uses an unsupported key type"
      );
    }
    throw AcmeError.badPublicKey("The account public key could not be normalized");
  }

  // Fail closed if any legacy account public key has not been indexed yet.
  // Otherwise an equivalent key could be registered a second time.
  await ensureAccountPublicKeyIndex(database);

  let existing: AccountRow | null;
  try {
    existing = await database.getAccountByPublicKeyFingerprint(
      publicKeyFingerprint
    );
  } catch {
    throw AcmeError.serverInternal("Account lookup failed");
  }

  const termsOfServiceUrl = getTermsOfServiceUrl();

  if (verified.payload.onlyReturnExisting) {
    if (!existing) {
      throw new AcmeError(
        "accountDoesNotExist",
        "No account exists for the provided key",
        400
      );
    }
    return formatAccountResponse(existing, baseUrl, 200);
  }

  if (existing) {
    return respondWithExistingAccount(
      existing,
      verified.payload,
      database,
      baseUrl,
      termsOfServiceUrl
    );
  }

  // Create new account
  // If server requires agreement to terms of service (termsOfServiceUrl is provided in directory):
  // "拒绝未设置 termsOfServiceAgreed: true 的新账户创建请求" (RFC 8555 § 7.3)
  if (termsOfServiceUrl && verified.payload.termsOfServiceAgreed !== true) {
    throw AcmeError.userActionRequired(
      "Terms of service must be agreed to",
      termsOfServiceUrl
    );
  }

  const accountId = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  const newAccount: AccountRow = {
    id: accountId,
    // Store the JWK representation the client used to sign this request. The
    // RFC 7638 thumbprint is computed from exactly this representation, so
    // existing/new key authorizations remain consistent with the stored key.
    jwk: JSON.stringify(verified.header.jwk),
    thumbprint: verified.thumbprint,
    public_key_fingerprint: publicKeyFingerprint,
    contact: verified.payload.contact ? JSON.stringify(verified.payload.contact) : null,
    status: "valid",
    created_at: now,
    terms_of_service: verified.payload.termsOfServiceAgreed === true ? (termsOfServiceUrl || "true") : null,
  };

  try {
    await database.saveAccount(newAccount);
  } catch (error: unknown) {
    if (!isUniqueConstraintError(error)) {
      // Never reflect the underlying D1/SQLite error to the ACME client.
      throw AcmeError.serverInternal("Account registration failed");
    }

    // A concurrent registration created the same actual key first. The
    // UNIQUE index is authoritative: return that account per RFC 8555
    // § 7.3.1 instead of creating a duplicate.
    let raced: AccountRow | null = null;
    try {
      raced = await database.getAccountByPublicKeyFingerprint(
        publicKeyFingerprint
      );
      if (!raced) {
        raced = await database.getAccountByThumbprint(verified.thumbprint);
      }
    } catch {
      throw AcmeError.serverInternal("Account registration was not completed");
    }
    if (!raced) {
      throw AcmeError.serverInternal("Account registration was not completed");
    }
    return respondWithExistingAccount(
      raced,
      verified.payload,
      database,
      baseUrl,
      termsOfServiceUrl
    );
  }

  return formatAccountResponse(newAccount, baseUrl, 201);
}

export async function handleAccount(
  request: Request,
  database: Database,
  baseUrl: string,
  accountId: string,
  env?: AcmeEnv
): Promise<Response> {
  const verified = await verifyAcmeJws<{
    contact?: string[];
    status?: "deactivated";
    termsOfServiceAgreed?: boolean;
  }>(request, database);

  if (!verified.account || verified.account.id !== accountId) {
    throw AcmeError.unauthorized("Account does not match kid");
  }

  const account = verified.account;
  const termsOfServiceUrl = getTermsOfServiceUrl();

  if (verified.payload.status === "deactivated") {
    await database.updateAccount(accountId, { status: "deactivated" });
    account.status = "deactivated";
  } else if (verified.payload.contact !== undefined) {
    const contactStr = verified.payload.contact ? JSON.stringify(verified.payload.contact) : null;
    await database.updateAccount(accountId, { contact: contactStr });
    account.contact = contactStr;
  }

  if (verified.payload.termsOfServiceAgreed !== undefined) {
    if (verified.payload.termsOfServiceAgreed === false) {
      // RFC 8555 § 7.1.2: "This field cannot be updated to 'false'."
      throw AcmeError.malformed("termsOfServiceAgreed cannot be updated to 'false'");
    }
    const agreedTos = termsOfServiceUrl || account.terms_of_service || "true";
    await database.updateAccount(accountId, { terms_of_service: agreedTos });
    account.terms_of_service = agreedTos;
  }

  return formatAccountResponse(account, baseUrl, 200);
}

export function formatAccountResponse(
  account: AccountRow,
  baseUrl: string,
  status: number
): Response {
  const body: Record<string, unknown> = {
    status: account.status,
    orders: `${baseUrl}/account/${account.id}/orders`,
  };

  if (account.contact) {
    try {
      const parsed = JSON.parse(account.contact);
      if (Array.isArray(parsed) && parsed.length > 0) {
        body.contact = parsed;
      }
    } catch {
      // ignore
    }
  }

  if (account.terms_of_service) {
    body.termsOfServiceAgreed = true;
  }

  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      Location: `${baseUrl}/account/${account.id}`,
    },
  });
}
