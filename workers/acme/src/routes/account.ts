import { AcmeEnv, getTermsOfServiceUrl } from "../config";
import { verifyAcmeJws } from "../crypto/jws";
import { Database } from "../db/queries";
import { AccountRow } from "../db/types";
import { AcmeError } from "../errors";

interface NewAccountPayload {
  contact?: string[];
  termsOfServiceAgreed?: boolean;
  onlyReturnExisting?: boolean;
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

  const termsOfServiceUrl = getTermsOfServiceUrl(env);

  // Check if account with this thumbprint already exists
  const existing = await database.getAccountByThumbprint(verified.thumbprint);

  if (verified.payload.onlyReturnExisting) {
    if (!existing) {
      throw new AcmeError(
        "accountDoesNotExist",
        "No account exists for the provided key",
        404
      );
    }
    return formatAccountResponse(existing, baseUrl, 200);
  }

  if (existing) {
    // RFC 8555 § 7.3 & § 7.3.3:
    // "The server MUST NOT require agreement to the terms of service on this request unless the terms of service have changed."
    if (termsOfServiceUrl && existing.terms_of_service !== termsOfServiceUrl) {
      if (verified.payload.termsOfServiceAgreed === true) {
        existing.terms_of_service = termsOfServiceUrl;
        await database.updateAccount(existing.id, { terms_of_service: termsOfServiceUrl });
      } else {
        throw AcmeError.userActionRequired(
          "Terms of service have changed",
          termsOfServiceUrl
        );
      }
    }
    // Return existing account per RFC 8555 § 7.3.1
    return formatAccountResponse(existing, baseUrl, 200);
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
    jwk: JSON.stringify(verified.jwk),
    thumbprint: verified.thumbprint,
    contact: verified.payload.contact ? JSON.stringify(verified.payload.contact) : null,
    status: "valid",
    created_at: now,
    terms_of_service: verified.payload.termsOfServiceAgreed === true ? (termsOfServiceUrl || "true") : null,
  };

  await database.saveAccount(newAccount);
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
  const termsOfServiceUrl = getTermsOfServiceUrl(env);

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
