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
  baseUrl: string
): Promise<Response> {
  const verified = await verifyAcmeJws<NewAccountPayload>(
    request,
    database,
    "/new-account"
  );

  if (!verified.header.jwk) {
    throw AcmeError.malformed("newAccount request must include jwk in protected header");
  }

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
    // Return existing account per RFC 8555 § 7.3.1
    return formatAccountResponse(existing, baseUrl, 200);
  }

  // Create new account
  const accountId = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  const newAccount: AccountRow = {
    id: accountId,
    jwk: JSON.stringify(verified.jwk),
    thumbprint: verified.thumbprint,
    contact: verified.payload.contact ? JSON.stringify(verified.payload.contact) : null,
    status: "valid",
    created_at: now,
  };

  await database.saveAccount(newAccount);
  return formatAccountResponse(newAccount, baseUrl, 201);
}

export async function handleAccount(
  request: Request,
  database: Database,
  baseUrl: string,
  accountId: string
): Promise<Response> {
  const verified = await verifyAcmeJws<{
    contact?: string[];
    status?: "deactivated";
  }>(request, database);

  if (!verified.account || verified.account.id !== accountId) {
    throw AcmeError.unauthorized("Account does not match kid");
  }

  const account = verified.account;

  if (verified.payload.status === "deactivated") {
    await database.updateAccount(accountId, { status: "deactivated" });
    account.status = "deactivated";
  } else if (verified.payload.contact) {
    const contactStr = JSON.stringify(verified.payload.contact);
    await database.updateAccount(accountId, { contact: contactStr });
    account.contact = contactStr;
  }

  return formatAccountResponse(account, baseUrl, 200);
}

function formatAccountResponse(
  account: AccountRow,
  baseUrl: string,
  status: number
): Response {
  const contact = account.contact ? JSON.parse(account.contact) : [];
  const body = {
    status: account.status,
    contact,
    orders: `${baseUrl}/account/${account.id}/orders`,
  };

  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      Location: `${baseUrl}/account/${account.id}`,
    },
  });
}
