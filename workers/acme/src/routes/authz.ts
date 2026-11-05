import { verifyAcmeJws } from "../crypto/jws";
import { Database } from "../db/queries";
import { AcmeError } from "../errors";

export async function handleGetAuthz(
  request: Request,
  database: Database,
  baseUrl: string,
  authzId: string
): Promise<Response> {
  const verified = await verifyAcmeJws(request, database);
  if (!verified.account) {
    throw AcmeError.unauthorized();
  }

  const authz = await database.getAuthorizationById(authzId);
  if (!authz) {
    throw AcmeError.notFound("Authorization not found");
  }

  const body = {
    status: authz.status,
    expires: new Date(authz.expires_at * 1000).toISOString(),
    identifier: {
      type: "dns",
      value: authz.identifier_value,
    },
    challenges: [
      {
        type: "dns-01",
        url: `${baseUrl}/challenge/${authz.id}`,
        token: authz.token,
        status: authz.status,
      },
    ],
  };

  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
    },
  });
}
