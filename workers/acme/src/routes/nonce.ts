import { createAndSaveNonce } from "../crypto/nonce";
import { Database } from "../db/queries";

export async function handleNewNonce(
  request: Request,
  database: Database
): Promise<Response> {
  const nonce = await createAndSaveNonce(database);
  const status = request.method === "HEAD" ? 200 : 204;

  return new Response(null, {
    status,
    headers: {
      "Replay-Nonce": nonce,
      "Cache-Control": "no-store",
    },
  });
}
