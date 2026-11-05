import { AcmeEnv } from "./config";
import { Database } from "./db/queries";
import { AcmeError } from "./errors";
import { createAndSaveNonce } from "./crypto/nonce";
import { handleDirectory } from "./routes/directory";
import { handleNewNonce } from "./routes/nonce";
import { handleAccount, handleNewAccount } from "./routes/account";
import { handleFinalizeOrder, handleGetOrder, handleNewOrder } from "./routes/order";
import { handleGetAuthz } from "./routes/authz";
import { handleChallenge } from "./routes/challenge";
import { handleGetCertificate } from "./routes/certificate";
import { handleRevokeCert } from "./routes/revoke";
import { handleRenewalInfo } from "./routes/ari";

let schemaInitialized = false;

export default {
  async fetch(
    request: Request,
    env: AcmeEnv,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);
    const baseUrl = env.ACME_BASE_URL || url.origin;
    const database = new Database(env.DB);

    // Auto-initialize schema on startup
    if (!schemaInitialized) {
      try {
        await database.initSchema();
        schemaInitialized = true;
      } catch {
        // Continue if already initialized
      }
    }

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Expose-Headers": "Link, Location, Replay-Nonce, Retry-After",
        },
      });
    }

    try {
      const response = await routeRequest(request, url, database, baseUrl, env);

      // In RFC 8555 § 6.5.1, the server MUST include Replay-Nonce on POST responses
      // and Link rel="index" to the ACME directory.
      const headers = new Headers(response.headers);
      headers.set("Link", `<${baseUrl}/directory>;rel="index"`);
      headers.set("Access-Control-Allow-Origin", "*");
      headers.set(
        "Access-Control-Expose-Headers",
        "Link, Location, Replay-Nonce, Retry-After"
      );

      if (request.method === "POST" && !headers.has("Replay-Nonce")) {
        const freshNonce = await createAndSaveNonce(database);
        headers.set("Replay-Nonce", freshNonce);
      }

      return new Response(response.body, {
        status: response.status,
        headers,
      });
    } catch (err: unknown) {
      let freshNonce = "";
      try {
        freshNonce = await createAndSaveNonce(database);
      } catch {
        // Nonce generation failed
      }

      const extraHeaders: Record<string, string> = {
        Link: `<${baseUrl}/directory>;rel="index"`,
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Expose-Headers": "Link, Location, Replay-Nonce, Retry-After",
      };
      if (freshNonce) {
        extraHeaders["Replay-Nonce"] = freshNonce;
      }

      if (err instanceof AcmeError) {
        return err.toResponse(extraHeaders);
      }

      const message = err instanceof Error ? err.message : String(err);
      return AcmeError.serverInternal(message).toResponse(extraHeaders);
    }
  },
};

async function routeRequest(
  request: Request,
  url: URL,
  database: Database,
  baseUrl: string,
  env: AcmeEnv
): Promise<Response> {
  const path = url.pathname.replace(/\/+$/, "") || "/";

  // Directory
  if (path === "/directory" || path === "/") {
    return handleDirectory(request, env, baseUrl);
  }

  // Nonce
  if (path === "/new-nonce") {
    return await handleNewNonce(request, database);
  }

  // New Account
  if (path === "/new-account") {
    if (request.method !== "POST") return methodNotAllowed();
    return await handleNewAccount(request, database, baseUrl);
  }

  // Account
  const accountMatch = path.match(/^\/account\/([a-zA-Z0-9_-]+)$/);
  if (accountMatch) {
    if (request.method !== "POST") return methodNotAllowed();
    return await handleAccount(request, database, baseUrl, accountMatch[1]);
  }

  // New Order
  if (path === "/new-order") {
    if (request.method !== "POST") return methodNotAllowed();
    return await handleNewOrder(request, database, baseUrl, env);
  }

  // Order Finalize
  const finalizeMatch = path.match(/^\/order\/([a-zA-Z0-9_-]+)\/finalize$/);
  if (finalizeMatch) {
    if (request.method !== "POST") return methodNotAllowed();
    return await handleFinalizeOrder(
      request,
      database,
      baseUrl,
      finalizeMatch[1],
      env
    );
  }

  // Order Detail
  const orderMatch = path.match(/^\/order\/([a-zA-Z0-9_-]+)$/);
  if (orderMatch) {
    if (request.method !== "POST") return methodNotAllowed();
    return await handleGetOrder(request, database, baseUrl, orderMatch[1]);
  }

  // Authorization Detail
  const authzMatch = path.match(/^\/authz\/([a-zA-Z0-9_-]+)$/);
  if (authzMatch) {
    if (request.method !== "POST") return methodNotAllowed();
    return await handleGetAuthz(request, database, baseUrl, authzMatch[1]);
  }

  // Challenge Trigger
  const challengeMatch = path.match(/^\/challenge\/([a-zA-Z0-9_-]+)$/);
  if (challengeMatch) {
    if (request.method !== "POST") return methodNotAllowed();
    return await handleChallenge(request, database, baseUrl, challengeMatch[1]);
  }

  // Certificate Download
  const certMatch = path.match(/^\/cert\/([a-zA-Z0-9_-]+)$/);
  if (certMatch) {
    return await handleGetCertificate(request, database, certMatch[1]);
  }

  // Revoke Cert
  if (path === "/revoke-cert") {
    if (request.method !== "POST") return methodNotAllowed();
    return await handleRevokeCert(request, database);
  }

  // RFC 9773 ACME Renewal Information (ARI)
  const ariMatch = path.match(/^\/renewal-info\/([a-zA-Z0-9_.-]+)$/);
  if (ariMatch) {
    return await handleRenewalInfo(request, database, ariMatch[1]);
  }

  throw AcmeError.notFound(`Endpoint '${path}' not found`);
}

function methodNotAllowed(): Response {
  return new Response("Method Not Allowed", { status: 405 });
}
