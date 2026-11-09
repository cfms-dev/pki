import "reflect-metadata";
import { AcmeEnv, CONFIG } from "./config";
import { Database } from "./db/queries";
import { AcmeError } from "./errors";
import { createAndSaveNonce } from "./crypto/nonce";
import { bindPublishedRequestUrl } from "./crypto/jws";
import { handleDirectory } from "./routes/directory";
import { handleNewNonce } from "./routes/nonce";
import { handleAccount, handleNewAccount } from "./routes/account";
import { handleKeyChange } from "./routes/key-change";
import { handleFinalizeOrder, handleGetOrder, handleNewOrder } from "./routes/order";
import { handleGetAuthz } from "./routes/authz";
import { handleChallenge } from "./routes/challenge";
import { handleGetCertificate } from "./routes/certificate";
import { handleRevokeCert } from "./routes/revoke";
import { handleRenewalInfo } from "./routes/ari";
import { checkIngress } from "./ratelimit/ingress";

export default {
  async scheduled(_event: ScheduledController, env: AcmeEnv, _ctx: ExecutionContext): Promise<void> {
    const database = new Database(env.DB);
    try {
      const result = await database.cleanupExpiredNonces();
      console.log(JSON.stringify({ event: result.backlog ? "acme_nonce_cleanup_backlog" : "acme_nonce_cleanup", ...result }));
    } catch {
      console.error(JSON.stringify({ event: "acme_nonce_cleanup_failed" }));
      throw new Error("Nonce cleanup failed");
    }
  },
  async fetch(
    request: Request,
    env: AcmeEnv,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);
    const baseUrl = CONFIG.ACME_BASE_URL.trim() || url.origin;
    bindPublishedRequestUrl(request, baseUrl);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    // Assets normally bypass this Worker. Missing website resources must also
    // stay outside the ACME database and nonce/error paths.
    if (["/", "/index", "/index.html", "/terms", "/terms.html", "/privacy", "/privacy.html"].includes(path)
      || path === "/zh-cn" || path.startsWith("/zh-cn/")
      || path.endsWith(".css") || path.startsWith("/images/")) {
      return env.ASSETS.fetch(request);
    }

    // CORS preflight does not touch the database.
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

    // Read-only directory discovery never touches D1.
    const isDirectoryRead =
      path === "/directory" &&
      (request.method === "GET" || request.method === "HEAD");
    if (!isDirectoryRead) {
      const rejected = await checkIngress(request, path, env, baseUrl);
      if (rejected) return rejected;
    }
    // Do not even access the D1 binding on the read-only discovery path.
    if (isDirectoryRead) {
      const response = handleDirectory(request, env, baseUrl);
      const headers = new Headers(response.headers);
      headers.set("Link", `<${baseUrl}/directory>;rel="index"`);
      headers.set("Access-Control-Allow-Origin", "*");
      headers.set("Access-Control-Expose-Headers", "Link, Location, Replay-Nonce, Retry-After");
      return new Response(response.body, { status: response.status, headers });
    }
    const database = new Database(env.DB);
    try {
      const response = await routeRequest(request, path, database, baseUrl, env);

      // In RFC 8555 § 6.5.1, the server MUST include Replay-Nonce on POST responses
      // and Link rel="index" to the ACME directory.
      const headers = new Headers(response.headers);
      const indexLink = `<${baseUrl}/directory>;rel="index"`;
      const existingLink = headers.get("Link");
      headers.set(
        "Link",
        existingLink ? `${existingLink}, ${indexLink}` : indexLink
      );
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

      // Log a correlation ID, never arbitrary exception strings that may
      // contain request bodies, JWKs, PEMs or bound database parameters.
      const errorId = crypto.randomUUID();
      console.error(JSON.stringify({ event: "acme_internal_error", errorId, path, name: err instanceof Error ? err.name : "UnknownError" }));
      return AcmeError.serverInternal(`Internal server error (${errorId})`).toResponse(extraHeaders);
    }
  },
};

async function routeRequest(
  request: Request,
  path: string,
  database: Database,
  baseUrl: string,
  env: AcmeEnv
): Promise<Response> {
  // Directory
  if (path === "/directory") {
    return handleDirectory(request, env, baseUrl);
  }

  // Nonce
  if (path === "/new-nonce") {
    return await handleNewNonce(request, database);
  }

  // New Account
  if (path === "/new-account") {
    if (request.method !== "POST") return methodNotAllowed();
    return await handleNewAccount(request, database, baseUrl, env);
  }

  // Account Key Rollover (RFC 8555 § 7.3.5)
  if (path === "/key-change") {
    if (request.method !== "POST") return methodNotAllowed();
    return await handleKeyChange(request, database, baseUrl);
  }

  // Account
  const accountMatch = path.match(/^\/account\/([a-zA-Z0-9_-]+)$/);
  if (accountMatch) {
    if (request.method !== "POST") return methodNotAllowed();
    return await handleAccount(request, database, baseUrl, accountMatch[1], env);
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
    const challengeFetch =
      typeof env.fetch === "function" ? (env.fetch as typeof fetch) : fetch;
    return await handleChallenge(
      request,
      database,
      baseUrl,
      challengeMatch[1],
      challengeFetch
    );
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
