import type { AcmeEnv } from "../config";
import { AcmeError } from "../errors";

/** Admission rejection deliberately bypasses D1, including nonce generation. */
export async function checkIngress(request: Request, path: string, env: AcmeEnv, baseUrl: string): Promise<Response | null> {
  const headers = {
    "Retry-After": "60",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Expose-Headers": "Link, Retry-After",
    Link: `<${baseUrl}/directory>;rel="index"`,
  };
  // Cloudflare supplies this header. Never use X-Forwarded-For or a client
  // supplied account ID; missing platform metadata shares a bounded fallback.
  const key = request.headers.get("CF-Connecting-IP") || "unknown-source";
  try {
    if (!(await env.API_RATE_LIMITER.limit({ key })).success) {
      return AcmeError.rateLimited("Too many API requests from this source").toResponse(headers);
    }
    if (path === "/new-account" && request.method === "POST" &&
        !(await env.ACCOUNT_REGISTRATION_LIMITER.limit({ key })).success) {
      return AcmeError.rateLimited("Too many account registration requests from this source").toResponse(headers);
    }
    return null;
  } catch {
    // A missing or failed binding must not turn a deployment error into an
    // unthrottled database write path. Do not reflect binding exceptions.
    console.error(JSON.stringify({ event: "acme_ingress_limiter_unavailable" }));
    return new AcmeError("serverInternal", "Request admission is temporarily unavailable", 503).toResponse(headers);
  }
}
