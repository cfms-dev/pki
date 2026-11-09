import { AcmeEnv, CONFIG } from "../config";

export function isWebsitePath(path: string): boolean {
  return ["/", "/index.html", "/terms.html", "/privacy.html"].includes(path)
    || path.endsWith(".css") || path.startsWith("/images/");
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]!);
}

/** Replace placeholders once so inserted values remain literal text. */
export function renderHome(template: string, baseUrl: string): string {
  const values = {
    DIRECTORY_URL: `${baseUrl}/directory`,
    CRL_URL: CONFIG.CRL_BASE_URL.trim(),
  };
  return template.replace(/\{\{(DIRECTORY_URL|CRL_URL)\}\}/g,
    (_, key: keyof typeof values) => escapeHtml(values[key]));
}

async function serveWebsite(request: Request, path: string, env: AcmeEnv, baseUrl: string): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method Not Allowed", {
      status: 405, headers: { Allow: "GET, HEAD, OPTIONS" },
    });
  }
  if (path === "/index.html") {
    const target = new URL(request.url);
    target.pathname = "/";
    return new Response(null, { status: 308, headers: { Location: target.href } });
  }

  const assetUrl = new URL(request.url);
  assetUrl.pathname = path === "/" ? "/index.html" : path;
  // Fetch a complete template even for HEAD or conditional client requests:
  // the asset's validators describe the source, not the rendered homepage.
  const asset = await env.ASSETS.fetch(new Request(assetUrl, {
    method: path === "/" ? "GET" : request.method,
    headers: path === "/" ? undefined : request.headers,
  }));
  if (path !== "/" || asset.status !== 200) return asset;

  const html = renderHome(await asset.text(), baseUrl);
  const headers = new Headers(asset.headers);
  for (const name of ["ETag", "Last-Modified", "Content-Length", "Content-Encoding"]) headers.delete(name);
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", "public, max-age=300");
  return new Response(request.method === "HEAD" ? null : html, { headers });
}

/** Website failures stay outside the ACME nonce/database error path. */
export async function handleWebsite(request: Request, path: string, env: AcmeEnv, baseUrl: string): Promise<Response> {
  let response: Response;
  try {
    response = await serveWebsite(request, path, env, baseUrl);
  } catch {
    console.error(JSON.stringify({ event: "website_asset_error", path }));
    response = new Response("Website temporarily unavailable", {
      status: 500, headers: { "Cache-Control": "no-store" },
    });
  }
  const headers = new Headers(response.headers);
  headers.append("Link", `<${baseUrl}/directory>;rel="index"`);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Expose-Headers", "Link, Location, Replay-Nonce, Retry-After");
  return new Response(request.method === "HEAD" ? null : response.body, {
    status: response.status, headers,
  });
}
