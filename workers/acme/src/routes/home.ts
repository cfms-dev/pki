import { CONFIG } from "../config";
import homeTemplate from "./home.html";

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]!);
}

/** Replace placeholders in one pass so inserted values remain literal text. */
export function renderHome(baseUrl: string): string {
  const values = {
    DIRECTORY_URL: `${baseUrl}/directory`,
    CRL_URL: CONFIG.CRL_BASE_URL.trim(),
  };
  return homeTemplate.replace(/\{\{(DIRECTORY_URL|CRL_URL)\}\}/g,
    (_, key: keyof typeof values) => escapeHtml(values[key]));
}

export function handleHome(request: Request, baseUrl: string): Response {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method Not Allowed", {
      status: 405,
      headers: { Allow: "GET, HEAD, OPTIONS" },
    });
  }
  return new Response(request.method === "HEAD" ? null : renderHome(baseUrl), {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "public, max-age=300",
    },
  });
}
