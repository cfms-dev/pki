import { readFile } from "node:fs/promises";
import { URL as NodeURL } from "node:url";

/** File-backed asset double; actual routing is covered by runtime-smoke.mjs. */
export const testAssets = {
  async fetch(input: RequestInfo | URL): Promise<Response> {
    const request = input instanceof Request ? input : new Request(input);
    const name = new URL(request.url).pathname.slice(1);
    if (!["index.html", "terms.html", "privacy.html", "styles.css"].includes(name)) {
      return new Response(null, { status: 404 });
    }
    const content = await readFile(new NodeURL(`../public/${name}`, import.meta.url), "utf8");
    return new Response(request.method === "HEAD" ? null : content, {
      headers: {
        "Content-Type": name.endsWith(".css") ? "text/css; charset=utf-8" : "text/html; charset=utf-8",
        ETag: '"source-asset"',
        "Last-Modified": "Mon, 09 Nov 2026 00:00:00 GMT",
        "Content-Length": String(Buffer.byteLength(content)),
      },
    });
  },
} as Fetcher;
