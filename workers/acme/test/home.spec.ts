import { readFileSync } from "node:fs";
import { URL as NodeURL } from "node:url";
import { testAssets } from "./website-test-helpers";
import { describe, expect, it, vi } from "vitest";
import { AcmeEnv, CONFIG } from "../src/config";
import worker from "../src/index";
import { renderHome } from "../src/routes/website";
import { testContext } from "./acme-test-helpers";

const base = "https://acme.test";
// A public page must work even when every database operation is unavailable.
const env: AcmeEnv = {
  ASSETS: testAssets,
  get DB(): D1Database { throw new Error("Public request accessed D1"); },
};

function request(path = "/", method = "GET") {
  return worker.fetch(new Request(`${base}${path}`, {
    method, headers: { Accept: "application/json" },
  }), env, testContext);
}

describe("Static service homepage", () => {
  it.each(["/", "/terms.html", "/privacy.html"])("serves %s with shared styles and policy navigation", async (path) => {
    const response = await request(path);
    expect(response.status).toBe(200);
    expect(response.headers.get("Replay-Nonce")).toBeNull();
    const html = await response.text();
    for (const href of ["/", "/styles.css", "/terms.html", "/privacy.html"]) {
      expect(html).toContain(`href="${href}"`);
    }
    expect(html).not.toMatch(/\{\{\w+\}\}/);
    expect(html).not.toContain("<script");
    const head = await request(path, "HEAD");
    expect(head.status).toBe(200);
    expect([...head.headers]).toEqual([...response.headers]);
    expect(await head.text()).toBe("");
  });

  it("serves CSS and missing resources without D1", async () => {
    const css = await request("/styles.css");
    expect(css.status).toBe(200);
    expect(css.headers.get("Content-Type")).toContain("text/css");
    expect(await css.text()).toContain("@media (max-width: 640px)");
    for (const path of ["/missing.css", "/images/missing.png"]) {
      expect((await request(path)).status).toBe(404);
    }
  });

  it.each(["GET", "HEAD"])("redirects the index alias for %s without exposing the template", async (method) => {
    const response = await request("/index.html?ref=test", method);
    expect(response.status).toBe(308);
    expect(response.headers.get("Location")).toBe(`${base}/?ref=test`);
    expect(await response.text()).toBe("");
  });

  it.each(["/index.html", "/terms.html", "/privacy.html", "/styles.css"])("rejects write methods on %s before accessing assets or D1", async (path) => {
    const fetchAsset = vi.spyOn(testAssets, "fetch").mockRejectedValue(new Error("Must not fetch"));
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      const response = await request(path, method);
      expect(response.status).toBe(405);
      expect(response.headers.get("Allow")).toBe("GET, HEAD, OPTIONS");
      expect(response.headers.get("Replay-Nonce")).toBeNull();
    }
    expect((await request(path, "OPTIONS")).status).toBe(204);
    expect(fetchAsset).not.toHaveBeenCalled();
  });

  it.each(["/", "/terms.html", "/privacy.html", "/styles.css"])("keeps failures for %s out of the database error path", async (path) => {
    vi.spyOn(testAssets, "fetch").mockRejectedValue(new Error("Asset unavailable"));
    vi.spyOn(console, "error").mockImplementation(() => {});
    const response = await request(path);
    expect(response.status).toBe(500);
    expect(response.headers.get("Replay-Nonce")).toBeNull();
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(await response.text()).toBe("Website temporarily unavailable");
    expect(await (await request(path, "HEAD")).text()).toBe("");
  });

  it("does not reuse source validators for dynamically rendered HTML", async () => {
    const fetchAsset = vi.spyOn(testAssets, "fetch");
    const response = await worker.fetch(new Request(base, {
      headers: { "If-None-Match": '"source-asset"', "If-Modified-Since": "Mon, 09 Nov 2026 00:00:00 GMT", Range: "bytes=0-10" },
    }), env, testContext);
    expect(response.status).toBe(200);
    for (const header of ["ETag", "Last-Modified", "Content-Length"]) expect(response.headers.get(header)).toBeNull();
    const forwarded = fetchAsset.mock.calls[0][0] as Request;
    expect([...forwarded.headers]).toEqual([]);
    expect(response.headers.get("Cache-Control")).toBe("public, max-age=300");
    expect(await response.text()).toContain(`${base}/directory`);
  });

  it("passes a missing homepage response through without D1", async () => {
    vi.spyOn(testAssets, "fetch").mockResolvedValue(new Response(null, { status: 404 }));
    expect((await request()).status).toBe(404);
  });

  it("serves HTML with protocol and CRL links without D1", async () => {
    CONFIG.CRL_BASE_URL = "  https://distribution.example/pki/crl/  ";
    const response = await request();
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(response.headers.get("Link")).toBe(`<${base}/directory>;rel="index"`);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(response.headers.get("Access-Control-Expose-Headers")).toContain("Link");
    const html = await response.text();
    expect(html).toContain("Certificate issuance,");
    expect(html).toContain(`href="${base}/directory"`);
    expect(html).toContain('href="https://distribution.example/pki/crl/"');
    expect(html).toContain("DNS-01");
    expect(html).toContain("HTTP-01");
    expect(html).not.toContain("{{DIRECTORY_URL}}");
    expect(html).not.toContain("{{CRL_URL}}");
    expect(html).not.toContain("<script");
  });

  it("returns the GET headers and no body for HEAD", async () => {
    const get = await request();
    const head = await request("/", "HEAD");
    expect(head.status).toBe(get.status);
    expect([...head.headers]).toEqual([...get.headers]);
    expect(await head.text()).toBe("");
  });

  it.each(["POST", "PUT", "PATCH", "DELETE"])("rejects %s without D1", async (method) => {
    const response = await request("/", method);
    expect(response.status).toBe(405);
    expect(response.headers.get("Allow")).toBe("GET, HEAD, OPTIONS");
    expect(response.headers.get("Link")).toContain(`${base}/directory`);
  });

  it("keeps preflight handling independent of D1", async () => {
    const response = await request("/", "OPTIONS");
    expect(response.status).toBe(204);
    expect(response.headers.get("Access-Control-Allow-Methods")).toContain("GET, HEAD");
    expect(await response.text()).toBe("");
  });

  it("uses the trimmed published URL for homepage and directory links", async () => {
    CONFIG.ACME_BASE_URL = "  https://published.example  ";
    const response = await request();
    expect(await response.text()).toContain('href="https://published.example/directory"');
    expect(response.headers.get("Link")).toContain("https://published.example/directory");
    const directory = await worker.fetch(new Request(`${base}/directory`), {
      ASSETS: testAssets,
      DB: new Proxy({} as D1Database, { get() { throw new Error("Directory accessed D1"); } }),
    }, testContext);
    expect(directory.headers.get("Content-Type")).toBe("application/json");
    expect(await directory.json()).toMatchObject({
      newNonce: "https://published.example/new-nonce",
      newAccount: "https://published.example/new-account",
      newOrder: "https://published.example/new-order",
      revokeCert: "https://published.example/revoke-cert",
      keyChange: "https://published.example/key-change",
      renewalInfo: "https://published.example/renewal-info",
    });
  });

  it("escapes substitutions without interpreting inserted placeholders", () => {
    CONFIG.CRL_BASE_URL = 'https://distribution.example/<>&"\'';
    const html = renderHome(readFileSync(new NodeURL('../public/index.html', import.meta.url), 'utf8'), 'https://published.example/<>&"\'{{CRL_URL}}');
    expect(html).toContain('https://distribution.example/&lt;&gt;&amp;&quot;&#39;');
    expect(html).toContain('https://published.example/&lt;&gt;&amp;&quot;&#39;{{CRL_URL}}/directory');
    expect(html).not.toContain(CONFIG.CRL_BASE_URL);
  });
});
