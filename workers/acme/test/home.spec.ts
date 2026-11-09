import { describe, expect, it } from "vitest";
import { AcmeEnv, CONFIG } from "../src/config";
import worker from "../src/index";
import { renderHome } from "../src/routes/home";
import { testContext } from "./acme-test-helpers";

const base = "https://acme.test";
// A public page must work even when every database operation is unavailable.
const env: AcmeEnv = {
  DB: new Proxy({} as D1Database, {
    get() { throw new Error("Public request accessed D1"); },
  }),
};

function request(path = "/", method = "GET") {
  return worker.fetch(new Request(`${base}${path}`, {
    method, headers: { Accept: "application/json" },
  }), env, testContext);
}

describe("Static service homepage", () => {
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
    const directory = await request("/directory");
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
    const html = renderHome('https://published.example/<>&"\'{{CRL_URL}}');
    expect(html).toContain('https://distribution.example/&lt;&gt;&amp;&quot;&#39;');
    expect(html).toContain('https://published.example/&lt;&gt;&amp;&quot;&#39;{{CRL_URL}}/directory');
    expect(html).not.toContain(CONFIG.CRL_BASE_URL);
  });
});
