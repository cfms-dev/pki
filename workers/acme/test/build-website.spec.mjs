import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { CONFIG } from "../src/config.ts";
import { buildWebsite, renderTemplate } from "../scripts/build-website.mjs";

let root;
const output = (name) => path.join(root, "dist", "website", name);

beforeEach(async () => {
  root = await mkdtemp(path.join(tmpdir(), "cfms-website-test-"));
  await cp(new URL("../public/", import.meta.url), path.join(root, "public"), { recursive: true });
});
afterEach(async () => {
  if (root) {
    expect(root.startsWith(path.join(tmpdir(), "cfms-website-test-"))).toBe(true);
    await rm(root, { recursive: true, force: true });
  }
});

describe("Static website build", () => {
  it.each(["", "https://published.example"])("builds with ACME_BASE_URL=%j and a relative directory link", async (baseUrl) => {
    CONFIG.ACME_BASE_URL = baseUrl;
    CONFIG.CRL_BASE_URL = "  https://distribution.example/crl/  ";
    const source = await readFile(path.join(root, "public", "index.html"), "utf8");
    await buildWebsite(root);
    const home = await readFile(output("index.html"), "utf8");
    expect(home).toContain('<a href="/directory"><code>/directory</code></a>');
    expect(home).toContain('href="https://distribution.example/crl/"');
    expect(home).not.toContain("https://published.example");
    expect(await readFile(path.join(root, "public", "index.html"), "utf8")).toBe(source);
    for (const name of ["index.html", "terms.html", "privacy.html"]) {
      const html = await readFile(output(name), "utf8");
      for (const href of ["/", "/styles.css", "/terms", "/privacy"]) expect(html).toContain(`href="${href}"`);
      expect(html).not.toMatch(/\{\{\w+\}\}/);
      expect(html).not.toContain("<script");
    }
    expect(await readFile(output("styles.css"))).toEqual(
      await readFile(new URL("../../../src/cfms_pki/templates/web/styles.css", import.meta.url))
    );
  });

  it.each(["https://distribution.example/pki/crl/", "https://distribution.example/pki/crl"])("preserves the project prefix from %s across all translated pages", async (crlUrl) => {
    CONFIG.CRL_BASE_URL = crlUrl;
    await buildWebsite(root);
    for (const prefix of ["", "zh-cn/"]) {
      for (const page of ["index", "terms", "privacy"]) {
        const html = await readFile(output(`${prefix}${page}.html`), "utf8");
        expect(html).toContain(`<html lang="${prefix ? "zh-CN" : "en"}">`);
        const nav = html.split('<div class="nav-links">')[1].split("</div>")[0];
        const links = [...nav.matchAll(/<a href="([^"]+)"/g)].map((match) => match[1]);
        expect(links).toEqual([
          `https://distribution.example/pki/${prefix}`,
          prefix ? `https://distribution.example/pki/${prefix}crl/` : crlUrl,
          `/${prefix}`, "https://github.com/cfms-dev/pki",
        ]);
        expect(nav).toContain(`href="/${prefix}" aria-current="${page === "index" ? "page" : "location"}"`);
        const alternate = `/${prefix ? "" : "zh-cn/"}${page === "index" ? "" : page}`;
        expect(html).toContain(`class="language-switch" href="${alternate}"`);
        for (const policy of ["terms", "privacy"]) {
          expect(html).toContain(`href="/${prefix}${policy}" aria-current="${page === policy ? "page" : "false"}"`);
        }
        expect(html).not.toMatch(/\{\{/);
        expect(html).not.toContain("<script");
        if (prefix) expect(html).toContain(page === "index" ? "证书签发，" : "2026 年 11 月 9 日");
      }
    }
  });

  it("copies nested binary resources and removes obsolete files on rebuild", async () => {
    await mkdir(path.join(root, "public", "images"));
    const bytes = Buffer.from([0, 255, 137, 80, 78, 71]);
    await writeFile(path.join(root, "public", "images", "fixture.png"), bytes);
    await buildWebsite(root);
    expect(await readFile(output("images/fixture.png"))).toEqual(bytes);
    await writeFile(output("obsolete.html"), "old content");
    await rm(path.join(root, "public", "images", "fixture.png"));
    CONFIG.CRL_BASE_URL = "https://updated.example/crl/";
    await buildWebsite(root);
    await expect(readFile(output("obsolete.html"))).rejects.toHaveProperty("code", "ENOENT");
    await expect(readFile(output("images/fixture.png"))).rejects.toHaveProperty("code", "ENOENT");
    expect(await readFile(output("index.html"), "utf8")).toContain("https://updated.example/crl/");
  });

  it("escapes HTML in one pass and keeps inserted replacement tokens literal", () => {
    const template = '<a href="{{CRL_URL}}">{{CRL_URL}}</a>';
    expect(renderTemplate(template, { CRL_URL: 'https://example.test/<>&"\'{{CRL_URL}}$&' })).toBe(
      '<a href="https://example.test/&lt;&gt;&amp;&quot;&#39;{{CRL_URL}}$&amp;">https://example.test/&lt;&gt;&amp;&quot;&#39;{{CRL_URL}}$&amp;</a>'
    );
    expect(() => renderTemplate("{{UNKNOWN}}", {})).toThrow("Unknown website template placeholder");
  });
});
