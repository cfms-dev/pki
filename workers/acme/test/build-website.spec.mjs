import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { CONFIG } from "../src/config.ts";
import { buildWebsite, renderHome } from "../scripts/build-website.mjs";

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
    for (const name of ["terms.html", "privacy.html", "styles.css"]) {
      expect(await readFile(output(name))).toEqual(await readFile(path.join(root, "public", name)));
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
    expect(renderHome(template, ' https://example.test/<>&"\'{{CRL_URL}}$& ')).toBe(
      '<a href="https://example.test/&lt;&gt;&amp;&quot;&#39;{{CRL_URL}}$&amp;">https://example.test/&lt;&gt;&amp;&quot;&#39;{{CRL_URL}}$&amp;</a>'
    );
    expect(() => renderHome("{{UNKNOWN}}", "https://example.test/")).toThrow("Unknown homepage template placeholder");
  });
});
