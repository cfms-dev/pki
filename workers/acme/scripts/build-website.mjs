import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CONFIG } from "../src/config.ts";

const workerRoot = fileURLToPath(new URL("../", import.meta.url));
const sharedRoot = fileURLToPath(new URL("../../../src/cfms_pki/templates/web/", import.meta.url));

/** Replace only source placeholders, never text inserted by a previous replacement. */
export function renderTemplate(template, values, fragments = []) {
  // Shared Jinja templates use this condition for non-link current-page labels.
  const selected = template.replace(
    /\{% if (\w+) == "page" %\}([\s\S]*?)\{% else %\}([\s\S]*?)\{% endif %\}/g,
    (_, key, current, link) => values[key] === "page" ? current : link,
  );
  return selected.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, key) => {
    if (!Object.hasOwn(values, key)) throw new Error(`Unknown website template placeholder: ${key}`);
    const value = String(values[key]);
    // Only locally rendered HTML fragments bypass escaping in the outer shell.
    if (fragments.includes(key)) return value;
    return value.replace(/[&<>"']/g, (character) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[character]);
  });
}

/** Keep source files separate from the disposable, deploy-ready website. */
export async function buildWebsite(root = workerRoot) {
  const source = path.resolve(root, "public");
  const output = path.resolve(root, "dist", "website");
  // The deletion target is always the named website output under this workspace.
  if (path.relative(path.resolve(root), output) !== path.join("dist", "website")) {
    throw new Error("Website output must stay within the workspace");
  }
  const crlUrl = CONFIG.CRL_BASE_URL.trim();
  const directoryUrl = new URL(crlUrl);
  if (!directoryUrl.pathname.endsWith("/")) directoryUrl.pathname += "/";
  const overviewUrl = new URL("../", directoryUrl);
  const header = await readFile(path.join(sharedRoot, "header.html"), "utf8");
  const footer = await readFile(path.join(sharedRoot, "footer.html"), "utf8");
  await rm(output, { recursive: true, force: true });
  await mkdir(path.dirname(output), { recursive: true });
  await cp(source, output, { recursive: true });
  await cp(path.join(sharedRoot, "styles.css"), path.join(output, "styles.css"));
  for (const locale of ["en", "zh-cn"]) {
    const messages = JSON.parse(await readFile(path.join(sharedRoot, locale, "messages.json"), "utf8"));
    const prefix = locale === "en" ? "" : "zh-cn/";
    const alternatePrefix = locale === "en" ? "zh-cn/" : "";
    for (const page of ["acme", "terms", "privacy"]) {
      const file = page === "acme" ? "index.html" : `${page}.html`;
      const values = {
        ...messages,
        title: messages[`${page}_title`], desc: messages[`${page}_desc`],
        overview_href: new URL(prefix, overviewUrl).href,
        crl_href: locale === "en" ? crlUrl : new URL(`${prefix}crl/`, overviewUrl).href,
        acme_href: `/${prefix}`,
        terms_href: `/${prefix}terms`, privacy_href: `/${prefix}privacy`,
        switch_href: `/${alternatePrefix}${page === "acme" ? "" : page}`,
        overview_current: "false", crl_current: "false",
        acme_current: page === "acme" ? "page" : "location",
        home_current: page === "acme" ? "page" : "false",
        terms_current: page === "terms" ? "page" : "false",
        privacy_current: page === "privacy" ? "page" : "false",
        overview_arrow: "↗", crl_arrow: "↗", acme_arrow: "",
      };
      const content = await readFile(path.join(sharedRoot, locale, `${page}.html`), "utf8");
      const html = renderTemplate(await readFile(path.join(source, file), "utf8"), {
        ...values,
        header: renderTemplate(header, values),
        footer: renderTemplate(footer, values),
        content: renderTemplate(content, values),
      }, ["header", "footer", "content"]);
      await mkdir(path.join(output, prefix), { recursive: true });
      await writeFile(path.join(output, prefix, file), html, "utf8");
    }
  }
}

if (import.meta.main) await buildWebsite();
