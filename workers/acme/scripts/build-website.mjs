import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CONFIG } from "../src/config.ts";

const workerRoot = fileURLToPath(new URL("../", import.meta.url));

/** Replace only source placeholders, never text inserted by a previous replacement. */
export function renderHome(template, crlUrl) {
  if (/\{\{\w+\}\}/.test(template.replaceAll("{{CRL_URL}}", ""))) {
    throw new Error("Unknown homepage template placeholder");
  }
  const escaped = crlUrl.trim().replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
  return template.replace(/\{\{CRL_URL\}\}/g, () => escaped);
}

/** Keep source files separate from the disposable, deploy-ready website. */
export async function buildWebsite(root = workerRoot) {
  const source = path.resolve(root, "public");
  const output = path.resolve(root, "dist", "website");
  // The deletion target is always the named website output under this workspace.
  if (path.relative(path.resolve(root), output) !== path.join("dist", "website")) {
    throw new Error("Website output must stay within the workspace");
  }
  const html = renderHome(await readFile(path.join(source, "index.html"), "utf8"), CONFIG.CRL_BASE_URL);
  await rm(output, { recursive: true, force: true });
  await mkdir(path.dirname(output), { recursive: true });
  await cp(source, output, { recursive: true });
  await writeFile(path.join(output, "index.html"), html, "utf8");
}

if (import.meta.main) await buildWebsite();
