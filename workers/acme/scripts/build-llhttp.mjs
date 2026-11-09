// Reuse Node.js/Undici's llhttp build; no HTTP client code enters the Worker.
import { createRequire } from "node:module";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const require = createRequire(import.meta.url);
const version = require("undici/package.json").version;
if (version !== "8.12.4") throw new Error("Review the llhttp ABI before upgrading Undici");
const bytes = require("undici/lib/llhttp/llhttp-wasm.js");
const module = new WebAssembly.Module(bytes);
const exports = new Set(WebAssembly.Module.exports(module).map((item) => item.name));
for (const name of ["memory", "_initialize", "malloc", "free", "llhttp_alloc", "llhttp_free", "llhttp_execute", "llhttp_finish", "llhttp_get_status_code", "llhttp_get_http_major", "llhttp_get_http_minor", "llhttp_get_upgrade"]) {
  if (!exports.has(name)) throw new Error(`Missing llhttp export: ${name}`);
}
const directory = new URL("../generated/llhttp/", import.meta.url);
await mkdir(directory, { recursive: true });
// Unchanged outputs must not retrigger Wrangler's additional-module watcher.
async function writeArtifact(name, content) {
  const file = new URL(name, directory);
  const next = Buffer.from(content);
  try {
    if ((await readFile(file)).equals(next)) return;
  } catch (error) { if (error.code !== "ENOENT") throw error; }
  await writeFile(file, next);
}
await writeArtifact("llhttp.wasm", bytes);
await writeArtifact("llhttp-license.txt", await readFile(new URL("../src/http01/LLHTTP-LICENSE.txt", import.meta.url)));
await writeArtifact("undici-license.txt", await readFile(require.resolve("undici/LICENSE")));
// preserve_file_names retains import specifiers after bundling. Keep the WASM
// import beside the generated binary so its ./llhttp.wasm specifier stays valid.
await writeArtifact("llhttp-module.ts", 'import module from "./llhttp.wasm";\nexport default module;\n');
await writeArtifact("llhttp-provenance.json", JSON.stringify({
  source: "https://github.com/nodejs/undici/tree/v8.12.4/lib/llhttp",
  undici: version, llhttp: "9.3.1", license: "MIT",
  sha256: createHash("sha256").update(bytes).digest("hex"),
}, null, 2) + "\n");
