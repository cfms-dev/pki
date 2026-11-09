import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { d1Client } from "./d1-client.mjs";

if (process.argv.length !== 2) throw new Error("Usage: node scripts/cleanup-nonces.mjs");
const result = await build({
  stdin: { contents: 'export { Database } from "./src/db/queries";',
    resolveDir: fileURLToPath(new URL("../", import.meta.url)) },
  bundle: true, write: false, platform: "node", format: "esm",
});
const { Database } = await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString("base64")}`);
try {
  const database = new Database(d1Client());
  await database.initSchema();
  console.log(JSON.stringify(await database.cleanupExpiredNonces()));
} catch {
  // Never print remote errors or credentials.
  console.error(JSON.stringify({ event: "acme_nonce_cleanup_failed" }));
  process.exitCode = 1;
}
