import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { d1Client } from "./d1-client.mjs";

// Bundle TS in memory: no emitted source files and no private keys on disk.
const result = await build({
  stdin: { contents: 'export { Database } from "./src/db/queries"; export { migrateAccountPublicKeyFingerprints } from "./src/db/account-keys";',
    resolveDir: fileURLToPath(new URL("../", import.meta.url)) },
  bundle: true, write: false, platform: "node", format: "esm",
});
const { Database, migrateAccountPublicKeyFingerprints } = await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString("base64")}`);
const database = new Database(d1Client());
await database.initSchema();
while (true) {
  const summary = await migrateAccountPublicKeyFingerprints(database);
  console.log(JSON.stringify(summary));
  if (summary.remaining === 0) break;
  if (summary.scanned === 0) throw new Error("Unresolved account_key_conflicts; repair public keys/conflicts and rerun");
}
