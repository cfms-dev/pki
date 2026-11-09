import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const kit = path.join(root, "node_modules/drizzle-kit/bin.cjs");
const run = (args) => execFileSync(process.execPath, [kit, ...args], { cwd: root, stdio: "pipe" });
function contents(directory) {
  return readdirSync(directory, { recursive: true }).sort()
    .filter((name) => name.endsWith(".sql") || name.endsWith(".json"))
    .map((name) => [name, readFileSync(path.join(directory, name), "utf8")]);
}

run(["check"]);
const temporary = mkdtempSync(path.join(tmpdir(), "cfms-drizzle-check-"));
try {
  cpSync(path.join(root, "drizzle"), temporary, { recursive: true });
  const before = JSON.stringify(contents(temporary));
  run(["generate", "--dialect=sqlite", "--schema=./src/db/schema.ts", `--out=${temporary.replaceAll("\\", "/")}`]);
  if (JSON.stringify(contents(temporary)) !== before) {
    throw new Error("Database schema has uncommitted migrations; run npm run db:generate");
  }
  console.log("Migration history and schema snapshots are in sync");
} finally {
  if (path.dirname(path.resolve(temporary)) !== path.resolve(tmpdir()) || !path.basename(temporary).startsWith("cfms-drizzle-check-")) {
    throw new Error("Unexpected migration check temporary directory");
  }
  rmSync(temporary, { recursive: true, force: true });
}
