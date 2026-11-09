import { readFileSync } from "node:fs";

// Used by disposable test databases. Wrangler owns production migration history.
export function readMigrations(directory = new URL("../drizzle/", import.meta.url)) {
  const journal = JSON.parse(readFileSync(new URL("meta/_journal.json", directory), "utf8"));
  return journal.entries.map(({ tag }) => ({
    name: `${tag}.sql`,
    sql: readFileSync(new URL(`${tag}.sql`, directory), "utf8"),
  }));
}

export function migrationStatements() {
  return readMigrations().flatMap(({ sql }) => sql.split("--> statement-breakpoint").map((s) => s.trim()).filter(Boolean));
}
