/** Fixed diagnostic labels only: driver messages may contain SQL and parameters. */
export function databaseErrorCategory(error: unknown): "schema" | "quota" | "overloaded" | "timeout" | "unavailable" | "unknown" {
  const seen = new Set<unknown>();
  while (error instanceof Error && !seen.has(error)) {
    seen.add(error);
    // Inspect only the underlying driver error, not Drizzle's SQL/params wrapper.
    if (error.cause === undefined) {
      const message = error.message;
      if (/no such (?:table|column)|D1_COLUMN_NOTFOUND/i.test(message)) return "schema";
      if (/daily row (?:read|write) limit|maximum (?:account storage limit|DB size)/i.test(message)) return "quota";
      if (/D1 DB is overloaded/i.test(message)) return "overloaded";
      if (/timeout|timed out/i.test(message)) return "timeout";
      if (/Network connection lost|Replica disconnected from primary|D1 DB.*reset|D1 DB.*transient issue|object to be reset/i.test(message)) return "unavailable";
      return "unknown";
    }
    error = error.cause;
  }
  return "unknown";
}

/** Drizzle wraps driver errors; classify the underlying constraint error. */
export function isUniqueConstraintError(error: unknown): boolean {
  const seen = new Set<unknown>();
  while (error instanceof Error && !seen.has(error)) {
    seen.add(error);
    // Wrapper messages include SQL/parameters, which may contain user input.
    if (error.cause === undefined && /UNIQUE constraint failed|SQLITE_CONSTRAINT_UNIQUE/i.test(error.message)) return true;
    error = error.cause;
  }
  return false;
}
