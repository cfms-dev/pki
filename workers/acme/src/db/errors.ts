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
