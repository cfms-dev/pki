import { DatabaseSync } from "node:sqlite";

export function createMockD1Database(): D1Database {
  const db = new DatabaseSync(":memory:");

  return {
    prepare(query: string): D1PreparedStatement {
      return createPreparedStatement(db, query, []);
    },
    async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
      const results: D1Result<T>[] = [];
      for (const stmt of statements) {
        results.push(await (stmt as unknown as { run(): Promise<D1Result<T>> }).run());
      }
      return results;
    },
    async exec(query: string): Promise<D1ExecResult> {
      db.exec(query);
      return { count: 1, duration: 0 };
    },
    async dump(): Promise<ArrayBuffer> {
      return new ArrayBuffer(0);
    },
  } as unknown as D1Database;
}

function createPreparedStatement(
  db: DatabaseSync,
  query: string,
  params: unknown[]
): D1PreparedStatement {
  return {
    bind(...newParams: unknown[]): D1PreparedStatement {
      return createPreparedStatement(db, query, newParams);
    },
    async first<T = unknown>(colName?: string): Promise<T | null> {
      const stmt = db.prepare(query);
      const row = stmt.get(...(params as any[])) as Record<string, unknown> | undefined;
      if (!row) return null;
      if (colName) {
        return (row[colName] as T) ?? null;
      }
      return row as T;
    },
    async all<T = unknown>(): Promise<D1Result<T>> {
      const stmt = db.prepare(query);
      const results = stmt.all(...(params as any[])) as T[];
      return {
        results,
        success: true,
        meta: {
          duration: 0,
          rows_read: results.length,
          rows_written: 0,
        },
      } as unknown as D1Result<T>;
    },
    async run<T = unknown>(): Promise<D1Result<T>> {
      const stmt = db.prepare(query);
      const result = stmt.run(...(params as any[]));
      return {
        results: [],
        success: true,
        meta: {
          changes: Number(result.changes),
          last_row_id: Number(result.lastInsertRowid),
          duration: 0,
          rows_read: 0,
          rows_written: Number(result.changes),
        },
      } as unknown as D1Result<T>;
    },
    async raw<T = unknown>(): Promise<T[]> {
      const stmt = db.prepare(query);
      return stmt.all(...(params as any[])) as T[];
    },
  } as unknown as D1PreparedStatement;
}
