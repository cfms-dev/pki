import { DatabaseSync } from "node:sqlite";
import { readMigrations } from "../scripts/migrations.mjs";

export function createMockD1Database(migrate = true): D1Database {
  const db = new DatabaseSync(":memory:");
  if (migrate) for (const migration of readMigrations()) db.exec(migration.sql);
  let pendingBatch: Promise<unknown> = Promise.resolve();

  return {
    prepare(query: string): D1PreparedStatement {
      return createPreparedStatement(db, query, []);
    },
    async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
      // D1 serializes transactions. Preserve that property when concurrent
      // finalize requests share this in-memory SQLite connection.
      const execute = async () => {
        const results: D1Result<T>[] = [];
        db.exec("BEGIN");
        try {
          for (const stmt of statements) {
            results.push(await (stmt as unknown as { run(): Promise<D1Result<T>> }).run());
          }
          db.exec("COMMIT");
        } catch (error) { db.exec("ROLLBACK"); throw error; }
        return results;
      };
      const result = pendingBatch.then(execute);
      pendingBatch = result.catch(() => {});
      return result;
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
  function execute<T>(): D1Result<T> {
    const stmt = db.prepare(query);
    const before = Number(db.prepare("SELECT total_changes() AS n").get()!.n);
    const results = stmt.columns().length ? stmt.all(...(params as any[])) as T[] : [];
    if (!stmt.columns().length) stmt.run(...(params as any[]));
    const changes = Number(db.prepare("SELECT total_changes() AS n").get()!.n) - before;
    return {
      results, success: true,
      meta: { changes, last_row_id: Number(db.prepare("SELECT last_insert_rowid() AS n").get()!.n),
        duration: 0, rows_read: results.length, rows_written: changes },
    } as D1Result<T>;
  }
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
    async all<T = unknown>(): Promise<D1Result<T>> { return execute<T>(); },
    async run<T = unknown>(): Promise<D1Result<T>> { return execute<T>(); },
    async raw<T = unknown>(): Promise<T[]> {
      const stmt = db.prepare(query);
      stmt.setReturnArrays(true);
      return stmt.all(...(params as any[])) as T[];
    },
  } as unknown as D1PreparedStatement;
}
