export function d1Client() {
  const account = process.env.CLOUDFLARE_ACCOUNT_ID;
  const database = process.env.CLOUDFLARE_D1_DATABASE_ID;
  const token = process.env.CLOUDFLARE_API_TOKEN;
  if (![account, database, token].every(Boolean)) throw new Error("Cloudflare account, database and API token are required");
  async function execute(statements) {
    const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(account)}/d1/database/${encodeURIComponent(database)}/query`, {
      method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(statements.length === 1 ? statements[0] : { batch: statements }), signal: AbortSignal.timeout(30000),
    });
    if (!response.ok) throw new Error(`D1 query failed (HTTP ${response.status})`);
    const body = await response.json();
    if (!body.success || !Array.isArray(body.result) || body.result.length !== statements.length || body.result.some((r) => !r.success)) {
      const errors = [...(body.errors ?? []), ...(body.result ?? []).flatMap((result) => result.errors ?? [])];
      // Preserve only controlled error categories used by idempotent schema
      // upgrades and uniqueness checks, never raw API error messages.
      if (errors.some((error) => /duplicate column name/i.test(error.message ?? ""))) throw new Error("duplicate column name");
      if (errors.some((error) => /UNIQUE constraint failed|SQLITE_CONSTRAINT_UNIQUE/i.test(error.message ?? ""))) throw new Error("UNIQUE constraint failed");
      throw new Error("D1 query failed");
    }
    return body.result;
  }
  function statement(sql, params = []) {
    return {
      sql, params,
      bind(...values) { return statement(sql, values); },
      async run() { return (await execute([{ sql, params }]))[0]; },
      async all() { return this.run(); },
      async first(column) { const row = (await this.run()).results[0]; return row ? (column ? row[column] : row) : null; },
      async raw() {
        const rows = (await this.run()).results;
        return rows.map((row) => Object.values(row));
      },
    };
  }
  return { prepare: statement, batch: (statements) => execute(statements.map(({ sql, params }) => ({ sql, params }))) };
}
