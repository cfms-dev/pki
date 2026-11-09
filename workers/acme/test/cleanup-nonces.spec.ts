import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

it("runs the nonce cleanup CLI through the REST adapter against a disposable SQL peer", () => {
  const source = `
    import assert from 'node:assert/strict';
    import { DatabaseSync } from 'node:sqlite';
    import { readFileSync } from 'node:fs';
    const db = new DatabaseSync(':memory:');
    db.exec(readFileSync('schema.sql', 'utf8'));
    const now = Math.floor(Date.now()/1000);
    db.prepare('INSERT INTO nonces VALUES (?, ?)').run('expired', now-1);
    db.prepare('INSERT INTO nonces VALUES (?, ?)').run('live', now+300);
    process.env.CLOUDFLARE_ACCOUNT_ID = 'test-account';
    process.env.CLOUDFLARE_D1_DATABASE_ID = 'test-database';
    process.env.CLOUDFLARE_API_TOKEN = 'disposable-test-token';
    globalThis.fetch = async (url, init) => {
      assert.equal(url, 'https://api.cloudflare.com/client/v4/accounts/test-account/d1/database/test-database/query');
      assert.equal(init.method, 'POST');
      const body = JSON.parse(init.body), queries = body.batch ?? [body];
      const result = [];
      db.exec('BEGIN');
      try {
        for (const query of queries) {
          const statement = db.prepare(query.sql);
          let rows = [];
          if (statement.columns().length) rows = statement.all(...query.params);
          else statement.run(...query.params);
          result.push({ success: true, results: rows, meta: { changes: db.prepare('SELECT changes() AS n').get().n } });
        }
        db.exec('COMMIT');
        return Response.json({ success: true, result });
      } catch (error) {
        db.exec('ROLLBACK');
        return Response.json({ success: false, result: [], errors: [{ message: error.message }] });
      }
    };
    process.on('exit', (code) => {
      assert.equal(code, 0);
      assert.equal(db.prepare('SELECT COUNT(*) AS n FROM nonces').get().n, 1);
      assert.equal(db.prepare('SELECT nonce FROM nonces').get().nonce, 'live');
    });
  `;
  const preload = `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
  const output = execFileSync(process.execPath, ["--import", preload, "scripts/cleanup-nonces.mjs"],
    { cwd: fileURLToPath(new URL("../", import.meta.url).href), encoding: "utf8", timeout: 20000 });
  expect(JSON.parse(output)).toEqual({ deleted: 1, backlog: false });
});
