import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import { readMigrations } from "../scripts/migrations.mjs";
import { Database, isAccountFingerprintIndexSql } from "../src/db/queries";
import { createMockD1Database } from "./mock-d1";

describe("committed schema migrations", () => {
  it("creates the current schema and preserves rows when the baseline is adopted again", () => {
    const sqlite = new DatabaseSync(":memory:");
    try {
      const apply = () => { for (const migration of readMigrations()) sqlite.exec(migration.sql); };
      apply();
      expect(sqlite.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all()).toHaveLength(10);
      sqlite.exec(`INSERT INTO accounts (id, jwk, thumbprint, status, created_at) VALUES ('a', '{}', 'thumb', 'valid', 1);
        INSERT INTO certificates (id, cert_id, serial_number, aki, subject, san, pem, not_before, not_after, account_id, created_at)
        VALUES ('c', 'aki.serial', 'serial', 'aki', 'subject', '["example.com"]', 'public-pem', 1, 2, 'a', 1);
        INSERT INTO issuance_ledger VALUES ('c', 'bucket', 1);`);
      const tables = ["accounts", "certificates", "issuance_ledger", "security_migrations"];
      const before = tables.map((table) => sqlite.prepare(`SELECT * FROM ${table}`).all());
      apply();
      expect(tables.map((table) => sqlite.prepare(`SELECT * FROM ${table}`).all())).toEqual(before);
      expect(sqlite.prepare("PRAGMA table_info(authorizations)").all()).toEqual(expect.arrayContaining([expect.objectContaining({ name: "identifier_type", dflt_value: "'dns'" })]));
      const index = sqlite.prepare("SELECT sql FROM sqlite_master WHERE name = 'idx_accounts_public_key_fingerprint'").get();
      expect(isAccountFingerprintIndexSql(index?.sql as string)).toBe(true);
      sqlite.exec("DELETE FROM security_migrations");
      apply();
      expect(sqlite.prepare("SELECT * FROM security_migrations").all()).toEqual([]);
    } finally { sqlite.close(); }
  });

  it("does not create schema when the data access class is constructed or queried", async () => {
    const binding = createMockD1Database(false);
    const database = new Database(binding);
    await expect(database.saveNonce("test", 1)).rejects.toThrow();
    expect((await binding.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all()).results).toEqual([]);
  });
});
