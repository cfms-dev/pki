import { sql } from "drizzle-orm";
import { index, integer, primaryKey, sqliteTable, text, unique, uniqueIndex } from "drizzle-orm/sqlite-core";

// JSON remains TEXT, timestamps are Unix seconds, and flags remain integers.
// Relationships deliberately have no foreign keys or cascading deletes.
export const nonces = sqliteTable("nonces", {
  nonce: text().primaryKey(),
  expires_at: integer().notNull(),
}, (t) => [index("idx_nonces_expiry").on(t.expires_at)]);

export const accounts = sqliteTable("accounts", {
  id: text().primaryKey(),
  jwk: text().notNull(),
  thumbprint: text().notNull().unique(),
  public_key_fingerprint: text(),
  contact: text(),
  status: text({ enum: ["valid", "deactivated", "revoked"] }).notNull(),
  created_at: integer().notNull(),
  terms_of_service: text(),
}, (t) => [
  uniqueIndex("idx_accounts_public_key_fingerprint").on(t.public_key_fingerprint),
  index("idx_accounts_missing_public_key_fingerprint").on(t.id).where(sql`${t.public_key_fingerprint} IS NULL`),
]);

export const accountKeyConflicts = sqliteTable("account_key_conflicts", {
  account_id: text().primaryKey(),
  reason: text().notNull(),
  public_key_fingerprint: text(),
  conflicting_account_id: text(),
  detected_at: integer().notNull(),
});

export const orders = sqliteTable("orders", {
  id: text().primaryKey(),
  account_id: text().notNull(),
  status: text({ enum: ["pending", "ready", "processing", "valid", "invalid"] }).notNull(),
  identifiers: text().notNull(),
  not_before: integer(),
  not_after: integer(),
  replaces_cert_id: text(),
  is_ari_renewal: integer().notNull().default(0),
  created_at: integer().notNull(),
  expires_at: integer().notNull(),
  certificate_id: text(),
  processing_started_at: integer(),
  finalize_generation: integer().notNull().default(0),
}, (t) => [index("idx_orders_account").on(t.account_id)]);

export const authorizations = sqliteTable("authorizations", {
  id: text().primaryKey(),
  order_id: text().notNull(),
  identifier_value: text().notNull(),
  identifier_type: text({ enum: ["dns", "ip"] }).notNull().default("dns"),
  status: text({ enum: ["pending", "valid", "invalid"] }).notNull(),
  token: text().notNull(),
  expires_at: integer().notNull(),
  created_at: integer().notNull(),
}, (t) => [index("idx_authorizations_order").on(t.order_id)]);

export const challenges = sqliteTable("challenges", {
  id: text().primaryKey(),
  authorization_id: text().notNull(),
  type: text({ enum: ["dns-01", "http-01"] }).notNull(),
  token: text().notNull(),
  status: text({ enum: ["pending", "processing", "valid", "invalid"] }).notNull(),
  error: text(),
  validated_at: integer(),
  processing_started_at: integer(),
  validation_generation: integer().notNull().default(0),
  created_at: integer().notNull(),
}, (t) => [
  unique().on(t.authorization_id, t.type),
  index("idx_challenges_authorization").on(t.authorization_id),
]);

export const certificates = sqliteTable("certificates", {
  id: text().primaryKey(),
  cert_id: text().notNull().unique(),
  serial_number: text().notNull(),
  aki: text().notNull(),
  subject: text().notNull(),
  san: text().notNull(),
  pem: text().notNull(),
  not_before: integer().notNull(),
  not_after: integer().notNull(),
  account_id: text().notNull(),
  created_at: integer().notNull(),
  revoked_at: integer(),
  revocation_reason: text(),
  replaced_by_cert_id: text(),
  ca_id: text(),
}, (t) => [index("idx_certificates_serial").on(t.serial_number)]);

export const rateLimits = sqliteTable("rate_limits", {
  key: text().primaryKey(),
  counter: integer().notNull(),
  window_start: integer().notNull(),
});

export const issuanceLedger = sqliteTable("issuance_ledger", {
  certificate_id: text().notNull(),
  bucket_key: text().notNull(),
  issued_at: integer().notNull(),
}, (t) => [
  primaryKey({ columns: [t.certificate_id, t.bucket_key] }),
  index("idx_issuance_ledger_bucket_time").on(t.bucket_key, t.issued_at),
]);

export const securityMigrations = sqliteTable("security_migrations", {
  name: text().primaryKey(),
  completed_at: integer().notNull(),
});
