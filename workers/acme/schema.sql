-- Cloudflare D1 SQLite Schema for CFMS-PKI ACME Server

CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    jwk TEXT NOT NULL,
    thumbprint TEXT UNIQUE NOT NULL,
    public_key_fingerprint TEXT, -- base64url(SHA-256(canonical SPKI DER)); NULL only for un-migrated legacy rows
    contact TEXT,
    status TEXT NOT NULL, -- 'valid', 'deactivated', 'revoked'
    created_at INTEGER NOT NULL,
    terms_of_service TEXT
);

-- SQLite UNIQUE indexes permit multiple NULLs, so this can be created before
-- the legacy fingerprint backfill runs. It is the authoritative concurrency
-- guard against registering the same actual public key twice.
CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_public_key_fingerprint
    ON accounts (public_key_fingerprint);

-- Keeps the per-request "is the legacy backfill complete?" probe cheap.
CREATE INDEX IF NOT EXISTS idx_accounts_missing_public_key_fingerprint
    ON accounts (id) WHERE public_key_fingerprint IS NULL;

-- Administrator-facing record of legacy accounts that could not be indexed
-- (invalid JWK or a duplicated actual public key). No private key material is
-- stored here.
CREATE TABLE IF NOT EXISTS account_key_conflicts (
    account_id TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    public_key_fingerprint TEXT,
    conflicting_account_id TEXT,
    detected_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    status TEXT NOT NULL, -- 'pending', 'ready', 'processing', 'valid', 'invalid'
    identifiers TEXT NOT NULL, -- JSON array of domain names: ["example.com", "*.example.com"]
    not_before INTEGER,
    not_after INTEGER,
    replaces_cert_id TEXT, -- RFC 9773 predecessor certID
    is_ari_renewal INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    certificate_id TEXT,
    processing_started_at INTEGER,
    finalize_generation INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS authorizations (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL,
    identifier_value TEXT NOT NULL,
    status TEXT NOT NULL, -- 'pending', 'valid', 'invalid'
    token TEXT NOT NULL, -- legacy dns-01 token; mirrored into challenges.token
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    authorization_id TEXT NOT NULL,
    type TEXT NOT NULL, -- 'dns-01', 'http-01'
    token TEXT NOT NULL,
    status TEXT NOT NULL, -- 'pending', 'processing', 'valid', 'invalid'
    error TEXT, -- JSON-encoded ACME problem document
    validated_at INTEGER,
    processing_started_at INTEGER,
    validation_generation INTEGER NOT NULL DEFAULT 0, -- fences stale processing attempts
    created_at INTEGER NOT NULL,
    UNIQUE (authorization_id, type)
);

CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    cert_id TEXT UNIQUE NOT NULL, -- RFC 9773: Base64URL(AKI) + "." + Base64URL(Serial)
    serial_number TEXT NOT NULL,
    aki TEXT NOT NULL,
    subject TEXT NOT NULL,
    san TEXT NOT NULL, -- JSON array of domains
    pem TEXT NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    account_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revocation_reason TEXT,
    replaced_by_cert_id TEXT,
    ca_id TEXT
);

CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    counter INTEGER NOT NULL,
    window_start INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_orders_account ON orders (account_id);
CREATE INDEX IF NOT EXISTS idx_authorizations_order ON authorizations (order_id);
CREATE INDEX IF NOT EXISTS idx_challenges_authorization ON challenges (authorization_id);
CREATE INDEX IF NOT EXISTS idx_certificates_cert_id ON certificates (cert_id);
CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates (serial_number);

-- Successful-issuance accounting; old order counters are not migrated.
CREATE TABLE IF NOT EXISTS issuance_ledger (
    certificate_id TEXT NOT NULL,
    bucket_key TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    PRIMARY KEY (certificate_id, bucket_key)
);
CREATE INDEX IF NOT EXISTS idx_issuance_ledger_bucket_time ON issuance_ledger (bucket_key, issued_at);
CREATE TABLE IF NOT EXISTS security_migrations (name TEXT PRIMARY KEY, completed_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_nonces_expiry ON nonces (expires_at);
INSERT OR IGNORE INTO security_migrations (name, completed_at)
    SELECT 'issuance-ledger-v1', unixepoch() WHERE NOT EXISTS (SELECT 1 FROM certificates);
