-- Cloudflare D1 SQLite Schema for CFMS-PKI ACME Server

CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    jwk TEXT NOT NULL,
    thumbprint TEXT UNIQUE NOT NULL,
    contact TEXT,
    status TEXT NOT NULL, -- 'valid', 'deactivated', 'revoked'
    created_at INTEGER NOT NULL
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
    certificate_id TEXT
);

CREATE TABLE IF NOT EXISTS authorizations (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL,
    identifier_value TEXT NOT NULL,
    status TEXT NOT NULL, -- 'pending', 'valid', 'invalid'
    token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
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
    replaced_by_cert_id TEXT
);

CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    counter INTEGER NOT NULL,
    window_start INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_orders_account ON orders (account_id);
CREATE INDEX IF NOT EXISTS idx_authorizations_order ON authorizations (order_id);
CREATE INDEX IF NOT EXISTS idx_certificates_cert_id ON certificates (cert_id);
CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates (serial_number);
