import {
  AccountRow,
  AuthorizationRow,
  CertificateRow,
  NonceRow,
  OrderRow,
  RateLimitRow,
} from "./types";

export class Database {
  constructor(private db: D1Database) {}

  async initSchema(): Promise<void> {
    await this.db.batch([
      this.db.prepare(`
        CREATE TABLE IF NOT EXISTS nonces (
            nonce TEXT PRIMARY KEY,
            expires_at INTEGER NOT NULL
        );
      `),
      this.db.prepare(`
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            jwk TEXT NOT NULL,
            thumbprint TEXT UNIQUE NOT NULL,
            contact TEXT,
            status TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
      `),
      this.db.prepare(`
        CREATE TABLE IF NOT EXISTS orders (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            status TEXT NOT NULL,
            identifiers TEXT NOT NULL,
            not_before INTEGER,
            not_after INTEGER,
            replaces_cert_id TEXT,
            is_ari_renewal INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            certificate_id TEXT
        );
      `),
      this.db.prepare(`
        CREATE TABLE IF NOT EXISTS authorizations (
            id TEXT PRIMARY KEY,
            order_id TEXT NOT NULL,
            identifier_value TEXT NOT NULL,
            status TEXT NOT NULL,
            token TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
      `),
      this.db.prepare(`
        CREATE TABLE IF NOT EXISTS certificates (
            id TEXT PRIMARY KEY,
            cert_id TEXT UNIQUE NOT NULL,
            serial_number TEXT NOT NULL,
            aki TEXT NOT NULL,
            subject TEXT NOT NULL,
            san TEXT NOT NULL,
            pem TEXT NOT NULL,
            not_before INTEGER NOT NULL,
            not_after INTEGER NOT NULL,
            account_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            revoked_at INTEGER,
            revocation_reason TEXT,
            replaced_by_cert_id TEXT
        );
      `),
      this.db.prepare(`
        CREATE TABLE IF NOT EXISTS rate_limits (
            key TEXT PRIMARY KEY,
            counter INTEGER NOT NULL,
            window_start INTEGER NOT NULL
        );
      `),
      this.db.prepare(`CREATE INDEX IF NOT EXISTS idx_orders_account ON orders (account_id);`),
      this.db.prepare(`CREATE INDEX IF NOT EXISTS idx_authorizations_order ON authorizations (order_id);`),
      this.db.prepare(`CREATE INDEX IF NOT EXISTS idx_certificates_cert_id ON certificates (cert_id);`),
      this.db.prepare(`CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates (serial_number);`),
    ]);
  }

  // --- Nonce Operations ---
  async saveNonce(nonce: string, expiresAt: number): Promise<void> {
    await this.db
      .prepare("INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)")
      .bind(nonce, expiresAt)
      .run();
  }

  async consumeNonce(nonce: string, now: number): Promise<boolean> {
    // Delete valid, unexpired nonce atomically
    const res = await this.db
      .prepare("DELETE FROM nonces WHERE nonce = ? AND expires_at > ?")
      .bind(nonce, now)
      .run();
    return (res.meta?.changes ?? 0) > 0;
  }

  // --- Account Operations ---
  async getAccountById(id: string): Promise<AccountRow | null> {
    return await this.db
      .prepare("SELECT * FROM accounts WHERE id = ?")
      .bind(id)
      .first<AccountRow>();
  }

  async getAccountByThumbprint(thumbprint: string): Promise<AccountRow | null> {
    return await this.db
      .prepare("SELECT * FROM accounts WHERE thumbprint = ?")
      .bind(thumbprint)
      .first<AccountRow>();
  }

  async saveAccount(account: AccountRow): Promise<void> {
    await this.db
      .prepare(
        "INSERT INTO accounts (id, jwk, thumbprint, contact, status, created_at) VALUES (?, ?, ?, ?, ?, ?)"
      )
      .bind(
        account.id,
        account.jwk,
        account.thumbprint,
        account.contact,
        account.status,
        account.created_at
      )
      .run();
  }

  async updateAccount(
    id: string,
    updates: { contact?: string | null; status?: "valid" | "deactivated" | "revoked" }
  ): Promise<void> {
    const fields: string[] = [];
    const values: unknown[] = [];
    if (updates.contact !== undefined) {
      fields.push("contact = ?");
      values.push(updates.contact);
    }
    if (updates.status !== undefined) {
      fields.push("status = ?");
      values.push(updates.status);
    }
    if (fields.length === 0) return;
    values.push(id);
    await this.db
      .prepare(`UPDATE accounts SET ${fields.join(", ")} WHERE id = ?`)
      .bind(...values)
      .run();
  }

  // --- Order Operations ---
  async saveOrder(order: OrderRow): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO orders (id, account_id, status, identifiers, not_before, not_after,
          replaces_cert_id, is_ari_renewal, created_at, expires_at, certificate_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        order.id,
        order.account_id,
        order.status,
        order.identifiers,
        order.not_before,
        order.not_after,
        order.replaces_cert_id,
        order.is_ari_renewal,
        order.created_at,
        order.expires_at,
        order.certificate_id
      )
      .run();
  }

  async getOrderById(id: string): Promise<OrderRow | null> {
    return await this.db
      .prepare("SELECT * FROM orders WHERE id = ?")
      .bind(id)
      .first<OrderRow>();
  }

  async updateOrderStatus(
    id: string,
    status: OrderRow["status"],
    certificateId: string | null = null
  ): Promise<void> {
    if (certificateId !== null) {
      await this.db
        .prepare("UPDATE orders SET status = ?, certificate_id = ? WHERE id = ?")
        .bind(status, certificateId, id)
        .run();
    } else {
      await this.db
        .prepare("UPDATE orders SET status = ? WHERE id = ?")
        .bind(status, id)
        .run();
    }
  }

  // --- Authorization Operations ---
  async saveAuthorization(authz: AuthorizationRow): Promise<void> {
    await this.db
      .prepare(
        "INSERT INTO authorizations (id, order_id, identifier_value, status, token, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
      )
      .bind(
        authz.id,
        authz.order_id,
        authz.identifier_value,
        authz.status,
        authz.token,
        authz.expires_at,
        authz.created_at
      )
      .run();
  }

  async getAuthorizationById(id: string): Promise<AuthorizationRow | null> {
    return await this.db
      .prepare("SELECT * FROM authorizations WHERE id = ?")
      .bind(id)
      .first<AuthorizationRow>();
  }

  async getAuthorizationsByOrderId(orderId: string): Promise<AuthorizationRow[]> {
    const res = await this.db
      .prepare("SELECT * FROM authorizations WHERE order_id = ?")
      .bind(orderId)
      .all<AuthorizationRow>();
    return res.results || [];
  }

  async updateAuthorizationStatus(id: string, status: AuthorizationRow["status"]): Promise<void> {
    await this.db
      .prepare("UPDATE authorizations SET status = ? WHERE id = ?")
      .bind(status, id)
      .run();
  }

  // --- Certificate Operations ---
  async saveCertificate(cert: CertificateRow): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO certificates (id, cert_id, serial_number, aki, subject, san, pem,
          not_before, not_after, account_id, created_at, revoked_at, revocation_reason, replaced_by_cert_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        cert.id,
        cert.cert_id,
        cert.serial_number,
        cert.aki,
        cert.subject,
        cert.san,
        cert.pem,
        cert.not_before,
        cert.not_after,
        cert.account_id,
        cert.created_at,
        cert.revoked_at,
        cert.revocation_reason,
        cert.replaced_by_cert_id
      )
      .run();
  }

  async getCertificateById(id: string): Promise<CertificateRow | null> {
    return await this.db
      .prepare("SELECT * FROM certificates WHERE id = ?")
      .bind(id)
      .first<CertificateRow>();
  }

  async getCertificateByCertId(certId: string): Promise<CertificateRow | null> {
    return await this.db
      .prepare("SELECT * FROM certificates WHERE cert_id = ?")
      .bind(certId)
      .first<CertificateRow>();
  }

  async getCertificateBySerial(serial: string): Promise<CertificateRow | null> {
    return await this.db
      .prepare("SELECT * FROM certificates WHERE serial_number = ?")
      .bind(serial)
      .first<CertificateRow>();
  }

  async findMatchingCertificate(domains: string[]): Promise<CertificateRow | null> {
    const sorted = JSON.stringify(domains.slice().sort());
    return await this.db
      .prepare(
        "SELECT * FROM certificates WHERE san = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1"
      )
      .bind(sorted)
      .first<CertificateRow>();
  }

  async markCertificateReplaced(certId: string, newCertId: string): Promise<void> {
    await this.db
      .prepare("UPDATE certificates SET replaced_by_cert_id = ? WHERE cert_id = ?")
      .bind(newCertId, certId)
      .run();
  }

  async revokeCertificate(
    certId: string,
    revokedAt: number,
    reason: string
  ): Promise<void> {
    await this.db
      .prepare(
        "UPDATE certificates SET revoked_at = ?, revocation_reason = ? WHERE cert_id = ?"
      )
      .bind(revokedAt, reason, certId)
      .run();
  }

  // --- Rate Limit Operations ---
  async checkAndIncrementRateLimit(
    key: string,
    limit: number,
    windowSeconds: number,
    now: number
  ): Promise<{ allowed: boolean; remaining: number }> {
    const existing = await this.db
      .prepare("SELECT * FROM rate_limits WHERE key = ?")
      .bind(key)
      .first<RateLimitRow>();

    if (!existing || now - existing.window_start >= windowSeconds) {
      await this.db
        .prepare(
          "INSERT OR REPLACE INTO rate_limits (key, counter, window_start) VALUES (?, 1, ?)"
        )
        .bind(key, now)
        .run();
      return { allowed: true, remaining: limit - 1 };
    }

    if (existing.counter >= limit) {
      return { allowed: false, remaining: 0 };
    }

    await this.db
      .prepare("UPDATE rate_limits SET counter = counter + 1 WHERE key = ?")
      .bind(key)
      .run();

    return { allowed: true, remaining: limit - (existing.counter + 1) };
  }
}
