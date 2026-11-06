import {
  AccountRow,
  AuthorizationRow,
  CertificateRow,
  OrderRow,
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
            created_at INTEGER NOT NULL,
            terms_of_service TEXT
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
      // cert_id is UNIQUE, so SQLite already maintains an implicit index for it.
      this.db.prepare(`DROP INDEX IF EXISTS idx_certificates_cert_id;`),
      this.db.prepare(`CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates (serial_number);`),
    ]);

    try {
      await this.db.prepare("ALTER TABLE accounts ADD COLUMN terms_of_service TEXT;").run();
    } catch {
      // Column may already exist
    }
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
        "INSERT INTO accounts (id, jwk, thumbprint, contact, status, created_at, terms_of_service) VALUES (?, ?, ?, ?, ?, ?, ?)"
      )
      .bind(
        account.id,
        account.jwk,
        account.thumbprint,
        account.contact,
        account.status,
        account.created_at,
        account.terms_of_service ?? null
      )
      .run();
  }

  async updateAccount(
    id: string,
    updates: {
      contact?: string | null;
      status?: "valid" | "deactivated" | "revoked";
      terms_of_service?: string | null;
    }
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
    if (updates.terms_of_service !== undefined) {
      fields.push("terms_of_service = ?");
      values.push(updates.terms_of_service);
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
    // Single atomic statement: reset the window, increment, or leave the
    // counter at limit + 1 to mark a rejected attempt.
    const row = await this.db
      .prepare(
        `INSERT INTO rate_limits (key, counter, window_start)
         VALUES (?, 1, ?)
         ON CONFLICT(key) DO UPDATE SET
           counter = CASE
             WHEN excluded.window_start - rate_limits.window_start >= ? THEN 1
             WHEN rate_limits.counter < ? THEN rate_limits.counter + 1
             ELSE MAX(rate_limits.counter, ? + 1)
           END,
           window_start = CASE
             WHEN excluded.window_start - rate_limits.window_start >= ? THEN excluded.window_start
             ELSE rate_limits.window_start
           END
         RETURNING counter`
      )
      .bind(key, now, windowSeconds, limit, limit, windowSeconds)
      .first<{ counter: number }>();

    const counter = row?.counter ?? 1;
    return {
      allowed: counter <= limit,
      remaining: Math.max(0, limit - counter),
    };
  }
}
