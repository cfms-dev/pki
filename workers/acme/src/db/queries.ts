import {
  AccountRow,
  AuthorizationRow,
  CertificateRow,
  ChallengeRow,
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
        CREATE TABLE IF NOT EXISTS challenges (
            id TEXT PRIMARY KEY,
            authorization_id TEXT NOT NULL,
            type TEXT NOT NULL,
            token TEXT NOT NULL,
            status TEXT NOT NULL,
            error TEXT,
            validated_at INTEGER,
            processing_started_at INTEGER,
            validation_generation INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            UNIQUE (authorization_id, type)
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
      this.db.prepare(`CREATE INDEX IF NOT EXISTS idx_challenges_authorization ON challenges (authorization_id);`),
      // cert_id is UNIQUE, so SQLite already maintains an implicit index for it.
      this.db.prepare(`DROP INDEX IF EXISTS idx_certificates_cert_id;`),
      this.db.prepare(`CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates (serial_number);`),
    ]);

    try {
      await this.db.prepare("ALTER TABLE accounts ADD COLUMN terms_of_service TEXT;").run();
    } catch {
      // Column may already exist
    }

    // Upgrade a `challenges` table that was created before validation
    // generations were introduced. Fresh databases already have the column
    // from the CREATE TABLE statement above, in which case this ALTER fails
    // harmlessly with "duplicate column name".
    try {
      await this.db
        .prepare(
          "ALTER TABLE challenges ADD COLUMN validation_generation INTEGER NOT NULL DEFAULT 0;"
        )
        .run();
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

  async updateAuthorizationStatusIfPending(
    id: string,
    status: AuthorizationRow["status"]
  ): Promise<boolean> {
    const res = await this.db
      .prepare("UPDATE authorizations SET status = ? WHERE id = ? AND status = 'pending'")
      .bind(status, id)
      .run();
    return (res.meta?.changes ?? 0) > 0;
  }

  // --- Challenge Operations ---
  async saveChallenge(challenge: ChallengeRow): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO challenges (id, authorization_id, type, token, status, error,
          validated_at, processing_started_at, validation_generation, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        challenge.id,
        challenge.authorization_id,
        challenge.type,
        challenge.token,
        challenge.status,
        challenge.error,
        challenge.validated_at,
        challenge.processing_started_at,
        challenge.validation_generation,
        challenge.created_at
      )
      .run();
  }

  /** Inserts a challenge unless the (authorization, type) pair already exists. */
  async saveChallengeIfAbsent(challenge: ChallengeRow): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR IGNORE INTO challenges (id, authorization_id, type, token, status, error,
          validated_at, processing_started_at, validation_generation, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        challenge.id,
        challenge.authorization_id,
        challenge.type,
        challenge.token,
        challenge.status,
        challenge.error,
        challenge.validated_at,
        challenge.processing_started_at,
        challenge.validation_generation,
        challenge.created_at
      )
      .run();
  }

  async getChallengeById(id: string): Promise<ChallengeRow | null> {
    return await this.db
      .prepare("SELECT * FROM challenges WHERE id = ?")
      .bind(id)
      .first<ChallengeRow>();
  }

  async getChallengesByAuthorizationId(authorizationId: string): Promise<ChallengeRow[]> {
    const res = await this.db
      .prepare(
        `SELECT * FROM challenges
         WHERE authorization_id = ?
         ORDER BY CASE type WHEN 'dns-01' THEN 0 ELSE 1 END, created_at, id`
      )
      .bind(authorizationId)
      .all<ChallengeRow>();
    return res.results || [];
  }

  /**
   * Atomically moves a pending challenge into `processing` and increments its
   * validation generation. A stale `processing` row (for example after an
   * isolate crash) can be reclaimed after `staleBefore`, ensuring validations
   * cannot remain stuck forever. The returned generation must be passed to the
   * completion methods; only the current generation may change the row.
   */
  async claimChallengeForValidation(
    id: string,
    now: number,
    staleBefore: number
  ): Promise<number | null> {
    const row = await this.db
      .prepare(
        `UPDATE challenges
         SET status = 'processing',
             processing_started_at = ?,
             error = NULL,
             validation_generation = COALESCE(validation_generation, 0) + 1
         WHERE id = ?
           AND (status = 'pending'
                OR (status = 'processing'
                    AND (processing_started_at IS NULL OR processing_started_at < ?)))
         RETURNING validation_generation`
      )
      .bind(now, id, staleBefore)
      .first<{ validation_generation: number }>();
    return row?.validation_generation ?? null;
  }

  /**
   * Records a successful validation and advances the authorization/order state.
   * Returns false when another request already completed this challenge or when
   * this attempt's claim was reclaimed by a newer generation.
   */
  async completeChallengeValidationSuccess(
    challengeId: string,
    validationGeneration: number,
    authorizationId: string,
    orderId: string,
    validatedAt: number
  ): Promise<boolean> {
    const res = await this.db
      .prepare(
        `UPDATE challenges
         SET status = 'valid', error = NULL, validated_at = ?, processing_started_at = NULL
         WHERE id = ? AND status = 'processing' AND validation_generation = ?
           AND EXISTS (
             SELECT 1 FROM authorizations
             WHERE id = ? AND status IN ('pending', 'valid')
           )`
      )
      .bind(validatedAt, challengeId, validationGeneration, authorizationId)
      .run();
    if ((res.meta?.changes ?? 0) === 0) {
      return false;
    }

    await this.updateAuthorizationStatusIfPending(authorizationId, "valid");
    await this.markOrderReadyIfAllAuthorizationsValid(orderId);
    return true;
  }

  /**
   * Records a failed validation and invalidates the authorization, its other
   * pending challenges, and any open order so no certificate can be issued.
   * Returns false when the attempt is no longer the current generation.
   */
  async completeChallengeValidationFailure(
    challengeId: string,
    validationGeneration: number,
    authorizationId: string,
    orderId: string,
    errorJson: string
  ): Promise<boolean> {
    const res = await this.db
      .prepare(
        `UPDATE challenges
         SET status = 'invalid', error = ?, validated_at = NULL, processing_started_at = NULL
         WHERE id = ? AND status = 'processing' AND validation_generation = ?`
      )
      .bind(errorJson, challengeId, validationGeneration)
      .run();
    if ((res.meta?.changes ?? 0) === 0) {
      return false;
    }

    // Another challenge may already have made the authorization valid. In that
    // case the failed challenge is recorded but must not invalidate a valid
    // authorization or order.
    const authzInvalidated = await this.updateAuthorizationStatusIfPending(
      authorizationId,
      "invalid"
    );
    if (authzInvalidated) {
      await this.db
        .prepare(
          `UPDATE challenges
           SET status = 'invalid', error = ?, processing_started_at = NULL
           WHERE authorization_id = ? AND id <> ? AND status IN ('pending', 'processing')`
        )
        .bind(errorJson, authorizationId, challengeId)
        .run();
      await this.invalidateOpenOrder(orderId);
    }
    return true;
  }

  async invalidatePendingChallengesForAuthorization(
    authorizationId: string,
    errorJson: string
  ): Promise<void> {
    await this.db
      .prepare(
        `UPDATE challenges
         SET status = 'invalid', error = ?, processing_started_at = NULL
         WHERE authorization_id = ? AND status IN ('pending', 'processing')`
      )
      .bind(errorJson, authorizationId)
      .run();
  }

  async invalidateChallenge(challengeId: string, errorJson: string): Promise<boolean> {
    const res = await this.db
      .prepare(
        `UPDATE challenges
         SET status = 'invalid', error = ?, processing_started_at = NULL
         WHERE id = ? AND status IN ('pending', 'processing')`
      )
      .bind(errorJson, challengeId)
      .run();
    return (res.meta?.changes ?? 0) > 0;
  }

  async markOrderReadyIfAllAuthorizationsValid(orderId: string): Promise<void> {
    await this.db
      .prepare(
        `UPDATE orders
         SET status = 'ready'
         WHERE id = ? AND status = 'pending'
           AND EXISTS (SELECT 1 FROM authorizations WHERE order_id = ?)
           AND NOT EXISTS (
             SELECT 1 FROM authorizations WHERE order_id = ? AND status <> 'valid'
           )`
      )
      .bind(orderId, orderId, orderId)
      .run();
  }

  async invalidateOpenOrder(orderId: string): Promise<void> {
    await this.db
      .prepare(
        `UPDATE orders SET status = 'invalid'
         WHERE id = ? AND status IN ('pending', 'ready')`
      )
      .bind(orderId)
      .run();
  }

  /**
   * Atomically claims a ready order for issuance so concurrent finalize
   * requests cannot both sign a certificate.
   */
  async claimOrderForFinalize(orderId: string): Promise<boolean> {
    const res = await this.db
      .prepare("UPDATE orders SET status = 'processing' WHERE id = ? AND status = 'ready'")
      .bind(orderId)
      .run();
    return (res.meta?.changes ?? 0) > 0;
  }

  async releaseOrderFromProcessing(orderId: string): Promise<void> {
    await this.db
      .prepare(
        "UPDATE orders SET status = 'ready' WHERE id = ? AND status = 'processing' AND certificate_id IS NULL"
      )
      .bind(orderId)
      .run();
  }

  /** Returns the challenge types that successfully validated each order identifier. */
  async getValidChallengeTypesByOrderId(
    orderId: string
  ): Promise<Array<{ identifier_value: string; type: string }>> {
    const res = await this.db
      .prepare(
        `SELECT a.identifier_value AS identifier_value, c.type AS type
         FROM authorizations a
         JOIN challenges c ON c.authorization_id = a.id
         WHERE a.order_id = ? AND a.status = 'valid' AND c.status = 'valid'`
      )
      .bind(orderId)
      .all<{ identifier_value: string; type: string }>();
    return res.results || [];
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
  async getRateLimitCounter(
    key: string,
    windowSeconds: number,
    now: number
  ): Promise<number> {
    const row = await this.db
      .prepare("SELECT counter, window_start FROM rate_limits WHERE key = ?")
      .bind(key)
      .first<{ counter: number; window_start: number }>();
    if (!row) return 0;
    if (now - row.window_start >= windowSeconds) return 0;
    return row.counter;
  }

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
