import { AcmeIdentifier, asIdentifiers } from "../acme/identifiers";
import {
  AccountRow,
  AuthorizationRow,
  CertificateRow,
  ChallengeRow,
  OrderRow,
} from "./types";

export function isUniqueIndexSql(sql: string | null | undefined): boolean {
  return typeof sql === "string" && /^\s*CREATE\s+UNIQUE\s+INDEX\b/i.test(sql);
}

export function isAccountFingerprintIndexSql(
  sql: string | null | undefined
): boolean {
  return (
    isUniqueIndexSql(sql) &&
    typeof sql === "string" &&
    /\bON\s+["`\[]?accounts["`\]]?\s*\(\s*["`\[]?public_key_fingerprint["`\]]?\s*\)\s*;?\s*$/i.test(sql) &&
    // A partial UNIQUE index would not constrain every account.
    !/\bWHERE\b/i.test(sql)
  );
}

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
            public_key_fingerprint TEXT,
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
            certificate_id TEXT,
            processing_started_at INTEGER,
            finalize_generation INTEGER NOT NULL DEFAULT 0
        );
      `),
      this.db.prepare(`
        CREATE TABLE IF NOT EXISTS authorizations (
            id TEXT PRIMARY KEY,
            order_id TEXT NOT NULL,
            identifier_value TEXT NOT NULL,
            identifier_type TEXT NOT NULL DEFAULT 'dns',
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
            replaced_by_cert_id TEXT,
            ca_id TEXT
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

    for (const [table, column, definition] of [
      ["orders", "processing_started_at", "INTEGER"],
      ["orders", "finalize_generation", "INTEGER NOT NULL DEFAULT 0"],
      ["certificates", "ca_id", "TEXT"],
      ["authorizations", "identifier_type", "TEXT NOT NULL DEFAULT 'dns'"],
    ]) {
      const columns = await this.db.prepare(`PRAGMA table_info(${table})`).all<{ name: string }>();
      if (!(columns.results ?? []).some((entry) => entry.name === column)) {
        try { await this.db.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`).run(); }
        catch (error) { if (!/duplicate column name/i.test(String(error))) throw error; }
      }
    }

    try {
      await this.db.prepare("ALTER TABLE accounts ADD COLUMN terms_of_service TEXT;").run();
    } catch {
      // Column may already exist
    }

    // Public key identity index. The column is nullable because legacy rows
    // cannot have their cryptographic fingerprint computed by SQLite; a
    // separate, idempotent application-level migration backfills them.
    try {
      await this.db
        .prepare("ALTER TABLE accounts ADD COLUMN public_key_fingerprint TEXT;")
        .run();
    } catch {
      // Column may already exist
    }

    // Administrator-facing record of legacy keys that could not be indexed.
    // It intentionally stores only account IDs, reason codes, and public
    // fingerprints (public hashes), never JWKs or private key material.
    await this.db
      .prepare(
        `CREATE TABLE IF NOT EXISTS account_key_conflicts (
            account_id TEXT PRIMARY KEY,
            reason TEXT NOT NULL,
            public_key_fingerprint TEXT,
            conflicting_account_id TEXT,
            detected_at INTEGER NOT NULL
        );`
      )
      .run();

    // SQLite permits multiple NULLs in a UNIQUE index, so this index can be
    // created before the legacy backfill and still guarantees that no two
    // accounts are ever assigned the same actual public key.
    try {
      await this.db
        .prepare(
          "CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_public_key_fingerprint ON accounts (public_key_fingerprint);"
        )
        .run();
    } catch {
      // The index is re-checked by ensureAccountPublicKeyIndex() before any
      // operation that depends on account-key identity. Record the failure so
      // an administrator can inspect it instead of silently proceeding.
      try {
        await this.db
          .prepare(
            `INSERT INTO account_key_conflicts
               (account_id, reason, public_key_fingerprint, conflicting_account_id, detected_at)
             VALUES (?, ?, NULL, NULL, ?)
             ON CONFLICT(account_id) DO UPDATE SET
               reason = excluded.reason,
               detected_at = excluded.detected_at`
          )
          .bind(
            "__accounts_public_key_fingerprint_index__",
            "unique_index_creation_failed",
            Math.floor(Date.now() / 1000)
          )
          .run();
      } catch {
        // Surfaced by ensureAccountPublicKeyIndex() as a fail-closed error.
      }
    }

    // An index with the right name may pre-exist without UNIQUE semantics.
    // Record that state rather than assuming the name is enough.
    const fingerprintIndex = await this.accountFingerprintIndexInfo();
    if (!fingerprintIndex || !isAccountFingerprintIndexSql(fingerprintIndex.sql)) {
      try {
        await this.db
          .prepare(
            `INSERT INTO account_key_conflicts
               (account_id, reason, public_key_fingerprint, conflicting_account_id, detected_at)
             VALUES (?, ?, NULL, NULL, ?)
             ON CONFLICT(account_id) DO UPDATE SET
               reason = excluded.reason,
               detected_at = excluded.detected_at`
          )
          .bind(
            "__accounts_public_key_fingerprint_index__",
            "unique_index_missing",
            Math.floor(Date.now() / 1000)
          )
          .run();
      } catch {
        // Surfaced by ensureAccountPublicKeyIndex() as a fail-closed error.
      }
    }

    // Optional partial index that keeps the "is migration complete?" check a
    // cheap existence probe instead of an index-wide IS NULL scan on every
    // newAccount/keyChange/finalize request.
    try {
      await this.db
        .prepare(
          `CREATE INDEX IF NOT EXISTS idx_accounts_missing_public_key_fingerprint
             ON accounts (id) WHERE public_key_fingerprint IS NULL;`
        )
        .run();
    } catch {
      // Not required for correctness; the UNIQUE index also covers IS NULL.
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

  /**
   * Looks up an account by the canonical actual-public-key fingerprint.
   * This is a point lookup through the UNIQUE
   * idx_accounts_public_key_fingerprint index.
   */
  async getAccountByPublicKeyFingerprint(
    fingerprint: string
  ): Promise<AccountRow | null> {
    return await this.db
      .prepare("SELECT * FROM accounts WHERE public_key_fingerprint = ?")
      .bind(fingerprint)
      .first<AccountRow>();
  }

  async accountFingerprintIndexInfo(): Promise<{
    name: string;
    sql: string | null;
  } | null> {
    const row = await this.db
      .prepare(
        "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND name = ? AND tbl_name = 'accounts'"
      )
      .bind("idx_accounts_public_key_fingerprint")
      .first<{ name: string; sql: string | null }>();
    return row ?? null;
  }

  async countAccountsMissingPublicKeyFingerprint(): Promise<number> {
    const row = await this.db
      .prepare(
        "SELECT COUNT(*) AS count FROM accounts WHERE public_key_fingerprint IS NULL"
      )
      .first<{ count: number }>();
    return row?.count ?? 0;
  }

  /**
   * Cheap existence probe used on every key-identity-sensitive request.
   * Backed by the partial idx_accounts_missing_public_key_fingerprint index
   * (or, as a fallback, the UNIQUE fingerprint index).
   */
  async hasAccountsMissingPublicKeyFingerprint(): Promise<boolean> {
    const row = await this.db
      .prepare(
        "SELECT 1 AS present FROM accounts WHERE public_key_fingerprint IS NULL LIMIT 1"
      )
      .first<{ present: number }>();
    return !!row;
  }

  /**
   * Legacy rows that still need a fingerprint and have no recorded conflict.
   * Conflicted rows are left untouched until an administrator resolves them;
   * excluding them keeps repeated migration runs cheap. The UNIQUE index on
   * public_key_fingerprint also serves this IS NULL predicate.
   */
  async listAccountsMissingPublicKeyFingerprint(
    limit: number
  ): Promise<AccountRow[]> {
    const res = await this.db
      .prepare(
        `SELECT * FROM accounts
         WHERE public_key_fingerprint IS NULL
           AND id NOT IN (SELECT account_id FROM account_key_conflicts)
         ORDER BY created_at, id
         LIMIT ?`
      )
      .bind(limit)
      .all<AccountRow>();
    return res.results || [];
  }

  /** Assigns a fingerprint only while the row is still un-migrated. */
  async setAccountPublicKeyFingerprint(
    id: string,
    fingerprint: string
  ): Promise<boolean> {
    const res = await this.db
      .prepare(
        `UPDATE accounts
         SET public_key_fingerprint = ?
         WHERE id = ? AND public_key_fingerprint IS NULL`
      )
      .bind(fingerprint, id)
      .run();
    return (res.meta?.changes ?? 0) > 0;
  }

  async recordAccountKeyConflict(conflict: {
    account_id: string;
    reason: string;
    public_key_fingerprint: string | null;
    conflicting_account_id: string | null;
    detected_at: number;
  }): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO account_key_conflicts
           (account_id, reason, public_key_fingerprint, conflicting_account_id, detected_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(account_id) DO UPDATE SET
           reason = excluded.reason,
           public_key_fingerprint = excluded.public_key_fingerprint,
           conflicting_account_id = excluded.conflicting_account_id,
           detected_at = excluded.detected_at`
      )
      .bind(
        conflict.account_id,
        conflict.reason,
        conflict.public_key_fingerprint,
        conflict.conflicting_account_id,
        conflict.detected_at
      )
      .run();
  }

  async listAccountKeyConflicts(limit = 100): Promise<
    Array<{
      account_id: string;
      reason: string;
      public_key_fingerprint: string | null;
      conflicting_account_id: string | null;
      detected_at: number;
    }>
  > {
    const res = await this.db
      .prepare(
        `SELECT account_id, reason, public_key_fingerprint,
                conflicting_account_id, detected_at
         FROM account_key_conflicts
         ORDER BY detected_at, account_id
         LIMIT ?`
      )
      .bind(limit)
      .all<{
        account_id: string;
        reason: string;
        public_key_fingerprint: string | null;
        conflicting_account_id: string | null;
        detected_at: number;
      }>();
    return res.results || [];
  }

  async clearAccountKeyConflict(accountId: string): Promise<void> {
    await this.db
      .prepare("DELETE FROM account_key_conflicts WHERE account_id = ?")
      .bind(accountId)
      .run();
  }

  async saveAccount(account: AccountRow): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO accounts
           (id, jwk, thumbprint, public_key_fingerprint, contact, status, created_at, terms_of_service)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        account.id,
        account.jwk,
        account.thumbprint,
        account.public_key_fingerprint ?? null,
        account.contact,
        account.status,
        account.created_at,
        account.terms_of_service ?? null
      )
      .run();
  }

  /**
   * Compare-and-swap rotation of an account key.
   *
   * The WHERE clause is keyed on the previously read thumbprint, so two
   * concurrent keyChange requests cannot both win. The UNIQUE index on
   * public_key_fingerprint is the final protection against reusing another
   * account's actual key.
   */
  async updateAccountKey(
    id: string,
    expectedThumbprint: string,
    update: {
      jwk: string;
      thumbprint: string;
      publicKeyFingerprint: string;
    }
  ): Promise<boolean> {
    const res = await this.db
      .prepare(
        `UPDATE accounts
         SET jwk = ?, thumbprint = ?, public_key_fingerprint = ?
         WHERE id = ? AND thumbprint = ? AND status = 'valid'`
      )
      .bind(
        update.jwk,
        update.thumbprint,
        update.publicKeyFingerprint,
        id,
        expectedThumbprint
      )
      .run();
    return (res.meta?.changes ?? 0) > 0;
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
        "INSERT INTO authorizations (id, order_id, identifier_value, identifier_type, status, token, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
      )
      .bind(
        authz.id,
        authz.order_id,
        authz.identifier_value,
        authz.identifier_type ?? "dns",
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
  async claimOrderForFinalize(orderId: string, now = Math.floor(Date.now() / 1000)): Promise<number | null> {
    const row = await this.db.prepare(
      `UPDATE orders SET status = 'processing', processing_started_at = ?, finalize_generation = finalize_generation + 1
       WHERE id = ? AND expires_at > ? AND (status = 'ready' OR (status = 'processing' AND COALESCE(processing_started_at, 0) < ?))
       RETURNING finalize_generation`
    ).bind(now, orderId, now, now - 60).first<{ finalize_generation: number }>();
    return row?.finalize_generation ?? null;
  }

  async releaseOrderFromProcessing(orderId: string, generation: number): Promise<void> {
    await this.db.prepare(
      `UPDATE orders SET status = 'ready', processing_started_at = NULL
       WHERE id = ? AND status = 'processing' AND finalize_generation = ? AND certificate_id IS NULL`
    ).bind(orderId, generation).run();
  }

  async invalidateFinalizeClaim(orderId: string, generation: number): Promise<void> {
    await this.db.prepare("UPDATE orders SET status = 'invalid' WHERE id = ? AND status = 'processing' AND finalize_generation = ?")
      .bind(orderId, generation).run();
  }

  /** All three writes share D1's batch transaction and the INSERT's fenced guard. */
  async completeOrder(orderId: string, generation: number, cert: CertificateRow, predecessor: string | null, now: number): Promise<boolean> {
    const results = await this.db.batch([
      this.db.prepare(
        `INSERT INTO certificates (id, cert_id, serial_number, aki, subject, san, pem, not_before, not_after,
          account_id, created_at, revoked_at, revocation_reason, replaced_by_cert_id, ca_id)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?
         WHERE EXISTS (SELECT 1 FROM orders o JOIN accounts a ON a.id = o.account_id
           WHERE o.id = ? AND o.status = 'processing' AND o.finalize_generation = ?
           AND o.processing_started_at > ? AND o.expires_at > ? AND a.status = 'valid')
         AND EXISTS (SELECT 1 FROM authorizations WHERE order_id = ?)
         AND NOT EXISTS (SELECT 1 FROM authorizations WHERE order_id = ? AND (status != 'valid' OR expires_at <= ?))
         AND (? IS NULL OR EXISTS (SELECT 1 FROM certificates WHERE cert_id = ? AND replaced_by_cert_id IS NULL))`
      ).bind(cert.id, cert.cert_id, cert.serial_number, cert.aki, cert.subject, cert.san, cert.pem,
        cert.not_before, cert.not_after, cert.account_id, cert.created_at, cert.ca_id ?? null,
        orderId, generation, now - 60, now, orderId, orderId, now, predecessor, predecessor),
      this.db.prepare(
        `UPDATE certificates SET replaced_by_cert_id = ? WHERE cert_id = ? AND replaced_by_cert_id IS NULL
         AND EXISTS (SELECT 1 FROM certificates WHERE id = ?)`
      ).bind(cert.cert_id, predecessor, cert.id),
      this.db.prepare(
        `UPDATE orders SET status = 'valid', certificate_id = ?, processing_started_at = NULL
         WHERE id = ? AND finalize_generation = ? AND status = 'processing'
         AND EXISTS (SELECT 1 FROM certificates WHERE id = ?)`
      ).bind(cert.id, orderId, generation, cert.id),
    ]);
    return (results[0].meta?.changes ?? 0) === 1 && (results[2].meta?.changes ?? 0) === 1;
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
          not_before, not_after, account_id, created_at, revoked_at, revocation_reason, replaced_by_cert_id, ca_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
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
        cert.replaced_by_cert_id,
        cert.ca_id ?? null
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

  async revokeCertificate(
    certId: string,
    revokedAt: number,
    reason: string
  ): Promise<boolean> {
    const result = await this.db
      .prepare(
        "UPDATE certificates SET revoked_at = ?, revocation_reason = ? WHERE cert_id = ? AND revoked_at IS NULL"
      )
      .bind(revokedAt, reason, certId)
      .run();
    return (result.meta?.changes ?? 0) === 1;
  }

  async accountHasValidAuthorizations(accountId: string, domains: (string | AcmeIdentifier)[], now: number): Promise<boolean> {
    for (const domain of asIdentifiers(domains)) {
      const row = await this.db.prepare(
        `SELECT a.id FROM authorizations a JOIN orders o ON o.id = a.order_id
         WHERE o.account_id = ? AND a.identifier_value = ? AND a.identifier_type = ? AND a.status = 'valid' AND a.expires_at > ? LIMIT 1`
      ).bind(accountId, domain.value, domain.type, now).first();
      if (!row) return false;
    }
    return true;
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
