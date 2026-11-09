import { and, count, eq, gt, inArray, isNull, notInArray, sql } from "drizzle-orm";
import { drizzle, type DrizzleD1Database } from "drizzle-orm/d1";
import * as schema from "./schema";
import type { AccountInsert, AccountKeyConflictInsert, AccountKeyConflictRow, AuthorizationInsert,
  CertificateInsert, ChallengeInsert, OrderInsert } from "./types";
import { AcmeIdentifier, asIdentifiers, readIdentifiers } from "../acme/identifiers";
import { AcmeError } from "../errors";
import { IssuanceBucket, issuanceBuckets } from "../ratelimit/issuance";
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
  private readonly db: DrizzleD1Database<typeof schema>;

  constructor(binding: D1Database) {
    this.db = drizzle(binding, { schema, logger: false });
  }

  // --- Nonce Operations ---
  async saveNonce(nonce: string, expiresAt: number): Promise<void> {
    await this.db.insert(schema.nonces).values({ nonce, expires_at: expiresAt }).run();
  }

  async consumeNonce(nonce: string, now: number): Promise<boolean> {
    const result = await this.db.delete(schema.nonces)
      .where(and(eq(schema.nonces.nonce, nonce), gt(schema.nonces.expires_at, now))).run();
    return (result.meta.changes ?? 0) > 0;
  }

  /** Bounded, index-backed cleanup; safe to repeat or run alongside consumption. */
  async cleanupExpiredNonces(now = Math.floor(Date.now() / 1000), maxBatches = 100): Promise<{ deleted: number; backlog: boolean }> {
    if (!Number.isSafeInteger(maxBatches) || maxBatches < 1 || maxBatches > 100) throw new Error("Invalid cleanup batch count");
    let deleted = 0;
    for (let batch = 0; batch < maxBatches; batch++) {
      const result = await this.db.run(sql`DELETE FROM nonces WHERE nonce IN
        (SELECT nonce FROM nonces WHERE expires_at <= ${now} ORDER BY expires_at LIMIT 1000)`);
      const count = result.meta?.changes ?? 0;
      deleted += count;
      if (count < 1000) return { deleted, backlog: false };
    }
    const backlog = await this.db.get(sql`SELECT 1 FROM nonces WHERE expires_at <= ${now} LIMIT 1`);
    return { deleted, backlog: !!backlog };
  }

  async ensureIssuanceLedgerReady(): Promise<void> {
    const ready = await this.db.select({ name: schema.securityMigrations.name }).from(schema.securityMigrations)
      .where(eq(schema.securityMigrations.name, "issuance-ledger-v1")).get();
    if (!ready) throw new AcmeError("serverInternal", "Issuance accounting is not initialized", 503,
      undefined, undefined, { "Retry-After": "60" });
  }

  async assertIssuanceCapacity(buckets: IssuanceBucket[], now: number): Promise<void> {
    const exceeded = await this.db.get<{ key: string; cap: number; window_seconds: number }>(sql`SELECT json_extract(b.value, '$.key') AS key,
        json_extract(b.value, '$.limit') AS cap, json_extract(b.value, '$.windowSeconds') AS window_seconds
      FROM json_each(${JSON.stringify(buckets)}) b WHERE (SELECT COUNT(*) FROM issuance_ledger l
        WHERE l.bucket_key = json_extract(b.value, '$.key') AND l.issued_at > ${now} - json_extract(b.value, '$.windowSeconds'))
        >= json_extract(b.value, '$.limit') LIMIT 1`);
    if (!exceeded) return;
    // The cap-th newest entry must expire to admit another issuance, including
    // when a historical backfill legitimately contains more than today's cap.
    const row = await this.db.get<{ issued_at: number }>(sql`SELECT issued_at FROM issuance_ledger WHERE bucket_key = ${exceeded.key} AND issued_at > ${now - exceeded.window_seconds}
      ORDER BY issued_at DESC LIMIT 1 OFFSET ${exceeded.cap - 1}`);
    const retry = Math.max(1, (row?.issued_at ?? now) + exceeded.window_seconds - now);
    throw new AcmeError("rateLimited", `Certificate issuance rate limit exceeded for '${exceeded.key}'`, 429,
      undefined, undefined, { "Retry-After": String(retry) });
  }

  // --- Account Operations ---
  async getAccountById(id: string): Promise<AccountRow | null> {
    return (await this.db.select().from(schema.accounts).where(eq(schema.accounts.id, id)).get()) ?? null;
  }

  async getAccountByThumbprint(thumbprint: string): Promise<AccountRow | null> {
    return (await this.db.select().from(schema.accounts).where(eq(schema.accounts.thumbprint, thumbprint)).get()) ?? null;
  }

  /**
   * Looks up an account by the canonical actual-public-key fingerprint.
   * This is a point lookup through the UNIQUE
   * idx_accounts_public_key_fingerprint index.
   */
  async getAccountByPublicKeyFingerprint(fingerprint: string): Promise<AccountRow | null> {
    return (await this.db.select().from(schema.accounts).where(eq(schema.accounts.public_key_fingerprint, fingerprint)).get()) ?? null;
  }

  async accountFingerprintIndexInfo(): Promise<{
    name: string;
    sql: string | null;
  } | null> {
    const row = await this.db.get<{ name: string; sql: string | null }>(sql`SELECT name, sql FROM sqlite_master WHERE type = 'index' AND name = ${"idx_accounts_public_key_fingerprint"} AND tbl_name = 'accounts'`);
    return row ?? null;
  }

  async countAccountsMissingPublicKeyFingerprint(): Promise<number> {
    const row = await this.db.select({ count: count() }).from(schema.accounts)
      .where(isNull(schema.accounts.public_key_fingerprint)).get();
    return row?.count ?? 0;
  }

  /**
   * Cheap existence probe used on every key-identity-sensitive request.
   * Backed by the partial idx_accounts_missing_public_key_fingerprint index
   * (or, as a fallback, the UNIQUE fingerprint index).
   */
  async hasAccountsMissingPublicKeyFingerprint(): Promise<boolean> {
    return !!(await this.db.select({ id: schema.accounts.id }).from(schema.accounts)
      .where(isNull(schema.accounts.public_key_fingerprint)).limit(1).get());
  }

  /**
   * Legacy rows that still need a fingerprint and have no recorded conflict.
   * Conflicted rows are left untouched until an administrator resolves them;
   * excluding them keeps repeated migration runs cheap. The UNIQUE index on
   * public_key_fingerprint also serves this IS NULL predicate.
   */
  async listAccountsMissingPublicKeyFingerprint(limit: number): Promise<AccountRow[]> {
    return this.db.select().from(schema.accounts).where(and(
      isNull(schema.accounts.public_key_fingerprint),
      notInArray(schema.accounts.id, this.db.select({ id: schema.accountKeyConflicts.account_id }).from(schema.accountKeyConflicts)),
    )).orderBy(schema.accounts.created_at, schema.accounts.id).limit(limit).all();
  }

  /** Assigns a fingerprint only while the row is still un-migrated. */
  async setAccountPublicKeyFingerprint(id: string, fingerprint: string): Promise<boolean> {
    const result = await this.db.update(schema.accounts).set({ public_key_fingerprint: fingerprint })
      .where(and(eq(schema.accounts.id, id), isNull(schema.accounts.public_key_fingerprint))).run();
    return (result.meta.changes ?? 0) > 0;
  }

  async recordAccountKeyConflict(conflict: AccountKeyConflictInsert): Promise<void> {
    await this.db.insert(schema.accountKeyConflicts).values(conflict).onConflictDoUpdate({
      target: schema.accountKeyConflicts.account_id,
      set: { reason: conflict.reason, public_key_fingerprint: conflict.public_key_fingerprint ?? null,
        conflicting_account_id: conflict.conflicting_account_id ?? null, detected_at: conflict.detected_at },
    }).run();
  }

  async listAccountKeyConflicts(limit = 100): Promise<AccountKeyConflictRow[]> {
    return this.db.select().from(schema.accountKeyConflicts)
      .orderBy(schema.accountKeyConflicts.detected_at, schema.accountKeyConflicts.account_id).limit(limit).all();
  }

  async clearAccountKeyConflict(accountId: string): Promise<void> {
    await this.db.delete(schema.accountKeyConflicts).where(eq(schema.accountKeyConflicts.account_id, accountId)).run();
  }

  async saveAccount(account: AccountInsert): Promise<void> {
    await this.db.insert(schema.accounts).values(account).run();
  }

  /**
   * Compare-and-swap rotation of an account key.
   *
   * The WHERE clause is keyed on the previously read thumbprint, so two
   * concurrent keyChange requests cannot both win. The UNIQUE index on
   * public_key_fingerprint is the final protection against reusing another
   * account's actual key.
   */
  async updateAccountKey(id: string, expectedThumbprint: string, update: {
    jwk: string; thumbprint: string; publicKeyFingerprint: string;
  }): Promise<boolean> {
    const result = await this.db.update(schema.accounts).set({ jwk: update.jwk,
      thumbprint: update.thumbprint, public_key_fingerprint: update.publicKeyFingerprint })
      .where(and(eq(schema.accounts.id, id), eq(schema.accounts.thumbprint, expectedThumbprint),
        eq(schema.accounts.status, "valid"))).run();
    return (result.meta.changes ?? 0) > 0;
  }

  async updateAccount(id: string, updates: Partial<Pick<AccountInsert, "contact" | "status" | "terms_of_service">>): Promise<void> {
    if (Object.values(updates).every((value) => value === undefined)) return;
    await this.db.update(schema.accounts).set(updates).where(eq(schema.accounts.id, id)).run();
  }

  // --- Order Operations ---
  async saveOrder(order: OrderInsert): Promise<void> {
    await this.db.insert(schema.orders).values(order).run();
  }

  async getOrderById(id: string): Promise<OrderRow | null> {
    return (await this.db.select().from(schema.orders).where(eq(schema.orders.id, id)).get()) ?? null;
  }

  async updateOrderStatus(id: string, status: OrderRow["status"], certificateId: string | null = null): Promise<void> {
    await this.db.update(schema.orders).set(certificateId === null ? { status } : { status, certificate_id: certificateId })
      .where(eq(schema.orders.id, id)).run();
  }

  // --- Authorization Operations ---
  async saveAuthorization(authz: AuthorizationInsert): Promise<void> {
    await this.db.insert(schema.authorizations).values(authz).run();
  }

  async getAuthorizationById(id: string): Promise<AuthorizationRow | null> {
    return (await this.db.select().from(schema.authorizations).where(eq(schema.authorizations.id, id)).get()) ?? null;
  }

  async getAuthorizationsByOrderId(orderId: string): Promise<AuthorizationRow[]> {
    return this.db.select().from(schema.authorizations).where(eq(schema.authorizations.order_id, orderId)).all();
  }

  async updateAuthorizationStatus(id: string, status: AuthorizationRow["status"]): Promise<void> {
    await this.db.update(schema.authorizations).set({ status }).where(eq(schema.authorizations.id, id)).run();
  }

  async updateAuthorizationStatusIfPending(id: string, status: AuthorizationRow["status"]): Promise<boolean> {
    const result = await this.db.update(schema.authorizations).set({ status })
      .where(and(eq(schema.authorizations.id, id), eq(schema.authorizations.status, "pending"))).run();
    return (result.meta.changes ?? 0) > 0;
  }

  // --- Challenge Operations ---
  async saveChallenge(challenge: ChallengeInsert): Promise<void> {
    await this.db.insert(schema.challenges).values(challenge).run();
  }

  /** Inserts a challenge unless the (authorization, type) pair already exists. */
  async saveChallengeIfAbsent(challenge: ChallengeInsert): Promise<void> {
    await this.db.insert(schema.challenges).values(challenge).onConflictDoNothing().run();
  }

  async getChallengeById(id: string): Promise<ChallengeRow | null> {
    return (await this.db.select().from(schema.challenges).where(eq(schema.challenges.id, id)).get()) ?? null;
  }

  async getChallengesByAuthorizationId(authorizationId: string): Promise<ChallengeRow[]> {
    return this.db.select().from(schema.challenges).where(eq(schema.challenges.authorization_id, authorizationId))
      .orderBy(sql`CASE ${schema.challenges.type} WHEN 'dns-01' THEN 0 ELSE 1 END`, schema.challenges.created_at, schema.challenges.id).all();
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
    const row = await this.db.get<{ validation_generation: number }>(sql`UPDATE challenges
         SET status = 'processing',
             processing_started_at = ${now},
             error = NULL,
             validation_generation = COALESCE(validation_generation, 0) + 1
         WHERE id = ${id}
           AND (status = 'pending'
                OR (status = 'processing'
                    AND (processing_started_at IS NULL OR processing_started_at < ${staleBefore})))
         RETURNING validation_generation`);
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
    const res = await this.db.run(sql`UPDATE challenges
         SET status = 'valid', error = NULL, validated_at = ${validatedAt}, processing_started_at = NULL
         WHERE id = ${challengeId} AND status = 'processing' AND validation_generation = ${validationGeneration}
           AND EXISTS (
             SELECT 1 FROM authorizations
             WHERE id = ${authorizationId} AND status IN ('pending', 'valid')
           )`);
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
    const res = await this.db.run(sql`UPDATE challenges
         SET status = 'invalid', error = ${errorJson}, validated_at = NULL, processing_started_at = NULL
         WHERE id = ${challengeId} AND status = 'processing' AND validation_generation = ${validationGeneration}`);
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
      await this.db.run(sql`UPDATE challenges
           SET status = 'invalid', error = ${errorJson}, processing_started_at = NULL
           WHERE authorization_id = ${authorizationId} AND id <> ${challengeId} AND status IN ('pending', 'processing')`);
      await this.invalidateOpenOrder(orderId);
    }
    return true;
  }

  async invalidatePendingChallengesForAuthorization(
    authorizationId: string,
    errorJson: string
  ): Promise<void> {
    await this.db.run(sql`UPDATE challenges
         SET status = 'invalid', error = ${errorJson}, processing_started_at = NULL
         WHERE authorization_id = ${authorizationId} AND status IN ('pending', 'processing')`);
  }

  async invalidateChallenge(challengeId: string, errorJson: string): Promise<boolean> {
    const res = await this.db.run(sql`UPDATE challenges
         SET status = 'invalid', error = ${errorJson}, processing_started_at = NULL
         WHERE id = ${challengeId} AND status IN ('pending', 'processing')`);
    return (res.meta?.changes ?? 0) > 0;
  }

  async markOrderReadyIfAllAuthorizationsValid(orderId: string): Promise<void> {
    await this.db.run(sql`UPDATE orders
         SET status = 'ready'
         WHERE id = ${orderId} AND status = 'pending'
           AND EXISTS (SELECT 1 FROM authorizations WHERE order_id = ${orderId})
           AND NOT EXISTS (
             SELECT 1 FROM authorizations WHERE order_id = ${orderId} AND status <> 'valid'
           )`);
  }

  async invalidateOpenOrder(orderId: string): Promise<void> {
    await this.db.update(schema.orders).set({ status: "invalid" })
      .where(and(eq(schema.orders.id, orderId), inArray(schema.orders.status, ["pending", "ready"]))).run();
  }

  /**
   * Atomically claims a ready order for issuance so concurrent finalize
   * requests cannot both sign a certificate.
   */
  async claimOrderForFinalize(orderId: string, now = Math.floor(Date.now() / 1000)): Promise<number | null> {
    const row = await this.db.get<{ finalize_generation: number }>(sql`UPDATE orders SET status = 'processing', processing_started_at = ${now}, finalize_generation = finalize_generation + 1
       WHERE id = ${orderId} AND expires_at > ${now} AND (status = 'ready' OR (status = 'processing' AND COALESCE(processing_started_at, 0) < ${now - 60}))
       RETURNING finalize_generation`);
    return row?.finalize_generation ?? null;
  }

  async releaseOrderFromProcessing(orderId: string, generation: number): Promise<void> {
    await this.db.run(sql`UPDATE orders SET status = 'ready', processing_started_at = NULL
       WHERE id = ${orderId} AND status = 'processing' AND finalize_generation = ${generation} AND certificate_id IS NULL`);
  }

  async invalidateFinalizeClaim(orderId: string, generation: number): Promise<void> {
    await this.db.run(sql`UPDATE orders SET status = 'invalid' WHERE id = ${orderId} AND status = 'processing' AND finalize_generation = ${generation}`);
  }

  /** Certificate, quota ledger, replacement and order commit in one D1 transaction. */
  async completeOrder(orderId: string, generation: number, cert: CertificateRow, predecessor: string | null, now: number): Promise<boolean> {
    await this.ensureIssuanceLedgerReady();
    const buckets = predecessor ? [] : issuanceBuckets(readIdentifiers(cert.san));
    const bucketsJson = JSON.stringify(buckets);
    // These SELECT projections follow the column order declared in schema.ts.
    // Use insert/update builders so D1's batch receives actual prepared queries.
    const results = await this.db.batch([
      this.db.insert(schema.certificates).select(sql`SELECT ${cert.id}, ${cert.cert_id}, ${cert.serial_number}, ${cert.aki}, ${cert.subject}, ${cert.san}, ${cert.pem}, ${cert.not_before}, ${cert.not_after}, ${cert.account_id}, ${cert.created_at}, NULL, NULL, NULL, ${cert.ca_id ?? null}
         WHERE EXISTS (SELECT 1 FROM orders o JOIN accounts a ON a.id = o.account_id
           WHERE o.id = ${orderId} AND o.status = 'processing' AND o.finalize_generation = ${generation}
           AND o.processing_started_at > ${now - 60} AND o.expires_at > ${now} AND a.status = 'valid'
           AND ((o.is_ari_renewal = 0 AND ${predecessor} IS NULL) OR (o.is_ari_renewal = 1 AND o.replaces_cert_id = ${predecessor})))
         AND EXISTS (SELECT 1 FROM security_migrations WHERE name = 'issuance-ledger-v1')
         AND EXISTS (SELECT 1 FROM authorizations WHERE order_id = ${orderId})
         AND NOT EXISTS (SELECT 1 FROM authorizations WHERE order_id = ${orderId} AND (status != 'valid' OR expires_at <= ${now}))
         AND (${predecessor} IS NULL OR EXISTS (SELECT 1 FROM certificates WHERE cert_id = ${predecessor} AND replaced_by_cert_id IS NULL))
         AND NOT EXISTS (SELECT 1 FROM json_each(${bucketsJson}) b WHERE
           (SELECT COUNT(*) FROM issuance_ledger l WHERE l.bucket_key = json_extract(b.value, '$.key')
             AND l.issued_at > ${now} - json_extract(b.value, '$.windowSeconds')) >= json_extract(b.value, '$.limit'))`),
      this.db.insert(schema.issuanceLedger).select(sql`SELECT ${cert.id}, json_extract(value, '$.key'), ${now} FROM json_each(${bucketsJson})
        WHERE EXISTS (SELECT 1 FROM certificates c JOIN orders o ON o.id = ${orderId}
          WHERE c.id = ${cert.id} AND o.status = 'processing' AND o.finalize_generation = ${generation} AND o.certificate_id IS NULL)`),
      this.db.update(schema.certificates).set({ replaced_by_cert_id: cert.cert_id })
        .where(sql`cert_id = ${predecessor} AND replaced_by_cert_id IS NULL
          AND EXISTS (SELECT 1 FROM certificates WHERE id = ${cert.id})`),
      this.db.update(schema.orders).set({ status: 'valid', certificate_id: cert.id, processing_started_at: null })
        .where(sql`id = ${orderId} AND finalize_generation = ${generation} AND status = 'processing'
          AND EXISTS (SELECT 1 FROM certificates WHERE id = ${cert.id})`),
    ]);
    const completed = (results[0].meta?.changes ?? 0) === 1 && (results[3].meta?.changes ?? 0) === 1;
    if (!completed) await this.assertIssuanceCapacity(buckets, now);
    return completed;
  }

  /** Returns the challenge types that successfully validated each order identifier. */
  async getValidChallengeTypesByOrderId(
    orderId: string
  ): Promise<Array<{ identifier_value: string; type: string }>> {
    return this.db.select({ identifier_value: schema.authorizations.identifier_value, type: schema.challenges.type })
      .from(schema.authorizations)
      .innerJoin(schema.challenges, eq(schema.challenges.authorization_id, schema.authorizations.id))
      .where(and(eq(schema.authorizations.order_id, orderId), eq(schema.authorizations.status, "valid"),
        eq(schema.challenges.status, "valid"))).all();
  }

  // --- Certificate Operations ---
  async saveCertificate(cert: CertificateInsert): Promise<void> {
    await this.db.insert(schema.certificates).values(cert).run();
  }

  async getCertificateById(id: string): Promise<CertificateRow | null> {
    return (await this.db.select().from(schema.certificates).where(eq(schema.certificates.id, id)).get()) ?? null;
  }

  async getCertificateByCertId(certId: string): Promise<CertificateRow | null> {
    return (await this.db.select().from(schema.certificates).where(eq(schema.certificates.cert_id, certId)).get()) ?? null;
  }

  async revokeCertificate(certId: string, revokedAt: number, reason: string): Promise<boolean> {
    const result = await this.db.update(schema.certificates).set({ revoked_at: revokedAt, revocation_reason: reason })
      .where(and(eq(schema.certificates.cert_id, certId), isNull(schema.certificates.revoked_at))).run();
    return (result.meta.changes ?? 0) === 1;
  }

  async accountHasValidAuthorizations(accountId: string, domains: (string | AcmeIdentifier)[], now: number): Promise<boolean> {
    for (const domain of asIdentifiers(domains)) {
      const row = await this.db.select({ id: schema.authorizations.id }).from(schema.authorizations)
        .innerJoin(schema.orders, eq(schema.orders.id, schema.authorizations.order_id))
        .where(and(eq(schema.orders.account_id, accountId), eq(schema.authorizations.identifier_value, domain.value),
          eq(schema.authorizations.identifier_type, domain.type), eq(schema.authorizations.status, "valid"),
          gt(schema.authorizations.expires_at, now))).limit(1).get();
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
    const row = await this.db.select({ counter: schema.rateLimits.counter, window_start: schema.rateLimits.window_start })
      .from(schema.rateLimits).where(eq(schema.rateLimits.key, key)).get();
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
    const row = await this.db.get<{ counter: number }>(sql`INSERT INTO rate_limits (key, counter, window_start)
         VALUES (${key}, 1, ${now})
         ON CONFLICT(key) DO UPDATE SET
           counter = CASE
             WHEN excluded.window_start - rate_limits.window_start >= ${windowSeconds} THEN 1
             WHEN rate_limits.counter < ${limit} THEN rate_limits.counter + 1
             ELSE MAX(rate_limits.counter, ${limit} + 1)
           END,
           window_start = CASE
             WHEN excluded.window_start - rate_limits.window_start >= ${windowSeconds} THEN excluded.window_start
             ELSE rate_limits.window_start
           END
         RETURNING counter`);

    const counter = row?.counter ?? 1;
    return {
      allowed: counter <= limit,
      remaining: Math.max(0, limit - counter),
    };
  }
}
