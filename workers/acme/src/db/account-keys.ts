import { isUniqueConstraintError } from "./errors";
import { AccountRow } from "./types";
import { Database, isAccountFingerprintIndexSql } from "./queries";
import { AcmeError } from "../errors";
import { normalizePublicKey } from "../crypto/jws";

/**
 * Reason codes stored in account_key_conflicts. These are administrator-facing
 * values and never contain key material.
 */
export type AccountKeyConflictReason =
  | "invalid_public_key"
  | "duplicate_public_key"
  | "unique_index_creation_failed"
  | "unique_index_missing";

export interface AccountKeyMigrationSummary {
  /** Legacy rows whose JWK was examined in this run. */
  scanned: number;
  /** Rows that received a fingerprint in this run. */
  updated: number;
  /** Rows that could not be indexed and were recorded as conflicts. */
  conflicts: number;
  /** Accounts still missing a fingerprint after this run (includes conflicts). */
  remaining: number;
}

const MIGRATION_BATCH_SIZE = 50;
// One bounded batch per administrator invocation; the management script
// resumes batches until complete. Public requests never perform backfills.
const MIGRATION_MAX_BATCHES = 1;



async function assertAccountFingerprintIndex(database: Database): Promise<void> {
  let index: { name: string; sql: string | null } | null;
  try {
    index = await database.accountFingerprintIndexInfo();
  } catch {
    throw AcmeError.serverInternal(
      "Unable to verify the account public key identity index; refusing to perform a key-reuse check"
    );
  }

  if (!index || !isAccountFingerprintIndexSql(index.sql)) {
    throw AcmeError.serverInternal(
      "The account public key identity index is unavailable; refusing to perform a key-reuse check"
    );
  }
}

/**
 * Idempotently backfills public_key_fingerprint for legacy account rows.
 *
 * The migration:
 *  - only considers rows whose fingerprint is still NULL and that have no
 *    recorded conflict, so repeated runs do not rescan resolved rows;
 *  - computes the fingerprint from the stored JWK through the same unified
 *    normalization used for registration/keyChange/finalize;
 *  - never deletes, renumbers, or rewrites account identity/jwk/thumbprint;
 *  - records duplicate-key or invalid-key conditions in
 *    account_key_conflicts for administrator review instead of choosing a
 *    winner silently.
 *
 * A UNIQUE index on public_key_fingerprint is created before the backfill
 * (SQLite allows multiple NULLs), so a concurrent registration cannot race a
 * legacy row into a duplicate account without one side hitting the index.
 */
export async function migrateAccountPublicKeyFingerprints(
  database: Database
): Promise<AccountKeyMigrationSummary> {
  await assertAccountFingerprintIndex(database);

  const summary: AccountKeyMigrationSummary = {
    scanned: 0,
    updated: 0,
    conflicts: 0,
    remaining: 0,
  };

  let batches = 0;
  while (batches < MIGRATION_MAX_BATCHES) {
    const rows = await database.listAccountsMissingPublicKeyFingerprint(
      MIGRATION_BATCH_SIZE
    );
    if (rows.length === 0) break;
    batches++;

    for (const row of rows) {
      summary.scanned++;

      let fingerprint: string;
      try {
        const jwk = JSON.parse(row.jwk) as unknown;
        const identity = await normalizePublicKey(jwk);
        fingerprint = identity.fingerprint;
      } catch {
        await database.recordAccountKeyConflict({
          account_id: row.id,
          reason: "invalid_public_key",
          public_key_fingerprint: null,
          conflicting_account_id: null,
          detected_at: Math.floor(Date.now() / 1000),
        });
        summary.conflicts++;
        continue;
      }

      // A pre-existing account (registered after this deployment, or a legacy
      // row that has already been resolved) may already own this actual key.
      const existing = await database.getAccountByPublicKeyFingerprint(fingerprint);
      if (existing && existing.id !== row.id) {
        await recordDuplicate(database, row, fingerprint, existing.id);
        summary.conflicts++;
        continue;
      }

      try {
        const updated = await database.setAccountPublicKeyFingerprint(
          row.id,
          fingerprint
        );
        if (updated) {
          summary.updated++;
        }
      } catch (error: unknown) {
        if (!isUniqueConstraintError(error)) {
          throw AcmeError.serverInternal(
            "Account public key identity migration failed; no accounts were modified"
          );
        }

        // Another account won the race for this fingerprint. Leave this row
        // unindexed and record the conflict for manual review.
        const holder = await database.getAccountByPublicKeyFingerprint(fingerprint);
        await recordDuplicate(database, row, fingerprint, holder?.id ?? null);
        summary.conflicts++;
      }
    }
  }

  summary.remaining = await database.countAccountsMissingPublicKeyFingerprint();
  return summary;
}

async function recordDuplicate(
  database: Database,
  row: AccountRow,
  fingerprint: string,
  conflictingAccountId: string | null
): Promise<void> {
  await database.recordAccountKeyConflict({
    account_id: row.id,
    reason: "duplicate_public_key",
    public_key_fingerprint: fingerprint,
    conflicting_account_id: conflictingAccountId,
    detected_at: Math.floor(Date.now() / 1000),
  });
}

/**
 * Fail-closed guard for every operation whose correctness depends on knowing
 * all account public keys (newAccount, keyChange, finalize).
 *
 * It verifies that the UNIQUE identity index actually exists and, when legacy
 * rows remain, rejects the request until the management script finishes. If any account cannot be
 * indexed (invalid legacy JWK, duplicate actual key, failed index creation),
 * the operation is rejected rather than assuming the key is unused.
 */
export async function ensureAccountPublicKeyIndex(
  database: Database
): Promise<void> {
  await assertAccountFingerprintIndex(database);

  let missing: boolean;
  try {
    missing = await database.hasAccountsMissingPublicKeyFingerprint();
  } catch {
    throw AcmeError.serverInternal(
      "Unable to verify that all account public keys are indexed; refusing to perform a key-reuse check"
    );
  }
  if (!missing) return;

  let remaining = 0;
  try {
    remaining = await database.countAccountsMissingPublicKeyFingerprint();
  } catch {
    // The count is only used for the operator-facing message.
  }
  throw new AcmeError("serverInternal",
    `Account public key identity migration is incomplete${
      remaining > 0 ? ` (${remaining} account(s) unresolved)` : ""
    }; run npm run migrate:account-keys and resolve account_key_conflicts before issuing certificates or changing account keys`, 503
  );
}
