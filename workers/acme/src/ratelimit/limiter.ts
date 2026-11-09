import { AcmeIdentifier, asIdentifiers, identifierKey } from "../acme/identifiers";
import { CONFIG } from "../config";
import type { Database } from "../db/queries";
import { AcmeError } from "../errors";

export { getRegisteredDomain, issuanceGroup } from "./issuance";

export class RateLimiter {
  constructor(private db: Database) {}

  /** Unverified orders consume only their own account's request budget. */
  async checkNewOrderLimits(
    accountId: string,
    now = Math.floor(Date.now() / 1000)
  ): Promise<void> {
    const accountOrderKey = `orders:account:${accountId}`;
    const accountCheck = await this.db.checkAndIncrementRateLimit(
      accountOrderKey,
      CONFIG.RATE_LIMIT_NEW_ORDERS_PER_ACCOUNT,
      CONFIG.RATE_LIMIT_NEW_ORDERS_WINDOW_SECONDS,
      now
    );
    if (!accountCheck.allowed) {
      throw AcmeError.rateLimited(
        `Too many new orders for account ${accountId}. Limit is ${CONFIG.RATE_LIMIT_NEW_ORDERS_PER_ACCOUNT} per 3 hours.`
      );
    }
  }

  /**
   * Checks the failed-challenge validation limit without consuming a slot.
   * Call `recordFailedValidation` only after an attempt actually fails.
   */
  async checkFailedValidationLimit(
    accountId: string,
    hostname: string | AcmeIdentifier,
    now = Math.floor(Date.now() / 1000)
  ): Promise<void> {
    const key = this.failedValidationKey(accountId, hostname);
    const counter = await this.db.getRateLimitCounter(
      key,
      CONFIG.RATE_LIMIT_FAILED_WINDOW_SECONDS,
      now
    );
    if (counter >= CONFIG.RATE_LIMIT_FAILED_VALIDATIONS) {
      throw AcmeError.rateLimited(
        `Too many failed challenge attempts for ${typeof hostname === "string" ? hostname : hostname.value}. Limit is ${CONFIG.RATE_LIMIT_FAILED_VALIDATIONS} per hour.`
      );
    }
  }

  /** Records one failed challenge validation attempt. */
  async recordFailedValidation(
    accountId: string,
    hostname: string | AcmeIdentifier,
    now = Math.floor(Date.now() / 1000)
  ): Promise<void> {
    await this.db.checkAndIncrementRateLimit(
      this.failedValidationKey(accountId, hostname),
      CONFIG.RATE_LIMIT_FAILED_VALIDATIONS,
      CONFIG.RATE_LIMIT_FAILED_WINDOW_SECONDS,
      now
    );
  }

  private failedValidationKey(accountId: string, hostname: string | AcmeIdentifier): string {
    const identifier = asIdentifiers([hostname])[0];
    const key = identifier.type === "dns" ? identifier.value : identifierKey(identifier);
    return `failed:authz:${accountId}:${key}`;
  }
}
