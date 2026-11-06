import { CONFIG } from "../config";
import { Database } from "../db/queries";
import { AcmeError } from "../errors";

/**
 * Extracts effective registered domain (eTLD+1 simplified)
 */
export function getRegisteredDomain(domain: string): string {
  const clean = domain.startsWith("*.") ? domain.slice(2) : domain;
  const parts = clean.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) {
    return clean.toLowerCase();
  }
  // Handles common 2-level TLDs like .co.uk, .com.cn
  const secondLast = parts[parts.length - 2];
  if (
    ["com", "co", "net", "org", "gov", "edu"].includes(secondLast) &&
    parts[parts.length - 1].length === 2
  ) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

export class RateLimiter {
  constructor(private db: Database) {}

  /**
   * Checks rate limits for creating a new order.
   * If isAriRenewal is true, duplicate certificate and registered domain limits are EXEMPT!
   */
  async checkNewOrderLimits(
    accountId: string,
    domains: string[],
    isAriRenewal: boolean,
    now = Math.floor(Date.now() / 1000)
  ): Promise<void> {
    // 1. Account new orders limit (anti-abuse)
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

    // 2. If ARI renewal is approved, EXEMPT from issuance rate limits!
    if (isAriRenewal) {
      return;
    }

    // 3. Registered Domain Limit
    const registeredDomains = new Set(domains.map(getRegisteredDomain));
    for (const regDomain of registeredDomains) {
      const domainKey = `issuance:domain:${regDomain}`;
      const domainCheck = await this.db.checkAndIncrementRateLimit(
        domainKey,
        CONFIG.RATE_LIMIT_CERTS_PER_DOMAIN,
        CONFIG.RATE_LIMIT_DOMAIN_WINDOW_SECONDS,
        now
      );
      if (!domainCheck.allowed) {
        throw AcmeError.rateLimited(
          `Rate limit exceeded for registered domain '${regDomain}'. Limit is ${CONFIG.RATE_LIMIT_CERTS_PER_DOMAIN} per 7 days.`
        );
      }
    }

    // 4. Duplicate Certificate Limit
    const sortedDomains = domains.slice().sort().join(",");
    const duplicateKey = `issuance:duplicate:${sortedDomains}`;
    const duplicateCheck = await this.db.checkAndIncrementRateLimit(
      duplicateKey,
      CONFIG.RATE_LIMIT_DUPLICATE_CERTS,
      CONFIG.RATE_LIMIT_DUPLICATE_WINDOW_SECONDS,
      now
    );
    if (!duplicateCheck.allowed) {
      throw AcmeError.rateLimited(
        `Duplicate certificate limit exceeded for [${sortedDomains}]. Limit is ${CONFIG.RATE_LIMIT_DUPLICATE_CERTS} duplicates per 7 days.`
      );
    }
  }

  /**
   * Checks the failed-challenge validation limit without consuming a slot.
   * Call `recordFailedValidation` only after an attempt actually fails.
   */
  async checkFailedValidationLimit(
    accountId: string,
    hostname: string,
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
        `Too many failed challenge attempts for ${hostname}. Limit is ${CONFIG.RATE_LIMIT_FAILED_VALIDATIONS} per hour.`
      );
    }
  }

  /** Records one failed challenge validation attempt. */
  async recordFailedValidation(
    accountId: string,
    hostname: string,
    now = Math.floor(Date.now() / 1000)
  ): Promise<void> {
    await this.db.checkAndIncrementRateLimit(
      this.failedValidationKey(accountId, hostname),
      CONFIG.RATE_LIMIT_FAILED_VALIDATIONS,
      CONFIG.RATE_LIMIT_FAILED_WINDOW_SECONDS,
      now
    );
  }

  private failedValidationKey(accountId: string, hostname: string): string {
    return `failed:authz:${accountId}:${hostname.toLowerCase()}`;
  }
}
