import { describe, it, expect, beforeEach } from "vitest";
import { createMockD1Database } from "./mock-d1";
import { Database } from "../src/db/queries";
import { RateLimiter } from "../src/ratelimit/limiter";
import { AcmeError } from "../src/errors";
import { CONFIG } from "../src/config";

describe("Account order and failed-validation rate limits", () => {
  let db: Database;
  let limiter: RateLimiter;

  beforeEach(async () => {
    db = new Database(createMockD1Database());
    await db.initSchema();
    limiter = new RateLimiter(db);
  });

  it("isolates unverified orders to their own account's budget", async () => {
    const now = 1700000000;
    for (let i = 0; i < CONFIG.RATE_LIMIT_NEW_ORDERS_PER_ACCOUNT; i++) {
      await limiter.checkNewOrderLimits("attacker", now);
    }
    await expect(limiter.checkNewOrderLimits("attacker", now)).rejects.toThrowError(AcmeError);
    await expect(limiter.checkNewOrderLimits("victim", now)).resolves.toBeUndefined();
    await expect(limiter.checkNewOrderLimits("attacker", now + CONFIG.RATE_LIMIT_NEW_ORDERS_WINDOW_SECONDS)).resolves.toBeUndefined();
  });

  it("should count only failed challenge attempts toward the failed-validation limit", async () => {
    const now = 1700000000;
    const hostname = "example.com";

    // Successful checks do not consume the failed-attempt budget.
    for (let i = 0; i < CONFIG.RATE_LIMIT_FAILED_VALIDATIONS * 3; i++) {
      await expect(
        limiter.checkFailedValidationLimit("acc-success", hostname, now)
      ).resolves.not.toThrow();
    }

    for (let i = 0; i < CONFIG.RATE_LIMIT_FAILED_VALIDATIONS; i++) {
      await limiter.checkFailedValidationLimit("acc-failed", hostname, now);
      await limiter.recordFailedValidation("acc-failed", hostname, now);
    }

    await expect(
      limiter.checkFailedValidationLimit("acc-failed", hostname, now)
    ).rejects.toThrowError(AcmeError);
  });
});
