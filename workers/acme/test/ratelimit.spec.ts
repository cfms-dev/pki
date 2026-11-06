import { describe, it, expect, beforeEach } from "vitest";
import { createMockD1Database } from "./mock-d1";
import { Database } from "../src/db/queries";
import { RateLimiter } from "../src/ratelimit/limiter";
import { AcmeError } from "../src/errors";
import { CONFIG } from "../src/config";

describe("Rate Limiting & ARI Renewal Exemption", () => {
  let db: Database;
  let limiter: RateLimiter;

  beforeEach(async () => {
    db = new Database(createMockD1Database());
    await db.initSchema();
    limiter = new RateLimiter(db);
  });

  it("should enforce duplicate certificate rate limit (max 5) for regular orders", async () => {
    const domains = ["example.com", "www.example.com"];
    const now = 1700000000;

    // Issue 5 allowed orders
    for (let i = 0; i < 5; i++) {
      await expect(
        limiter.checkNewOrderLimits("acc-1", domains, false, now)
      ).resolves.not.toThrow();
    }

    // 6th order should be blocked by duplicate rate limit
    await expect(
      limiter.checkNewOrderLimits("acc-1", domains, false, now)
    ).rejects.toThrowError(AcmeError);
  });

  it("should grant rate limit exemption for valid ARI renewal orders", async () => {
    const domains = ["example.com", "www.example.com"];
    const now = 1700000000;

    // Hit the limit of 5 duplicate orders
    for (let i = 0; i < 5; i++) {
      await limiter.checkNewOrderLimits("acc-1", domains, false, now);
    }

    // Attempting a 6th regular order is blocked
    await expect(
      limiter.checkNewOrderLimits("acc-1", domains, false, now)
    ).rejects.toThrowError(AcmeError);

    // But an ARI Renewal order (isAriRenewal = true) is EXEMPT and succeeds!
    await expect(
      limiter.checkNewOrderLimits("acc-1", domains, true, now)
    ).resolves.not.toThrow();
  });

  it("should reset the rate limit window after it elapses", async () => {
    const domains = ["example.com"];
    const now = 1700000000;

    for (let i = 0; i < CONFIG.RATE_LIMIT_DUPLICATE_CERTS; i++) {
      await limiter.checkNewOrderLimits("acc-reset", domains, false, now);
    }

    await expect(
      limiter.checkNewOrderLimits("acc-reset", domains, false, now)
    ).rejects.toThrowError(AcmeError);

    await expect(
      limiter.checkNewOrderLimits(
        "acc-reset",
        domains,
        false,
        now + CONFIG.RATE_LIMIT_DUPLICATE_WINDOW_SECONDS
      )
    ).resolves.not.toThrow();
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
