import { describe, it, expect, beforeEach } from "vitest";
import { createMockD1Database } from "./mock-d1";
import { Database } from "../src/db/queries";
import { RateLimiter } from "../src/ratelimit/limiter";
import { AcmeError } from "../src/errors";

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
});
