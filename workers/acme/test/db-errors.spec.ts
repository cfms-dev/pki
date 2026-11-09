import { DrizzleQueryError } from "drizzle-orm/errors";
import { describe, expect, it } from "vitest";
import { isUniqueConstraintError } from "../src/db/errors";

describe("database error classification", () => {
  it("recognizes a UNIQUE error through Drizzle and D1 wrappers", () => {
    expect(isUniqueConstraintError(new DrizzleQueryError("insert", [],
      new Error("D1_ERROR", { cause: new Error("UNIQUE constraint failed: accounts.public_key_fingerprint") })))).toBe(true);
  });

  it("ignores SQL/parameter text in wrappers and handles cyclic causes", () => {
    expect(isUniqueConstraintError(new DrizzleQueryError("insert", ["UNIQUE constraint failed"], new Error("offline")))).toBe(false);
    const cyclic = new Error("other failure");
    cyclic.cause = cyclic;
    expect(isUniqueConstraintError(cyclic)).toBe(false);
  });
});
