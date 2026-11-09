import { DrizzleQueryError } from "drizzle-orm/errors";
import { describe, expect, it } from "vitest";
import { databaseErrorCategory, isUniqueConstraintError } from "../src/db/errors";

describe("database error classification", () => {
  it.each([
    ["D1_ERROR: no such table: nonces", "schema"],
    ["D1_ERROR: no such column: expires_at", "schema"],
    ["D1_COLUMN_NOTFOUND: expires_at", "schema"],
    ["D1_ERROR: Your account has exceeded D1's free tier daily row read limit.", "quota"],
    ["D1_ERROR: Your account has exceeded D1's free tier daily row write limit.", "quota"],
    ["D1_ERROR: Exceeded maximum DB size.", "quota"],
    ["D1_ERROR: D1 DB is overloaded. Too many requests queued.", "overloaded"],
    ["D1_ERROR: D1 DB storage operation exceeded timeout which caused object to be reset.", "timeout"],
    ["D1_ERROR: Network connection lost.", "unavailable"],
    ["D1_ERROR: D1 DB reset because its code was updated.", "unavailable"],
    ["D1_ERROR: Cannot resolve D1 DB due to transient issue on remote node.", "unavailable"],
    ["private unexpected error", "unknown"],
  ])("classifies wrapped %s without returning its text", (message, category) => {
    const error = new DrizzleQueryError("delete", ["private parameter"], new Error(message));
    expect(databaseErrorCategory(error)).toBe(category);
  });

  it("does not classify wrapper SQL or parameters and terminates on cyclic causes", () => {
    const error = new DrizzleQueryError("no such table", ["Network connection lost"], new Error("other failure"));
    expect(databaseErrorCategory(error)).toBe("unknown");
    const cyclic = new Error("Network connection lost");
    cyclic.cause = cyclic;
    expect(databaseErrorCategory(cyclic)).toBe("unknown");
    expect(databaseErrorCategory("no such table: nonces")).toBe("unknown");
  });

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
