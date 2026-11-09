import { afterEach, describe, expect, it, vi } from "vitest";
import { validateCaa } from "../src/dns/caa";
import { validateDns01Challenge } from "../src/dns/validator";

afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

describe("DNS failures never authorize issuance", () => {
  it.each([{ Status: 2 }, { Status: 3 }, {}, { Status: 0, Answer: {} }, { Status: 0, Answer: [{ type: 257, data: "malformed" }] }])("fails closed for %j", async (body) => {
    const fetcher = vi.fn(async () => Response.json(body));
    await expect(validateCaa("example.com", undefined, fetcher)).rejects.toMatchObject({ type: "urn:ietf:params:acme:error:dns" });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it("allows successful empty answers and recovers only transport failures", async () => {
    const fetcher = vi.fn(async (input) => {
      if (String(input).startsWith("https://cloudflare")) throw new Error("offline");
      return Response.json({ Status: 0 });
    });
    expect((await validateCaa("example.com", undefined, fetcher)).valid).toBe(true);
  });
  it("rejects total resolver failure, alias cycles and oversized answers", async () => {
    await expect(validateCaa("example.com", undefined, async () => { throw new Error("offline"); })).rejects.toThrow();
    await expect(validateCaa("example.com", undefined, async () => Response.json({ Status: 0, Answer: [{ type: 5, data: "example.com." }] }))).rejects.toThrow("cycle");
    await expect(validateDns01Challenge("example.com", "token", "thumbprint", async () => new Response("x".repeat(65537)))).rejects.toThrow("64 KiB");
  });
  it("bounds a resolver that ignores cancellation", async () => {
    vi.useFakeTimers();
    const pending = validateCaa("example.com", undefined, () => new Promise(() => {}));
    const rejected = expect(pending).rejects.toThrow();
    await vi.advanceTimersByTimeAsync(20001);
    await rejected;
  });
});
