import { describe, it, expect } from "vitest";
import {
  cleanTxtRecord,
  computeExpectedDnsDigest,
  getDnsChallengeHostname,
  validateDns01Challenge,
} from "../src/dns/validator";

describe("DNS-01 Challenge Validation", () => {
  it("should compute correct DNS challenge hostname", () => {
    expect(getDnsChallengeHostname("example.com")).toBe("_acme-challenge.example.com");
    expect(getDnsChallengeHostname("*.example.com")).toBe("_acme-challenge.example.com");
    expect(getDnsChallengeHostname("sub.test.org")).toBe("_acme-challenge.sub.test.org");
    expect(getDnsChallengeHostname("*.wildcard.cfms.pki")).toBe(
      "_acme-challenge.wildcard.cfms.pki"
    );
  });

  it("should clean quoted TXT responses", () => {
    expect(cleanTxtRecord('"abc123xyz"')).toBe("abc123xyz");
    expect(cleanTxtRecord('  "hello world"  ')).toBe("hello world");
    expect(cleanTxtRecord("unquotedString")).toBe("unquotedString");
  });

  it("should compute expected DNS digest correctly", async () => {
    const token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
    const thumbprint = "k6NxjwD82VO8-p_nI7n91_O_WjG9xNq7YmI7d8z4Q0I";
    const digest = await computeExpectedDnsDigest(token, thumbprint);

    expect(typeof digest).toBe("string");
    expect(digest.length).toBeGreaterThan(20);
    // Base64url contains no '+', '/', or '='
    expect(digest).not.toMatch(/[+/=]/);
  });

  it("should successfully validate DNS-01 challenge when DoH returns matching TXT record", async () => {
    const token = "testToken1234567890";
    const thumbprint = "testThumbprint12345";
    const expectedDigest = await computeExpectedDnsDigest(token, thumbprint);

    const mockFetch: typeof fetch = async (input, init) => {
      const url = String(input);
      if (url.includes("_acme-challenge.example.com")) {
        return new Response(
          JSON.stringify({
            Status: 0,
            Answer: [
              {
                name: "_acme-challenge.example.com.",
                type: 16,
                TTL: 60,
                data: `"${expectedDigest}"`,
              },
            ],
          }),
          { status: 200, headers: { "Content-Type": "application/dns-json" } }
        );
      }
      return new Response(JSON.stringify({ Status: 3, Answer: [] }), { status: 200 });
    };

    const res = await validateDns01Challenge("example.com", token, thumbprint, mockFetch);
    expect(res.valid).toBe(true);
    expect(res.queriedRecords).toContain(expectedDigest);
  });

  it("should fail validation when DoH returns mismatched TXT record", async () => {
    const token = "testToken1234567890";
    const thumbprint = "testThumbprint12345";

    const mockFetch: typeof fetch = async () => {
      return new Response(
        JSON.stringify({
          Status: 0,
          Answer: [
            {
              name: "_acme-challenge.example.com.",
              type: 16,
              TTL: 60,
              data: '"wrongDigestValue"',
            },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/dns-json" } }
      );
    };

    const res = await validateDns01Challenge("example.com", token, thumbprint, mockFetch);
    expect(res.valid).toBe(false);
    expect(res.error).toContain("None of the TXT records");
  });
});
