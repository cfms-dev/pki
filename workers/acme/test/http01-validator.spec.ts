import { describe, it, expect, afterEach } from "vitest";
import {
  computeKeyAuthorization,
  isIpLiteralHost,
  isPublicIpAddress,
  isUnsafeHostname,
  isValidChallengeToken,
  validateHttp01Challenge,
  validateHttp01Target,
} from "../src/http01/validator";
import { generateNonceString } from "../src/crypto/nonce";

const PUBLIC_A = "93.184.216.34";
const PUBLIC_AAAA = "2606:2800:220:1:248:1893:25c8:1946";
const THUMBPRINT = "A".repeat(43);
const TOKEN = generateNonceString();
const KEY_AUTHORIZATION = `${TOKEN}.${THUMBPRINT}`;

type FetchHandler = (
  input: RequestInfo | URL,
  init?: RequestInit
) => Promise<Response>;

const originalFetch = globalThis.fetch;

function install(handler: FetchHandler): void {
  globalThis.fetch = handler as typeof fetch;
}

function dohResponse(url: string, addresses: string[]): Response {
  const recordType = new URL(url).searchParams.get("type");
  const matching = addresses.filter((address) =>
    recordType === "A" ? !address.includes(":") : address.includes(":")
  );
  return new Response(
    JSON.stringify({
      Status: 0,
      Answer: matching.map((data) => ({
        type: recordType === "A" ? 1 : 28,
        data,
      })),
    }),
    { status: 200, headers: { "Content-Type": "application/dns-json" } }
  );
}

function isDohUrl(url: string): boolean {
  return (
    url.startsWith("https://cloudflare-dns.com/dns-query") ||
    url.startsWith("https://dns.google/resolve")
  );
}

function challengeFetch(
  addresses: string[],
  challengeHandler: FetchHandler
): FetchHandler {
  return async (input, init) => {
    const url = String(input);
    if (isDohUrl(url)) {
      return dohResponse(url, addresses);
    }
    return challengeHandler(input, init);
  };
}

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("HTTP-01 helper functions", () => {
  it("computes the RFC 8555 key authorization", () => {
    expect(computeKeyAuthorization("token", "thumbprint")).toBe("token.thumbprint");
    expect(KEY_AUTHORIZATION).toBe(`${TOKEN}.${THUMBPRINT}`);
  });

  it("requires a base64url token with at least 128 bits of entropy", () => {
    expect(isValidChallengeToken(generateNonceString())).toBe(true);
    expect(isValidChallengeToken("a".repeat(21))).toBe(false);
    expect(isValidChallengeToken("a".repeat(22))).toBe(true);
    expect(isValidChallengeToken(`${"a".repeat(21)}=`)).toBe(false);
    expect(isValidChallengeToken(`${"a".repeat(21)}+`)).toBe(false);
  });

  it("classifies public and special-use IP addresses", () => {
    expect(isPublicIpAddress("8.8.8.8")).toBe(true);
    expect(isPublicIpAddress("1.1.1.1")).toBe(true);
    expect(isPublicIpAddress("93.184.216.34")).toBe(true);
    expect(isPublicIpAddress(PUBLIC_AAAA)).toBe(true);
    expect(isPublicIpAddress("2606:4700:4700::1111")).toBe(true);

    for (const address of [
      "0.0.0.0",
      "10.0.0.1",
      "100.64.0.1",
      "127.0.0.1",
      "169.254.1.1",
      "172.16.0.1",
      "192.0.0.1",
      "192.0.2.1",
      "192.168.1.1",
      "198.18.0.1",
      "198.51.100.1",
      "203.0.113.1",
      "224.0.0.1",
      "255.255.255.255",
      "::",
      "::1",
      "::2",
      "::ffff:10.0.0.1",
      "fe80::1",
      "fc00::1",
      "2001:db8::1",
      "2001::1",
      "2002:0a00:0001::1",
      "3fff::1",
    ]) {
      expect(isPublicIpAddress(address), address).toBe(false);
    }
  });

  it("recognizes IP literals and unsafe hostnames", () => {
    expect(isIpLiteralHost("127.0.0.1")).toBe(true);
    expect(isIpLiteralHost("[::1]")).toBe(true);
    expect(isIpLiteralHost("2130706433")).toBe(true);
    expect(isIpLiteralHost("example.com")).toBe(false);
    expect(isUnsafeHostname("localhost")).toBe(true);
    expect(isUnsafeHostname("metadata.google.internal")).toBe(true);
    expect(isUnsafeHostname("example.com")).toBe(false);
  });

  it("rejects unsafe redirect targets before any network access", () => {
    expect(
      validateHttp01Target(new URL("http://127.0.0.1/x"), { initial: false })
    ).toContain("IP address");
    expect(
      validateHttp01Target(new URL("http://example.com:8080/x"), { initial: false })
    ).toContain("port 80");
    expect(
      validateHttp01Target(new URL("https://example.com:8443/x"), { initial: false })
    ).toContain("port 443");
    expect(
      validateHttp01Target(new URL("ftp://example.com/x"), { initial: false })
    ).toContain("HTTP or HTTPS");
    expect(
      validateHttp01Target(new URL("http://localhost/x"), { initial: false })
    ).not.toBeNull();
    expect(
      validateHttp01Target(new URL("http://example.com/x"), { initial: true })
    ).toBeNull();
    expect(
      validateHttp01Target(new URL("https://example.com/x"), { initial: true })
    ).toContain("must use HTTP");
  });
});

describe("HTTP-01 validation", () => {
  it("accepts a correct key authorization and ignores trailing whitespace", async () => {
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    install(
      challengeFetch([PUBLIC_A], async (input, init) => {
        requests.push({ url: String(input), init });
        return new Response(`${KEY_AUTHORIZATION} \r\n\t`, { status: 200 });
      })
    );

    const result = await validateHttp01Challenge("example.com", TOKEN, THUMBPRINT, {
      fetchImpl: globalThis.fetch,
    });

    expect(result.valid).toBe(true);
    expect(requests).toHaveLength(1);
    expect(requests[0].url).toBe(
      `http://example.com/.well-known/acme-challenge/${TOKEN}`
    );
    expect(new URL(requests[0].url).protocol).toBe("http:");
    expect(new URL(requests[0].url).port).toBe("");
    expect(requests[0].init?.redirect).toBe("manual");
    expect(requests[0].init?.cache).toBe("no-store");
  });

  it("accepts a target that resolves only to a public IPv6 address", async () => {
    install(
      challengeFetch([PUBLIC_AAAA], async () => new Response(KEY_AUTHORIZATION, { status: 200 }))
    );

    const result = await validateHttp01Challenge("example.com", TOKEN, THUMBPRINT, {
      fetchImpl: globalThis.fetch,
    });

    expect(result.valid).toBe(true);
    expect(result.addresses).toContain(PUBLIC_AAAA);
  });

  it("rejects leading or internal whitespace and wrong tokens/thumbprints", async () => {
    const cases = [
      ` ${KEY_AUTHORIZATION}`,
      `${TOKEN}.${THUMBPRINT}x`,
      `${TOKEN}.${"B".repeat(43)}`,
      `${TOKEN}.${THUMBPRINT}\n${TOKEN}.${THUMBPRINT}`,
    ];

    for (const body of cases) {
      install(
        challengeFetch([PUBLIC_A], async () => new Response(body, { status: 200 }))
      );
      const result = await validateHttp01Challenge(
        "example.com",
        TOKEN,
        THUMBPRINT,
        { fetchImpl: globalThis.fetch }
      );
      expect(result.valid, body).toBe(false);
      expect(result.errorType).toBe("incorrectResponse");
    }
  });

  it("rejects 404, 500, empty, and oversized responses", async () => {
    const responses: Array<[string, Response]> = [
      ["404", new Response("not found", { status: 404 })],
      ["500", new Response("error", { status: 500 })],
      ["empty", new Response("", { status: 200 })],
      ["oversized", new Response("x".repeat(9000), { status: 200 })],
    ];

    for (const [name, response] of responses) {
      install(challengeFetch([PUBLIC_A], async () => response));
      const result = await validateHttp01Challenge(
        "example.com",
        TOKEN,
        THUMBPRINT,
        { fetchImpl: globalThis.fetch }
      );
      expect(result.valid, name).toBe(false);
      expect(result.errorType, name).toBe("incorrectResponse");
    }
  });

  it("follows a legitimate relative redirect", async () => {
    const requested: string[] = [];
    install(
      challengeFetch([PUBLIC_A], async (input) => {
        const url = String(input);
        requested.push(url);
        if (url.endsWith("/.well-known/acme-challenge/final")) {
          return new Response(KEY_AUTHORIZATION, { status: 200 });
        }
        return new Response(null, {
          status: 302,
          headers: { Location: "/.well-known/acme-challenge/final" },
        });
      })
    );

    const result = await validateHttp01Challenge("example.com", TOKEN, THUMBPRINT, {
      fetchImpl: globalThis.fetch,
    });

    expect(result.valid).toBe(true);
    expect(result.redirects).toHaveLength(1);
    expect(requested.at(-1)).toContain("/.well-known/acme-challenge/final");
  });

  it("allows a redirect from HTTP/80 to HTTPS/443", async () => {
    install(
      challengeFetch([PUBLIC_A], async (input) => {
        const url = new URL(String(input));
        if (url.protocol === "https:") {
          return new Response(KEY_AUTHORIZATION, { status: 200 });
        }
        return new Response(null, {
          status: 301,
          headers: { Location: `https://${url.host}${url.pathname}` },
        });
      })
    );

    const result = await validateHttp01Challenge("example.com", TOKEN, THUMBPRINT, {
      fetchImpl: globalThis.fetch,
    });

    expect(result.valid).toBe(true);
    expect(result.redirects?.[0]).toMatch(/^https:\/\/example\.com\//);
  });

  it("accepts a cache HIT only when it contains the exact key authorization", async () => {
    // A cache HIT with the current token is a legitimate HTTP-01 response. A
    // stale cached body carries a different token and still fails the body
    // comparison, so cf-cache-status is not an independent rejection reason.
    install(
      challengeFetch(
        [PUBLIC_A],
        async () =>
          new Response(KEY_AUTHORIZATION, {
            status: 200,
            headers: { "CF-Cache-Status": "HIT" },
          })
      )
    );

    const accepted = await validateHttp01Challenge("example.com", TOKEN, THUMBPRINT, {
      fetchImpl: globalThis.fetch,
    });
    expect(accepted.valid).toBe(true);

    install(
      challengeFetch(
        [PUBLIC_A],
        async () =>
          new Response("stale-cached-value", {
            status: 200,
            headers: { "CF-Cache-Status": "HIT" },
          })
      )
    );

    const rejected = await validateHttp01Challenge("example.com", TOKEN, THUMBPRINT, {
      fetchImpl: globalThis.fetch,
    });
    expect(rejected.valid).toBe(false);
    expect(rejected.errorType).toBe("incorrectResponse");
    expect(rejected.error).toContain("key authorization");
  });

  it("enforces the redirect limit", async () => {
    install(
      challengeFetch([PUBLIC_A], async (input) => {
        const url = new URL(String(input));
        return new Response(null, {
          status: 302,
          headers: { Location: `${url.pathname}/next` },
        });
      })
    );

    const result = await validateHttp01Challenge("example.com", TOKEN, THUMBPRINT, {
      fetchImpl: globalThis.fetch,
      maxRedirects: 2,
    });

    expect(result.valid).toBe(false);
    expect(result.error).toContain("Too many");
  });

  it("rejects redirects to private, local, IP-literal, and non-default ports", async () => {
    const targets = [
      "http://internal.example.org/",
      "http://127.0.0.1/",
      "http://localhost/",
      "http://example.com:8080/",
      "ftp://example.com/",
    ];

    for (const target of targets) {
      install(async (input) => {
        const url = String(input);
        if (isDohUrl(url)) {
          return dohResponse(
            url,
            url.includes("internal.example.org") ? ["10.0.0.1"] : [PUBLIC_A]
          );
        }
        return new Response(null, {
          status: 302,
          headers: { Location: target },
        });
      });

      const result = await validateHttp01Challenge(
        "example.com",
        TOKEN,
        THUMBPRINT,
        { fetchImpl: globalThis.fetch }
      );
      expect(result.valid, target).toBe(false);
      expect(result.errorType, target).toBe("unauthorized");
    }
  });

  it("rejects a target when any A/AAAA answer is non-public, not just the first", async () => {
    let challengeRequests = 0;
    install(
      challengeFetch(["93.184.216.34", "fc00::1"], async () => {
        challengeRequests++;
        return new Response(KEY_AUTHORIZATION, { status: 200 });
      })
    );

    const result = await validateHttp01Challenge("example.com", TOKEN, THUMBPRINT, {
      fetchImpl: globalThis.fetch,
    });

    expect(result.valid).toBe(false);
    expect(result.errorType).toBe("unauthorized");
    expect(result.error).toContain("non-public");
    expect(challengeRequests).toBe(0);
  });

  it("fails an HTTPS redirect when the validation network rejects the origin certificate", async () => {
    // Workers fetch performs outbound TLS with Full (strict) verification and
    // no opt-out; an untrusted certificate surfaces as an error response (526)
    // or a fetch failure. Either way HTTP-01 cannot accept the body.
    install(
      challengeFetch([PUBLIC_A], async (input) => {
        const url = new URL(String(input));
        if (url.protocol === "https:") {
          return new Response("Invalid SSL certificate", { status: 526 });
        }
        return new Response(null, {
          status: 301,
          headers: { Location: `https://${url.host}${url.pathname}` },
        });
      })
    );

    const result = await validateHttp01Challenge("example.com", TOKEN, THUMBPRINT, {
      fetchImpl: globalThis.fetch,
    });

    expect(result.valid).toBe(false);
    expect(result.errorType).toBe("incorrectResponse");
    expect(result.error).toContain("526");
  });

  it("rejects a target that resolves to a private address before making the HTTP request", async () => {
    let challengeRequests = 0;
    install(
      challengeFetch(["10.0.0.1"], async () => {
        challengeRequests++;
        return new Response(KEY_AUTHORIZATION, { status: 200 });
      })
    );

    const result = await validateHttp01Challenge("example.com", TOKEN, THUMBPRINT, {
      fetchImpl: globalThis.fetch,
    });

    expect(result.valid).toBe(false);
    expect(result.errorType).toBe("unauthorized");
    expect(result.error).toContain("non-public");
    expect(challengeRequests).toBe(0);
  });

  it("fails closed when DNS resolution fails", async () => {
    install(async () => new Response("bad gateway", { status: 502 }));

    const result = await validateHttp01Challenge("example.com", TOKEN, THUMBPRINT, {
      fetchImpl: globalThis.fetch,
    });

    expect(result.valid).toBe(false);
    expect(result.errorType).toBe("dns");
  });

  it("times out a hanging validation request", async () => {
    install(
      challengeFetch([PUBLIC_A], async () => new Promise<Response>(() => {}))
    );

    const result = await validateHttp01Challenge("example.com", TOKEN, THUMBPRINT, {
      fetchImpl: globalThis.fetch,
      requestTimeoutMs: 20,
      totalTimeoutMs: 60,
    });

    expect(result.valid).toBe(false);
    expect(result.errorType).toBe("connection");
    expect(result.error).toContain("timed out");
  });

  it("rejects wildcard and malformed identifiers without network access", async () => {
    let requests = 0;
    install(async () => {
      requests++;
      return new Response("", { status: 200 });
    });

    const wildcard = await validateHttp01Challenge("*.example.com", TOKEN, THUMBPRINT, {
      fetchImpl: globalThis.fetch,
    });
    expect(wildcard.valid).toBe(false);
    expect(wildcard.errorType).toBe("malformed");

    const badToken = await validateHttp01Challenge("example.com", "short", THUMBPRINT, {
      fetchImpl: globalThis.fetch,
    });
    expect(badToken.valid).toBe(false);
    expect(badToken.errorType).toBe("malformed");

    expect(requests).toBe(0);
  });
});
