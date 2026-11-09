import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as x509 from "@peculiar/x509";
import worker from "../src/index";
import { AcmeEnv } from "../src/config";
import { Database } from "../src/db/queries";
import { base64UrlEncode } from "../src/crypto/nonce";
import { computeExpectedDnsDigest } from "../src/dns/validator";
import {
  ACME_BASE_URL,
  TestAccount,
  createOrder,
  createTestEnvironment,
  dohAnswer,
  getAuthorization,
  getNonce,
  installFetchMock,
  makeCsr,
  makeJwsRequest,
  registerAccount,
  testContext,
  triggerChallenge,
} from "./acme-test-helpers";

const PUBLIC_A = "93.184.216.34";

function isDohUrl(url: string): boolean {
  return (
    url.startsWith("https://cloudflare-dns.com/dns-query") ||
    url.startsWith("https://dns.google/resolve")
  );
}

describe("HTTP-01 ACME integration", () => {
  let env: AcmeEnv;
  let database: Database;
  let account: TestAccount;
  let restoreFetch: (() => void) | null = null;

  beforeEach(async () => {
    ({ env, database } = await createTestEnvironment());
    account = await registerAccount(env);
    restoreFetch = null;
  });

  afterEach(() => {
    restoreFetch?.();
    restoreFetch = null;
  });

  function installHttpMock(options: {
    addresses?: string[];
    challenge?: (url: string) => Response | Promise<Response>;
    caaRecords?: string[];
  }): void {
    const addresses = options.addresses ?? [PUBLIC_A];
    restoreFetch = installFetchMock(async (input) => {
      const url = String(input);
      if (isDohUrl(url)) {
        const type = new URL(url).searchParams.get("type");
        if (type === "A") {
          return dohAnswer(
            addresses
              .filter((address) => !address.includes(":"))
              .map((data) => ({ type: 1, data }))
          );
        }
        if (type === "AAAA") {
          return dohAnswer(
            addresses
              .filter((address) => address.includes(":"))
              .map((data) => ({ type: 28, data }))
          );
        }
        // CAA queries default to no records, which permits issuance.
        return dohAnswer(
          (options.caaRecords ?? []).map((data) => ({ type: 257, data }))
        );
      }
      if (options.challenge) {
        return options.challenge(url);
      }
      return new Response("not found", { status: 404 });
    });
  }

  async function getHttp01Challenge(domain = "example.com") {
    const order = await createOrder(env, account, [{ type: "dns", value: domain }]);
    const authzUrl = (order.body.authorizations as string[])[0];
    const authz = await getAuthorization(env, account, authzUrl, order.nonce);
    const challenges = authz.body.challenges as Array<{
      type: string;
      url: string;
      token: string;
      status: string;
    }>;
    const http = challenges.find((challenge) => challenge.type === "http-01");
    return { order, authzUrl, authz, challenges, http, nonce: authz.nonce };
  }

  async function getOrderBody(orderUrl: string, nonce: string) {
    const result = await makeJwsRequest(env, orderUrl, "", account, nonce);
    return {
      body: (await result.response.json()) as Record<string, unknown>,
      nonce: result.nextNonce,
      status: result.response.status,
    };
  }

  interface AuthzChallenge {
    type: string;
    url: string;
    token: string;
    status: string;
  }

  /**
   * Creates an order with two domains, returning the dns-01 challenge for the
   * first and the http-01 challenge for the second.
   */
  async function setupMixedMethodOrder() {
    const order = await createOrder(env, account, [
      { type: "dns", value: "dns.example.com" },
      { type: "dns", value: "http.example.com" },
    ]);
    const [dnsAuthzUrl, httpAuthzUrl] = order.body.authorizations as string[];
    const dnsAuthz = await getAuthorization(env, account, dnsAuthzUrl, order.nonce);
    const httpAuthz = await getAuthorization(env, account, httpAuthzUrl, dnsAuthz.nonce);
    const dns = (dnsAuthz.body.challenges as AuthzChallenge[]).find(
      (challenge) => challenge.type === "dns-01"
    )!;
    const http = (httpAuthz.body.challenges as AuthzChallenge[]).find(
      (challenge) => challenge.type === "http-01"
    )!;
    const dnsDigest = await computeExpectedDnsDigest(dns.token, account.thumbprint);
    return { order, dns, http, dnsDigest, nonce: httpAuthz.nonce };
  }

  function installMixedMethodFetch(options: {
    dnsDigest: string;
    httpToken: string;
    caaByDomain: Record<string, string>;
  }): void {
    restoreFetch = installFetchMock(async (input) => {
      const url = new URL(String(input));
      if (isDohUrl(url.href)) {
        const name = url.searchParams.get("name") || "";
        const type = url.searchParams.get("type");
        if (type === "TXT") {
          return dohAnswer(
            name === "_acme-challenge.dns.example.com"
              ? [{ type: 16, data: `"${options.dnsDigest}"` }]
              : []
          );
        }
        if (type === "A") {
          return dohAnswer([{ type: 1, data: PUBLIC_A }]);
        }
        if (type === "AAAA") {
          return dohAnswer([]);
        }
        if (type === "CAA") {
          const value = options.caaByDomain[name];
          return dohAnswer(value ? [{ type: 257, data: value }] : []);
        }
      }
      return new Response(`${options.httpToken}.${account.thumbprint}`, {
        status: 200,
      });
    });
  }

  async function validateMixedMethodOrder(context: {
    dns: AuthzChallenge;
    http: AuthzChallenge;
    nonce: string;
  }) {
    const dnsResult = await triggerChallenge(env, account, context.dns.url, context.nonce);
    expect(dnsResult.body.status).toBe("valid");
    const httpResult = await triggerChallenge(env, account, context.http.url, dnsResult.nonce);
    expect(httpResult.body.status).toBe("valid");
    return httpResult;
  }

  it("creates an HTTP-01 challenge, validates it, marks the order ready and issues a 90-day certificate", async () => {
    const { order, authz, challenges, http, nonce } = await getHttp01Challenge();

    expect(order.response.status).toBe(201);
    expect(authz.body.status).toBe("pending");
    expect(challenges.map((challenge) => challenge.type).sort()).toEqual([
      "dns-01",
      "http-01",
    ]);
    expect(http).toBeDefined();
    expect(http!.status).toBe("pending");
    expect(http!.url).toBe(`${ACME_BASE_URL}/challenge/${http!.url.split("/").pop()}`);
    expect(http!.token).toMatch(/^[A-Za-z0-9_-]{22,}$/);
    expect(http!.token).not.toContain("=");

    const keyAuthorization = `${http!.token}.${account.thumbprint}`;
    installHttpMock({
      challenge: async () =>
        new Response(`${keyAuthorization} \n`, { status: 200 }),
    });

    const triggered = await triggerChallenge(env, account, http!.url, nonce);
    expect(triggered.response.status).toBe(200);
    expect(triggered.body.type).toBe("http-01");
    expect(triggered.body.status).toBe("valid");
    expect(typeof triggered.body.validated).toBe("string");

    const ready = await getOrderBody(order.url, triggered.nonce);
    expect(ready.body.status).toBe("ready");

    const csr = await makeCsr(["example.com"]);
    const finalized = await makeJwsRequest(
      env,
      `${order.url}/finalize`,
      { csr },
      account,
      ready.nonce
    );
    expect(finalized.response.status).toBe(200);
    const finalizedBody = (await finalized.response.json()) as {
      status: string;
      certificate: string;
    };
    expect(finalizedBody.status).toBe("valid");
    expect(finalizedBody.certificate).toContain(`${ACME_BASE_URL}/cert/`);

    const certResponse = await worker.fetch(
      new Request(finalizedBody.certificate),
      env,
      testContext
    );
    expect(certResponse.status).toBe(200);
    const chain = await certResponse.text();
    const leaf = new x509.X509Certificate(chain);
    expect(leaf.subject).toBe("CN=example.com");
    const validityDays =
      (leaf.notAfter.getTime() - leaf.notBefore.getTime()) / (86400 * 1000);
    expect(Math.round(validityDays)).toBe(90);
  });

  it("rejects finalize CSRs whose SANs differ from the order, including IP SANs", async () => {
    const { order, http, nonce } = await getHttp01Challenge();
    installHttpMock({
      challenge: async () =>
        new Response(`${http!.token}.${account.thumbprint}`, { status: 200 }),
    });

    const triggered = await triggerChallenge(env, account, http!.url, nonce);
    expect(triggered.body.status).toBe("valid");
    const ready = await getOrderBody(order.url, triggered.nonce);
    expect(ready.body.status).toBe("ready");

    // An extra DNS SAN not present in the order must be rejected.
    const extraCsr = await makeCsr(["example.com", "evil.example.com"]);
    const extra = await makeJwsRequest(
      env,
      `${order.url}/finalize`,
      { csr: extraCsr },
      account,
      ready.nonce
    );
    expect(extra.response.status).toBe(400);
    expect(((await extra.response.json()) as { type: string }).type).toBe(
      "urn:ietf:params:acme:error:badCSR"
    );

    // A bad CSR must leave the order ready so the client can retry.
    const afterExtra = await getOrderBody(order.url, extra.nextNonce);
    expect(afterExtra.body.status).toBe("ready");

    // An IP SAN is an identifier the order never authorized and must be
    // rejected even though the server would only copy order domains into the
    // issued certificate.
    const certKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const ipCsr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=example.com",
      keys: certKeys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new x509.SubjectAlternativeNameExtension([
          { type: "dns", value: "example.com" },
          { type: "ip", value: "192.0.2.1" },
        ]),
      ],
    });
    const ipResult = await makeJwsRequest(
      env,
      `${order.url}/finalize`,
      { csr: base64UrlEncode(ipCsr.rawData) },
      account,
      afterExtra.nonce
    );
    expect(ipResult.response.status).toBe(400);
    expect(((await ipResult.response.json()) as { type: string }).type).toBe(
      "urn:ietf:params:acme:error:badCSR"
    );

    const afterIp = await getOrderBody(order.url, ipResult.nextNonce);
    expect(afterIp.body.status).toBe("ready");

    const correct = await makeJwsRequest(
      env,
      `${order.url}/finalize`,
      { csr: await makeCsr(["example.com"]) },
      account,
      afterIp.nonce
    );
    expect(correct.response.status).toBe(200);
  });

  it("keeps an order pending until every authorization is valid", async () => {
    const order = await createOrder(env, account, [
      { type: "dns", value: "example.com" },
      { type: "dns", value: "www.example.com" },
    ]);
    const [authzUrl1, authzUrl2] = order.body.authorizations as string[];

    const authz1 = await getAuthorization(env, account, authzUrl1, order.nonce);
    const authz2 = await getAuthorization(env, account, authzUrl2, authz1.nonce);
    const http1 = (authz1.body.challenges as Array<{ type: string; url: string }>).find(
      (challenge) => challenge.type === "http-01"
    )!;
    const http2 = (authz2.body.challenges as Array<{ type: string; url: string }>).find(
      (challenge) => challenge.type === "http-01"
    )!;

    installHttpMock({
      challenge: async (url) => {
        const token = new URL(url).pathname.split("/").pop()!;
        return new Response(`${token}.${account.thumbprint}`, { status: 200 });
      },
    });

    const first = await triggerChallenge(env, account, http1.url, authz2.nonce);
    expect(first.body.status).toBe("valid");
    const afterFirst = await getOrderBody(order.url, first.nonce);
    expect(afterFirst.body.status).toBe("pending");

    const second = await triggerChallenge(env, account, http2.url, afterFirst.nonce);
    expect(second.body.status).toBe("valid");
    const afterSecond = await getOrderBody(order.url, second.nonce);
    expect(afterSecond.body.status).toBe("ready");
  });

  it("invalidates the challenge, authorization and order on a wrong key authorization and finalize is rejected", async () => {
    const { order, authzUrl, http, nonce } = await getHttp01Challenge();

    installHttpMock({
      challenge: async () => new Response("wrong-token-value", { status: 200 }),
    });

    const triggered = await triggerChallenge(env, account, http!.url, nonce);
    expect(triggered.response.status).toBe(200);
    expect(triggered.body.status).toBe("invalid");
    const error = triggered.body.error as { type: string; detail: string; status: number };
    expect(error.type).toBe("urn:ietf:params:acme:error:incorrectResponse");
    expect(error.detail).toBeTruthy();

    const authz = await getAuthorization(env, account, authzUrl, triggered.nonce);
    expect(authz.body.status).toBe("invalid");
    const challengeStates = (authz.body.challenges as Array<{ status: string }>).map(
      (challenge) => challenge.status
    );
    expect(challengeStates.every((status) => status === "invalid")).toBe(true);

    const orderBody = await getOrderBody(order.url, authz.nonce);
    expect(orderBody.body.status).toBe("invalid");

    const csr = await makeCsr(["example.com"]);
    const finalized = await makeJwsRequest(
      env,
      `${order.url}/finalize`,
      { csr },
      account,
      orderBody.nonce
    );
    expect(finalized.response.status).toBe(403);
    const problem = (await finalized.response.json()) as { type: string };
    expect(problem.type).toBe("urn:ietf:params:acme:error:orderNotReady");

    const certCount = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM certificates"
    ).first<{ count: number }>();
    expect(certCount?.count).toBe(0);
  });

  it("does not re-run validation once a challenge is invalid", async () => {
    const { http, nonce } = await getHttp01Challenge();
    let challengeRequests = 0;

    installHttpMock({
      challenge: async () => {
        challengeRequests++;
        return new Response("wrong", { status: 200 });
      },
    });

    const first = await triggerChallenge(env, account, http!.url, nonce);
    expect(first.body.status).toBe("invalid");
    expect(challengeRequests).toBe(1);

    const secondNonce = await getNonce(env);
    const second = await triggerChallenge(env, account, http!.url, secondNonce);
    expect(second.body.status).toBe("invalid");
    expect(challengeRequests).toBe(1);
  });

  it("rejects non-public IP identifiers without creating an order", async () => {
    const result = await createOrder(env, account, [
      { type: "ip", value: "192.0.2.1" },
    ]);

    expect(result.response.status).toBe(400);
    expect(result.body.type).toBe(
      "urn:ietf:params:acme:error:rejectedIdentifier"
    );
    expect(String(result.body.detail).toLowerCase()).toContain("ip");

    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM orders").first<{
      count: number;
    }>();
    expect(count?.count).toBe(0);
  });

  it("offers only dns-01 for wildcard identifiers and rejects an injected HTTP-01 challenge", async () => {
    const { authzUrl, authz, challenges, nonce } = await getHttp01Challenge("*.example.com");

    expect(challenges.map((challenge) => challenge.type)).toEqual(["dns-01"]);
    expect(authz.body.wildcard).toBe(true);
    // RFC 8555 § 7.1.4: the wildcard authorization identifier is the base
    // domain, with the "*." prefix removed.
    expect((authz.body.identifier as { value: string }).value).toBe("example.com");

    const authzId = authzUrl.split("/").pop()!;
    const injectedId = crypto.randomUUID();
    await database.saveChallenge({
      id: injectedId,
      authorization_id: authzId,
      type: "http-01",
      token: "a".repeat(22),
      status: "pending",
      error: null,
      validated_at: null,
      processing_started_at: null,
      validation_generation: 0,
      created_at: Math.floor(Date.now() / 1000),
    });

    installHttpMock({
      challenge: async () => new Response("should-not-be-reached", { status: 200 }),
    });

    const triggered = await triggerChallenge(
      env,
      account,
      `${ACME_BASE_URL}/challenge/${injectedId}`,
      nonce
    );
    expect(triggered.body.status).toBe("invalid");
    const error = triggered.body.error as { type: string };
    expect(error.type).toBe("urn:ietf:params:acme:error:malformed");

    const dbChallenge = await database.getChallengeById(injectedId);
    expect(dbChallenge?.status).toBe("invalid");
  });

  it("finalizes a wildcard order when the CSR SAN matches the wildcard identifier", async () => {
    const { order, challenges, nonce } = await getHttp01Challenge("*.example.com");
    const dns = challenges.find((challenge) => challenge.type === "dns-01")!;
    const dnsDigest = await computeExpectedDnsDigest(dns.token, account.thumbprint);

    restoreFetch = installFetchMock(async (input) => {
      const url = new URL(String(input));
      if (isDohUrl(url.href)) {
        const type = url.searchParams.get("type");
        if (type === "TXT") {
          return dohAnswer([{ type: 16, data: `"${dnsDigest}"` }]);
        }
        if (type === "A") {
          return dohAnswer([{ type: 1, data: PUBLIC_A }]);
        }
        if (type === "AAAA" || type === "CAA") {
          return dohAnswer([]);
        }
      }
      return new Response("not found", { status: 404 });
    });

    const triggered = await triggerChallenge(env, account, dns.url, nonce);
    expect(triggered.body.status).toBe("valid");
    const ready = await getOrderBody(order.url, triggered.nonce);
    expect(ready.body.status).toBe("ready");

    const finalized = await makeJwsRequest(
      env,
      `${order.url}/finalize`,
      { csr: await makeCsr(["*.example.com"]) },
      account,
      ready.nonce
    );
    expect(finalized.response.status).toBe(200);
    const body = (await finalized.response.json()) as {
      status: string;
      certificate: string;
    };
    expect(body.status).toBe("valid");

    const certResponse = await worker.fetch(
      new Request(body.certificate),
      env,
      testContext
    );
    const leaf = new x509.X509Certificate(await certResponse.text());
    expect(leaf.subject).toBe("CN=*.example.com");
  });

  it("rejects finalization after authorization expiry", async () => {
    const { order, authzUrl, nonce } = await getHttp01Challenge();
    const authzId = authzUrl.split("/").pop()!;
    await env.DB.prepare(
      "UPDATE authorizations SET status = 'valid', expires_at = ? WHERE id = ?"
    )
      .bind(Math.floor(Date.now() / 1000) - 10, authzId)
      .run();
    await env.DB.prepare("UPDATE orders SET status = 'ready' WHERE id = ?")
      .bind(order.url.split("/").pop())
      .run();

    const csr = await makeCsr(["example.com"]);
    const finalized = await makeJwsRequest(
      env,
      `${order.url}/finalize`,
      { csr },
      account,
      nonce
    );
    expect(finalized.response.status).toBe(403);
    const problem = (await finalized.response.json()) as { type: string };
    expect(problem.type).toBe("urn:ietf:params:acme:error:orderNotReady");

    const certCount = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM certificates"
    ).first<{ count: number }>();
    expect(certCount?.count).toBe(0);
  });

  it("allows concurrent dns-01 and http-01 successes without invalidating the order", async () => {
    const { order, authzUrl, challenges } = await getHttp01Challenge();
    const dns = challenges.find((challenge) => challenge.type === "dns-01")!;
    const http = challenges.find((challenge) => challenge.type === "http-01")!;
    const dnsDigest = await computeExpectedDnsDigest(dns.token, account.thumbprint);

    restoreFetch = installFetchMock(async (input) => {
      const url = String(input);
      if (isDohUrl(url)) {
        const type = new URL(url).searchParams.get("type");
        if (type === "TXT") {
          return dohAnswer([{ type: 16, data: `"${dnsDigest}"` }]);
        }
        if (type === "A") {
          return dohAnswer([{ type: 1, data: PUBLIC_A }]);
        }
        return dohAnswer([]);
      }
      return new Response(`${http.token}.${account.thumbprint}`, { status: 200 });
    });

    const nonce1 = await getNonce(env);
    const nonce2 = await getNonce(env);
    const [dnsResult, httpResult] = await Promise.all([
      triggerChallenge(env, account, dns.url, nonce1),
      triggerChallenge(env, account, http.url, nonce2),
    ]);
    expect(dnsResult.body.status).toBe("valid");
    expect(httpResult.body.status).toBe("valid");

    const nonce = await getNonce(env);
    const authz = await getAuthorization(env, account, authzUrl, nonce);
    expect(authz.body.status).toBe("valid");
    const states = (authz.body.challenges as Array<{ status: string }>).map(
      (challenge) => challenge.status
    );
    expect(states.sort()).toEqual(["valid", "valid"]);

    const orderBody = await getOrderBody(order.url, authz.nonce);
    expect(orderBody.body.status).toBe("ready");
  });

  it("serializes concurrent challenge submissions into a single validation", async () => {
    const { order, authzUrl, http } = await getHttp01Challenge();
    const keyAuthorization = `${http!.token}.${account.thumbprint}`;

    let challengeRequests = 0;
    let releaseGate: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      releaseGate = resolve;
    });

    installHttpMock({
      challenge: async () => {
        challengeRequests++;
        await gate;
        return new Response(keyAuthorization, { status: 200 });
      },
    });

    const nonce1 = await getNonce(env);
    const nonce2 = await getNonce(env);

    const first = triggerChallenge(env, account, http!.url, nonce1);
    const second = triggerChallenge(env, account, http!.url, nonce2);

    // Give the second request time to observe the `processing` claim.
    await new Promise((resolve) => setTimeout(resolve, 25));
    releaseGate();

    const [firstResult, secondResult] = await Promise.all([first, second]);
    expect(challengeRequests).toBe(1);
    expect(["valid", "processing"]).toContain(firstResult.body.status);
    expect(["valid", "processing"]).toContain(secondResult.body.status);

    const nonce = await getNonce(env);
    const authz = await getAuthorization(env, account, authzUrl, nonce);
    expect(authz.body.status).toBe("valid");

    const orderBody = await getOrderBody(order.url, authz.nonce);
    expect(orderBody.body.status).toBe("ready");
  });

  it("finalizes when CAA validationmethods allows the HTTP-01 method used", async () => {
    const { order, http, nonce } = await getHttp01Challenge();
    const keyAuthorization = `${http!.token}.${account.thumbprint}`;
    installHttpMock({
      caaRecords: [
        '0 issue "cfms-pki.crpteam.club; validationmethods=http-01"',
      ],
      challenge: async () => new Response(keyAuthorization, { status: 200 }),
    });

    const triggered = await triggerChallenge(env, account, http!.url, nonce);
    expect(triggered.body.status).toBe("valid");
    const ready = await getOrderBody(order.url, triggered.nonce);
    expect(ready.body.status).toBe("ready");

    const csr = await makeCsr(["example.com"]);
    const finalized = await makeJwsRequest(
      env,
      `${order.url}/finalize`,
      { csr },
      account,
      ready.nonce
    );
    expect(finalized.response.status).toBe(200);
    const body = (await finalized.response.json()) as { status: string };
    expect(body.status).toBe("valid");
  });

  it("rejects finalization when CAA limits validation to dns-01 but HTTP-01 was used", async () => {
    const { order, http, nonce } = await getHttp01Challenge();
    const keyAuthorization = `${http!.token}.${account.thumbprint}`;
    installHttpMock({
      caaRecords: [
        '0 issue "cfms-pki.crpteam.club; validationmethods=dns-01"',
      ],
      challenge: async () => new Response(keyAuthorization, { status: 200 }),
    });

    const triggered = await triggerChallenge(env, account, http!.url, nonce);
    expect(triggered.body.status).toBe("valid");
    const ready = await getOrderBody(order.url, triggered.nonce);
    expect(ready.body.status).toBe("ready");

    const csr = await makeCsr(["example.com"]);
    const finalized = await makeJwsRequest(
      env,
      `${order.url}/finalize`,
      { csr },
      account,
      ready.nonce
    );
    expect(finalized.response.status).toBe(403);
    const problem = (await finalized.response.json()) as { type: string };
    expect(problem.type).toBe("urn:ietf:params:acme:error:caa");

    const certCount = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM certificates"
    ).first<{ count: number }>();
    expect(certCount?.count).toBe(0);
  });

  it("prevents concurrent finalize requests from issuing more than one certificate", async () => {
    const { order, http, nonce } = await getHttp01Challenge();
    const keyAuthorization = `${http!.token}.${account.thumbprint}`;
    installHttpMock({
      challenge: async () => new Response(keyAuthorization, { status: 200 }),
    });

    const triggered = await triggerChallenge(env, account, http!.url, nonce);
    expect(triggered.body.status).toBe("valid");
    const ready = await getOrderBody(order.url, triggered.nonce);
    expect(ready.body.status).toBe("ready");

    const csr = await makeCsr(["example.com"]);
    const nonce1 = await getNonce(env);
    const nonce2 = await getNonce(env);
    const [first, second] = await Promise.all([
      makeJwsRequest(env, `${order.url}/finalize`, { csr }, account, nonce1),
      makeJwsRequest(env, `${order.url}/finalize`, { csr }, account, nonce2),
    ]);

    expect([first.response.status, second.response.status]).toContain(200);
    const certCount = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM certificates"
    ).first<{ count: number }>();
    expect(certCount?.count).toBe(1);
  });

  it("marks a challenge invalid instead of leaving it processing when validation throws", async () => {
    const { order, http, nonce } = await getHttp01Challenge();

    installHttpMock({
      challenge: async () => {
        throw new Error("unexpected network failure with internal details");
      },
    });

    const triggered = await triggerChallenge(env, account, http!.url, nonce);
    expect(triggered.body.status).toBe("invalid");
    const error = triggered.body.error as { type: string; detail: string };
    expect(error.type).toBe("urn:ietf:params:acme:error:connection");
    expect(error.detail).not.toContain("internal details");

    const challengeId = http!.url.split("/").pop()!;
    const dbChallenge = await database.getChallengeById(challengeId);
    expect(dbChallenge?.status).toBe("invalid");
    expect(dbChallenge?.processing_started_at).toBeNull();

    const orderBody = await getOrderBody(order.url, triggered.nonce);
    expect(orderBody.body.status).toBe("invalid");
  });

  it("rejects challenge access by a different account", async () => {
    const { http } = await getHttp01Challenge();
    const otherAccount = await registerAccount(env);
    const nonce = await getNonce(env);

    const result = await makeJwsRequest(
      env,
      http!.url,
      {},
      otherAccount,
      nonce
    );
    expect(result.response.status).toBe(403);

    const status = await env.DB.prepare(
      "SELECT status FROM challenges WHERE id = ?"
    )
      .bind(http!.url.split("/").pop())
      .first<{ status: string }>();
    expect(status?.status).toBe("pending");
  });

  it("allows CAA validationmethods=http-01 when HTTP-01 was actually used", async () => {
    const { evaluateCaaRecords } = await import("../src/dns/caa");
    const record = {
      flags: 0,
      tag: "issue",
      value: "cfms-pki.crpteam.club; validationmethods=http-01",
      issuerDomain: "cfms-pki.crpteam.club",
      parameters: { validationmethods: "http-01" },
    };

    expect(
      evaluateCaaRecords([record], false, undefined, "cfms-pki.crpteam.club", [
        "http-01",
      ]).valid
    ).toBe(true);
    expect(
      evaluateCaaRecords([record], false, undefined, "cfms-pki.crpteam.club", [
        "dns-01",
      ]).valid
    ).toBe(false);
  });

  it("evaluates CAA validationmethods against each domain's actual method in a mixed order", async () => {
    const context = await setupMixedMethodOrder();
    installMixedMethodFetch({
      dnsDigest: context.dnsDigest,
      httpToken: context.http.token,
      caaByDomain: {
        "dns.example.com":
          '0 issue "cfms-pki.crpteam.club; validationmethods=dns-01"',
        "http.example.com":
          '0 issue "cfms-pki.crpteam.club; validationmethods=http-01"',
      },
    });

    const triggered = await validateMixedMethodOrder(context);
    const ready = await getOrderBody(context.order.url, triggered.nonce);
    expect(ready.body.status).toBe("ready");

    const finalized = await makeJwsRequest(
      env,
      `${context.order.url}/finalize`,
      { csr: await makeCsr(["dns.example.com", "http.example.com"]) },
      account,
      ready.nonce
    );
    expect(finalized.response.status).toBe(200);
    expect(((await finalized.response.json()) as { status: string }).status).toBe(
      "valid"
    );
  });

  it("rejects finalize when CAA validationmethods does not allow the method actually used for a domain", async () => {
    const context = await setupMixedMethodOrder();
    // Deliberately swap the allowed methods: dns.example.com was validated
    // with dns-01 and http.example.com with http-01, so neither record
    // authorizes the method actually used.
    installMixedMethodFetch({
      dnsDigest: context.dnsDigest,
      httpToken: context.http.token,
      caaByDomain: {
        "dns.example.com":
          '0 issue "cfms-pki.crpteam.club; validationmethods=http-01"',
        "http.example.com":
          '0 issue "cfms-pki.crpteam.club; validationmethods=dns-01"',
      },
    });

    const triggered = await validateMixedMethodOrder(context);
    const ready = await getOrderBody(context.order.url, triggered.nonce);
    expect(ready.body.status).toBe("ready");

    const finalized = await makeJwsRequest(
      env,
      `${context.order.url}/finalize`,
      { csr: await makeCsr(["dns.example.com", "http.example.com"]) },
      account,
      ready.nonce
    );
    expect(finalized.response.status).toBe(403);
    expect(((await finalized.response.json()) as { type: string }).type).toBe(
      "urn:ietf:params:acme:error:caa"
    );

    const certCount = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM certificates"
    ).first<{ count: number }>();
    expect(certCount?.count).toBe(0);
  });

  it("finalizes a legacy order whose authorizations predate the challenges table", async () => {
    const order = await createOrder(env, account, [
      { type: "dns", value: "legacy.example.com" },
    ]);
    const authzUrl = (order.body.authorizations as string[])[0];
    const authzId = authzUrl.split("/").pop()!;
    const now = Math.floor(Date.now() / 1000);

    // Simulate a pre-HTTP-01 order: no challenge rows at all, authorization
    // already valid, order already ready.
    await env.DB.prepare("DELETE FROM challenges WHERE authorization_id = ?")
      .bind(authzId)
      .run();
    await env.DB.prepare(
      "UPDATE authorizations SET status = 'valid', expires_at = ? WHERE id = ?"
    )
      .bind(now + 3600, authzId)
      .run();
    await env.DB.prepare("UPDATE orders SET status = 'ready' WHERE id = ?")
      .bind(order.url.split("/").pop())
      .run();

    // CAA lookups return no records, which permits issuance.
    installHttpMock({});

    const finalized = await makeJwsRequest(
      env,
      `${order.url}/finalize`,
      { csr: await makeCsr(["legacy.example.com"]) },
      account,
      order.nonce
    );
    expect(finalized.response.status).toBe(200);
    const body = (await finalized.response.json()) as {
      status: string;
      certificate: string;
    };
    expect(body.status).toBe("valid");

    const certResponse = await worker.fetch(
      new Request(body.certificate),
      env,
      testContext
    );
    const leaf = new x509.X509Certificate(await certResponse.text());
    expect(leaf.subject).toBe("CN=legacy.example.com");
  });
});
