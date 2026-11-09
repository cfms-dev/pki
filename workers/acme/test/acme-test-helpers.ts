import { testAssets } from "./website-test-helpers";
import { mockCaCertificate } from "./ca-test-helpers";
import * as x509 from "@peculiar/x509";
import worker from "../src/index";
import { AcmeEnv } from "../src/config";
import { Database } from "../src/db/queries";
import { createMockD1Database } from "./mock-d1";
import { base64UrlEncode } from "../src/crypto/nonce";
import { calculateJwkThumbprint } from "../src/crypto/jws";

export const ACME_BASE_URL = "https://acme.test";

export type AccountKeyAlgorithm = "ES256" | "RS256" | "EdDSA";

export interface TestAccount {
  keys: CryptoKeyPair;
  jwk: JsonWebKey;
  thumbprint: string;
  kid: string;
  /** JWS algorithm used to sign requests for this account. Defaults to ES256. */
  alg?: AccountKeyAlgorithm;
}

export interface TestEnvironment {
  env: AcmeEnv;
  database: Database;
  d1: D1Database;
  caFixture: { pem: string };
}

interface CaMaterial {
  certPem: string;
  keyPem: string;
}

let caMaterialPromise: Promise<CaMaterial> | null = null;

async function createCaMaterial(): Promise<CaMaterial> {
  const keys = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: "0102030405060708090a",
    subject: "CN=HTTP-01 Test Intermediate CA, O=CFMS",
    issuer: "CN=CFMS Root CA",
    notBefore: new Date(Date.now() - 10000),
    notAfter: new Date(Date.now() + 365 * 86400 * 1000),
    publicKey: keys.publicKey,
    signingKey: keys.privateKey,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
    ],
  });

  const pkcs8 = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
  return {
    certPem: cert.toString("pem"),
    keyPem: `-----BEGIN PRIVATE KEY-----\n${Buffer.from(pkcs8 as ArrayBuffer).toString("base64")}\n-----END PRIVATE KEY-----`,
  };
}

export async function createTestEnvironment(): Promise<TestEnvironment> {
  caMaterialPromise ??= createCaMaterial();
  const ca = await caMaterialPromise;

  const d1 = createMockD1Database();
  const database = new Database(d1);
  await database.initSchema();

  const caFixture = mockCaCertificate(ca.certPem);
  const env: AcmeEnv = {
    ASSETS: testAssets,
    DB: d1,
    PK_GENERIC_INTERMEDIATE: ca.keyPem,
  };

  return { env, database, d1, caFixture };
}

export const testContext = {
  waitUntil: () => {},
  passThroughOnException: () => {},
} as unknown as ExecutionContext;

export async function getNonce(env: AcmeEnv): Promise<string> {
  const response = await worker.fetch(
    new Request(`${ACME_BASE_URL}/new-nonce`, { method: "HEAD" }),
    env,
    testContext
  );
  const nonce = response.headers.get("Replay-Nonce");
  if (!nonce) throw new Error("Server did not return a Replay-Nonce");
  return nonce;
}

export async function makeJwsRequest(
  env: AcmeEnv,
  url: string,
  payload: Record<string, unknown> | "",
  account: Pick<TestAccount, "keys" | "jwk" | "kid" | "alg">,
  nonce: string,
  keyMode: "jwk" | "kid" = "kid"
): Promise<{ response: Response; nextNonce: string }> {
  const alg = account.alg ?? "ES256";
  const protectedHeader: Record<string, unknown> = {
    alg,
    nonce,
    url,
  };
  if (keyMode === "jwk") protectedHeader.jwk = account.jwk;
  else protectedHeader.kid = account.kid;

  const protectedB64 = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(protectedHeader))
  );
  const payloadB64 =
    payload === ""
      ? ""
      : base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));

  const signature = await crypto.subtle.sign(
    alg === "ES256"
      ? { name: "ECDSA", hash: "SHA-256" }
      : alg === "RS256"
        ? { name: "RSASSA-PKCS1-v1_5" }
        : { name: "Ed25519" },
    account.keys.privateKey,
    new TextEncoder().encode(`${protectedB64}.${payloadB64}`)
  );

  const response = await worker.fetch(
    new Request(url, {
      method: "POST",
      headers: { "Content-Type": "application/jose+json" },
      body: JSON.stringify({
        protected: protectedB64,
        payload: payloadB64,
        signature: base64UrlEncode(signature),
      }),
    }),
    env,
    testContext
  );

  return {
    response,
    nextNonce: response.headers.get("Replay-Nonce") || "",
  };
}

export async function registerAccount(env: AcmeEnv): Promise<TestAccount> {
  const keys = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", keys.publicKey)) as JsonWebKey;

  const thumbprint = await calculateJwkThumbprint(jwk);

  const nonce = await getNonce(env);
  const response = await makeJwsRequest(
    env,
    `${ACME_BASE_URL}/new-account`,
    { contact: ["mailto:admin@example.com"], termsOfServiceAgreed: true },
    { keys, jwk, kid: "" },
    nonce,
    "jwk"
  );
  if (response.response.status !== 201 && response.response.status !== 200) {
    throw new Error(`Account creation failed: ${response.response.status}`);
  }
  const kid = response.response.headers.get("Location");
  if (!kid) throw new Error("Account response did not include Location");

  return { keys, jwk, thumbprint, kid, alg: "ES256" };
}

export async function createOrder(
  env: AcmeEnv,
  account: TestAccount,
  identifiers: Array<{ type: string; value: string }>
): Promise<{
  response: Response;
  body: Record<string, unknown>;
  url: string;
  nonce: string;
}> {
  const nonce = await getNonce(env);
  const result = await makeJwsRequest(
    env,
    `${ACME_BASE_URL}/new-order`,
    { identifiers },
    account,
    nonce
  );
  const body = (await result.response.json()) as Record<string, unknown>;
  return {
    response: result.response,
    body,
    url: result.response.headers.get("Location") || "",
    nonce: result.nextNonce,
  };
}

export async function getAuthorization(
  env: AcmeEnv,
  account: TestAccount,
  authzUrl: string,
  nonce: string
): Promise<{ body: Record<string, unknown>; nonce: string }> {
  const result = await makeJwsRequest(env, authzUrl, "", account, nonce);
  const body = (await result.response.json()) as Record<string, unknown>;
  return { body, nonce: result.nextNonce };
}

export async function triggerChallenge(
  env: AcmeEnv,
  account: TestAccount,
  challengeUrl: string,
  nonce: string
): Promise<{ response: Response; body: Record<string, unknown>; nonce: string }> {
  const result = await makeJwsRequest(env, challengeUrl, {}, account, nonce);
  const body = (await result.response.json()) as Record<string, unknown>;
  return { response: result.response, body, nonce: result.nextNonce };
}

export async function makeCsr(
  domains: string[]
): Promise<string> {
  const keys = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;

  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: `CN=${domains[0]}`,
    keys,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: [
      new x509.SubjectAlternativeNameExtension(
        domains.map((domain) => ({ type: "dns" as const, value: domain }))
      ),
    ],
  });

  return base64UrlEncode(csr.rawData);
}

export function dohAnswer(
  records: Array<{ type: number; data: string }>
): Response {
  return new Response(
    JSON.stringify({ Status: 0, Answer: records }),
    { status: 200, headers: { "Content-Type": "application/dns-json" } }
  );
}

export function installFetchMock(
  handler: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = handler as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}
