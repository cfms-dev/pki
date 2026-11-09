import { migrateAccountPublicKeyFingerprints } from "../src/db/account-keys";
import { describe, it, expect, beforeEach } from "vitest";
import { AcmeEnv } from "../src/config";
import { calculateJwkThumbprint, normalizePublicKey } from "../src/crypto/jws";
import { Database } from "../src/db/queries";
import {
  AccountKeyAlgorithm,
  ACME_BASE_URL,
  getNonce,
  makeJwsRequest,
  TestEnvironment,
  createTestEnvironment,
} from "./acme-test-helpers";
import {
  exportPublicJwk,
  generateAccountKeys,
  padBase64Url,
  registerAccountJwk,
} from "./account-key-test-helpers";

async function countAccounts(env: AcmeEnv): Promise<number> {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM accounts"
  ).first<{ count: number }>();
  return row?.count ?? 0;
}

async function accountCountForFingerprint(
  env: AcmeEnv,
  fingerprint: string
): Promise<number> {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM accounts WHERE public_key_fingerprint = ?"
  )
    .bind(fingerprint)
    .first<{ count: number }>();
  return row?.count ?? 0;
}

describe("ACME account public key uniqueness (RFC 8555 § 7.3.1, § 11.1)", () => {
  let env: AcmeEnv;
  let database: Database;
  let testEnv: TestEnvironment;

  beforeEach(async () => {
    testEnv = await createTestEnvironment();
    env = testEnv.env;
    database = testEnv.database;
  });

  async function paddedEcJwk(alg: AccountKeyAlgorithm = "ES256") {
    const keys = await generateAccountKeys(alg);
    const canonical = await exportPublicJwk(keys);
    if (alg !== "ES256") {
      throw new Error("paddedEcJwk only supports ES256");
    }
    const padded = {
      ...canonical,
      x: padBase64Url(canonical.x as string),
      y: padBase64Url(canonical.y as string),
    };
    return { keys, canonical, padded };
  }

  it("does not create a second account for a differently encoded EC key", async () => {
    const { keys, canonical, padded } = await paddedEcJwk();

    const first = await registerAccountJwk(env, keys, padded);
    expect(first.status).toBe(201);

    const second = await registerAccountJwk(env, keys, canonical);
    expect(second.status).toBe(200);
    expect(second.kid).toBe(first.kid);

    expect(await countAccounts(env)).toBe(1);
    const id = first.kid.split("/").pop()!;
    const row = await database.getAccountById(id);
    const expectedFingerprint = (await normalizePublicKey(canonical)).fingerprint;
    expect(row?.public_key_fingerprint).toBe(expectedFingerprint);
    // The stored protocol representation/thumbprint must not be rewritten:
    // existing key authorizations depend on it.
    expect(row?.jwk).toBe(JSON.stringify(padded));
    expect(row?.thumbprint).toBe(await calculateJwkThumbprint(padded));
    await expect(accountCountForFingerprint(env, expectedFingerprint)).resolves.toBe(1);
  });

  it("onlyReturnExisting finds an account through an equivalent key encoding", async () => {
    const { keys, canonical, padded } = await paddedEcJwk();
    const first = await registerAccountJwk(env, keys, padded);
    expect(first.status).toBe(201);

    const lookup = await registerAccountJwk(
      env,
      keys,
      canonical,
      "ES256",
      { onlyReturnExisting: true }
    );
    expect(lookup.status).toBe(200);
    expect(lookup.kid).toBe(first.kid);
    expect(await countAccounts(env)).toBe(1);
  });

  it("onlyReturnExisting returns accountDoesNotExist instead of creating an account", async () => {
    const keys = await generateAccountKeys("ES256");
    const jwk = await exportPublicJwk(keys);

    const result = await registerAccountJwk(
      env,
      keys,
      jwk,
      "ES256",
      { onlyReturnExisting: true }
    );
    expect(result.status).toBe(400);
    expect(result.body.type).toBe("urn:ietf:params:acme:error:accountDoesNotExist");
    expect(await countAccounts(env)).toBe(0);
  });

  it("returns the existing account unchanged when a different encoding is registered", async () => {
    const { keys, canonical, padded } = await paddedEcJwk();
    const first = await registerAccountJwk(env, keys, padded, "ES256", {
      contact: ["mailto:first@example.com"],
    });
    expect(first.status).toBe(201);

    const second = await registerAccountJwk(env, keys, canonical, "ES256", {
      contact: ["mailto:second@example.com"],
    });
    expect(second.status).toBe(200);
    expect(second.kid).toBe(first.kid);
    expect(second.body.contact).toEqual(["mailto:first@example.com"]);

    const id = first.kid.split("/").pop()!;
    const row = await database.getAccountById(id);
    expect(row?.contact).toBe(JSON.stringify(["mailto:first@example.com"]));
    expect(row?.status).toBe("valid");
  });

  it("still allows different actual public keys to create different accounts", async () => {
    const firstKeys = await generateAccountKeys("ES256");
    const secondKeys = await generateAccountKeys("ES256");
    const first = await registerAccountJwk(
      env,
      firstKeys,
      await exportPublicJwk(firstKeys)
    );
    const second = await registerAccountJwk(
      env,
      secondKeys,
      await exportPublicJwk(secondKeys)
    );

    expect(first.status).toBe(201);
    expect(second.status).toBe(201);
    expect(first.kid).not.toBe(second.kid);
    expect(await countAccounts(env)).toBe(2);
  });

  it("does not create a duplicate RSA account for non-canonical integer encodings", async () => {
    const keys = await generateAccountKeys("RS256");
    const canonical = await exportPublicJwk(keys);
    const padded = {
      ...canonical,
      n: padBase64Url(canonical.n as string, 3),
      e: padBase64Url(canonical.e as string, 1),
    };

    const first = await registerAccountJwk(env, keys, padded, "RS256");
    expect(first.status).toBe(201);

    const second = await registerAccountJwk(env, keys, canonical, "RS256");
    expect(second.status).toBe(200);
    expect(second.kid).toBe(first.kid);
    expect(await countAccounts(env)).toBe(1);
  });

  it("ignores JWK field order and unrelated optional members for account identity", async () => {
    const keys = await generateAccountKeys("ES256");
    const canonical = await exportPublicJwk(keys);
    const reordered = {
      y: canonical.y,
      crv: canonical.crv,
      x: canonical.x,
      kty: canonical.kty,
    } as JsonWebKey;

    const first = await registerAccountJwk(env, keys, canonical);
    expect(first.status).toBe(201);

    const decorated = {
      ...reordered,
      kid: "client-key-id",
      use: "sig",
      key_ops: ["sign"],
      alg: "ES256",
    } as JsonWebKey;
    const second = await registerAccountJwk(env, keys, decorated);
    expect(second.status).toBe(200);
    expect(second.kid).toBe(first.kid);
    expect(await countAccounts(env)).toBe(1);
  });

  it("backfills a legacy account and returns it instead of creating a duplicate", async () => {
    const keys = await generateAccountKeys("ES256");
    const canonical = await exportPublicJwk(keys);
    const padded = {
      ...canonical,
      x: padBase64Url(canonical.x as string),
      y: padBase64Url(canonical.y as string),
    };
    const legacyId = crypto.randomUUID();
    const legacyThumbprint = await calculateJwkThumbprint(padded);
    const now = Math.floor(Date.now() / 1000);
    await database.saveAccount({
      id: legacyId,
      jwk: JSON.stringify(padded),
      thumbprint: legacyThumbprint,
      contact: null,
      status: "valid",
      created_at: now,
    });

    const rowBefore = await database.getAccountById(legacyId);
    expect(rowBefore?.public_key_fingerprint ?? null).toBeNull();

    // Registering with the canonical representation runs the one-time
    // backfill, then resolves the same account by actual-key fingerprint.
    const blocked = await registerAccountJwk(env, keys, canonical);
    expect(blocked.status).toBe(503);
    await migrateAccountPublicKeyFingerprints(database);
    const result = await registerAccountJwk(env, keys, canonical);
    expect(result.status).toBe(200);
    expect(result.kid).toBe(`${ACME_BASE_URL}/account/${legacyId}`);
    expect(await countAccounts(env)).toBe(1);

    const rowAfter = await database.getAccountById(legacyId);
    expect(rowAfter?.public_key_fingerprint).toBe(
      (await normalizePublicKey(canonical)).fingerprint
    );
    // The legacy protocol thumbprint is preserved for pending challenges.
    expect(rowAfter?.thumbprint).toBe(legacyThumbprint);
    expect(rowAfter?.jwk).toBe(JSON.stringify(padded));
  });

  it("supports Ed25519 (EdDSA) account registration and lookup", async () => {
    const keys = await generateAccountKeys("EdDSA");
    const jwk = await exportPublicJwk(keys);

    const first = await registerAccountJwk(env, keys, jwk, "EdDSA");
    expect(first.status).toBe(201);
    const id = first.kid.split("/").pop()!;
    const row = await database.getAccountById(id);
    expect(row?.public_key_fingerprint).toBe(
      (await normalizePublicKey(jwk)).fingerprint
    );

    const lookup = await registerAccountJwk(
      env,
      keys,
      jwk,
      "EdDSA",
      { onlyReturnExisting: true }
    );
    expect(lookup.status).toBe(200);
    expect(lookup.kid).toBe(first.kid);
    expect(await countAccounts(env)).toBe(1);
  });

  it("serializes concurrent registrations of the same actual key", async () => {
    const { keys, canonical, padded } = await paddedEcJwk();
    const registerPayload = {
      contact: ["mailto:race@example.com"],
      termsOfServiceAgreed: true,
    };

    const nonceA = await getNonce(env);
    const nonceB = await getNonce(env);

    const [a, b] = await Promise.all([
      makeJwsRequest(
        env,
        `${ACME_BASE_URL}/new-account`,
        registerPayload,
        { keys, jwk: padded, kid: "", alg: "ES256" },
        nonceA,
        "jwk"
      ),
      makeJwsRequest(
        env,
        `${ACME_BASE_URL}/new-account`,
        registerPayload,
        { keys, jwk: canonical, kid: "", alg: "ES256" },
        nonceB,
        "jwk"
      ),
    ]);

    const statuses = [a.response.status, b.response.status].sort();
    expect(statuses).toEqual([200, 201]);
    expect(await countAccounts(env)).toBe(1);
    expect(a.response.headers.get("Location")).toBe(
      b.response.headers.get("Location")
    );
  });
});
