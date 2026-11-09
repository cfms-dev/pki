import { describe, it, expect, beforeEach } from "vitest";
import { AcmeEnv } from "../src/config";
import { calculateJwkThumbprint, normalizePublicKey } from "../src/crypto/jws";
import { Database } from "../src/db/queries";
import { AccountRow } from "../src/db/types";
import {
  ACME_BASE_URL,
  AccountKeyAlgorithm,
  createOrder,
  createTestEnvironment,
  getAuthorization,
  getNonce,
  makeJwsRequest,
  TestAccount,
  TestEnvironment,
} from "./acme-test-helpers";
import {
  exportPublicJwk,
  generateAccountKeys,
  makeKeyChangeRequest,
  padBase64Url,
  registerAccountJwk,
  registerFreshAccount,
} from "./account-key-test-helpers";

function accountIdOf(account: Pick<TestAccount, "kid">): string {
  return account.kid.split("/").pop()!;
}

async function accountRow(database: Database, account: TestAccount): Promise<AccountRow> {
  const row = await database.getAccountById(accountIdOf(account));
  if (!row) throw new Error("Account row not found");
  return row;
}

async function authenticatedAccountRequest(
  env: AcmeEnv,
  account: TestAccount,
  keys: CryptoKeyPair,
  jwk: JsonWebKey,
  alg: AccountKeyAlgorithm
): Promise<number> {
  const nonce = await getNonce(env);
  const result = await makeJwsRequest(
    env,
    account.kid,
    "",
    { keys, jwk, kid: account.kid, alg },
    nonce
  );
  return result.response.status;
}

describe("ACME account key rollover (RFC 8555 § 7.3.5)", () => {
  let env: AcmeEnv;
  let database: Database;
  let testEnv: TestEnvironment;

  beforeEach(async () => {
    testEnv = await createTestEnvironment();
    env = testEnv.env;
    database = testEnv.database;
  });

  it("rotates the account key without changing the account ID, URL, or orders", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const order = await createOrder(env, account, [
      { type: "dns", value: "rollover.example.com" },
    ]);
    expect(order.response.status).toBe(201);
    const authzUrl = (order.body.authorizations as string[])[0];
    const authzBefore = await getAuthorization(env, account, authzUrl, order.nonce);
    expect(authzBefore.body.status).toBe("pending");

    const newKeys = await generateAccountKeys("ES256");
    const newJwk = await exportPublicJwk(newKeys);
    const nonce = await getNonce(env);
    const change = await makeKeyChangeRequest(
      env,
      account,
      newKeys,
      newJwk,
      "ES256",
      nonce
    );
    expect(change.response.status).toBe(200);

    const row = await accountRow(database, account);
    expect(row.id).toBe(accountIdOf(account));
    expect(row.jwk).toBe(JSON.stringify(newJwk));
    expect(row.thumbprint).toBe(await calculateJwkThumbprint(newJwk));
    expect(row.public_key_fingerprint).toBe(
      (await normalizePublicKey(newJwk)).fingerprint
    );
    expect(row.status).toBe("valid");

    // Old key no longer authenticates; new key does.
    expect(
      await authenticatedAccountRequest(env, account, account.keys, account.jwk, "ES256")
    ).toBe(403);
    expect(
      await authenticatedAccountRequest(env, account, newKeys, newJwk, "ES256")
    ).toBe(200);

    // Existing order and authorization remain owned by the same account and
    // retain their status.
    const rolled: TestAccount = {
      ...account,
      keys: newKeys,
      jwk: newJwk,
      alg: "ES256",
    };
    const orderAfter = await makeJwsRequest(env, order.url, "", rolled, change.nextNonce);
    expect(orderAfter.response.status).toBe(200);
    const orderBody = (await orderAfter.response.json()) as Record<string, unknown>;
    expect(orderBody.status).toBe("pending");

    const authzAfter = await getAuthorization(
      env,
      rolled,
      authzUrl,
      orderAfter.nextNonce
    );
    expect(authzAfter.body.status).toBe("pending");
  });

  it("rotates between account key algorithms", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const newKeys = await generateAccountKeys("RS256");
    const newJwk = await exportPublicJwk(newKeys);
    const nonce = await getNonce(env);

    const change = await makeKeyChangeRequest(
      env,
      account,
      newKeys,
      newJwk,
      "RS256",
      nonce
    );
    expect(change.response.status).toBe(200);

    expect(
      await authenticatedAccountRequest(env, account, newKeys, newJwk, "RS256")
    ).toBe(200);
    // ES256 cannot be used with the stored RSA account key.
    expect(
      await authenticatedAccountRequest(env, account, account.keys, account.jwk, "ES256")
    ).toBe(400);
  });

  it("rotates to an Ed25519 (EdDSA) key", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const newKeys = await generateAccountKeys("EdDSA");
    const newJwk = await exportPublicJwk(newKeys);
    const nonce = await getNonce(env);

    const change = await makeKeyChangeRequest(
      env,
      account,
      newKeys,
      newJwk,
      "EdDSA",
      nonce
    );
    expect(change.response.status).toBe(200);

    expect(
      await authenticatedAccountRequest(env, account, newKeys, newJwk, "EdDSA")
    ).toBe(200);
    const row = await accountRow(database, account);
    expect(row.public_key_fingerprint).toBe(
      (await normalizePublicKey(newJwk)).fingerprint
    );
  });

  it("rejects a new key already used by another account and returns its URL", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const other = await registerFreshAccount(env, "ES256");
    const before = await accountRow(database, account);
    const nonce = await getNonce(env);

    const change = await makeKeyChangeRequest(
      env,
      account,
      other.keys,
      other.jwk,
      "ES256",
      nonce
    );
    expect(change.response.status).toBe(409);
    expect(change.response.headers.get("Location")).toBe(other.kid);
    const body = (await change.response.json()) as Record<string, unknown>;
    expect(body.type).toBe("urn:ietf:params:acme:error:malformed");
    expect(String(body.detail)).not.toMatch(/UNIQUE constraint/i);

    const after = await accountRow(database, account);
    expect(after.jwk).toBe(before.jwk);
    expect(after.thumbprint).toBe(before.thumbprint);
    expect(after.public_key_fingerprint).toBe(before.public_key_fingerprint);
  });

  it("rejects another account's key through a non-canonical JWK encoding", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const other = await registerFreshAccount(env, "ES256");
    const otherCanonical = await exportPublicJwk(other.keys);
    const otherPadded = {
      ...otherCanonical,
      x: padBase64Url(otherCanonical.x as string),
      y: padBase64Url(otherCanonical.y as string),
    };

    const nonce = await getNonce(env);
    const change = await makeKeyChangeRequest(
      env,
      account,
      other.keys,
      otherPadded,
      "ES256",
      nonce
    );
    expect(change.response.status).toBe(409);
    expect(change.response.headers.get("Location")).toBe(other.kid);
  });

  it("rejects a mismatched oldKey and leaves the account key unchanged", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const other = await registerFreshAccount(env, "ES256");
    const before = await accountRow(database, account);
    const newKeys = await generateAccountKeys("ES256");
    const newJwk = await exportPublicJwk(newKeys);
    const nonce = await getNonce(env);

    const change = await makeKeyChangeRequest(
      env,
      account,
      newKeys,
      newJwk,
      "ES256",
      nonce,
      { oldKey: other.jwk }
    );
    expect(change.response.status).toBe(403);
    expect(change.response.headers.get("Location")).toBeNull();

    const after = await accountRow(database, account);
    expect(after.jwk).toBe(before.jwk);
    expect(after.public_key_fingerprint).toBe(before.public_key_fingerprint);
  });

  it("rejects an inner JWS with a different url", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const newKeys = await generateAccountKeys("ES256");
    const newJwk = await exportPublicJwk(newKeys);
    const nonce = await getNonce(env);

    const change = await makeKeyChangeRequest(
      env,
      account,
      newKeys,
      newJwk,
      "ES256",
      nonce,
      { innerUrl: `${ACME_BASE_URL}/new-order` }
    );
    expect(change.response.status).toBe(400);
  });

  it("rejects an inner JWS that includes a nonce", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const newKeys = await generateAccountKeys("ES256");
    const newJwk = await exportPublicJwk(newKeys);
    const nonce = await getNonce(env);

    const change = await makeKeyChangeRequest(
      env,
      account,
      newKeys,
      newJwk,
      "ES256",
      nonce,
      { includeNonce: true }
    );
    expect(change.response.status).toBe(400);
  });

  it("rejects an invalid inner signature", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const newKeys = await generateAccountKeys("ES256");
    const newJwk = await exportPublicJwk(newKeys);
    const nonce = await getNonce(env);

    const change = await makeKeyChangeRequest(
      env,
      account,
      newKeys,
      newJwk,
      "ES256",
      nonce,
      { corruptInnerSignature: true }
    );
    expect(change.response.status).toBe(403);
  });

  it("treats a rollover to the same actual key as an idempotent no-op", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const canonical = await exportPublicJwk(account.keys);
    const padded = {
      ...canonical,
      x: padBase64Url(canonical.x as string),
      y: padBase64Url(canonical.y as string),
    };
    const before = await accountRow(database, account);
    const nonce = await getNonce(env);

    const change = await makeKeyChangeRequest(
      env,
      account,
      account.keys,
      padded,
      "ES256",
      nonce
    );
    expect(change.response.status).toBe(200);

    const after = await accountRow(database, account);
    // The stored protocol representation/thumbprint must not change.
    expect(after.jwk).toBe(before.jwk);
    expect(after.thumbprint).toBe(before.thumbprint);
    expect(after.public_key_fingerprint).toBe(before.public_key_fingerprint);
    expect(
      await authenticatedAccountRequest(env, account, account.keys, account.jwk, "ES256")
    ).toBe(200);
  });

  it("requires an account kid rather than a bare jwk", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const newKeys = await generateAccountKeys("ES256");
    const newJwk = await exportPublicJwk(newKeys);
    const nonce = await getNonce(env);

    const innerHeader = {
      alg: "ES256",
      jwk: newJwk,
      url: `${ACME_BASE_URL}/key-change`,
    };
    const innerPayload = { account: account.kid, oldKey: account.jwk };
    const protectedB64 = Buffer.from(JSON.stringify(innerHeader)).toString(
      "base64url"
    );
    const payloadB64 = Buffer.from(JSON.stringify(innerPayload)).toString(
      "base64url"
    );
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      newKeys.privateKey,
      new TextEncoder().encode(`${protectedB64}.${payloadB64}`)
    );
    const inner = {
      protected: protectedB64,
      payload: payloadB64,
      signature: Buffer.from(signature).toString("base64url"),
    };

    const result = await makeJwsRequest(
      env,
      `${ACME_BASE_URL}/key-change`,
      inner,
      { keys: account.keys, jwk: account.jwk, kid: "", alg: "ES256" },
      nonce,
      "jwk"
    );
    expect(result.response.status).toBe(400);
  });

  it("rejects keyChange for a deactivated account", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const nonce = await getNonce(env);
    const deactivated = await makeJwsRequest(
      env,
      account.kid,
      { status: "deactivated" },
      account,
      nonce
    );
    expect(deactivated.response.status).toBe(200);

    const newKeys = await generateAccountKeys("ES256");
    const newJwk = await exportPublicJwk(newKeys);
    const change = await makeKeyChangeRequest(
      env,
      account,
      newKeys,
      newJwk,
      "ES256",
      deactivated.nextNonce
    );
    expect(change.response.status).toBe(403);
  });

  it("keeps exactly one of two concurrent different-key rollovers", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const firstKeys = await generateAccountKeys("ES256");
    const secondKeys = await generateAccountKeys("ES256");
    const firstJwk = await exportPublicJwk(firstKeys);
    const secondJwk = await exportPublicJwk(secondKeys);
    const nonceA = await getNonce(env);
    const nonceB = await getNonce(env);

    const [a, b] = await Promise.all([
      makeKeyChangeRequest(env, account, firstKeys, firstJwk, "ES256", nonceA),
      makeKeyChangeRequest(env, account, secondKeys, secondJwk, "ES256", nonceB),
    ]);

    const statuses = [a.response.status, b.response.status].sort();
    expect(statuses).toEqual([200, 403]);

    const row = await accountRow(database, account);
    const winnerIsFirst = row.public_key_fingerprint ===
      (await normalizePublicKey(firstJwk)).fingerprint;
    const winnerIsSecond = row.public_key_fingerprint ===
      (await normalizePublicKey(secondJwk)).fingerprint;
    expect(winnerIsFirst || winnerIsSecond).toBe(true);
    expect(winnerIsFirst && winnerIsSecond).toBe(false);

    expect(
      await authenticatedAccountRequest(env, account, account.keys, account.jwk, "ES256")
    ).toBe(403);
    expect(
      await authenticatedAccountRequest(
        env,
        account,
        winnerIsFirst ? firstKeys : secondKeys,
        winnerIsFirst ? firstJwk : secondJwk,
        "ES256"
      )
    ).toBe(200);
    expect(
      await authenticatedAccountRequest(
        env,
        account,
        winnerIsFirst ? secondKeys : firstKeys,
        winnerIsFirst ? secondJwk : firstJwk,
        "ES256"
      )
    ).toBe(403);
  });

  it("treats concurrent idempotent rollovers to the same key as success", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const newKeys = await generateAccountKeys("ES256");
    const newJwk = await exportPublicJwk(newKeys);
    const nonceA = await getNonce(env);
    const nonceB = await getNonce(env);

    const [a, b] = await Promise.all([
      makeKeyChangeRequest(env, account, newKeys, newJwk, "ES256", nonceA),
      makeKeyChangeRequest(env, account, newKeys, newJwk, "ES256", nonceB),
    ]);
    expect([a.response.status, b.response.status]).toEqual([200, 200]);

    const row = await accountRow(database, account);
    expect(row.thumbprint).toBe(await calculateJwkThumbprint(newJwk));
    expect(
      await authenticatedAccountRequest(env, account, newKeys, newJwk, "ES256")
    ).toBe(200);
  });

  it("serializes a concurrent keyChange and newAccount for the same new key", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const newKeys = await generateAccountKeys("ES256");
    const newJwk = await exportPublicJwk(newKeys);
    const fingerprint = (await normalizePublicKey(newJwk)).fingerprint;

    const changeNonce = await getNonce(env);
    const createNonce = await getNonce(env);

    const [change, created] = await Promise.all([
      makeKeyChangeRequest(env, account, newKeys, newJwk, "ES256", changeNonce),
      makeJwsRequest(
        env,
        `${ACME_BASE_URL}/new-account`,
        {
          contact: ["mailto:concurrent@example.com"],
          termsOfServiceAgreed: true,
        },
        { keys: newKeys, jwk: newJwk, kid: "", alg: "ES256" },
        createNonce,
        "jwk"
      ),
    ]);

    expect([200, 201]).toContain(created.response.status);
    expect([200, 409]).toContain(change.response.status);

    const countRow = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM accounts WHERE public_key_fingerprint = ?"
    )
      .bind(fingerprint)
      .first<{ count: number }>();
    expect(countRow?.count).toBe(1);

    const row = await accountRow(database, account);
    if (change.response.status === 200) {
      expect(row.public_key_fingerprint).toBe(fingerprint);
    } else {
      // A new account claimed the key first; the existing account keeps its
      // old key and the response points at the new account.
      expect(row.public_key_fingerprint).not.toBe(fingerprint);
      const location = change.response.headers.get("Location");
      expect(location).toBeTruthy();
      const holderId = location!.split("/").pop()!;
      expect((await database.getAccountById(holderId))?.public_key_fingerprint).toBe(
        fingerprint
      );
    }
  });

  it("does not modify jwk, thumbprint, or account identity when rejecting a reused key", async () => {
    const account = await registerFreshAccount(env, "ES256");
    const other = await registerFreshAccount(env, "ES256");
    const before = await accountRow(database, account);
    const nonce = await getNonce(env);

    await makeKeyChangeRequest(
      env,
      account,
      other.keys,
      other.jwk,
      "ES256",
      nonce
    );

    const after = await accountRow(database, account);
    expect(after).toEqual(before);
  });
});
