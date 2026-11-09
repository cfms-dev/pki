import { describe, expect, it } from "vitest";
import { AcmeEnv, CONFIG } from "../src/config";
import worker from "../src/index";
import { validateCaaForOrder } from "../src/dns/caa";
import { createMockD1Database } from "./mock-d1";
import { testContext } from "./acme-test-helpers";

const legacyEnv = (): AcmeEnv => ({
  DB: createMockD1Database(),
  ACME_BASE_URL: "https://legacy.example",
  WEBSITE_URL: "https://legacy.example/site",
  TERMS_OF_SERVICE_URL: "https://legacy.example/terms",
  CAA_IDENTITIES: ["legacy.example"],
  CAA_ISSUER_DOMAIN_NAME: "legacy.example",
  EXTERNAL_ACCOUNT_REQUIRED: "true",
});

describe("Code-owned configuration", () => {
  it("ignores legacy directory metadata and base URL environment variables", async () => {
    const response = await worker.fetch(new Request("https://request.example/directory"), legacyEnv(), testContext);
    expect(response.status).toBe(200);
    const body = await response.json() as { meta: Record<string, unknown> };
    expect(body).toMatchObject({
      newOrder: "https://request.example/new-order",
      meta: { website: CONFIG.WEBSITE_URL, caaIdentities: [CONFIG.CAA_ISSUER_DOMAIN_NAME] },
    });
    expect(body.meta).not.toHaveProperty("termsOfService");
    expect(body.meta).not.toHaveProperty("externalAccountRequired");
    expect(response.headers.get("Link")).toContain("https://request.example/directory");
  });

  it("uses the configured published URL when set, regardless of legacy bindings", async () => {
    CONFIG.ACME_BASE_URL = "  https://published.example  ";
    const response = await worker.fetch(new Request("https://request.example/directory"), legacyEnv(), testContext);
    expect(await response.json()).toMatchObject({ newAccount: "https://published.example/new-account" });
    expect(response.headers.get("Link")).toContain("https://published.example/directory");
  });

  it("uses the same configured issuer in directory metadata and CAA enforcement", async () => {
    CONFIG.CAA_ISSUER_DOMAIN_NAME = "  configured.example  ";
    const env = legacyEnv();
    const response = await worker.fetch(new Request("https://request.example/directory"), env, testContext);
    expect(await response.json()).toMatchObject({ meta: { caaIdentities: ["configured.example"] } });
    const query = (issuer: string) => async () => Response.json({
      Status: 0, Answer: [{ type: 257, data: `0 issue "${issuer}"` }],
    });
    await expect(validateCaaForOrder(["example.org"], "https://request.example/account/1", env, query("configured.example"))).resolves.toBeUndefined();
    await expect(validateCaaForOrder(["example.org"], "https://request.example/account/1", env, query("legacy.example"))).rejects.toThrow("CAA issue record forbids issuance");
  });

  it("publishes an explicit, trimmed CAA identity list", async () => {
    CONFIG.CAA_IDENTITIES = ["  ca-one.example  ", " ", "ca-two.example"];
    const response = await worker.fetch(new Request("https://request.example/directory"), legacyEnv(), testContext);
    expect(await response.json()).toMatchObject({ meta: { caaIdentities: ["ca-one.example", "ca-two.example"] } });
  });
});
