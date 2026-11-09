import { testAssets } from "./website-test-helpers";
import { describe, expect, it } from "vitest";
import { AcmeEnv, CONFIG } from "../src/config";
import worker from "../src/index";
import { validateCaaForOrder } from "../src/dns/caa";
import { createMockD1Database } from "./mock-d1";
import { testContext } from "./acme-test-helpers";

describe("Code-owned configuration", () => {
  it("uses the trimmed configured published URL when set", async () => {
    CONFIG.ACME_BASE_URL = "  https://published.example  ";
    const env: AcmeEnv = { ASSETS: testAssets, DB: createMockD1Database() };
    const response = await worker.fetch(new Request("https://request.example/directory"), env, testContext);
    expect(await response.json()).toMatchObject({ newAccount: "https://published.example/new-account" });
    expect(response.headers.get("Link")).toContain("https://published.example/directory");
  });

  it("uses the same configured issuer in directory metadata and CAA enforcement", async () => {
    CONFIG.CAA_ISSUER_DOMAIN_NAME = "  configured.example  ";
    const env: AcmeEnv = { ASSETS: testAssets, DB: createMockD1Database() };
    const response = await worker.fetch(new Request("https://request.example/directory"), env, testContext);
    expect(await response.json()).toMatchObject({ meta: { caaIdentities: ["configured.example"] } });
    const query = (issuer: string) => async () => Response.json({
      Status: 0, Answer: [{ type: 257, data: `0 issue "${issuer}"` }],
    });
    await expect(validateCaaForOrder(["example.org"], "https://request.example/account/1", env, query("configured.example"))).resolves.toBeUndefined();
    await expect(validateCaaForOrder(["example.org"], "https://request.example/account/1", env, query("other.example"))).rejects.toThrow("CAA issue record forbids issuance");
  });

  it("publishes an explicit, trimmed CAA identity list", async () => {
    CONFIG.CAA_IDENTITIES = ["  ca-one.example  ", " ", "ca-two.example"];
    const env: AcmeEnv = { ASSETS: testAssets, DB: createMockD1Database() };
    const response = await worker.fetch(new Request("https://request.example/directory"), env, testContext);
    expect(await response.json()).toMatchObject({ meta: { caaIdentities: ["ca-one.example", "ca-two.example"] } });
  });
});
