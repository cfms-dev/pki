import { describe, expect, it, vi } from "vitest";
import { AcmeEnv } from "../src/config";
import worker from "../src/index";
import { testContext } from "./acme-test-helpers";
import { testAssets } from "./website-test-helpers";

const env: AcmeEnv = {
  ASSETS: testAssets,
  get DB(): D1Database { throw new Error("Website accessed D1"); },
};

describe("Website requests that reach the Worker", () => {
  it.each(["/", "/index", "/index.html", "/terms", "/terms.html", "/privacy", "/privacy.html", "/styles.css", "/missing.css", "/images/missing.png", "/zh-cn", "/zh-cn/", "/zh-cn/index", "/zh-cn/index.html", "/zh-cn/terms", "/zh-cn/terms.html", "/zh-cn/privacy", "/zh-cn/privacy.html", "/zh-cn/missing"])("forwards %s unchanged, without D1 or ACME headers", async (path) => {
    const response = new Response(null, { status: 404, headers: { ETag: '"asset"' } });
    const assets = vi.spyOn(testAssets, "fetch").mockResolvedValue(response);
    const request = new Request(`https://website.test${path}?test=1`);
    expect(await worker.fetch(request, env, testContext)).toBe(response);
    expect(assets).toHaveBeenCalledExactlyOnceWith(request);
    expect(response.headers.get("Link")).toBeNull();
    expect(response.headers.get("Replay-Nonce")).toBeNull();
  });

  it.each(["HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])("leaves %s method handling to Assets", async (method) => {
    const response = new Response(null, { status: method === "HEAD" ? 200 : 405 });
    const assets = vi.spyOn(testAssets, "fetch").mockResolvedValue(response);
    const request = new Request("https://website.test/", { method });
    expect(await worker.fetch(request, env, testContext)).toBe(response);
    expect(assets).toHaveBeenCalledExactlyOnceWith(request);
  });

  it("does not convert asset failures into ACME errors or nonce generation", async () => {
    const failure = new Error("Assets unavailable");
    vi.spyOn(testAssets, "fetch").mockRejectedValue(failure);
    await expect(worker.fetch(new Request("https://website.test/"), env, testContext)).rejects.toBe(failure);
  });
});
