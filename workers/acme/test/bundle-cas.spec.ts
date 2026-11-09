import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const certificate = fs.readFileSync("cas/generic-intermediate.pem", "utf-8");

describe("CA packaging", () => {
  let repoDir: string;
  let script: string;
  let outputDir: string;

  beforeEach(() => {
    repoDir = fs.mkdtempSync(path.join(os.tmpdir(), "cfms-ca-bundle-"));
    script = path.join(repoDir, "workers/acme/scripts/bundle-cas.mjs");
    outputDir = path.join(repoDir, "workers/acme/cas");
    fs.mkdirSync(path.dirname(script), { recursive: true });
    fs.copyFileSync("scripts/bundle-cas.mjs", script);
    fs.mkdirSync(path.join(repoDir, "registry"));
    fs.mkdirSync(path.join(repoDir, "certs"));
    fs.writeFileSync(path.join(repoDir, "registry/ca.json"), JSON.stringify({
      cas: { test: { location: "certs/test.pem", pk_env: "PK_TEST" } },
    }));
    fs.writeFileSync(path.join(repoDir, "certs/test.pem"), certificate);
  });

  afterEach(() => {
    fs.rmSync(repoDir, { recursive: true, force: true });
  });

  function bundle() {
    return spawnSync(process.execPath, [script], { cwd: os.tmpdir(), encoding: "utf-8" });
  }

  it("builds from the repository registry regardless of cwd and leaves unchanged files untouched", () => {
    const first = bundle();
    expect(first.status, first.stderr).toBe(0);
    const certPath = path.join(outputDir, "test.pem");
    const manifestPath = path.join(outputDir, "manifest.json");
    expect(fs.readFileSync(certPath, "utf-8")).toBe(certificate);
    expect(JSON.parse(fs.readFileSync(manifestPath, "utf-8"))).toEqual({
      cas: { test: { certFile: "test.pem", pkEnv: "PK_TEST", crlFile: "test.crl" } },
    });
    const timestamp = new Date("2020-01-01T00:00:00Z");
    fs.utimesSync(certPath, timestamp, timestamp);
    fs.utimesSync(manifestPath, timestamp, timestamp);
    const second = bundle();
    expect(second.status, second.stderr).toBe(0);
    expect(fs.statSync(certPath).mtime).toEqual(timestamp);
    expect(fs.statSync(manifestPath).mtime).toEqual(timestamp);
  });

  it("carries a configured CRL filename into the bundle", () => {
    fs.writeFileSync(path.join(repoDir, "registry/ca.json"), JSON.stringify({
      cas: { test: { location: "certs/test.pem", pk_env: "PK_TEST", crl_path: "crl/custom.crl" } },
    }));
    expect(bundle().status).toBe(0);
    expect(JSON.parse(fs.readFileSync(path.join(outputDir, "manifest.json"), "utf-8")).cas.test.crlFile).toBe("custom.crl");
  });

  it("fails if the registry is missing even when a previous bundle exists", () => {
    expect(bundle().status).toBe(0);
    fs.unlinkSync(path.join(repoDir, "registry/ca.json"));
    const result = bundle();
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("ca.json");
  });

  it.each([
    ["not PEM", "Invalid PEM certificate"],
    [certificate + "\n-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----", "contains private key data"],
  ])("rejects invalid or private-key-containing certificate (case %#)", (pem, error) => {
    fs.writeFileSync(path.join(repoDir, "certs/test.pem"), pem);
    const result = bundle();
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(error);
    expect(fs.existsSync(path.join(outputDir, "test.pem"))).toBe(false);
  });
});
