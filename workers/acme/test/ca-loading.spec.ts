import { testAssets } from "./website-test-helpers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { CONFIG } from "../src/config";
import { loadCaRegistry, readCaCertPem, selectIntermediateCa } from "../src/crypto/ca";
import { createMockD1Database } from "./mock-d1";

const ca = { id: "test-ca", certFile: "test-ca.pem", pkEnv: "PK_TEST", weight: 1 };
const certPem = fs.readFileSync("cas/generic-intermediate.pem", "utf-8").trim();

describe("CA loading", () => {
  let caDir: string;

  beforeEach(() => {
    caDir = fs.mkdtempSync(path.join(os.tmpdir(), "cfms-ca-loading-"));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(caDir, { recursive: true, force: true });
  });

  function writeManifest(value: unknown) {
    fs.writeFileSync(path.join(caDir, "manifest.json"), JSON.stringify(value));
  }

  it("loads the generated manifest and certificate from the designated directory", () => {
    writeManifest({ cas: { [ca.id]: { certFile: ca.certFile, pkEnv: ca.pkEnv } } });
    fs.writeFileSync(path.join(caDir, ca.certFile), certPem);
    expect(loadCaRegistry(caDir)).toEqual([ca]);
    expect(readCaCertPem(ca, caDir)).toBe(certPem);
  });

  it("reads manifest and certificate from the Workers bundle", () => {
    vi.spyOn(fs, "existsSync").mockImplementation((file) => file === "/bundle");
    vi.spyOn(fs, "readFileSync").mockImplementation((file) => {
      if (file === "/bundle/manifest.json") {
        return JSON.stringify({ cas: { [ca.id]: ca } });
      }
      if (file === "/bundle/test-ca.pem") return certPem;
      throw new Error(`Unexpected path: ${file}`);
    });
    expect(loadCaRegistry()).toEqual([ca]);
    expect(readCaCertPem(ca)).toBe(certPem);
  });

  it("fails when the manifest is missing, even if certificate files exist", () => {
    fs.writeFileSync(path.join(caDir, ca.certFile), certPem);
    expect(() => loadCaRegistry(caDir)).toThrow(/Failed to load.*manifest.json/);
  });

  it("reports invalid JSON", () => {
    fs.writeFileSync(path.join(caDir, "manifest.json"), "{ invalid JSON");
    expect(() => loadCaRegistry(caDir)).toThrow(/Failed to load.*manifest.json/);
  });

  it.each([null, [], {}, { cas: [] }, { cas: {} }])("rejects invalid manifest %j", (manifest) => {
    writeManifest(manifest);
    expect(() => loadCaRegistry(caDir)).toThrow(/expected non-empty 'cas' object/);
  });

  it.each([null, [], {}, { certFile: ca.certFile }, { certFile: ca.certFile, pkEnv: " " }])(
    "rejects invalid CA entry %j",
    (entry) => {
      writeManifest({ cas: { [ca.id]: entry } });
      expect(() => loadCaRegistry(caDir)).toThrow(/expected certFile and pkEnv/);
    }
  );

  it.each(["../ca.pem", "..\\ca.pem", "/ca.pem", "C:\\ca.pem", "sub/ca.pem", "sub\\ca.pem", "ca file.pem", ""])(
    "rejects unsafe certificate filename %j",
    (certFile) => {
      writeManifest({ cas: { [ca.id]: { certFile, pkEnv: ca.pkEnv } } });
      expect(() => loadCaRegistry(caDir)).toThrow();
      expect(() => readCaCertPem({ ...ca, certFile }, caDir)).toThrow(/Invalid intermediate CA filename/);
    }
  );

  it("reports a missing certificate", () => {
    expect(() => readCaCertPem(ca, caDir)).toThrow(/Failed to read Intermediate CA certificate for 'test-ca'/);
  });

  it.each(["not PEM", "-----BEGIN CERTIFICATE-----\nmissing end marker"])(
    "rejects malformed PEM from files",
    (pem) => {
      fs.writeFileSync(path.join(caDir, ca.certFile), pem);
      expect(() => readCaCertPem(ca, caDir)).toThrow(/invalid PEM format/);
    }
  );

  it("propagates a missing certificate error during CA selection", async () => {
    CONFIG.CA_DIR = caDir;
    const env = { ASSETS: testAssets, DB: createMockD1Database(), PK_TEST: "configured-key" };
    await expect(selectIntermediateCa(env, { candidates: [ca] })).rejects.toThrow(
      /Failed to read Intermediate CA certificate for 'test-ca'/
    );
  });
});
