import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as x509 from "@peculiar/x509";
import { AcmeEnv, CONFIG } from "../src/config";
import {
  IntermediateCaEntry,
  loadCaRegistry,
  readCaCertPem,
  selectIntermediateCa,
} from "../src/crypto/ca";
import { issueCertificateFromCsr, parseAndVerifyCsr } from "../src/crypto/x509";
import { createMockD1Database } from "./mock-d1";
import { base64UrlEncode } from "../src/crypto/nonce";

describe("Intermediate CA Dynamic Loading & Weighted Selection", () => {
  let originalExclusions: string[];
  let originalWeights: Record<string, number>;

  beforeEach(() => {
    originalExclusions = [...CONFIG.EXCLUDED_CA_IDS];
    originalWeights = { ...CONFIG.CA_WEIGHTS };
  });

  afterEach(() => {
    CONFIG.EXCLUDED_CA_IDS = originalExclusions;
    CONFIG.CA_WEIGHTS = originalWeights;
  });

  it("should dynamically load CA registry and read certificate from designated directory", () => {
    const registry = loadCaRegistry("cas");
    expect(registry.length).toBeGreaterThan(0);

    const genericCa = registry.find((ca) => ca.id === "generic-intermediate");
    expect(genericCa).toBeDefined();
    expect(genericCa!.certFile).toBe("generic-intermediate.pem");
    expect(genericCa!.pkEnv).toBe("PK_GENERIC_INTERMEDIATE");

    // Attempt to read certificate PEM from designated directory
    const certPem = readCaCertPem(genericCa!, "cas");
    expect(certPem).toContain("-----BEGIN CERTIFICATE-----");
    expect(certPem).toContain("-----END CERTIFICATE-----");

    const parsed = new x509.X509Certificate(certPem);
    expect(parsed.subject).toContain("CFMS Intermediate CA");
  });

  it("should throw error if certificate file does not exist in designated directory", () => {
    const nonExistentCa: IntermediateCaEntry = {
      id: "ghost-ca",
      certFile: "non-existent-ca.pem",
      pkEnv: "PK_GHOST_CA",
      weight: 1,
    };

    expect(() => readCaCertPem(nonExistentCa, "cas")).toThrowError(
      /Failed to read Intermediate CA certificate for 'ghost-ca'/
    );
  });

  it("should select the single available intermediate CA when private key is present", async () => {
    // Generate dummy key
    const keys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const pkcs8Der = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
    const pkPem = `-----BEGIN PRIVATE KEY-----\n${Buffer.from(pkcs8Der as ArrayBuffer).toString("base64")}\n-----END PRIVATE KEY-----`;

    const env: AcmeEnv = {
      DB: createMockD1Database(),
      CA_DIR: "cas",
      PK_GENERIC_INTERMEDIATE: pkPem,
    };

    const selected = await selectIntermediateCa(env);
    expect(selected.ca.id).toBe("generic-intermediate");
    expect(selected.certPem).toContain("-----BEGIN CERTIFICATE-----");
    expect(selected.privateKey).toBeDefined();
  });

  it("should exclude CA when configured in CONFIG.EXCLUDED_CA_IDS", async () => {
    CONFIG.EXCLUDED_CA_IDS = ["generic-intermediate"];

    const env: AcmeEnv = {
      DB: createMockD1Database(),
      CA_DIR: "cas",
      PK_GENERIC_INTERMEDIATE: "some-key",
    };

    await expect(selectIntermediateCa(env)).rejects.toThrowError(
      /No eligible Intermediate CA available for certificate issuance/
    );
  });

  it("should exclude CA when configured in env.EXCLUDED_CA_IDS", async () => {
    const env: AcmeEnv = {
      DB: createMockD1Database(),
      CA_DIR: "cas",
      EXCLUDED_CA_IDS: "generic-intermediate,other-ca",
      PK_GENERIC_INTERMEDIATE: "some-key",
    };

    await expect(selectIntermediateCa(env)).rejects.toThrowError(
      /No eligible Intermediate CA available for certificate issuance/
    );
  });

  it("should exclude CAs whose private keys are missing from the environment", async () => {
    const env: AcmeEnv = {
      DB: createMockD1Database(),
      CA_DIR: "cas",
      // PK_GENERIC_INTERMEDIATE is deliberately not set
    };

    await expect(selectIntermediateCa(env)).rejects.toThrowError(
      /No eligible Intermediate CA available for certificate issuance/
    );
  });

  it("should perform weighted random selection across multiple candidate CAs", async () => {
    // Generate two mock CAs
    const caAKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const caBKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;

    const caAPkPem = `-----BEGIN PRIVATE KEY-----\n${Buffer.from((await crypto.subtle.exportKey("pkcs8", caAKeys.privateKey)) as ArrayBuffer).toString("base64")}\n-----END PRIVATE KEY-----`;
    const caBPkPem = `-----BEGIN PRIVATE KEY-----\n${Buffer.from((await crypto.subtle.exportKey("pkcs8", caBKeys.privateKey)) as ArrayBuffer).toString("base64")}\n-----END PRIVATE KEY-----`;

    const candidates: IntermediateCaEntry[] = [
      { id: "ca-alpha", certFile: "generic-intermediate.pem", pkEnv: "PK_ALPHA", weight: 3 }, // 75%
      { id: "ca-beta", certFile: "generic-intermediate.pem", pkEnv: "PK_BETA", weight: 1 },   // 25%
    ];

    const env: AcmeEnv = {
      DB: createMockD1Database(),
      CA_DIR: "cas",
      PK_ALPHA: caAPkPem,
      PK_BETA: caBPkPem,
    };

    let alphaCount = 0;
    let betaCount = 0;
    const iterations = 1000;

    for (let i = 0; i < iterations; i++) {
      const selected = await selectIntermediateCa(env, { candidates });
      if (selected.ca.id === "ca-alpha") alphaCount++;
      if (selected.ca.id === "ca-beta") betaCount++;
    }

    const alphaRatio = alphaCount / iterations;
    const betaRatio = betaCount / iterations;

    // Expected ratio is ~0.75 for Alpha and ~0.25 for Beta
    expect(alphaRatio).toBeGreaterThan(0.65);
    expect(alphaRatio).toBeLessThan(0.85);
    expect(betaRatio).toBeGreaterThan(0.15);
    expect(betaRatio).toBeLessThan(0.35);
  });

  it("should issue a certificate using the dynamically selected Intermediate CA", async () => {
    // Create an intermediate CA
    const caKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;

    const caCert = await x509.X509CertificateGenerator.create({
      serialNumber: "0102030405060708090b",
      subject: "CN=Dynamic Selected Intermediate CA, O=CFMS",
      issuer: "CN=CFMS Root CA",
      notBefore: new Date(),
      notAfter: new Date(Date.now() + 365 * 86400 * 1000),
      publicKey: caKeys.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new x509.BasicConstraintsExtension(true, undefined, true),
        await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey),
      ],
    });

    const caPkPem = `-----BEGIN PRIVATE KEY-----\n${Buffer.from((await crypto.subtle.exportKey("pkcs8", caKeys.privateKey)) as ArrayBuffer).toString("base64")}\n-----END PRIVATE KEY-----`;

    const clientKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=service.example.org",
      keys: clientKeys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new x509.SubjectAlternativeNameExtension([
          { type: "dns", value: "service.example.org" },
        ]),
      ],
    });

    const mockEnv: AcmeEnv = {
      DB: createMockD1Database(),
      CA_DIR: "cas",
      CA_CERT_PEM: caCert.toString("pem"),
      PK_GENERIC_INTERMEDIATE: caPkPem,
    };

    const issued = await issueCertificateFromCsr(csr, ["service.example.org"], mockEnv);

    expect(issued.caId).toBe("generic-intermediate");
    expect(issued.chainPem).toContain(caCert.toString("pem"));

    const leaf = new x509.X509Certificate(issued.leafPem);
    expect(leaf.issuer).toBe("CN=Dynamic Selected Intermediate CA, O=CFMS");
    expect(leaf.subject).toBe("CN=service.example.org");

    // Verify signature with CA's public key
    const valid = await leaf.verify({
      publicKey: caKeys.publicKey,
      signatureOnly: true,
    });
    expect(valid).toBe(true);
  });

  it("should automatically skip expired intermediate CAs during selection", async () => {
    const expiredKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const expiredCert = await x509.X509CertificateGenerator.create({
      serialNumber: "0102030405060708090c",
      subject: "CN=Expired Intermediate CA, O=CFMS",
      issuer: "CN=CFMS Root CA",
      notBefore: new Date(Date.now() - 365 * 86400 * 1000),
      notAfter: new Date(Date.now() - 86400 * 1000), // Expired!
      publicKey: expiredKeys.publicKey,
      signingKey: expiredKeys.privateKey,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new x509.BasicConstraintsExtension(true, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign),
      ],
    });
    const expiredPkPem = `-----BEGIN PRIVATE KEY-----\n${Buffer.from((await crypto.subtle.exportKey("pkcs8", expiredKeys.privateKey)) as ArrayBuffer).toString("base64")}\n-----END PRIVATE KEY-----`;

    const env: AcmeEnv = {
      DB: createMockD1Database(),
      CA_DIR: "cas",
      CA_CERT_PEM: expiredCert.toString("pem"),
      PK_GENERIC_INTERMEDIATE: expiredPkPem,
    };

    // Since generic-intermediate's cert is expired, it should be excluded from selection
    await expect(selectIntermediateCa(env)).rejects.toThrowError(
      /No eligible Intermediate CA available for certificate issuance/
    );
  });
});
