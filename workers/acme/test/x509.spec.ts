import { mockCaCertificate } from "./ca-test-helpers";
import { describe, it, expect } from "vitest";
import * as x509 from "@peculiar/x509";
import {
  derivePublicKeyIdentity,
  issueCertificateFromCsr,
  parseAndVerifyCsr,
} from "../src/crypto/x509";
import { base64UrlEncode } from "../src/crypto/nonce";
import { AcmeEnv, CONFIG } from "../src/config";
import { createMockD1Database } from "./mock-d1";

describe("X.509 Certificate Issuance & CSR Handling", () => {
  it("should parse and verify PKCS#10 CSR", async () => {
    const clientKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;

    const csrObj = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=example.com",
      keys: clientKeys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new x509.SubjectAlternativeNameExtension([
          { type: "dns", value: "example.com" },
          { type: "dns", value: "www.example.com" },
        ]),
      ],
    });

    const csrDer = csrObj.rawData;
    const csrB64Url = base64UrlEncode(csrDer);

    const parsed = await parseAndVerifyCsr(csrB64Url);
    expect(parsed.domains).toEqual(["example.com", "www.example.com"]);
    expect(parsed.publicKey).toBeDefined();
  });

  it("rejects a CSR that requests a non-DNS SAN such as an IP address", async () => {
    const clientKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;

    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=example.com",
      keys: clientKeys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new x509.SubjectAlternativeNameExtension([
          { type: "dns", value: "example.com" },
          { type: "ip", value: "192.0.2.1" },
        ]),
      ],
    });

    await expect(parseAndVerifyCsr(base64UrlEncode(csr.rawData))).rejects.toMatchObject({
      type: "urn:ietf:params:acme:error:badCSR",
    });
  });

  it("accepts a SAN-only CSR without a subject commonName", async () => {
    const clientKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      keys: clientKeys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new x509.SubjectAlternativeNameExtension([
          { type: "dns", value: "example.com" },
        ]),
      ],
    });

    const parsed = await parseAndVerifyCsr(base64UrlEncode(csr.rawData));
    expect(parsed.domains).toEqual(["example.com"]);
  });

  it("includes a valid DNS commonName in the requested identifier set", async () => {
    const clientKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=evil.example.com",
      keys: clientKeys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new x509.SubjectAlternativeNameExtension([
          { type: "dns", value: "example.com" },
        ]),
      ],
    });

    const parsed = await parseAndVerifyCsr(base64UrlEncode(csr.rawData));
    expect(parsed.domains.sort()).toEqual(["evil.example.com", "example.com"]);
  });

  it("accepts a CN-only DNS identifier and ignores a descriptive CN when SANs exist", async () => {
    const cnKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const cnOnly = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=example.com",
      keys: cnKeys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    });
    const parsedCn = await parseAndVerifyCsr(base64UrlEncode(cnOnly.rawData));
    expect(parsedCn.domains).toEqual(["example.com"]);

    const sanKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const descriptiveCn = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=ACME Client",
      keys: sanKeys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new x509.SubjectAlternativeNameExtension([
          { type: "dns", value: "example.com" },
        ]),
      ],
    });
    const parsedSan = await parseAndVerifyCsr(base64UrlEncode(descriptiveCn.rawData));
    expect(parsedSan.domains).toEqual(["example.com"]);
  });

  it("normalizes a supported non-account key algorithm (ECDSA P-384)", async () => {
    const keys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-384" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=example.com",
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-384" },
      extensions: [
        new x509.SubjectAlternativeNameExtension([
          { type: "dns", value: "example.com" },
        ]),
      ],
    });

    const parsed = await parseAndVerifyCsr(base64UrlEncode(csr.rawData));
    expect(parsed.publicKeySpki.length).toBeGreaterThan(0);
    expect(parsed.publicKeyThumbprint).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("rejects a CSR whose public key cannot be normalized for key reuse checks", async () => {
    // X25519 is an SPKI algorithm the ACME server cannot use to verify a CSR
    // signature or to compare with an account key. Normalization must fail
    // closed instead of treating the key as "different" by default.
    const x25519 = (await crypto.subtle.generateKey({ name: "X25519" }, true, [
      "deriveBits",
    ])) as CryptoKeyPair;
    const spki = (await crypto.subtle.exportKey(
      "spki",
      x25519.publicKey
    )) as ArrayBuffer;

    await expect(
      derivePublicKeyIdentity(new x509.PublicKey(new Uint8Array(spki)))
    ).rejects.toMatchObject({
      type: "urn:ietf:params:acme:error:badCSR",
    });
  });

  it("should issue a 90-day leaf certificate signed by intermediate CA", async () => {
    // 1. Generate an Intermediate CA key pair for testing
    const caKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const caCert = await x509.X509CertificateGenerator.create({
      serialNumber: "0102030405060708090a",
      subject: "CN=CFMS Intermediate CA, O=CFMS",
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

    // Export CA private key to PKCS#8 PEM
    const pkcs8Der = await crypto.subtle.exportKey("pkcs8", caKeys.privateKey);
    const pkcs8B64 = Buffer.from(pkcs8Der as ArrayBuffer).toString("base64");
    const caKeyPem = `-----BEGIN PRIVATE KEY-----\n${pkcs8B64}\n-----END PRIVATE KEY-----`;

    // 2. Generate a client CSR
    const clientKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=app.example.com",
      keys: clientKeys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new x509.SubjectAlternativeNameExtension([
          { type: "dns", value: "app.example.com" },
          { type: "dns", value: "api.example.com" },
        ]),
      ],
    });

    mockCaCertificate(caCert.toString("pem"));
    const mockEnv: AcmeEnv = {
      DB: createMockD1Database(),
      PK_GENERIC_INTERMEDIATE: caKeyPem,
    };

    // 3. Issue certificate
    const issued = await issueCertificateFromCsr(
      csr,
      ["app.example.com", "api.example.com"],
      mockEnv,
      90
    );

    expect(issued.serialNumber).toBeDefined();
    expect(issued.certId).toContain(".");
    expect(issued.chainPem).toContain("-----BEGIN CERTIFICATE-----");

    // 4. Verify validity is exactly 90 days
    const validityDays = (issued.notAfter - issued.notBefore) / 86400;
    expect(validityDays).toBe(90);

    // 5. Verify issued certificate details
    const parsedCert = new x509.X509Certificate(issued.leafPem);
    expect(parsedCert.subject).toBe("CN=app.example.com");
    expect(parsedCert.issuer).toBe("CN=CFMS Intermediate CA, O=CFMS");

    // Verify signature with CA public key
    const sigValid = await parsedCert.verify({
      publicKey: caKeys.publicKey,
      signatureOnly: true,
    });
    expect(sigValid).toBe(true);
  });
});
