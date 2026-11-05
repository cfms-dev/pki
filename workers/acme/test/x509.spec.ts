import { describe, it, expect } from "vitest";
import * as x509 from "@peculiar/x509";
import {
  issueCertificateFromCsr,
  parseAndVerifyCsr,
} from "../src/crypto/x509";
import { base64UrlEncode } from "../src/crypto/nonce";
import { AcmeEnv, CONFIG } from "../src/config";
import { createMockD1Database } from "./mock-d1";

describe("X.509 Certificate Issuance & CSR Handling", () => {
  it("should parse and verify PKCS#10 CSR", async () => {
    const clientKeys = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );

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

  it("should issue a 90-day leaf certificate signed by intermediate CA", async () => {
    // 1. Generate an Intermediate CA key pair for testing
    const caKeys = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
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
        new x509.BasicConstraintsExtension(true, true),
        await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey),
      ],
    });

    // Export CA private key to PKCS#8 PEM
    const pkcs8Der = await crypto.subtle.exportKey("pkcs8", caKeys.privateKey);
    const pkcs8B64 = Buffer.from(pkcs8Der).toString("base64");
    const caKeyPem = `-----BEGIN PRIVATE KEY-----\n${pkcs8B64}\n-----END PRIVATE KEY-----`;

    // 2. Generate a client CSR
    const clientKeys = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
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

    const mockEnv: AcmeEnv = {
      DB: createMockD1Database(),
      CA_CERT_PEM: caCert.toString("pem"),
      PK_GENERIC_INTERMEDIATE: caKeyPem,
      PK_ENV_VAR: "PK_GENERIC_INTERMEDIATE",
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
