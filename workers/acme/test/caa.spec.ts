import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as x509 from "@peculiar/x509";
import { CAA_ISSUER_DOMAIN_NAME, CONFIG, AcmeEnv } from "../src/config";
import { handleDirectory } from "../src/routes/directory";
import {
  CaaRecord,
  evaluateCaaRecords,
  findRelevantCaaRecordSet,
  parseCaaRecord,
  parseCaaValue,
  validateCaa,
  validateCaaForOrder,
} from "../src/dns/caa";
import {
  IntermediateCaEntry,
  selectIntermediateCa,
  validateIntermediateCaCertificate,
} from "../src/crypto/ca";
import { createMockD1Database } from "./mock-d1";
import { Database } from "../src/db/queries";
import { handleFinalizeOrder, handleNewOrder } from "../src/routes/order";
import { base64UrlEncode } from "../src/crypto/nonce";
import { calculateJwkThumbprint } from "../src/crypto/jws";

describe("Unified CAA Identity & RFC 8659 Validation", () => {
  describe("1. Configuration and ACME Directory", () => {
    it("should export CAA_ISSUER_DOMAIN_NAME as cfms-pki.crpteam.club", () => {
      expect(CAA_ISSUER_DOMAIN_NAME).toBe("cfms-pki.crpteam.club");
      expect(CONFIG.CAA_ISSUER_DOMAIN_NAME).toBe("cfms-pki.crpteam.club");
    });

    it("should publish CAA_ISSUER_DOMAIN_NAME in ACME Directory meta.caaIdentities", async () => {
      const mockEnv: AcmeEnv = { DB: createMockD1Database() };
      const resp = handleDirectory(
        new Request("https://acme.test/directory"),
        mockEnv,
        "https://acme.test"
      );
      expect(resp.status).toBe(200);

      const data = (await resp.json()) as {
        meta: { caaIdentities: string[]; website: string };
      };
      expect(data.meta).toBeDefined();
      expect(data.meta.caaIdentities).toEqual(["cfms-pki.crpteam.club"]);
      expect(data.meta.caaIdentities[0]).toBe(CAA_ISSUER_DOMAIN_NAME);
    });
  });

  describe("2. CAA Record and Parameter Parsing", () => {
    it("should parse standard issue record without parameters", () => {
      const parsed = parseCaaRecord('0 issue "cfms-pki.crpteam.club"');
      expect(parsed).not.toBeNull();
      expect(parsed!.flags).toBe(0);
      expect(parsed!.tag).toBe("issue");
      expect(parsed!.issuerDomain).toBe("cfms-pki.crpteam.club");
      expect(parsed!.parameters).toEqual({});
    });

    it("should parse record with unquoted value or trailing dot", () => {
      const parsed = parseCaaRecord("0 issue cfms-pki.crpteam.club.");
      expect(parsed).not.toBeNull();
      expect(parsed!.issuerDomain).toBe("cfms-pki.crpteam.club");
    });

    it("should parse uppercase and whitespace gracefully", () => {
      const parsed = parseCaaRecord('  0   ISSUE   "  CFMS-PKI.CRPTEAM.CLUB  "  ');
      expect(parsed).not.toBeNull();
      expect(parsed!.tag).toBe("issue");
      expect(parsed!.issuerDomain).toBe("cfms-pki.crpteam.club");
    });

    it("should correctly parse optional parameters without including them in issuerDomain", () => {
      const parsed = parseCaaRecord(
        '0 issue "cfms-pki.crpteam.club; accounturi=https://acme.test/account/123; validationmethods=dns-01"'
      );
      expect(parsed).not.toBeNull();
      // Crucial requirement: Must not compare full property value as domain
      expect(parsed!.issuerDomain).toBe("cfms-pki.crpteam.club");
      expect(parsed!.parameters.accounturi).toBe("https://acme.test/account/123");
      expect(parsed!.parameters.validationmethods).toBe("dns-01");
    });

    it("should parse empty domain or semicolon (prohibition)", () => {
      const p1 = parseCaaRecord('0 issue ";"');
      expect(p1).not.toBeNull();
      expect(p1!.issuerDomain).toBe("");

      const p2 = parseCaaRecord('0 issue ""');
      expect(p2).not.toBeNull();
      expect(p2!.issuerDomain).toBe("");
    });

    it("should parse issuewild tag", () => {
      const parsed = parseCaaRecord('0 issuewild "cfms-pki.crpteam.club"');
      expect(parsed).not.toBeNull();
      expect(parsed!.flags).toBe(0);
      expect(parsed!.tag).toBe("issuewild");
      expect(parsed!.issuerDomain).toBe("cfms-pki.crpteam.club");
    });

    it("should parse critical flag bit 0 (0x80 = 128)", () => {
      const parsed = parseCaaRecord('128 customtag "some-val"');
      expect(parsed).not.toBeNull();
      expect(parsed!.flags).toBe(128);
      expect(parsed!.tag).toBe("customtag");
    });

    it("should parse RFC 3597 presentation format hex data", () => {
      // 00 05 6973737565 (issue) 63666d732d706b692e6372707465616d2e636c7562 (cfms-pki.crpteam.club)
      const hex = "0005697373756563666d732d706b692e6372707465616d2e636c7562";
      const parsed = parseCaaRecord(`\\# 27 ${hex}`);
      expect(parsed).not.toBeNull();
      expect(parsed!.flags).toBe(0);
      expect(parsed!.tag).toBe("issue");
      expect(parsed!.issuerDomain).toBe("cfms-pki.crpteam.club");
    });
  });

  describe("3. RFC 8659 CAA Authorization Logic", () => {
    it("should permit non-wildcard domain when issue matches CAA_ISSUER_DOMAIN_NAME", () => {
      const records: CaaRecord[] = [
        {
          flags: 0,
          tag: "issue",
          value: "cfms-pki.crpteam.club",
          issuerDomain: "cfms-pki.crpteam.club",
          parameters: {},
        },
      ];
      const res = evaluateCaaRecords(records, false);
      expect(res.valid).toBe(true);
    });

    it("should forbid non-wildcard domain when issue specifies another CA", () => {
      const records: CaaRecord[] = [
        {
          flags: 0,
          tag: "issue",
          value: "other-ca.com",
          issuerDomain: "other-ca.com",
          parameters: {},
        },
      ];
      const res = evaluateCaaRecords(records, false);
      expect(res.valid).toBe(false);
      expect(res.error).toContain("CAA issue record forbids issuance");
    });

    it("should forbid issuance when issue explicitly prohibits all CAs (issue ';')", () => {
      const records: CaaRecord[] = [
        {
          flags: 0,
          tag: "issue",
          value: ";",
          issuerDomain: "",
          parameters: {},
        },
      ];
      const res = evaluateCaaRecords(records, false);
      expect(res.valid).toBe(false);
    });

    it("should permit issuance when multiple issue records exist and at least one matches", () => {
      const records: CaaRecord[] = [
        {
          flags: 0,
          tag: "issue",
          value: "letsencrypt.org",
          issuerDomain: "letsencrypt.org",
          parameters: {},
        },
        {
          flags: 0,
          tag: "issue",
          value: "cfms-pki.crpteam.club",
          issuerDomain: "cfms-pki.crpteam.club",
          parameters: {},
        },
      ];
      const res = evaluateCaaRecords(records, false);
      expect(res.valid).toBe(true);
    });

    it("should ignore issuewild records for non-wildcard domains", () => {
      const records: CaaRecord[] = [
        {
          flags: 0,
          tag: "issuewild",
          value: ";",
          issuerDomain: "",
          parameters: {},
        },
        {
          flags: 0,
          tag: "issue",
          value: "cfms-pki.crpteam.club",
          issuerDomain: "cfms-pki.crpteam.club",
          parameters: {},
        },
      ];
      const res = evaluateCaaRecords(records, false);
      expect(res.valid).toBe(true);
    });

    it("should give issuewild precedence over issue for wildcard domains", () => {
      // issuewild forbids, while issue permits -> wildcard MUST be rejected
      const records: CaaRecord[] = [
        {
          flags: 0,
          tag: "issuewild",
          value: ";",
          issuerDomain: "",
          parameters: {},
        },
        {
          flags: 0,
          tag: "issue",
          value: "cfms-pki.crpteam.club",
          issuerDomain: "cfms-pki.crpteam.club",
          parameters: {},
        },
      ];
      const res = evaluateCaaRecords(records, true);
      expect(res.valid).toBe(false);
      expect(res.error).toContain("CAA issuewild record forbids issuance for wildcard domain");
    });

    it("should authorize wildcard domain when issuewild matches CAA_ISSUER_DOMAIN_NAME", () => {
      const records: CaaRecord[] = [
        {
          flags: 0,
          tag: "issuewild",
          value: "cfms-pki.crpteam.club",
          issuerDomain: "cfms-pki.crpteam.club",
          parameters: {},
        },
        {
          flags: 0,
          tag: "issue",
          value: "other-ca.com",
          issuerDomain: "other-ca.com",
          parameters: {},
        },
      ];
      const res = evaluateCaaRecords(records, true);
      expect(res.valid).toBe(true);
    });

    it("should fall back to issue for wildcard domains if issuewild is not present", () => {
      const records: CaaRecord[] = [
        {
          flags: 0,
          tag: "issue",
          value: "cfms-pki.crpteam.club",
          issuerDomain: "cfms-pki.crpteam.club",
          parameters: {},
        },
      ];
      const res = evaluateCaaRecords(records, true);
      expect(res.valid).toBe(true);
    });

    it("should leave non-wildcard issuance unrestricted if only non-issuing tags (e.g. iodef) are present", () => {
      const records: CaaRecord[] = [
        {
          flags: 0,
          tag: "iodef",
          value: "mailto:security@example.com",
          issuerDomain: "mailto:security@example.com",
          parameters: {},
        },
      ];
      const res = evaluateCaaRecords(records, false);
      expect(res.valid).toBe(true);
    });

    it("should reject issuance if any record has critical flag set on unrecognized tag", () => {
      const records: CaaRecord[] = [
        {
          flags: 128, // critical bit set!
          tag: "unknowncriticalproperty",
          value: "strict",
          issuerDomain: "strict",
          parameters: {},
        },
        {
          flags: 0,
          tag: "issue",
          value: "cfms-pki.crpteam.club",
          issuerDomain: "cfms-pki.crpteam.club",
          parameters: {},
        },
      ];
      const res = evaluateCaaRecords(records, false);
      expect(res.valid).toBe(false);
      expect(res.error).toContain("Unrecognized critical CAA property tag 'unknowncriticalproperty'");
    });

    it("should enforce RFC 8659 accounturi parameter check", () => {
      const records: CaaRecord[] = [
        {
          flags: 0,
          tag: "issue",
          value: "cfms-pki.crpteam.club; accounturi=https://acme.test/account/42",
          issuerDomain: "cfms-pki.crpteam.club",
          parameters: { accounturi: "https://acme.test/account/42" },
        },
      ];

      // Matching account URI -> authorized
      const resMatching = evaluateCaaRecords(records, false, "https://acme.test/account/42");
      expect(resMatching.valid).toBe(true);

      // Mismatched account URI -> denied
      const resMismatched = evaluateCaaRecords(records, false, "https://acme.test/account/999");
      expect(resMismatched.valid).toBe(false);
    });

    it("should enforce RFC 8659 validationmethods parameter check", () => {
      // Allows dns-01
      const recordsWithDns01: CaaRecord[] = [
        {
          flags: 0,
          tag: "issue",
          value: "cfms-pki.crpteam.club; validationmethods=dns-01",
          issuerDomain: "cfms-pki.crpteam.club",
          parameters: { validationmethods: "dns-01" },
        },
      ];
      expect(evaluateCaaRecords(recordsWithDns01, false).valid).toBe(true);

      // Disallows dns-01 (only allows http-01)
      const recordsHttp01Only: CaaRecord[] = [
        {
          flags: 0,
          tag: "issue",
          value: "cfms-pki.crpteam.club; validationmethods=http-01",
          issuerDomain: "cfms-pki.crpteam.club",
          parameters: { validationmethods: "http-01" },
        },
      ];
      expect(evaluateCaaRecords(recordsHttp01Only, false).valid).toBe(false);
    });
  });

  describe("4. DNS Resolution & Tree-Walking (Inheritance)", () => {
    it("should inherit CAA record from apex when subdomain has no CAA records", async () => {
      const mockFetch: typeof fetch = async (input) => {
        const url = String(input);
        if (url.includes("name=sub.example.org")) {
          return new Response(JSON.stringify({ Status: 0, Answer: [] }), {
            headers: { "Content-Type": "application/dns-json" },
          });
        }
        if (url.includes("name=example.org")) {
          return new Response(
            JSON.stringify({
              Status: 0,
              Answer: [
                {
                  name: "example.org.",
                  type: 257,
                  data: '0 issue "cfms-pki.crpteam.club"',
                },
              ],
            }),
            { headers: { "Content-Type": "application/dns-json" } }
          );
        }
        return new Response(JSON.stringify({ Status: 0, Answer: [] }), {
          headers: { "Content-Type": "application/dns-json" },
        });
      };

      const result = await validateCaa("sub.example.org", undefined, mockFetch);
      expect(result.valid).toBe(true);
      expect(result.relevantDomain).toBe("example.org");
    });

    it("should override parent CAA record when subdomain has its own CAA records", async () => {
      const mockFetch: typeof fetch = async (input) => {
        const url = String(input);
        if (url.includes("name=sub.example.org")) {
          return new Response(
            JSON.stringify({
              Status: 0,
              Answer: [
                {
                  name: "sub.example.org.",
                  type: 257,
                  data: '0 issue "other-ca.com"',
                },
              ],
            }),
            { headers: { "Content-Type": "application/dns-json" } }
          );
        }
        if (url.includes("name=example.org")) {
          return new Response(
            JSON.stringify({
              Status: 0,
              Answer: [
                {
                  name: "example.org.",
                  type: 257,
                  data: '0 issue "cfms-pki.crpteam.club"',
                },
              ],
            }),
            { headers: { "Content-Type": "application/dns-json" } }
          );
        }
        return new Response(JSON.stringify({ Status: 0, Answer: [] }), {
          headers: { "Content-Type": "application/dns-json" },
        });
      };

      const result = await validateCaa("sub.example.org", undefined, mockFetch);
      // Subdomain specifies other-ca.com, so it must be rejected even though parent authorized cfms-pki
      expect(result.valid).toBe(false);
      expect(result.relevantDomain).toBe("sub.example.org");
    });

    it("should follow CNAME alias target according to RFC 8659 Section 3.2", async () => {
      const mockFetch: typeof fetch = async (input) => {
        const url = String(input);
        if (url.includes("name=alias.example.org")) {
          return new Response(
            JSON.stringify({
              Status: 0,
              Answer: [
                {
                  name: "alias.example.org.",
                  type: 5,
                  data: "target.cdn.net.",
                },
              ],
            }),
            { headers: { "Content-Type": "application/dns-json" } }
          );
        }
        if (url.includes("name=target.cdn.net")) {
          return new Response(
            JSON.stringify({
              Status: 0,
              Answer: [
                {
                  name: "target.cdn.net.",
                  type: 257,
                  data: '0 issue "cfms-pki.crpteam.club"',
                },
              ],
            }),
            { headers: { "Content-Type": "application/dns-json" } }
          );
        }
        return new Response(JSON.stringify({ Status: 0, Answer: [] }), {
          headers: { "Content-Type": "application/dns-json" },
        });
      };

      const result = await validateCaa("alias.example.org", undefined, mockFetch);
      expect(result.valid).toBe(true);
      expect(result.relevantDomain).toBe("target.cdn.net");
    });

    it("should permit issuance when no CAA records exist anywhere in the domain tree", async () => {
      const mockFetch: typeof fetch = async () => {
        return new Response(JSON.stringify({ Status: 0, Answer: [] }), {
          headers: { "Content-Type": "application/dns-json" },
        });
      };

      const result = await validateCaa("nonexistent-caa.example.org", undefined, mockFetch);
      expect(result.valid).toBe(true);
      expect(result.relevantDomain).toBeUndefined();
    });
  });

  describe("5. Intermediate CA Pool & Unified CAA Identity Integration", () => {
    it("should enforce certificate validity and exclude expired or non-CA certificates", async () => {
      // 1. Valid CA
      const keys = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );
      const now = new Date();

      const validCert = await x509.X509CertificateGenerator.create({
        serialNumber: "0102030405",
        subject: "CN=Valid Intermediate CA",
        issuer: "CN=Root CA",
        notBefore: new Date(now.getTime() - 10000),
        notAfter: new Date(now.getTime() + 86400 * 1000),
        publicKey: keys.publicKey,
        signingKey: keys.privateKey,
        signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
        extensions: [
          new x509.BasicConstraintsExtension(true, true),
          new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign),
        ],
      });

      const caEntry: IntermediateCaEntry = {
        id: "test-ca",
        certFile: "test-ca.pem",
        pkEnv: "PK_TEST",
        weight: 1,
      };

      const checkValid = validateIntermediateCaCertificate(caEntry, validCert.toString("pem"), now);
      expect(checkValid.eligible).toBe(true);

      // 2. Expired CA
      const expiredCert = await x509.X509CertificateGenerator.create({
        serialNumber: "0102030406",
        subject: "CN=Expired CA",
        issuer: "CN=Root CA",
        notBefore: new Date(now.getTime() - 100000),
        notAfter: new Date(now.getTime() - 1000),
        publicKey: keys.publicKey,
        signingKey: keys.privateKey,
        signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
        extensions: [new x509.BasicConstraintsExtension(true, true)],
      });
      const checkExpired = validateIntermediateCaCertificate(caEntry, expiredCert.toString("pem"), now);
      expect(checkExpired.eligible).toBe(false);
      expect(checkExpired.reason).toContain("expired");

      // 3. Not a CA (basicConstraints CA=false)
      const leafCert = await x509.X509CertificateGenerator.create({
        serialNumber: "0102030407",
        subject: "CN=Not A CA",
        issuer: "CN=Root CA",
        notBefore: new Date(now.getTime() - 10000),
        notAfter: new Date(now.getTime() + 86400 * 1000),
        publicKey: keys.publicKey,
        signingKey: keys.privateKey,
        signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
        extensions: [new x509.BasicConstraintsExtension(false, true)],
      });
      const checkNotCa = validateIntermediateCaCertificate(caEntry, leafCert.toString("pem"), now);
      expect(checkNotCa.eligible).toBe(false);
      expect(checkNotCa.reason).toContain("lacks basicConstraints CA=true");

      // 4. Lacking keyCertSign
      const noSignCert = await x509.X509CertificateGenerator.create({
        serialNumber: "0102030408",
        subject: "CN=No Sign CA",
        issuer: "CN=Root CA",
        notBefore: new Date(now.getTime() - 10000),
        notAfter: new Date(now.getTime() + 86400 * 1000),
        publicKey: keys.publicKey,
        signingKey: keys.privateKey,
        signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
        extensions: [
          new x509.BasicConstraintsExtension(true, true),
          new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature), // missing keyCertSign
        ],
      });
      const checkNoSign = validateIntermediateCaCertificate(caEntry, noSignCert.toString("pem"), now);
      expect(checkNoSign.eligible).toBe(false);
      expect(checkNoSign.reason).toContain("forbids certificate signing");
    });

    it("should never change the CAA identity regardless of which intermediate CA is selected", async () => {
      // Regardless of selecting ca-alpha or ca-beta, the CAA validation identity is strictly CAA_ISSUER_DOMAIN_NAME
      expect(CAA_ISSUER_DOMAIN_NAME).toBe("cfms-pki.crpteam.club");
    });
  });

  describe("6. Order Finalize with Pre-Issuance CAA Verification", () => {
    let database: Database;
    let d1: D1Database;
    let accountKeys: CryptoKeyPair;
    let accountJwk: JsonWebKey;
    let accountThumbprint: string;
    let accountId: string;
    let caKeys: CryptoKeyPair;
    let caCertPem: string;
    let caPkPem: string;

    beforeEach(async () => {
      d1 = createMockD1Database();
      database = new Database(d1);
      await database.initSchema();

      accountKeys = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );
      accountJwk = await crypto.subtle.exportKey("jwk", accountKeys.publicKey);
      accountThumbprint = await calculateJwkThumbprint(accountJwk);
      accountId = crypto.randomUUID();

      await database.saveAccount({
        id: accountId,
        jwk: JSON.stringify(accountJwk),
        thumbprint: accountThumbprint,
        contact: JSON.stringify(["mailto:admin@example.org"]),
        status: "valid",
        created_at: Math.floor(Date.now() / 1000),
      });

      caKeys = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );
      const caCert = await x509.X509CertificateGenerator.create({
        serialNumber: "1234567890abcdef",
        subject: "CN=CFMS Intermediate CA 1, O=CFMS",
        issuer: "CN=CFMS Root CA",
        notBefore: new Date(Date.now() - 10000),
        notAfter: new Date(Date.now() + 365 * 86400 * 1000),
        publicKey: caKeys.publicKey,
        signingKey: caKeys.privateKey,
        signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
        extensions: [
          new x509.BasicConstraintsExtension(true, true),
          await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey),
        ],
      });
      caCertPem = caCert.toString("pem");
      const pkcs8Der = await crypto.subtle.exportKey("pkcs8", caKeys.privateKey);
      caPkPem = `-----BEGIN PRIVATE KEY-----\n${Buffer.from(pkcs8Der).toString("base64")}\n-----END PRIVATE KEY-----`;
    });

    async function createSignedJwsRequest(
      url: string,
      payload: Record<string, unknown>
    ): Promise<Request> {
      const nonce = crypto.randomUUID();
      await database.saveNonce(nonce, Math.floor(Date.now() / 1000) + 300);

      const protectedHeader = {
        alg: "ES256",
        nonce,
        url,
        kid: `https://acme.test/account/${accountId}`,
      };
      const protectedB64 = base64UrlEncode(
        new TextEncoder().encode(JSON.stringify(protectedHeader))
      );
      const payloadB64 = base64UrlEncode(
        new TextEncoder().encode(JSON.stringify(payload))
      );
      const sig = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        accountKeys.privateKey,
        new TextEncoder().encode(`${protectedB64}.${payloadB64}`)
      );

      return new Request(url, {
        method: "POST",
        headers: { "Content-Type": "application/jose+json" },
        body: JSON.stringify({
          protected: protectedB64,
          payload: payloadB64,
          signature: base64UrlEncode(sig),
        }),
      });
    }

    it("should succeed finalization when CAA allows cfms-pki.crpteam.club", async () => {
      const orderId = crypto.randomUUID();
      const authzId = crypto.randomUUID();
      const domain = "example.org";

      await database.saveOrder({
        id: orderId,
        account_id: accountId,
        status: "ready",
        identifiers: JSON.stringify([domain]),
        not_before: null,
        not_after: null,
        replaces_cert_id: null,
        is_ari_renewal: 0,
        created_at: Math.floor(Date.now() / 1000),
        expires_at: Math.floor(Date.now() / 1000) + 86400,
        certificate_id: null,
      });

      await database.saveAuthorization({
        id: authzId,
        order_id: orderId,
        identifier_value: domain,
        status: "valid",
        token: "validToken123",
        expires_at: Math.floor(Date.now() / 1000) + 86400,
        created_at: Math.floor(Date.now() / 1000),
      });

      const clientKeys = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );
      const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        name: `CN=${domain}`,
        keys: clientKeys,
        signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
        extensions: [
          new x509.SubjectAlternativeNameExtension([{ type: "dns", value: domain }]),
        ],
      });

      const finalizeReq = await createSignedJwsRequest(
        `https://acme.test/order/${orderId}/finalize`,
        { csr: base64UrlEncode(csr.rawData) }
      );

      const mockFetch: typeof fetch = async (input) => {
        const url = String(input);
        if (url.includes("name=example.org") && url.includes("type=CAA")) {
          return new Response(
            JSON.stringify({
              Status: 0,
              Answer: [
                {
                  name: "example.org.",
                  type: 257,
                  data: '0 issue "cfms-pki.crpteam.club"',
                },
              ],
            }),
            { headers: { "Content-Type": "application/dns-json" } }
          );
        }
        return new Response(JSON.stringify({ Status: 0, Answer: [] }), {
          headers: { "Content-Type": "application/dns-json" },
        });
      };

      const mockEnv: AcmeEnv = {
        DB: d1,
        CA_DIR: "cas",
        CA_CERT_PEM: caCertPem,
        PK_GENERIC_INTERMEDIATE: caPkPem,
        fetch: mockFetch,
      };

      const resp = await handleFinalizeOrder(
        finalizeReq,
        database,
        "https://acme.test",
        orderId,
        mockEnv
      );

      expect(resp.status).toBe(200);
      const body = (await resp.json()) as { status: string; certificate: string };
      expect(body.status).toBe("valid");
      expect(body.certificate).toBeDefined();

      // Check certificate saved in DB
      const certInDb = await database.getCertificateById(orderId); // order.certificate_id
      const certRow = await d1
        .prepare("SELECT * FROM certificates WHERE id = (SELECT certificate_id FROM orders WHERE id = ?)")
        .bind(orderId)
        .first<{ cert_id: string; pem: string; aki: string; serial_number: string }>();

      expect(certRow).toBeDefined();
      expect(certRow!.aki).toBeDefined();
      expect(certRow!.serial_number).toBeDefined();
      expect(certRow!.pem).toContain(caCertPem);
    });

    it("should reject finalization with 403 urn:ietf:params:acme:error:caa when CAA forbids CFMS-PKI", async () => {
      const orderId = crypto.randomUUID();
      const authzId = crypto.randomUUID();
      const domain = "forbidden.example.org";

      await database.saveOrder({
        id: orderId,
        account_id: accountId,
        status: "ready",
        identifiers: JSON.stringify([domain]),
        not_before: null,
        not_after: null,
        replaces_cert_id: null,
        is_ari_renewal: 0,
        created_at: Math.floor(Date.now() / 1000),
        expires_at: Math.floor(Date.now() / 1000) + 86400,
        certificate_id: null,
      });

      await database.saveAuthorization({
        id: authzId,
        order_id: orderId,
        identifier_value: domain,
        status: "valid",
        token: "validToken123",
        expires_at: Math.floor(Date.now() / 1000) + 86400,
        created_at: Math.floor(Date.now() / 1000),
      });

      const clientKeys = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );
      const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        name: `CN=${domain}`,
        keys: clientKeys,
        signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
        extensions: [
          new x509.SubjectAlternativeNameExtension([{ type: "dns", value: domain }]),
        ],
      });

      const finalizeReq = await createSignedJwsRequest(
        `https://acme.test/order/${orderId}/finalize`,
        { csr: base64UrlEncode(csr.rawData) }
      );

      // DoH returns other-ca.com only
      const mockFetch: typeof fetch = async (input) => {
        const url = String(input);
        if (url.includes("forbidden.example.org") && url.includes("type=CAA")) {
          return new Response(
            JSON.stringify({
              Status: 0,
              Answer: [
                {
                  name: "forbidden.example.org.",
                  type: 257,
                  data: '0 issue "other-ca.com"',
                },
              ],
            }),
            { headers: { "Content-Type": "application/dns-json" } }
          );
        }
        return new Response(JSON.stringify({ Status: 0, Answer: [] }), {
          headers: { "Content-Type": "application/dns-json" },
        });
      };

      const mockEnv: AcmeEnv = {
        DB: d1,
        CA_DIR: "cas",
        CA_CERT_PEM: caCertPem,
        PK_GENERIC_INTERMEDIATE: caPkPem,
        fetch: mockFetch,
      };

      await expect(
        handleFinalizeOrder(
          finalizeReq,
          database,
          "https://acme.test",
          orderId,
          mockEnv
        )
      ).rejects.toMatchObject({
        type: "urn:ietf:params:acme:error:caa",
        status: 403,
      });
    });
  });
});
