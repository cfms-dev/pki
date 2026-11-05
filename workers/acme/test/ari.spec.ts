import { describe, it, expect } from "vitest";
import { computeCertId, serialToDerContents } from "../src/ari/cert-id";
import {
  checkAriRenewalEligibility,
  computeSuggestedWindow,
} from "../src/ari/window";
import { CertificateRow } from "../src/db/types";

describe("RFC 9773 ACME Renewal Information (ARI)", () => {
  it("should correctly encode DER serial contents with positive MSB padding", () => {
    // 0x81 has MSB = 1 -> DER INTEGER must prepend 0x00
    const der1 = serialToDerContents("81020304");
    expect(der1[0]).toBe(0x00);
    expect(der1[1]).toBe(0x81);

    // 0x0f has MSB = 0 -> No leading 0x00 needed
    const der2 = serialToDerContents("0f020304");
    expect(der2[0]).toBe(0x0f);
  });

  it("should compute RFC 9773 certID formatted as Base64URL(AKI).Base64URL(Serial)", () => {
    const akiHex = "6201d570712233880fe20480a0831428240606fe";
    const serialHex = "0102030405060708090a0b0c0d0e0f10";

    const certId = computeCertId(akiHex, serialHex);
    expect(certId).toContain(".");

    const [part1, part2] = certId.split(".");
    expect(part1).toBeDefined();
    expect(part2).toBeDefined();

    // Must be base64url without '=' padding
    expect(part1).not.toContain("=");
    expect(part2).not.toContain("=");
    expect(part1).not.toMatch(/[+/]/);
    expect(part2).not.toMatch(/[+/]/);
  });

  it("should compute a 30-day suggested renewal window for a 90-day certificate", () => {
    const nowSec = 1700000000;
    const notBeforeSec = nowSec;
    const notAfterSec = nowSec + 90 * 86400; // 90 days validity

    const mockCert: CertificateRow = {
      id: "cert-1",
      cert_id: "test-aki.test-serial",
      serial_number: "01020304",
      aki: "11223344",
      subject: "CN=example.com",
      san: JSON.stringify(["example.com"]),
      pem: "-----BEGIN CERTIFICATE-----\n...",
      not_before: notBeforeSec,
      not_after: notAfterSec,
      account_id: "acc-1",
      created_at: notBeforeSec,
      revoked_at: null,
      revocation_reason: null,
      replaced_by_cert_id: null,
    };

    const window = computeSuggestedWindow(mockCert, 30, nowSec);
    const startSec = Math.floor(new Date(window.start).getTime() / 1000);
    const endSec = Math.floor(new Date(window.end).getTime() / 1000);

    // Window duration must be exactly 30 days
    expect((endSec - startSec) / 86400).toBe(30);

    // Window should end at not_after and start at day 60 (30 days before expiration)
    expect(endSec).toBe(notAfterSec);
    expect(startSec).toBe(notBeforeSec + 60 * 86400);
  });

  it("should shift suggested window into the past for revoked certificates", () => {
    const nowSec = 1700000000;
    const mockCert: CertificateRow = {
      id: "cert-revoked",
      cert_id: "test-aki.test-serial",
      serial_number: "01020304",
      aki: "11223344",
      subject: "CN=example.com",
      san: JSON.stringify(["example.com"]),
      pem: "-----BEGIN CERTIFICATE-----\n...",
      not_before: nowSec - 86400,
      not_after: nowSec + 89 * 86400,
      account_id: "acc-1",
      created_at: nowSec - 86400,
      revoked_at: nowSec,
      revocation_reason: "keyCompromise",
      replaced_by_cert_id: null,
    };

    const window = computeSuggestedWindow(mockCert, 30, nowSec);
    const startSec = Math.floor(new Date(window.start).getTime() / 1000);
    const endSec = Math.floor(new Date(window.end).getTime() / 1000);

    // Suggested window is in the past to trigger immediate renewal
    expect(endSec).toBeLessThanOrEqual(nowSec);
    expect(startSec).toBeLessThan(endSec);
  });

  it("should correctly evaluate ARI renewal eligibility", () => {
    const notBeforeSec = 1700000000;
    const notAfterSec = notBeforeSec + 90 * 86400;

    const cert: CertificateRow = {
      id: "cert-orig",
      cert_id: "aki.serial",
      serial_number: "112233",
      aki: "aabbcc",
      subject: "CN=example.com",
      san: JSON.stringify(["example.com", "www.example.com"]),
      pem: "...",
      not_before: notBeforeSec,
      not_after: notAfterSec,
      account_id: "acc-1",
      created_at: notBeforeSec,
      revoked_at: null,
      revocation_reason: null,
      replaced_by_cert_id: null,
    };

    // 1. Day 10 (before day 60 renewal window) -> Not eligible yet
    const day10 = notBeforeSec + 10 * 86400;
    const resDay10 = checkAriRenewalEligibility(cert, ["example.com"], day10);
    expect(resDay10.eligible).toBe(false);
    expect(resDay10.reason).toContain("before the suggested renewal window");

    // 2. Day 65 (inside 30-day renewal window) -> Eligible!
    const day65 = notBeforeSec + 65 * 86400;
    const resDay65 = checkAriRenewalEligibility(cert, ["example.com"], day65);
    expect(resDay65.eligible).toBe(true);

    // 3. Domain not in predecessor cert -> Not eligible
    const resDiffDomain = checkAriRenewalEligibility(cert, ["unrelated.org"], day65);
    expect(resDiffDomain.eligible).toBe(false);
    expect(resDiffDomain.reason).toContain("was not part of predecessor certificate");

    // 4. Predecessor already replaced -> Not eligible
    const certReplaced = { ...cert, replaced_by_cert_id: "new-cert-id" };
    const resReplaced = checkAriRenewalEligibility(certReplaced, ["example.com"], day65);
    expect(resReplaced.eligible).toBe(false);
    expect(resReplaced.reason).toContain("already been replaced");
  });
});
