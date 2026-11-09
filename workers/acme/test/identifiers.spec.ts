import { describe, it, expect, beforeEach } from "vitest";
import {
  isIpLiteralIdentifier,
  isValidDnsIdentifier,
  validateDnsIdentifier,
} from "../src/acme/identifiers";
import { AcmeEnv } from "../src/config";
import {
  TestAccount,
  createOrder,
  createTestEnvironment,
  registerAccount,
} from "./acme-test-helpers";

describe("DNS identifier validation", () => {
  it("normalizes case and preserves wildcard handling", () => {
    expect(validateDnsIdentifier(" Example.COM ")).toEqual({
      ok: true,
      value: "example.com",
    });
    expect(validateDnsIdentifier("*.Example.COM")).toEqual({
      ok: true,
      value: "*.example.com",
    });
    expect(validateDnsIdentifier("*.example.com", false)).toMatchObject({
      ok: false,
      errorType: "rejectedIdentifier",
    });
  });

  it("accepts ordinary, IDNA (A-label) and wildcard DNS names", () => {
    for (const name of [
      "example.com",
      "www.example.com",
      "sub-domain.example.co.uk",
      "a-b.c-d.example.com",
      "1.2.3.example.com",
      "xn--bcher-kva.example",
      "*.example.com",
      "*.sub.example.com",
    ]) {
      expect(isValidDnsIdentifier(name), name).toBe(true);
      expect(isIpLiteralIdentifier(name), name).toBe(false);
      expect(validateDnsIdentifier(name).ok, name).toBe(true);
    }
  });

  it("rejects IPv4 literals submitted as DNS identifiers", () => {
    for (const address of [
      "0.0.0.0",
      "10.0.0.1",
      "127.0.0.1",
      "169.254.169.254",
      "172.16.0.1",
      "192.168.1.1",
      "255.255.255.255",
    ]) {
      const result = validateDnsIdentifier(address);
      expect(isIpLiteralIdentifier(address), address).toBe(true);
      expect(isValidDnsIdentifier(address), address).toBe(false);
      expect(result.ok, address).toBe(false);
      if (!result.ok) {
        expect(result.errorType).toBe("rejectedIdentifier");
        expect(result.detail).toContain("IP address");
      }
    }
  });

  it("rejects IPv6 literals submitted as DNS identifiers", () => {
    for (const address of [
      "::",
      "::1",
      "2001:db8::1",
      "fe80::1",
      "::ffff:127.0.0.1",
      "[::1]",
      "[2001:db8::1]",
    ]) {
      const result = validateDnsIdentifier(address);
      expect(isIpLiteralIdentifier(address), address).toBe(true);
      expect(isValidDnsIdentifier(address), address).toBe(false);
      expect(result.ok, address).toBe(false);
      if (!result.ok) {
        expect(result.errorType).toBe("rejectedIdentifier");
        expect(result.detail).toContain("IP address");
      }
    }
  });

  it("rejects legacy numeric IPv4 notations that the URL parser turns into IPs", () => {
    for (const address of [
      "2130706433", // decimal integer form of 127.0.0.1
      "0x7f000001", // hexadecimal form
      "0x7f.1", // hexadecimal first label
      "0177.0.0.1", // octal form
      "127.1", // short form
      "127.0.1", // short form
      "127.0.0.1.", // trailing dot, normalized by the URL parser
    ]) {
      const result = validateDnsIdentifier(address);
      expect(isIpLiteralIdentifier(address), address).toBe(true);
      expect(isValidDnsIdentifier(address), address).toBe(false);
      expect(result.ok, address).toBe(false);
      if (!result.ok) {
        expect(result.errorType, address).toBe("rejectedIdentifier");
        expect(result.detail, address).toContain("IP address");
      }
    }
  });

  it("rejects IP literals hidden behind a wildcard label", () => {
    expect(isIpLiteralIdentifier("*.127.0.0.1")).toBe(true);
    expect(isIpLiteralIdentifier("*.::1")).toBe(true);
    expect(validateDnsIdentifier("*.127.0.0.1").ok).toBe(false);
  });

  it("rejects all-numeric hosts that no public DNS zone can contain", () => {
    for (const value of ["1.2.3.4.5", "example.123"]) {
      expect(isValidDnsIdentifier(value), value).toBe(false);
      expect(validateDnsIdentifier(value).ok, value).toBe(false);
    }
  });

  it("does not treat arbitrary dotted strings as IP literals", () => {
    for (const value of ["example.com", "1.2.3.example.com", "example.0x10.com"]) {
      expect(isIpLiteralIdentifier(value), value).toBe(false);
    }
  });
});

describe("new-order identifier enforcement", () => {
  let env: AcmeEnv;
  let account: TestAccount;

  beforeEach(async () => {
    ({ env } = await createTestEnvironment());
    account = await registerAccount(env);
  });

  async function countRows(table: "orders" | "authorizations" | "certificates") {
    const row = await env.DB.prepare(
      `SELECT COUNT(*) AS count FROM ${table}`
    ).first<{ count: number }>();
    return row?.count ?? 0;
  }

  it("rejects IP literals submitted with type 'dns' and persists nothing", async () => {
    const rejected = [
      "127.0.0.1",
      "::1",
      "2130706433",
      "0x7f000001",
      "0177.0.0.1",
      "127.1",
      "*.127.0.0.1",
    ];

    for (const value of rejected) {
      const result = await createOrder(env, account, [{ type: "dns", value }]);
      expect(result.response.status, value).toBe(400);
      expect(result.body.type, value).toBe(
        "urn:ietf:params:acme:error:rejectedIdentifier"
      );
    }

    expect(await countRows("orders")).toBe(0);
    expect(await countRows("authorizations")).toBe(0);
  });

  it("rejects a mixed order containing an IP literal before creating any row", async () => {
    const result = await createOrder(env, account, [
      { type: "dns", value: "example.com" },
      { type: "dns", value: "192.168.0.1" },
    ]);

    expect(result.response.status).toBe(400);
    expect(result.body.type).toBe(
      "urn:ietf:params:acme:error:rejectedIdentifier"
    );
    expect(await countRows("orders")).toBe(0);
    expect(await countRows("authorizations")).toBe(0);
  });

  it("keeps unsupportedIdentifier for unknown identifier types", async () => {
    for (const type of ["email", "uri"]) {
      const result = await createOrder(env, account, [
        { type, value: type === "ip" ? "127.0.0.1" : "value" },
      ]);
      expect(result.response.status, type).toBe(400);
      expect(result.body.type, type).toBe(
        "urn:ietf:params:acme:error:unsupportedIdentifier"
      );
    }

    expect(await countRows("orders")).toBe(0);
  });

  it("creates an order for normal and wildcard DNS identifiers", async () => {
    const result = await createOrder(env, account, [
      { type: "dns", value: "Example.COM" },
      { type: "dns", value: "*.Example.COM" },
    ]);

    expect(result.response.status).toBe(201);
    expect(result.body.identifiers).toEqual([
      { type: "dns", value: "example.com" },
      { type: "dns", value: "*.example.com" },
    ]);
    expect(await countRows("orders")).toBe(1);
    expect(await countRows("authorizations")).toBe(2);
  });
});
