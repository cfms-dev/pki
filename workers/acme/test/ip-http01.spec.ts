import { describe, expect, it, vi } from "vitest";
import { requestIpHttp01, type SocketConnect } from "../src/http01/socket";
import { validateHttp01Challenge } from "../src/http01/validator";

const token = "a".repeat(22);
const thumbprint = "b".repeat(43);
const body = `${token}.${thumbprint}`;
const ip = "93.184.216.34";
const ipv6 = "2606:4700:4700::1111";

export function fakeConnect(wire: string, options: { stall?: "open" | "read" | "write"; reject?: boolean } = {}) {
  const requests: string[] = [];
  let controller: ReadableStreamDefaultController<Uint8Array>;
  const close = vi.fn(async () => { try { controller.close(); } catch {} });
  const connect = vi.fn(() => ({
    opened: options.reject ? Promise.reject(new Error("platform refusal")) : options.stall === "open" ? new Promise(() => {}) : Promise.resolve({}),
    closed: options.reject ? Promise.reject(new Error("closed")) : new Promise(() => {}),
    readable: new ReadableStream<Uint8Array>({ start(c) { controller = c; if (options.stall !== "read") { c.enqueue(new TextEncoder().encode(wire)); c.close(); } } }),
    writable: new WritableStream<Uint8Array>({ write(value) { requests.push(new TextDecoder().decode(value)); if (options.stall === "write") return new Promise(() => {}); } }),
    close,
  })) as unknown as SocketConnect;
  return { connect, close, requests };
}

describe("IP HTTP-01 socket transport", () => {
  it.each([ip, ipv6])("dials %s numerically and sends the IP Host without DNS or fetch", async (address) => {
    const fake = fakeConnect(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
    const fetchImpl = vi.fn(() => { throw new Error("unexpected fetch"); });
    const result = await validateHttp01Challenge({ type: "ip", value: address }, token, thumbprint, { connectImpl: fake.connect, fetchImpl });
    expect(result.valid).toBe(true);
    const authority = address.includes(":") ? `[${address}]` : address;
    expect(fake.connect).toHaveBeenCalledWith(`${authority}:80`, { secureTransport: "off", allowHalfOpen: false });
    expect(fake.requests[0]).toContain(`Host: ${authority}\r\n`);
    expect(fake.requests[0]).toContain(`GET /.well-known/acme-challenge/${token} HTTP/1.1\r\n`);
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(fake.close).toHaveBeenCalled();
  });

  it("follows IP redirects using native TLS", async () => {
    const first = fakeConnect(`HTTP/1.1 302 Found\r\nLocation: https://[${ipv6}]/proof\r\nContent-Length: 0\r\n\r\n`);
    const second = fakeConnect(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n${body.length.toString(16)}\r\n${body}\r\n0\r\n\r\n`);
    const connect = vi.fn().mockImplementationOnce(first.connect).mockImplementationOnce(second.connect) as SocketConnect;
    expect((await validateHttp01Challenge({ type: "ip", value: ip }, token, thumbprint, { connectImpl: connect })).valid).toBe(true);
    expect(second.connect).toHaveBeenCalledWith(`[${ipv6}]:443`, { secureTransport: "on", allowHalfOpen: false });
    expect(first.close).toHaveBeenCalled();
    expect(second.close).toHaveBeenCalled();
  });

  it.each(["http://127.0.0.1/", "http://[::1]/", "http://example.com:8080/", "http://user@example.com/", "http://example.com/#fragment"])("rejects redirect %s before a second connection", async (location) => {
    const fake = fakeConnect(`HTTP/1.1 302 Found\r\nLocation: ${location}\r\nContent-Length: 0\r\n\r\n`);
    expect(await validateHttp01Challenge({ type: "ip", value: ip }, token, thumbprint, { connectImpl: fake.connect })).toMatchObject({ valid: false, errorType: "unauthorized" });
    expect(fake.connect).toHaveBeenCalledTimes(1);
  });

  it("follows an IP-to-domain redirect through the existing public DoH checks", async () => {
    const fake = fakeConnect("HTTP/1.1 302 Found\r\nLocation: https://proof.example.com/proof\r\nContent-Length: 0\r\n\r\n");
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input));
      if (url.hostname === "proof.example.com") return new Response(body);
      return Response.json({ Status: 0, Answer: url.searchParams.get("type") === "A" ? [{ type: 1, data: ip }] : [] });
    });
    expect(await validateHttp01Challenge({ type: "ip", value: ip }, token, thumbprint, { connectImpl: fake.connect, fetchImpl })).toMatchObject({ valid: true });
    expect(fetchImpl).toHaveBeenCalledTimes(3); // A, AAAA, then HTTPS
    expect(fake.connect).toHaveBeenCalledTimes(1);
  });

  it.each(["open", "write", "read"] as const)("closes a stalled %s within its deadline", async (stall) => {
    const fake = fakeConnect("", { stall });
    await expect(requestIpHttp01(new URL(`http://${ip}/`), { connectImpl: fake.connect, maxBodyBytes: 8192, timeoutMs: 20 })).rejects.toThrow("timed out");
    expect(fake.close).toHaveBeenCalled();
  });

  it("rejects empty EOF, truncated and oversized responses and closes the socket", async () => {
    for (const wire of ["", "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\na", "HTTP/1.1 200 OK\r\nContent-Length: 9999\r\n\r\n"]) {
      const fake = fakeConnect(wire);
      expect(await validateHttp01Challenge({ type: "ip", value: ip }, token, thumbprint, { connectImpl: fake.connect })).toMatchObject({ valid: false, errorType: "incorrectResponse" });
      expect(fake.close).toHaveBeenCalled();
    }
  });

  it("maps platform/TLS refusal to connection without fallback", async () => {
    const fake = fakeConnect("", { reject: true });
    const fetchImpl = vi.fn();
    expect(await validateHttp01Challenge({ type: "ip", value: ip }, token, thumbprint, { connectImpl: fake.connect, fetchImpl })).toMatchObject({ valid: false, errorType: "connection" });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(fake.close).toHaveBeenCalled();
  });

  it("closes a canceled socket without waiting for the request timeout", async () => {
    const fake = fakeConnect("", { stall: "read" });
    const controller = new AbortController();
    const request = requestIpHttp01(new URL(`http://${ip}/`), { connectImpl: fake.connect, maxBodyBytes: 8192, timeoutMs: 10000, signal: controller.signal });
    const rejection = expect(request).rejects.toThrow("canceled");
    await new Promise((resolve) => setTimeout(resolve, 10));
    controller.abort();
    await rejection;
    expect(fake.close).toHaveBeenCalled();
  });
});
