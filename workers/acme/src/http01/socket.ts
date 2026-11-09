import type { connect } from "cloudflare:sockets";
import { CONFIG } from "../config";
import { isPublicIpAddress } from "../acme/ip";
import { normalizeIpAddress } from "../acme/identifiers";
import { HttpResponseError, HttpResponseParser } from "./llhttp";

export { HttpResponseError } from "./llhttp";
export type SocketConnect = typeof connect;

export class SocketInitializationError extends Error {}

/** The caller owns redirects. This function can only dial public numeric hosts. */
export async function requestIpHttp01(url: URL, options: {
  timeoutMs: number;
  maxBodyBytes: number;
  connectImpl?: SocketConnect;
  signal?: AbortSignal;
}): Promise<Response> {
  options.signal?.throwIfAborted();
  const ip = normalizeIpAddress(url.hostname.replace(/^\[|\]$/g, ""));
  if (!ip || !isPublicIpAddress(ip) || url.username || url.password || url.href.includes("#") ||
      !["http:", "https:"].includes(url.protocol) ||
      (url.port && url.port !== (url.protocol === "https:" ? "443" : "80"))) {
    throw new HttpResponseError("Unsafe socket target");
  }
  let parser: HttpResponseParser;
  try {
    parser = await HttpResponseParser.create({
      maxHeaderBytes: CONFIG.HTTP01_MAX_HEADER_BYTES,
      maxWireBytes: CONFIG.HTTP01_MAX_WIRE_BYTES,
      maxBodyBytes: options.maxBodyBytes,
    });
  } catch { throw new SocketInitializationError("Unable to initialize HTTP parser"); }

  let socket: ReturnType<SocketConnect> | undefined;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let writer: WritableStreamDefaultWriter<Uint8Array> | undefined;
  let expired = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let abort: (() => void) | undefined;
  const close = () => { if (socket) void socket.close().catch(() => {}); };
  try {
    const connectImpl = options.connectImpl ?? (await import("cloudflare:sockets")).connect;
    const authority = ip.includes(":") ? `[${ip}]` : ip;
    const port = url.protocol === "https:" ? 443 : 80;
    socket = connectImpl(`${authority}:${port}`, { secureTransport: port === 443 ? "on" : "off", allowHalfOpen: false });
    // Either promise can reject, including after an aborted opening attempt.
    void socket.closed.catch(() => {});
    const operation = async () => {
      await socket!.opened;
      if (expired) throw new Error("Socket request timed out");
      writer = socket!.writable.getWriter();
      await writer.write(new TextEncoder().encode(
        `GET ${url.pathname}${url.search} HTTP/1.1\r\nHost: ${authority}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nConnection: close\r\n\r\n`
      ));
      writer.releaseLock();
      writer = undefined;
      if (expired) throw new Error("Socket request timed out");
      reader = socket!.readable.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (expired) throw new Error("Socket request timed out");
        if (done) { parser.finish(); break; }
        parser.push(value);
        if (parser.complete || parser.redirectReady) break;
      }
      const result = parser.result();
      return new Response([204, 205, 304].includes(result.status) ? null : result.body, { status: result.status, headers: result.headers });
    };
    return await Promise.race([
      operation(),
      new Promise<never>((_, reject) => {
        abort = () => {
          expired = true;
          close();
          reject(new Error("Socket request canceled"));
        };
        options.signal?.addEventListener("abort", abort, { once: true });
        if (options.signal?.aborted) abort();
        timer = setTimeout(() => {
          expired = true;
          close();
          reject(new Error("Socket request timed out"));
        }, options.timeoutMs);
      }),
    ]);
  } finally {
    expired = true;
    if (abort) options.signal?.removeEventListener("abort", abort);
    if (timer !== undefined) clearTimeout(timer);
    close();
    // Do not let a peer delay the deadline by stalling cancellation/close.
    if (reader) {
      void reader.cancel().catch(() => {});
      reader.releaseLock();
    }
    if (writer) {
      void writer.abort().catch(() => {});
      writer.releaseLock();
    }
    parser.dispose();
  }
}
