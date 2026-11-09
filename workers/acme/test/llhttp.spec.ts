import { describe, expect, it } from "vitest";
import { HttpResponseParser } from "../src/http01/llhttp";

const limits = { maxHeaderBytes: 16384, maxBodyBytes: 8192, maxWireBytes: 65536 };
const encode = (text: string) => new TextEncoder().encode(text);

async function parse(wire: string, size = 4096, overrides = {}) {
  const parser = await HttpResponseParser.create({ ...limits, ...overrides });
  try {
    const bytes = encode(wire);
    for (let offset = 0; offset < bytes.length; offset += size) parser.push(bytes.subarray(offset, offset + size));
    parser.finish();
    return parser.result();
  } finally { parser.dispose(); }
}

describe("strict llhttp WASM response adapter", () => {
  for (const size of [1, 2, 7, 4096]) {
    it(`parses fragmented fields, empty values and content-length with chunk size ${size}`, async () => {
      const result = await parse("HTTP/1.1 200 OK\r\nX-Empty:\r\nX-Test: hello\r\nContent-Length: 3\r\n\r\nabc", size);
      expect(result.status).toBe(200);
      expect(result.headers.get("x-empty")).toBe("");
      expect(result.headers.get("x-test")).toBe("hello");
      expect(new TextDecoder().decode(result.body)).toBe("abc");
    });

    it(`handles informational heads, chunks and trailers with chunk size ${size}`, async () => {
      const result = await parse("HTTP/1.1 103 Early Hints\r\nLink: </style>\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Test: original\r\n\r\n1;foo=bar\r\na\r\n2\r\nbc\r\n0\r\nX-Test: trailer\r\n\r\n", size);
      expect(result.headers.has("link")).toBe(false);
      expect(result.headers.get("x-test")).toBe("original");
      expect(new TextDecoder().decode(result.body)).toBe("abc");
    });
  }

  it("finishes EOF-delimited responses only at EOF", async () => {
    const parser = await HttpResponseParser.create(limits);
    try {
      parser.push(encode("HTTP/1.0 200 OK\r\n\r\nabc"));
      expect(parser.complete).toBe(false);
      expect(() => parser.result()).toThrow("Incomplete");
      parser.finish();
      expect(parser.complete).toBe(true);
    } finally { parser.dispose(); }
  });

  for (const wire of [
    "",
    "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na",
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n0\r\n\r\n",
    "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
    "HTTP/1.1 200 OK\r\nContent-Length: +3\r\n\r\nabc",
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nz\r\nabc\r\n0\r\n\r\n",
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
    "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    "HTTP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n",
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    "HTTP/1.1 200 OK\nContent-Length: 0\n\n",
    "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
    "HTTP/1.1 302 Found\r\nLocation: /one\r\nLocation: /two\r\nContent-Length: 0\r\n\r\n",
  ]) {
    it(`rejects malformed, truncated or unsupported response ${JSON.stringify(wire).slice(0, 80)}`, async () => {
      await expect(parse(wire)).rejects.toThrow();
    });
  }

  it("enforces header, trailer, body and raw wire limits", async () => {
    await expect(parse(`HTTP/1.1 200 OK\r\nX: ${" ".repeat(16400)}\r\n\r\n`)).rejects.toThrow("headers");
    await expect(parse(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: ${"a".repeat(16400)}\r\n\r\n`)).rejects.toThrow("headers");
    await expect(parse("HTTP/1.1 200 OK\r\nContent-Length: 8193\r\n\r\n")).rejects.toThrow("body");
    await expect(parse(`HTTP/1.0 200 OK\r\n\r\n${"a".repeat(8193)}`)).rejects.toThrow("body");
    await expect(parse("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 4096, { maxWireBytes: 16 })).rejects.toThrow("wire");
  });

  it("isolates concurrent parsers and releases parser state", async () => {
    const results = await Promise.all(["abc", "def"].map((body) => parse(`HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n${body}`, 1)));
    expect(results.map((result) => new TextDecoder().decode(result.body))).toEqual(["abc", "def"]);
    const parser = await HttpResponseParser.create(limits);
    parser.dispose();
    parser.dispose();
    expect(() => parser.push(encode("a"))).toThrow("disposed");
  });
});
