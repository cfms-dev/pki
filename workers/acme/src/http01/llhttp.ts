import wasmModule from "../../generated/llhttp/llhttp-module";

export class HttpResponseError extends Error {}

interface LlhttpExports {
  memory: WebAssembly.Memory;
  _initialize(): void;
  malloc(size: number): number;
  free(pointer: number): void;
  llhttp_alloc(type: number): number;
  llhttp_free(parser: number): void;
  llhttp_execute(parser: number, pointer: number, size: number): number;
  llhttp_finish(parser: number): number;
  llhttp_get_status_code(parser: number): number;
  llhttp_get_http_major(parser: number): number;
  llhttp_get_http_minor(parser: number): number;
  llhttp_get_upgrade(parser: number): number;
}

export interface ParsedHttpResponse {
  status: number;
  headers: Headers;
  body: Uint8Array;
}

/** One independent strict parser per connection. No connection reuse or upgrades. */
export class HttpResponseParser {
  private api!: LlhttpExports;
  private parser = 0;
  private input = 0;
  private readonly inputSize = 4096;
  private wireBytes = 0;
  private headerBytes = 0;
  private bodyBytes = 0;
  private chunks: Uint8Array[] = [];
  private field = "";
  private value = "";
  private readingValue = false;
  private headComplete = false;
  private finalComplete = false;
  private status = 0;
  private headers = new Headers();
  private failure: unknown;

  private constructor(private limits: { maxHeaderBytes: number; maxBodyBytes: number; maxWireBytes: number }) {}

  static async create(limits: { maxHeaderBytes: number; maxBodyBytes: number; maxWireBytes: number }): Promise<HttpResponseParser> {
    const result = new HttpResponseParser(limits);
    const noop = () => 0;
    // Exceptions must not unwind through WASM and leave its C stack dirty.
    const callback = (fn: (...args: number[]) => void) => (...args: number[]) => {
      try { fn(...args); return 0; }
      catch (error) { result.failure = error; return -1; }
    };
    const instance = await WebAssembly.instantiate(wasmModule, { env: {
      wasm_on_message_begin: callback(() => {
        if (result.finalComplete) throw new HttpResponseError("Multiple final HTTP responses");
        result.headComplete = false;
        result.headers = new Headers();
      }),
      wasm_on_url: noop,
      wasm_on_status: noop,
      wasm_on_header_field: callback((_p, at, size) => {
        if (result.readingValue) result.flushHeader();
        result.field += result.text(at, size);
      }),
      wasm_on_header_value: callback((_p, at, size) => {
        result.readingValue = true;
        result.value += result.text(at, size);
      }),
      wasm_on_headers_complete: callback((parser) => {
        result.flushHeader();
        const api = result.api;
        if (api.llhttp_get_http_major(parser) !== 1 || api.llhttp_get_http_minor(parser) > 1 || api.llhttp_get_upgrade(parser)) {
          throw new HttpResponseError("Unsupported HTTP version or upgrade");
        }
        result.status = api.llhttp_get_status_code(parser);
        if (result.status === 101 || result.status < 100 || result.status > 599) throw new HttpResponseError("Unsupported HTTP status or upgrade");
        result.headComplete = true;
        const transfer = result.headers.get("transfer-encoding");
        if (transfer && transfer.toLowerCase() !== "chunked") throw new HttpResponseError("Unsupported transfer encoding");
        const encoding = result.headers.get("content-encoding");
        if (encoding && encoding.toLowerCase() !== "identity") throw new HttpResponseError("Encoded HTTP body is not allowed");
        const length = result.headers.get("content-length");
        if (result.status === 200 && length !== null && Number(length) > result.limits.maxBodyBytes) {
          throw new HttpResponseError("HTTP body exceeded the allowed size");
        }
      }),
      wasm_on_body: callback((_p, at, size) => {
        result.bodyBytes += size;
        if (result.bodyBytes > result.limits.maxBodyBytes) throw new HttpResponseError("HTTP body exceeded the allowed size");
        result.chunks.push(new Uint8Array(result.api.memory.buffer, at, size).slice());
      }),
      wasm_on_message_complete: callback(() => {
        result.flushHeader(); // trailers never replace response headers
        if (result.status >= 200) result.finalComplete = true;
      }),
    } });
    result.api = instance.exports as unknown as LlhttpExports;
    result.api._initialize();
    result.parser = result.api.llhttp_alloc(2); // HTTP_RESPONSE
    result.input = result.api.malloc(result.inputSize);
    if (!result.parser || !result.input) { result.dispose(); throw new Error("llhttp allocation failed"); }
    return result;
  }

  private text(at: number, size: number): string {
    // Header bytes are ISO-8859-1, not UTF-8; preserve byte values for Headers.
    return Array.from(new Uint8Array(this.api.memory.buffer, at, size), (byte) => String.fromCharCode(byte)).join("");
  }

  private countHeader(size: number): void {
    this.headerBytes += size;
    if (this.headerBytes > this.limits.maxHeaderBytes) throw new HttpResponseError("HTTP headers exceeded the allowed size");
  }

  private flushHeader(): void {
    if (this.field && !this.headComplete) {
      if (this.field.toLowerCase() === "location" && this.headers.has("location")) throw new HttpResponseError("Multiple Location headers");
      this.headers.append(this.field, this.value);
    }
    this.field = this.value = "";
    this.readingValue = false;
  }

  private check(error: number): void {
    if (this.failure) throw this.failure instanceof HttpResponseError ? this.failure : new HttpResponseError("Malformed HTTP headers");
    if (error) throw new HttpResponseError("Malformed or truncated HTTP response");
  }

  push(bytes: Uint8Array): void {
    if (!this.parser) throw new Error("Parser is disposed");
    this.wireBytes += bytes.byteLength;
    if (this.wireBytes > this.limits.maxWireBytes) throw new HttpResponseError("HTTP wire response exceeded the allowed size");
    for (let offset = 0; offset < bytes.length; offset += this.inputSize) {
      const part = bytes.subarray(offset, offset + this.inputSize);
      new Uint8Array(this.api.memory.buffer, this.input, part.length).set(part);
      const beforeBody = this.bodyBytes;
      this.check(this.api.llhttp_execute(this.parser, this.input, part.length));
      // Count raw non-payload bytes, including whitespace and chunk framing.
      this.countHeader(part.length - (this.bodyBytes - beforeBody));
    }
  }

  get complete(): boolean { return this.finalComplete; }
  get redirectReady(): boolean { return this.headComplete && [301, 302, 303, 307, 308].includes(this.status); }

  finish(): void { this.check(this.api.llhttp_finish(this.parser)); }

  result(): ParsedHttpResponse {
    if (!this.finalComplete && !this.redirectReady) throw new HttpResponseError("Incomplete HTTP response");
    const body = new Uint8Array(this.bodyBytes);
    let offset = 0;
    for (const chunk of this.chunks) { body.set(chunk, offset); offset += chunk.length; }
    return { status: this.status, headers: this.headers, body };
  }

  dispose(): void {
    if (this.parser) this.api.llhttp_free(this.parser);
    if (this.input) this.api.free(this.input);
    this.parser = this.input = 0;
    this.chunks = [];
  }
}
