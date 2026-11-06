import { CONFIG } from "../config";
import {
  isIpLiteralIdentifier,
  isWildcardDnsName,
  isValidDnsIdentifier,
  normalizeDnsName,
} from "../acme/identifiers";

/**
 * RFC 8555 § 8.3 HTTP-01 validation.
 *
 * The implementation deliberately keeps all network access inside this module
 * and returns structured failures instead of throwing. This lets the challenge
 * route persist a problem document and move the authorization state machine on
 * without leaking internal errors to the client.
 */

export type Http01ErrorType =
  | "malformed"
  | "dns"
  | "connection"
  | "incorrectResponse"
  | "unauthorized"
  | "serverInternal";

export interface Http01ValidationResult {
  valid: boolean;
  errorType?: Http01ErrorType;
  error?: string;
  redirects?: string[];
  addresses?: string[];
}

export interface Http01ValidationOptions {
  fetchImpl?: typeof fetch;
  maxRedirects?: number;
  requestTimeoutMs?: number;
  totalTimeoutMs?: number;
  maxBodyBytes?: number;
  now?: () => number;
}

interface TimedResponse {
  response: Response;
  release: () => void;
}

type AddressRecordType = "A" | "AAAA";

interface DohRecordSet {
  addresses: string[];
  cnames: string[];
}

/**
 * A definitive DNS-level failure (NXDOMAIN, SERVFAIL, a malformed DoH answer,
 * an unusable CNAME target, ...). Asking another DoH provider cannot make the
 * result interpretable, so the whole validation fails closed.
 */
class DnsQueryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DnsQueryError";
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const DOH_PROVIDERS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
];
const DOH_STATUS_NOERROR = 0;
const DOH_STATUS_NXDOMAIN = 3;
const CNAME_RECORD_TYPE = 5;
const A_RECORD_TYPE = 1;
const AAAA_RECORD_TYPE = 28;
// A recursive resolver normally returns the whole CNAME chain plus the final
// address records. The explicit follow-up exists only for responses that stop
// at a CNAME, and is bounded to keep a hostile chain from consuming the budget.
const MAX_CNAME_FOLLOWS = 4;
const BLOCKED_HOST_SUFFIXES = [
  "localhost",
  "local",
  "localdomain",
  "internal",
  "intranet",
  "lan",
  "home",
  "home.arpa",
  "test",
  "invalid",
  "example",
  "onion",
  "alt",
  "arpa",
  "corp",
  "private",
];

class ValidationTimeoutError extends Error {
  constructor() {
    super("validation timeout");
    this.name = "ValidationTimeoutError";
  }
}

class ValidationFetchError extends Error {
  constructor() {
    super("validation fetch failed");
    this.name = "ValidationFetchError";
  }
}

/** RFC 8555 § 8.1: token + "." + base64url(JWK thumbprint). */
export function computeKeyAuthorization(token: string, thumbprint: string): string {
  return `${token}.${thumbprint}`;
}

/** The token must have at least 128 bits of entropy (22 base64url chars). */
export function isValidChallengeToken(token: string): boolean {
  return (
    typeof token === "string" &&
    token.length >= 22 &&
    token.length <= 256 &&
    /^[A-Za-z0-9_-]+$/.test(token)
  );
}

/** A JWK thumbprint is a non-empty base64url value (SHA-256 is 43 chars). */
export function isValidThumbprint(thumbprint: string): boolean {
  return (
    typeof thumbprint === "string" &&
    thumbprint.length > 0 &&
    thumbprint.length <= 128 &&
    /^[A-Za-z0-9_-]+$/.test(thumbprint)
  );
}

function failure(errorType: Http01ErrorType, error: string): Http01ValidationResult {
  return { valid: false, errorType, error };
}

function stripIpv6Brackets(hostname: string): string {
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    return hostname.slice(1, -1);
  }
  return hostname;
}

/** Rejects IPv4/IPv6 literals, including the legacy numeric IPv4 notations. */
export function isIpLiteralHost(hostname: string): boolean {
  // Delegates to the shared identifier check so identifier validation and
  // redirect validation agree on what the URL parser considers an IP address.
  return isIpLiteralIdentifier(stripIpv6Brackets(hostname));
}

/** Rejects names that are by definition local, private, or non-public. */
export function isUnsafeHostname(hostname: string): boolean {
  const host = normalizeDnsName(hostname);
  if (!host || !host.includes(".")) return true;
  return BLOCKED_HOST_SUFFIXES.some(
    (suffix) => host === suffix || host.endsWith(`.${suffix}`)
  );
}

export interface Http01TargetOptions {
  initial: boolean;
  expectedHostname?: string;
}

/**
 * Per-hop target policy. The first request MUST be plain HTTP on port 80.
 * Redirects may use HTTP/80 or HTTPS/443, must not contain credentials, and
 * must resolve through the public-DNS/path checks performed by the caller.
 */
export function validateHttp01Target(
  url: URL,
  options: Http01TargetOptions
): string | null {
  if (url.username || url.password) {
    return "Validation target must not contain URL credentials";
  }
  if (url.hash) {
    return "Validation target must not contain a fragment";
  }

  const hostname = normalizeDnsName(stripIpv6Brackets(url.hostname));
  if (isIpLiteralHost(hostname)) {
    return "IP address validation targets are not supported";
  }
  if (!isValidDnsIdentifier(hostname, false)) {
    return "Validation target is not a valid DNS hostname";
  }
  if (isUnsafeHostname(hostname)) {
    return "Validation target is not a public DNS hostname";
  }

  if (options.initial) {
    if (url.protocol !== "http:") {
      return "The initial HTTP-01 request must use HTTP";
    }
    if (url.port !== "" && url.port !== "80") {
      return "The initial HTTP-01 request must use port 80";
    }
    if (options.expectedHostname && hostname !== options.expectedHostname) {
      return "The initial HTTP-01 request must target the certificate identifier";
    }
    return null;
  }

  if (url.protocol === "http:") {
    if (url.port !== "" && url.port !== "80") {
      return "HTTP redirect targets must use port 80";
    }
    return null;
  }
  if (url.protocol === "https:") {
    if (url.port !== "" && url.port !== "443") {
      return "HTTPS redirect targets must use port 443";
    }
    return null;
  }
  return "Redirect targets must use HTTP or HTTPS";
}

function parseIpv4(address: string): number | null {
  const parts = address.split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith("0")) return null;
    const value = Number(part);
    if (!Number.isInteger(value) || value < 0 || value > 255) return null;
    octets.push(value);
  }
  return (
    octets[0] * 0x1000000 +
    octets[1] * 0x10000 +
    octets[2] * 0x100 +
    octets[3]
  ) >>> 0;
}

function isPublicIpv4(value: number): boolean {
  const a = (value >>> 24) & 0xff;
  const b = (value >>> 16) & 0xff;
  const c = (value >>> 8) & 0xff;

  if (a === 0) return false; // "this network"
  if (a === 10) return false; // RFC 1918
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT 100.64/10
  if (a === 127) return false; // loopback
  if (a === 169 && b === 254) return false; // link-local
  if (a === 172 && b >= 16 && b <= 31) return false; // RFC 1918
  if (a === 192 && b === 0 && c === 0) return false; // IETF protocol assignments
  if (a === 192 && b === 0 && c === 2) return false; // TEST-NET-1
  if (a === 192 && b === 88 && c === 99) return false; // 6to4 relay anycast
  if (a === 192 && b === 168) return false; // RFC 1918
  if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
  if (a === 198 && b === 51 && c === 100) return false; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return false; // TEST-NET-3
  if (a >= 224) return false; // multicast and reserved
  return true;
}

function parseIpv6(address: string): Uint8Array | null {
  let input = stripIpv6Brackets(address);
  if (!input || input.includes("%")) return null;
  if (input.includes(":::")) return null;

  const halves = input.split("::");
  if (halves.length > 2) return null;

  const parseGroups = (part: string): number[] | null => {
    if (part === "") return [];
    const pieces = part.split(":");
    const groups: number[] = [];
    for (let i = 0; i < pieces.length; i++) {
      const piece = pieces[i];
      if (piece.includes(".")) {
        if (i !== pieces.length - 1) return null;
        const v4 = parseIpv4(piece);
        if (v4 === null) return null;
        groups.push((v4 >>> 16) & 0xffff, v4 & 0xffff);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) return null;
        groups.push(parseInt(piece, 16));
      }
    }
    return groups;
  };

  const left = parseGroups(halves[0]);
  const right = halves.length === 2 ? parseGroups(halves[1]) : [];
  if (!left || !right) return null;

  let groups: number[];
  if (halves.length === 2) {
    const missing = 8 - left.length - right.length;
    if (missing < 1) return null;
    groups = [...left, ...new Array<number>(missing).fill(0), ...right];
  } else {
    if (left.length !== 8) return null;
    groups = left;
  }
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < groups.length; i++) {
    bytes[i * 2] = (groups[i] >>> 8) & 0xff;
    bytes[i * 2 + 1] = groups[i] & 0xff;
  }
  return bytes;
}

function isPublicIpv6(bytes: Uint8Array): boolean {
  const allZero = bytes.every((byte) => byte === 0);
  if (allZero) return false; // ::

  const firstFifteenZero = bytes.slice(0, 15).every((byte) => byte === 0);
  if (firstFifteenZero && bytes[15] === 1) return false; // ::1

  // IPv4-mapped (::ffff:a.b.c.d) addresses are only as safe as the embedded
  // IPv4 address. Deprecated IPv4-compatible (::a.b.c.d) addresses are
  // rejected outright because they are not valid globally routable IPv6
  // destinations.
  const firstTenZero = bytes.slice(0, 10).every((byte) => byte === 0);
  if (firstTenZero && bytes[10] === 0xff && bytes[11] === 0xff) {
    const v4 = ((bytes[12] << 24) | (bytes[13] << 16) | (bytes[14] << 8) | bytes[15]) >>> 0;
    return isPublicIpv4(v4);
  }
  const firstTwelveZero = bytes.slice(0, 12).every((byte) => byte === 0);
  if (firstTwelveZero) {
    return false;
  }

  // Only global unicast (2000::/3) is eligible.
  if ((bytes[0] & 0xe0) !== 0x20) return false;

  // 2001:db8::/32 documentation
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0x0d && bytes[3] === 0xb8) {
    return false;
  }
  // 2001::/32 Teredo and 2001:2::/48 benchmarking
  if (
    bytes[0] === 0x20 &&
    bytes[1] === 0x01 &&
    bytes[2] === 0x00 &&
    (bytes[3] === 0x00 || bytes[3] === 0x02)
  ) {
    return false;
  }
  // 2001:10::/28 and 2001:20::/28 ORCHID
  if (
    bytes[0] === 0x20 &&
    bytes[1] === 0x01 &&
    bytes[2] === 0x00 &&
    bytes[3] >= 0x10 &&
    bytes[3] <= 0x2f
  ) {
    return false;
  }
  // 2002::/16 6to4 can embed private IPv4 addresses.
  if (bytes[0] === 0x20 && bytes[1] === 0x02) return false;
  // 3fff::/20 documentation
  if (bytes[0] === 0x3f && (bytes[1] & 0xf0) === 0xf0) return false;

  return true;
}

/** True only for globally routable unicast IPv4/IPv6 addresses. */
export function isPublicIpAddress(address: string): boolean {
  const v4 = parseIpv4(address);
  if (v4 !== null) return isPublicIpv4(v4);
  const v6 = parseIpv6(address);
  if (v6 !== null) return isPublicIpv6(v6);
  return false;
}

function networkError(error: unknown): ValidationTimeoutError | ValidationFetchError {
  if (
    error instanceof ValidationTimeoutError ||
    (error instanceof Error && error.name === "AbortError")
  ) {
    return new ValidationTimeoutError();
  }
  return new ValidationFetchError();
}

async function withTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new ValidationTimeoutError()), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function requestWithTimeout(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
  timeoutMs: number
): Promise<TimedResponse> {
  const controller = new AbortController();
  const abortTimer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await withTimeout(
      Promise.resolve().then(() => fetchImpl(url, { ...init, signal: controller.signal })),
      timeoutMs + 50
    );
    return {
      response,
      release: () => clearTimeout(abortTimer),
    };
  } catch (error) {
    clearTimeout(abortTimer);
    throw networkError(error);
  }
}

async function fetchDohJson(
  fetchImpl: typeof fetch,
  url: string,
  timeoutMs: number
): Promise<unknown> {
  const { response, release } = await requestWithTimeout(
    fetchImpl,
    url,
    {
      method: "GET",
      redirect: "follow",
      cache: "no-store",
      headers: { Accept: "application/dns-json" },
    },
    timeoutMs
  );
  try {
    if (!response.ok) {
      throw new ValidationFetchError();
    }
    return await withTimeout(response.json(), timeoutMs);
  } catch (error) {
    throw networkError(error);
  } finally {
    release();
  }
}

interface AddressResolutionFailure {
  ok: false;
  errorType: "dns" | "connection" | "unauthorized";
  error: string;
}

type AddressResolution = { ok: true; addresses: string[] } | AddressResolutionFailure;

/**
 * Validates and normalises one DoH JSON response.
 *
 * Every A/AAAA record in the answer must be a well-formed address of the
 * requested family, and every CNAME target must be a usable DNS name. A
 * response that cannot be interpreted unambiguously is a failure, not an empty
 * result: NOERROR with no answers (NODATA) is the only allowed empty form.
 */
function parseDohAnswer(
  payload: unknown,
  recordType: AddressRecordType,
  queriedName: string
): DohRecordSet {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new DnsQueryError("DoH response was not a JSON object");
  }
  const response = payload as Record<string, unknown>;

  const status = response.Status;
  if (typeof status !== "number" || !Number.isInteger(status)) {
    throw new DnsQueryError("DoH response did not contain a DNS status");
  }
  if (status === DOH_STATUS_NXDOMAIN) {
    throw new DnsQueryError(`DNS name '${queriedName}' does not exist`);
  }
  if (status !== DOH_STATUS_NOERROR) {
    throw new DnsQueryError(
      `DNS query for '${queriedName}' returned unusable status ${status}`
    );
  }

  const addresses: string[] = [];
  const cnames: string[] = [];
  const answers = response.Answer;
  if (answers === undefined || answers === null) {
    // NOERROR/NODATA: the name exists but has no records of this type.
    return { addresses, cnames };
  }
  if (!Array.isArray(answers)) {
    throw new DnsQueryError("DoH response contained a malformed Answer section");
  }

  for (const entry of answers) {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new DnsQueryError("DoH response contained a malformed answer record");
    }
    const record = entry as Record<string, unknown>;
    const type = record.type;
    if (typeof type !== "number" || !Number.isInteger(type)) {
      throw new DnsQueryError("DoH response contained an answer without a record type");
    }
    if (type !== A_RECORD_TYPE && type !== AAAA_RECORD_TYPE && type !== CNAME_RECORD_TYPE) {
      continue;
    }

    const data = record.data;
    if (typeof data !== "string" || data.trim() === "") {
      throw new DnsQueryError("DoH response contained an answer record without usable data");
    }
    const value = data.trim();

    if (type === A_RECORD_TYPE) {
      if (recordType !== "A") continue;
      if (parseIpv4(value) === null) {
        throw new DnsQueryError("DoH response contained an invalid A record");
      }
      addresses.push(value);
    } else if (type === AAAA_RECORD_TYPE) {
      if (recordType !== "AAAA") continue;
      if (parseIpv6(value) === null) {
        throw new DnsQueryError("DoH response contained an invalid AAAA record");
      }
      addresses.push(value);
    } else {
      // The recursive resolver already follows aliases, so the returned
      // A/AAAA records belong to the end of the chain and are checked above.
      // The CNAME target itself must still be a usable DNS name: an IP-literal
      // or otherwise invalid alias is never accepted.
      const target = normalizeDnsName(value);
      if (isIpLiteralIdentifier(target) || !isValidDnsIdentifier(target, false)) {
        throw new DnsQueryError("DoH response contained an invalid CNAME target");
      }
      cnames.push(target);
    }
  }

  return { addresses, cnames };
}

async function queryDohRecords(
  provider: string,
  name: string,
  recordType: AddressRecordType,
  fetchImpl: typeof fetch,
  deadline: number,
  requestTimeoutMs: number,
  now: () => number
): Promise<DohRecordSet> {
  const remaining = deadline - now();
  if (remaining <= 0) {
    throw new ValidationTimeoutError();
  }
  const timeoutMs = Math.max(1, Math.min(requestTimeoutMs, remaining));
  const url = `${provider}?name=${encodeURIComponent(name)}&type=${recordType}`;
  const payload = await fetchDohJson(fetchImpl, url, timeoutMs);
  return parseDohAnswer(payload, recordType, name);
}

/**
 * Resolves one address family through one DoH provider. When the response
 * stops at a CNAME (no address records in the same answer), the alias target is
 * queried explicitly so the final address is still checked. Returns an empty
 * array only for a confirmed NOERROR/NODATA result.
 */
async function resolveAddressFamilyWithProvider(
  provider: string,
  hostname: string,
  recordType: AddressRecordType,
  fetchImpl: typeof fetch,
  deadline: number,
  requestTimeoutMs: number,
  now: () => number
): Promise<string[]> {
  let name = hostname;
  const visited = new Set<string>();

  for (let depth = 0; depth <= MAX_CNAME_FOLLOWS; depth++) {
    if (visited.has(name)) {
      throw new DnsQueryError("DNS CNAME loop detected");
    }
    visited.add(name);

    const records = await queryDohRecords(
      provider,
      name,
      recordType,
      fetchImpl,
      deadline,
      requestTimeoutMs,
      now
    );
    if (records.addresses.length > 0) {
      return records.addresses;
    }
    if (records.cnames.length === 0) {
      return [];
    }
    const next = records.cnames[records.cnames.length - 1];
    if (next === name) {
      throw new DnsQueryError("DNS CNAME loop detected");
    }
    name = next;
  }

  throw new DnsQueryError("DNS CNAME chain is too long");
}

/**
 * Resolves one address family, using the second DoH provider only for
 * transport-level failures. A definitive answer (including NXDOMAIN, an error
 * status, or a malformed answer) is never re-interpreted by another resolver.
 */
async function resolveAddressFamily(
  hostname: string,
  recordType: AddressRecordType,
  fetchImpl: typeof fetch,
  deadline: number,
  requestTimeoutMs: number,
  now: () => number
): Promise<string[]> {
  let lastError: Error | null = null;
  for (const provider of DOH_PROVIDERS) {
    try {
      return await resolveAddressFamilyWithProvider(
        provider,
        hostname,
        recordType,
        fetchImpl,
        deadline,
        requestTimeoutMs,
        now
      );
    } catch (error) {
      if (error instanceof DnsQueryError) {
        throw error;
      }
      lastError = error instanceof Error ? error : new Error(String(error));
    }
  }
  throw lastError ?? new DnsQueryError("DNS resolution failed");
}

/**
 * Resolves the target through public DNS-over-HTTPS and requires a definitive,
 * usable answer for *both* the A and the AAAA family before the HTTP request
 * is allowed to proceed. This is fail-closed:
 *
 * - one family may legitimately be empty (NOERROR/NODATA), but the other must
 *   produce at least one confirmed address;
 * - a timeout, transport error, malformed JSON, unexpected DNS status, invalid
 *   record data, or an unusable CNAME target aborts the validation;
 * - every returned address must be globally routable unicast.
 *
 * The DoH answer is advisory: Workers fetch() resolves DNS independently and
 * cannot be pinned to these addresses, so this is not a complete SSRF or DNS
 * rebinding defense (see the README "Operational limitations" section).
 */
async function resolvePublicAddresses(
  hostname: string,
  fetchImpl: typeof fetch,
  deadline: number,
  requestTimeoutMs: number,
  now: () => number
): Promise<AddressResolution> {
  const addresses: string[] = [];

  for (const recordType of ["A", "AAAA"] as const) {
    let familyAddresses: string[];
    try {
      familyAddresses = await resolveAddressFamily(
        hostname,
        recordType,
        fetchImpl,
        deadline,
        requestTimeoutMs,
        now
      );
    } catch (error) {
      const detail =
        error instanceof DnsQueryError ? error.message : "DNS query failed";
      return {
        ok: false,
        errorType: "dns",
        error: `DNS resolution for the validation target failed (${recordType}): ${detail}`,
      };
    }
    addresses.push(...familyAddresses);
  }

  const unique = Array.from(new Set(addresses));
  if (unique.length === 0) {
    return {
      ok: false,
      errorType: "dns",
      error: "The validation target has no A or AAAA records",
    };
  }

  // Any private, loopback, link-local, documentation, multicast, or otherwise
  // special-use address makes the whole target unsafe. This is intentionally
  // conservative (all addresses, not only the first one).
  if (unique.some((address) => !isPublicIpAddress(address))) {
    return {
      ok: false,
      errorType: "unauthorized",
      error: "The validation target resolves to a non-public address",
    };
  }

  return { ok: true, addresses: unique };
}

interface ReadBodyResult {
  ok: boolean;
  text: string;
  tooLarge?: boolean;
}

async function readBodyLimited(response: Response, maxBytes: number): Promise<ReadBodyResult> {
  if (!response.body) {
    return { ok: true, text: "" };
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value || value.byteLength === 0) continue;

    total += value.byteLength;
    if (total > maxBytes) {
      try {
        await reader.cancel();
      } catch {
        // Ignore cancellation failures; the response is rejected either way.
      }
      return { ok: false, text: "", tooLarge: true };
    }
    chunks.push(value);
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, text: new TextDecoder().decode(merged) };
}

function isRedirectStatus(status: number): boolean {
  return REDIRECT_STATUSES.has(status);
}

export async function validateHttp01Challenge(
  domain: string,
  token: string,
  thumbprint: string,
  options: Http01ValidationOptions = {}
): Promise<Http01ValidationResult> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const maxRedirects = options.maxRedirects ?? CONFIG.HTTP01_MAX_REDIRECTS;
  const requestTimeoutMs =
    options.requestTimeoutMs ?? CONFIG.HTTP01_REQUEST_TIMEOUT_MS;
  const totalTimeoutMs = options.totalTimeoutMs ?? CONFIG.HTTP01_TOTAL_TIMEOUT_MS;
  const maxBodyBytes = options.maxBodyBytes ?? CONFIG.HTTP01_MAX_BODY_BYTES;
  const now = options.now ?? Date.now;

  if (isWildcardDnsName(domain)) {
    return failure(
      "malformed",
      "Wildcard identifiers cannot be validated with HTTP-01"
    );
  }

  const hostname = normalizeDnsName(domain);
  if (!isValidDnsIdentifier(hostname, false)) {
    return failure("malformed", "Invalid DNS identifier for HTTP-01 validation");
  }
  if (!isValidChallengeToken(token)) {
    return failure("malformed", "Invalid HTTP-01 challenge token");
  }
  if (!isValidThumbprint(thumbprint)) {
    return failure("malformed", "Invalid account key thumbprint");
  }

  const keyAuthorization = computeKeyAuthorization(token, thumbprint);
  const deadline = now() + totalTimeoutMs;
  const redirects: string[] = [];
  const visited = new Set<string>();

  let current: URL;
  try {
    current = new URL(
      `http://${hostname}/.well-known/acme-challenge/${encodeURIComponent(token)}`
    );
  } catch {
    return failure("malformed", "Unable to construct the HTTP-01 validation URL");
  }

  for (let hop = 0; hop <= maxRedirects; hop++) {
    if (deadline - now() <= 0) {
      return failure("connection", "HTTP-01 validation timed out");
    }

    const targetError = validateHttp01Target(current, {
      initial: hop === 0,
      expectedHostname: hostname,
    });
    if (targetError) {
      return failure("unauthorized", targetError);
    }

    if (visited.has(current.href)) {
      return failure("connection", "HTTP-01 validation encountered a redirect loop");
    }
    visited.add(current.href);

    // SECURITY LIMITATION: this DoH lookup is advisory. Workers fetch()
    // performs its own DNS resolution and offers no supported way to pin the
    // connection to the addresses checked here, so a DNS-rebinding
    // authoritative server can answer differently to the DoH resolver and to
    // the fetch() resolver. The check is fail-closed: it rejects the target
    // unless both the A and the AAAA family produced a definitive answer and
    // every returned address is public. It is not a complete SSRF defense.
    // See README "Operational limitations". Every redirect hop repeats this
    // check before the next request is made.
    const resolution = await resolvePublicAddresses(
      normalizeDnsName(stripIpv6Brackets(current.hostname)),
      fetchImpl,
      deadline,
      requestTimeoutMs,
      now
    );
    if (!resolution.ok) {
      return failure(resolution.errorType, resolution.error);
    }

    // DNS resolution can consume most of the budget; recompute before the
    // actual challenge request so the total deadline is still respected.
    const requestBudget = deadline - now();
    if (requestBudget <= 0) {
      return failure("connection", "HTTP-01 validation timed out");
    }
    const requestTimeout = Math.max(1, Math.min(requestTimeoutMs, requestBudget));

    // Workers fetch() always verifies the TLS certificate of an HTTPS URL and
    // exposes no option to disable verification. Therefore an HTTPS redirect
    // target with a self-signed, expired, or otherwise untrusted certificate
    // fails the challenge here. This differs from validators (for example
    // Boulder) that deliberately skip certificate verification for HTTP-01;
    // see README "Operational limitations". The initial request is always
    // plain HTTP, so this only affects HTTPS redirect hops.
    let timed: TimedResponse;
    try {
      timed = await requestWithTimeout(
        fetchImpl,
        current.href,
        {
          method: "GET",
          redirect: "manual",
          cache: "no-store",
          headers: {
            Accept: "*/*",
            "Cache-Control": "no-cache",
            Pragma: "no-cache",
          },
        },
        requestTimeout
      );
    } catch (error) {
      if (error instanceof ValidationTimeoutError) {
        return failure("connection", "HTTP-01 validation request timed out");
      }
      return failure("connection", "HTTP-01 validation request failed");
    }

    const { response, release } = timed;
    try {
      if (isRedirectStatus(response.status)) {
        if (hop >= maxRedirects) {
          return failure("connection", "Too many HTTP redirects during HTTP-01 validation");
        }
        const location = response.headers.get("Location");
        if (!location) {
          return failure(
            "incorrectResponse",
            "HTTP redirect did not include a Location header"
          );
        }
        let next: URL;
        try {
          next = new URL(location, current);
        } catch {
          return failure("incorrectResponse", "HTTP redirect Location is not a valid URL");
        }
        redirects.push(next.href);
        current = next;
        continue;
      }

      if (response.status !== 200) {
        return failure(
          "incorrectResponse",
          `Expected HTTP 200 from the validation target, received ${response.status}`
        );
      }

      // RFC 8555 § 8.3 makes the key-authorization body authoritative. Cache
      // status is not: a stale cached body carries a different token and fails
      // the comparison below, while a HIT containing the exact expected value
      // is a valid response. Rejecting every HIT would break legitimate sites
      // (including Cloudflare-proxied ones) that cache .well-known responses;
      // the no-store/no-cache request headers above ask caches to bypass or
      // revalidate without changing the validation semantics.
      const bodyTimeout = Math.max(1, Math.min(requestTimeoutMs, deadline - now()));
      let body: ReadBodyResult;
      try {
        body = await withTimeout(readBodyLimited(response, maxBodyBytes), bodyTimeout);
      } catch (error) {
        if (error instanceof ValidationTimeoutError) {
          return failure("connection", "HTTP-01 validation response timed out");
        }
        return failure("connection", "Unable to read the HTTP-01 validation response");
      }

      if (body.tooLarge) {
        return failure(
          "incorrectResponse",
          "The HTTP-01 validation response body exceeded the allowed size"
        );
      }

      // Strict comparison: only trailing whitespace is ignored.
      const trimmed = body.text.trimEnd();
      if (trimmed.length === 0) {
        return failure("incorrectResponse", "The HTTP-01 validation response body was empty");
      }
      if (trimmed !== keyAuthorization) {
        return failure(
          "incorrectResponse",
          "The HTTP-01 validation response did not match the expected key authorization"
        );
      }

      return {
        valid: true,
        redirects,
        addresses: resolution.addresses,
      };
    } finally {
      release();
      if (!response.bodyUsed) {
        try {
          await response.body?.cancel();
        } catch {
          // The response is no longer needed.
        }
      }
    }
  }

  return failure("connection", "Too many HTTP redirects during HTTP-01 validation");
}
