import { isIP } from "node:net";
import { isPublicIpAddress } from "./ip";

const DNS_NAME_REGEX =
  /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

/** Largest value of a single IPv4 dotted-quad octet. */
const MAX_IPV4_OCTET = 255;

/** Largest value that fits into a 32-bit IPv4 address. */
const MAX_IPV4_VALUE = 0xffffffff;

export function normalizeDnsName(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/, "");
}

export function isWildcardDnsName(value: string): boolean {
  return value.startsWith("*.");
}

function isDecimalLabel(label: string): boolean {
  if (label.length === 0) return false;
  for (const char of label) {
    if (char < "0" || char > "9") return false;
  }
  return true;
}

/**
 * Parses one numeric host label using the URL IPv4 parser's rules: plain
 * decimal, a `0x`-prefixed hexadecimal value, or a leading-zero octal value.
 * Returns null when the label is not numeric or does not fit in 32 bits.
 */
function parseNumericLabel(label: string): number | null {
  let digits = label;
  let radix = 10;

  if (label.length > 2 && (label.startsWith("0x") || label.startsWith("0X"))) {
    digits = label.slice(2);
    radix = 16;
  } else if (label.length > 1 && label.startsWith("0")) {
    digits = label.slice(1);
    radix = 8;
  }
  if (digits.length === 0) return null;

  let value = 0;
  for (const char of digits) {
    const code = char.charCodeAt(0);
    let digit: number;
    if (code >= 0x30 && code <= 0x39) digit = code - 0x30;
    else if (code >= 0x41 && code <= 0x46) digit = code - 0x37;
    else if (code >= 0x61 && code <= 0x66) digit = code - 0x57;
    else return null;
    if (digit >= radix) return null;
    value = value * radix + digit;
    if (value > MAX_IPV4_VALUE) return null;
  }
  return value;
}

/** True for a canonical four-part dotted-decimal IPv4 literal. */
function isDottedQuadIpv4(host: string): boolean {
  const labels = host.split(".");
  if (labels.length !== 4) return false;
  for (const label of labels) {
    if (!isDecimalLabel(label) || label.length > 3) return false;
    if (Number(label) > MAX_IPV4_OCTET) return false;
  }
  return true;
}

/**
 * True for an all-numeric host such as "1.2.3.4.5". The URL parser refuses
 * these when they are not a valid four-part address, but no public DNS zone
 * uses an all-numeric final label, so they are treated as IP notation rather
 * than as a DNS name.
 */
function isAllNumericHost(host: string): boolean {
  const labels = host.split(".");
  if (labels.length === 0 || labels.length > 4) return false;
  return labels.every((label) => parseNumericLabel(label) !== null);
}

/**
 * Parses a hostname through the WHATWG URL parser, which applies the same
 * normalisation (including legacy IPv4 notation rewriting) used by HTTP
 * clients and by the Workers runtime. Returns null when the value cannot be
 * used as a URL host or was split into userinfo/port/path components.
 */
function parseUrlHost(value: string): string | null {
  try {
    const url = new URL(`http://${value}/`);
    if (url.username || url.password || url.port || url.search || url.hash) {
      return null;
    }
    if (url.pathname !== "/") return null;
    return url.hostname;
  } catch {
    return null;
  }
}

/**
 * True for a bare or bracketed IPv6 literal. The URL parser is the authority
 * here as well, so zone identifiers and other non-literal forms are not
 * misclassified as addresses.
 */
function isIpv6Literal(value: string): boolean {
  const inner =
    value.startsWith("[") && value.endsWith("]") ? value.slice(1, -1) : value;
  if (!inner.includes(":")) return false;
  try {
    new URL(`http://[${inner}]/`);
    return true;
  } catch {
    return false;
  }
}

/**
 * True when the value is an IPv4/IPv6 literal or a numeric host that the URL
 * parser interprets as one. A single leading "*." wildcard label is ignored,
 * so "*.127.0.0.1" is recognised as an IP address as well.
 */
export function isIpLiteralIdentifier(value: string): boolean {
  if (typeof value !== "string") return false;
  const candidate = normalizeDnsName(value);
  const host = isWildcardDnsName(candidate) ? candidate.slice(2) : candidate;
  if (host.length === 0) return false;

  // IPv6 literals contain a colon; use the URL parser to confirm the literal.
  if (host.includes(":")) {
    return isIpv6Literal(host);
  }

  const parsed = parseUrlHost(host);
  if (parsed !== null) {
    if (parsed.startsWith("[") && parsed.endsWith("]")) return true;
    return isDottedQuadIpv4(parsed);
  }

  // The URL parser rejects some numeric hosts outright (for example an
  // all-numeric final label that is not a valid IPv4 address). They are not
  // usable public DNS names either, so classify them as IP notation.
  return isAllNumericHost(host);
}

/**
 * Validates a DNS identifier. A trailing dot is not accepted for identifiers
 * submitted to new-order (the original API contract), but callers that deal
 * with redirect hostnames can normalize first.
 *
 * IP address literals are rejected, including legacy numeric IPv4 notations
 * and hosts that the URL parser normalises into an IP address.
 */
export function isValidDnsIdentifier(value: string, allowWildcard = true): boolean {
  if (typeof value !== "string" || value.length === 0 || value.length > 253) {
    return false;
  }
  if (!allowWildcard && value.startsWith("*.")) {
    return false;
  }
  if (!DNS_NAME_REGEX.test(value)) {
    return false;
  }
  if (isIpLiteralIdentifier(value)) {
    return false;
  }

  // Require the URL host parser to accept the name as a domain. This rejects
  // hosts it would treat as an IP address or refuse altogether (for example an
  // all-numeric final label).
  const base = isWildcardDnsName(value) ? value.slice(2) : value;
  const host = parseUrlHost(base);
  return host !== null && !host.startsWith("[");
}

export type DnsIdentifierValidation =
  | { ok: true; value: string }
  | { ok: false; errorType: "malformed" | "rejectedIdentifier"; detail: string };

/**
 * Single validation entry point for identifiers submitted with type "dns".
 * Returns the normalized (trimmed and lower-cased) value on success.
 *
 * IP literals are rejected here, before an Order or Authorization row is
 * created, to preserve the distinction between DNS and IP identifiers.
 */
export function validateDnsIdentifier(
  value: unknown,
  allowWildcard = true
): DnsIdentifierValidation {
  if (typeof value !== "string") {
    return {
      ok: false,
      errorType: "malformed",
      detail: "A 'dns' identifier value must be a string",
    };
  }

  const candidate = value.trim().toLowerCase();
  if (candidate.length === 0) {
    return {
      ok: false,
      errorType: "rejectedIdentifier",
      detail: "A 'dns' identifier must not be empty",
    };
  }
  if (candidate.length > 253) {
    return {
      ok: false,
      errorType: "rejectedIdentifier",
      detail: `DNS identifier is longer than 253 characters: '${value}'`,
    };
  }
  if (isIpLiteralIdentifier(candidate)) {
    return {
      ok: false,
      errorType: "rejectedIdentifier",
      detail: `Identifier '${value}' is an IP address literal; use type 'ip' for IP certificates`,
    };
  }
  if (!isValidDnsIdentifier(candidate, allowWildcard)) {
    return {
      ok: false,
      errorType: "rejectedIdentifier",
      detail: `Invalid domain syntax: '${value}'`,
    };
  }

  return { ok: true, value: candidate };
}


export interface AcmeIdentifier {
  type: "dns" | "ip";
  value: string;
}

/** IP identifiers do not accept URL syntax, scoped addresses or legacy IPv4. */
export function normalizeIpAddress(value: string): string | null {
  if (value.includes("%") || !isIP(value)) return null;
  if (isIP(value) === 4) return value;
  return new URL(`http://[${value}]/`).hostname.slice(1, -1);
}

export function validateIpIdentifier(value: unknown): DnsIdentifierValidation {
  if (typeof value !== "string") return { ok: false, errorType: "malformed", detail: "An 'ip' identifier value must be a string" };
  const address = normalizeIpAddress(value.trim());
  if (!address || !isPublicIpAddress(address)) {
    return { ok: false, errorType: "rejectedIdentifier", detail: "IP identifier must be a public, unscoped IPv4 or IPv6 address" };
  }
  return { ok: true, value: address };
}

export function identifierKey(identifier: AcmeIdentifier): string {
  return `${identifier.type}:${identifier.value}`;
}

/** Legacy string arrays were exclusively DNS names; never infer their type. */
export function readIdentifiers(json: string): AcmeIdentifier[] {
  const values: unknown = JSON.parse(json);
  if (!Array.isArray(values)) throw new Error("Invalid identifier metadata");
  return values.map((entry: unknown) => {
    if (typeof entry === "string") return { type: "dns", value: entry.toLowerCase() };
    if (!entry || typeof entry !== "object") throw new Error("Invalid identifier metadata");
    const item = entry as Record<string, unknown>;
    if ((item.type !== "dns" && item.type !== "ip") || typeof item.value !== "string") throw new Error("Invalid identifier metadata");
    const value = item.type === "ip" ? normalizeIpAddress(item.value) : item.value.toLowerCase();
    if (!value) throw new Error("Invalid IP metadata");
    return { type: item.type, value };
  });
}

/** Allows internal DNS-only callers to keep their string-array interface. */
export function asIdentifiers(values: readonly (string | AcmeIdentifier)[]): AcmeIdentifier[] {
  return values.map((value) => typeof value === "string" ? { type: "dns", value: value.toLowerCase() } : value);
}
