// Shared ACME identifier helpers.
//
// RFC 8555 only defines the "dns" identifier type. Wildcard identifiers are
// represented as "*.example.com" and are only eligible for dns-01 validation.

const DNS_NAME_REGEX =
  /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

export function normalizeDnsName(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/, "");
}

export function isWildcardDnsName(value: string): boolean {
  return value.startsWith("*.");
}

/**
 * Validates a DNS identifier. A trailing dot is not accepted for identifiers
 * submitted to new-order (the original API contract), but callers that deal
 * with redirect hostnames can normalize first.
 */
export function isValidDnsIdentifier(value: string, allowWildcard = true): boolean {
  if (typeof value !== "string" || value.length === 0 || value.length > 253) {
    return false;
  }
  if (!allowWildcard && value.startsWith("*.")) {
    return false;
  }
  return DNS_NAME_REGEX.test(value);
}
