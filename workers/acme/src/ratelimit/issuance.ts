import { AcmeIdentifier, asIdentifiers, identifierKey } from "../acme/identifiers";
import { parseIpv6 } from "../acme/ip";
import { CONFIG } from "../config";

export interface IssuanceBucket {
  key: string;
  limit: number;
  windowSeconds: number;
}

/** Preserve the existing registered-domain and IPv6 /64 grouping policy. */
export function getRegisteredDomain(domain: string): string {
  const clean = domain.startsWith("*.") ? domain.slice(2) : domain;
  const parts = clean.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return clean.toLowerCase();
  if (["com", "co", "net", "org", "gov", "edu"].includes(parts[parts.length - 2]) && parts[parts.length - 1].length === 2) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

export function issuanceGroup(identifier: AcmeIdentifier): string {
  if (identifier.type === "dns") return getRegisteredDomain(identifier.value);
  if (!identifier.value.includes(":")) return `ip:v4:${identifier.value}`;
  const bytes = parseIpv6(identifier.value);
  if (!bytes) throw new Error("Invalid IPv6 rate-limit identifier");
  return `ip:v6:${Array.from(bytes.slice(0, 8), (byte) => byte.toString(16).padStart(2, "0")).join("")}/64`;
}

/** One charge per group and one per exact, canonical identifier set. */
export function issuanceBuckets(domains: (string | AcmeIdentifier)[]): IssuanceBucket[] {
  const identifiers = [...new Map(asIdentifiers(domains).map((item) => [identifierKey(item), item])).values()];
  if (identifiers.length === 0) throw new Error("Cannot account for an empty identifier set");
  const groups = new Set(identifiers.map(issuanceGroup));
  return [
    ...[...groups].map((group) => ({
      key: group.startsWith("ip:") ? `issuance:${group}` : `issuance:domain:${group}`,
      limit: CONFIG.RATE_LIMIT_CERTS_PER_DOMAIN,
      windowSeconds: CONFIG.RATE_LIMIT_DOMAIN_WINDOW_SECONDS,
    })),
    {
      key: `issuance:duplicate:${identifiers.map((item) => item.type === "dns" ? item.value : identifierKey(item)).sort().join(",")}`,
      limit: CONFIG.RATE_LIMIT_DUPLICATE_CERTS,
      windowSeconds: CONFIG.RATE_LIMIT_DUPLICATE_WINDOW_SECONDS,
    },
  ];
}
