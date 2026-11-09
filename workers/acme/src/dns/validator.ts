import { dnsBudget, normalizeDnsTarget, queryDns } from "./doh";
import { AcmeError } from "../errors";
import { base64UrlEncode } from "../crypto/nonce";

export interface DnsValidationResult {
  valid: boolean;
  error?: string;
  queriedRecords?: string[];
}

/**
 * Computes expected DNS TXT record value for a dns-01 challenge:
 * digest = base64url(SHA256(token + "." + thumbprint))
 */
export async function computeExpectedDnsDigest(
  token: string,
  accountThumbprint: string
): Promise<string> {
  const keyAuthorization = `${token}.${accountThumbprint}`;
  const encoded = new TextEncoder().encode(keyAuthorization);
  const hash = await crypto.subtle.digest("SHA-256", encoded);
  return base64UrlEncode(hash);
}

/**
 * Extracts challenge host name:
 * Wildcard *.example.com -> _acme-challenge.example.com
 * Apex / sub example.com -> _acme-challenge.example.com
 */
export function getDnsChallengeHostname(domain: string): string {
  const cleanDomain = domain.startsWith("*.") ? domain.slice(2) : domain;
  return `_acme-challenge.${cleanDomain}`;
}

/**
 * Clean up quoted TXT strings from DoH responses
 */
export function cleanTxtRecord(raw: string): string {
  let cleaned = raw.trim();
  if (cleaned.startsWith('"') && cleaned.endsWith('"')) {
    cleaned = cleaned.slice(1, -1);
  }
  // Remove backslash escapes if any
  return cleaned.replace(/\\"/g, '"');
}

/**
 * Queries DoH endpoints to resolve TXT records for a hostname
 */
export async function resolveTxtRecords(
  hostname: string,
  fetchImpl: typeof fetch = fetch
): Promise<string[]> {
  const budget = dnsBudget();
  const visited = new Set<string>();
  let current = normalizeDnsTarget(hostname);
  for (let hop = 0; hop <= 8; hop++) {
    if (visited.has(current)) throw new AcmeError("dns", "TXT alias cycle");
    visited.add(current);
    const response = await queryDns(current, "TXT", fetchImpl, budget);
    const records = response.Answer.filter((answer) => answer.type === 16).map((answer) => cleanTxtRecord(answer.data));
    if (records.length) return records;
    const alias = response.Answer.find((answer) => answer.type === 5);
    if (!alias) return [];
    current = normalizeDnsTarget(alias.data);
  }
  throw new AcmeError("dns", "TXT alias limit exceeded");
}

/**
 * Validates dns-01 challenge against live or mocked DNS
 */
export async function validateDns01Challenge(
  domain: string,
  token: string,
  accountThumbprint: string,
  fetchImpl: typeof fetch = fetch
): Promise<DnsValidationResult> {
  const expectedDigest = await computeExpectedDnsDigest(token, accountThumbprint);
  const challengeHostname = getDnsChallengeHostname(domain);

  const txtRecords = await resolveTxtRecords(challengeHostname, fetchImpl);

  if (txtRecords.length === 0) {
    return {
      valid: false,
      error: `No TXT records found at ${challengeHostname}`,
      queriedRecords: [],
    };
  }

  const match = txtRecords.some((rec) => rec === expectedDigest);
  if (!match) {
    return {
      valid: false,
      error: `None of the TXT records at ${challengeHostname} matched expected digest '${expectedDigest}'`,
      queriedRecords: txtRecords,
    };
  }

  return {
    valid: true,
    queriedRecords: txtRecords,
  };
}
