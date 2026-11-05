import { CAA_ISSUER_DOMAIN_NAME, getCaaIssuerDomainName, AcmeEnv } from "../config";
import { AcmeError } from "../errors";

export interface CaaRecord {
  flags: number;
  tag: string;
  value: string;
  issuerDomain: string;
  parameters: Record<string, string>;
}

export interface CaaValidationResult {
  valid: boolean;
  error?: string;
  relevantDomain?: string;
  recordsFound?: CaaRecord[];
}

export interface DohCaaResponse {
  records: CaaRecord[];
  cnameTarget?: string;
  status: number;
}

/**
 * Parses the value portion of a CAA issue or issuewild record according to RFC 8659 Section 4.2:
 *   issue-value = *WSP [issuer-domain-name *WSP] [";" *WSP [parameters *WSP]]
 *   parameters = [parameter *(";" *WSP parameter)]
 *   parameter = tag *WSP "=" *WSP value
 *
 * Extracts the issuer domain name and parses key-value parameters.
 * Does not treat parameters as part of the issuer domain name.
 */
export function parseCaaValue(value: string): {
  issuerDomain: string;
  parameters: Record<string, string>;
} {
  const trimmed = value.trim();
  const semicolonIdx = trimmed.indexOf(";");
  let domainPart = "";
  let paramsPart = "";

  if (semicolonIdx === -1) {
    domainPart = trimmed;
  } else {
    domainPart = trimmed.slice(0, semicolonIdx).trim();
    paramsPart = trimmed.slice(semicolonIdx + 1).trim();
  }

  // Remove trailing dot if present and normalize to lowercase
  const issuerDomain = domainPart.replace(/\.+$/, "").toLowerCase();

  const parameters: Record<string, string> = {};
  if (paramsPart) {
    const rawParams = paramsPart.split(";");
    for (const rawParam of rawParams) {
      const p = rawParam.trim();
      if (!p) continue;
      const eqIdx = p.indexOf("=");
      if (eqIdx === -1) {
        parameters[p.toLowerCase()] = "";
      } else {
        const key = p.slice(0, eqIdx).trim().toLowerCase();
        let val = p.slice(eqIdx + 1).trim();
        if (val.startsWith('"') && val.endsWith('"') && val.length >= 2) {
          val = val.slice(1, -1);
        }
        parameters[key] = val;
      }
    }
  }

  return { issuerDomain, parameters };
}

/**
 * Parses a raw CAA presentation or DNS record string into a CaaRecord structure.
 * Supports standard format (`<flags> <tag> "<value>"` or `<flags> <tag> <value>`)
 * as well as RFC 3597 unknown RR hex format (`\# <length> <hexdata>`).
 */
export function parseCaaRecord(raw: string): CaaRecord | null {
  const trimmed = raw.trim();

  // Support RFC 3597 presentation format: \# <length> <hexdata>
  if (trimmed.startsWith("\\#")) {
    const tokens = trimmed.split(/\s+/);
    if (tokens.length >= 3) {
      try {
        const hex = tokens.slice(2).join("");
        const hexMatches = hex.match(/../g);
        if (hexMatches) {
          const bytes = new Uint8Array(hexMatches.map((h) => parseInt(h, 16)));
          if (bytes.length >= 2) {
            const flags = bytes[0];
            const tagLen = bytes[1];
            if (bytes.length >= 2 + tagLen) {
              const tag = new TextDecoder().decode(bytes.slice(2, 2 + tagLen)).toLowerCase();
              const valStr = new TextDecoder().decode(bytes.slice(2 + tagLen));
              const { issuerDomain, parameters } = parseCaaValue(valStr);
              return { flags, tag, value: valStr, issuerDomain, parameters };
            }
          }
        }
      } catch {
        return null;
      }
    }
  }

  const match = trimmed.match(/^(\d+)\s+([a-zA-Z0-9]+)\s+(.*)$/s);
  if (!match) return null;

  const flags = parseInt(match[1], 10);
  const tag = match[2].toLowerCase();
  let valueStr = match[3].trim();

  // Strip enclosing quotes from value string if present
  if (valueStr.startsWith('"') && valueStr.endsWith('"') && valueStr.length >= 2) {
    valueStr = valueStr.slice(1, -1).replace(/\\"/g, '"');
  }

  const { issuerDomain, parameters } = parseCaaValue(valueStr);
  return {
    flags,
    tag,
    value: valueStr,
    issuerDomain,
    parameters,
  };
}

/**
 * Checks if a specific CAA record authorizes CFMS-PKI issuance,
 * evaluating issuer domain name and any optional/mandatory parameters.
 */
function doesRecordAuthorize(
  record: CaaRecord,
  accountUri?: string,
  expectedIssuerDomain: string = CAA_ISSUER_DOMAIN_NAME
): boolean {
  const normalizedIssuer = record.issuerDomain.toLowerCase();
  const targetIssuer = expectedIssuerDomain.toLowerCase();

  // Issuer domain name must match the target CAA identity
  if (normalizedIssuer !== targetIssuer) {
    return false;
  }

  // RFC 8659 Section 4.3: accounturi parameter
  if (record.parameters.accounturi && accountUri) {
    if (record.parameters.accounturi !== accountUri) {
      return false;
    }
  }

  // RFC 8659 Section 4.4: validationmethods parameter
  if (record.parameters.validationmethods) {
    const methods = record.parameters.validationmethods
      .split(",")
      .map((m) => m.trim().toLowerCase());
    if (!methods.includes("dns-01")) {
      return false;
    }
  }

  return true;
}

/**
 * Evaluates a Relevant CAA Resource Record Set according to RFC 8659 rules:
 * - Flags: Checks the Issuer Critical Flag (bit 0, 0x80). If an unrecognized property tag
 *   has the critical flag set, issuance MUST NOT proceed.
 * - Wildcard domains: If `issuewild` is present, it supersedes `issue`.
 *   If no `issuewild` is present, falls back to `issue`.
 * - Non-wildcard domains: Only `issue` is evaluated. `issuewild` is ignored.
 * - If no issuing tags exist (e.g. only `iodef`), issuance is not restricted.
 */
export function evaluateCaaRecords(
  records: CaaRecord[],
  isWildcard: boolean,
  accountUri?: string,
  expectedIssuerDomain: string = CAA_ISSUER_DOMAIN_NAME
): CaaValidationResult {
  if (records.length === 0) {
    return { valid: true, recordsFound: [] };
  }

  // 1. Critical Tag Check:
  // Bit 0 (0x80) is the Issuer Critical Flag
  const recognizedTags = new Set(["issue", "issuewild", "iodef"]);
  for (const record of records) {
    if ((record.flags & 128) !== 0) {
      if (!recognizedTags.has(record.tag)) {
        return {
          valid: false,
          error: `Unrecognized critical CAA property tag '${record.tag}' forbids certificate issuance`,
          recordsFound: records,
        };
      }
    }
  }

  // 2. Authorization Evaluation
  if (isWildcard) {
    const issuewildRecords = records.filter((r) => r.tag === "issuewild");
    if (issuewildRecords.length > 0) {
      // issuewild takes precedence over issue for wildcard certificates
      const authorized = issuewildRecords.some((r) => doesRecordAuthorize(r, accountUri, expectedIssuerDomain));
      if (!authorized) {
        return {
          valid: false,
          error: `CAA issuewild record forbids issuance for wildcard domain by '${expectedIssuerDomain}'`,
          recordsFound: records,
        };
      }
      return { valid: true, recordsFound: records };
    }

    // If no issuewild tags are present, fall back to issue tags
    const issueRecords = records.filter((r) => r.tag === "issue");
    if (issueRecords.length > 0) {
      const authorized = issueRecords.some((r) => doesRecordAuthorize(r, accountUri, expectedIssuerDomain));
      if (!authorized) {
        return {
          valid: false,
          error: `CAA issue record forbids issuance for wildcard domain by '${expectedIssuerDomain}'`,
          recordsFound: records,
        };
      }
      return { valid: true, recordsFound: records };
    }

    // No issuewild and no issue records present (e.g. only iodef) -> unrestricted
    return { valid: true, recordsFound: records };
  } else {
    // Non-wildcard domain: issuewild is ignored
    const issueRecords = records.filter((r) => r.tag === "issue");
    if (issueRecords.length > 0) {
      const authorized = issueRecords.some((r) => doesRecordAuthorize(r, accountUri, expectedIssuerDomain));
      if (!authorized) {
        return {
          valid: false,
          error: `CAA issue record forbids issuance for domain by '${expectedIssuerDomain}'`,
          recordsFound: records,
        };
      }
      return { valid: true, recordsFound: records };
    }

    // No issue records present (e.g. only issuewild or iodef) -> unrestricted
    return { valid: true, recordsFound: records };
  }
}

/**
 * Queries DNS over HTTPS (DoH) providers for CAA records for a given domain name.
 */
export async function queryDohCaa(
  domain: string,
  fetchImpl: typeof fetch = fetch
): Promise<DohCaaResponse> {
  const providers = [
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=CAA`,
    `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=CAA`,
  ];

  let lastStatus = 0;

  for (const url of providers) {
    try {
      const resp = await fetchImpl(url, {
        headers: { Accept: "application/dns-json" },
      });
      if (!resp.ok) continue;

      const data = (await resp.json()) as {
        Status?: number;
        Answer?: Array<{ type: number; data: string; name?: string }>;
      };

      lastStatus = data.Status ?? 0;

      const records: CaaRecord[] = [];
      let cnameTarget: string | undefined;

      if (Array.isArray(data.Answer)) {
        for (const ans of data.Answer) {
          if (ans.type === 257 && ans.data) {
            const parsed = parseCaaRecord(ans.data);
            if (parsed) {
              records.push(parsed);
            }
          } else if (ans.type === 5 && ans.data) {
            // CNAME record
            let target = ans.data.trim();
            if (target.startsWith('"') && target.endsWith('"')) {
              target = target.slice(1, -1);
            }
            cnameTarget = target.replace(/\.+$/, "").toLowerCase();
          }
        }
      }

      if (records.length > 0 || cnameTarget || lastStatus === 3 || lastStatus === 0) {
        return { records, cnameTarget, status: lastStatus };
      }
    } catch {
      // Continue to next provider
    }
  }

  return { records: [], status: lastStatus };
}

/**
 * Implements RFC 8659 Section 3.1 & 3.2 Tree-Walking to find the Relevant CAA Resource Record Set:
 * 1. Begins at the domain itself.
 * 2. If CAA records exist, returns them (this is the Relevant CAA RRSet).
 * 3. If a CNAME is returned, queries the CNAME target for CAA records.
 * 4. If no CAA records exist, climbs to the parent domain and repeats.
 * 5. If root / apex is reached with no records found, returns null (meaning CAA permits issuance).
 */
export async function findRelevantCaaRecordSet(
  domain: string,
  fetchImpl: typeof fetch = fetch
): Promise<{ domain: string; records: CaaRecord[] } | null> {
  const cleanDomain = domain.startsWith("*.") ? domain.slice(2) : domain;
  let current: string = cleanDomain.toLowerCase().replace(/\.+$/, "");

  while (current.length > 0) {
    const resp = await queryDohCaa(current, fetchImpl);
    if (resp.records.length > 0) {
      return { domain: current, records: resp.records };
    }

    // Follow CNAME target if present (RFC 8659 Section 3.2)
    if (resp.cnameTarget) {
      let cnameDomain: string = resp.cnameTarget;
      let hops = 0;
      while (cnameDomain && hops < 8) {
        hops++;
        const cnameResp = await queryDohCaa(cnameDomain, fetchImpl);
        if (cnameResp.records.length > 0) {
          return { domain: cnameDomain, records: cnameResp.records };
        }
        if (cnameResp.cnameTarget) {
          cnameDomain = cnameResp.cnameTarget;
        } else {
          break;
        }
      }
    }

    // Climb to parent domain
    const dotIdx = current.indexOf(".");
    if (dotIdx === -1) {
      break;
    }
    current = current.slice(dotIdx + 1);
  }

  return null;
}

/**
 * Validates a single domain name against RFC 8659 CAA requirements using
 * the configured CAA identity (defaulting to `CAA_ISSUER_DOMAIN_NAME`).
 */
export async function validateCaa(
  domain: string,
  accountUri?: string,
  fetchImpl: typeof fetch = fetch,
  expectedIssuerDomain: string = CAA_ISSUER_DOMAIN_NAME
): Promise<CaaValidationResult> {
  const isWildcard = domain.startsWith("*.");
  const cleanDomain = isWildcard ? domain.slice(2) : domain;

  const relevant = await findRelevantCaaRecordSet(cleanDomain, fetchImpl);
  if (!relevant || relevant.records.length === 0) {
    // RFC 8659: If no Relevant CAA RRSet is found, issuance is permitted
    return { valid: true };
  }

  const result = evaluateCaaRecords(relevant.records, isWildcard, accountUri, expectedIssuerDomain);
  return {
    ...result,
    relevantDomain: relevant.domain,
  };
}

/**
 * Validates CAA for all domains in an ACME order.
 * Throws `AcmeError.caa` (HTTP 403) if any domain fails CAA validation.
 */
export async function validateCaaForOrder(
  domains: string[],
  accountUri: string,
  env?: { fetch?: typeof fetch; CAA_ISSUER_DOMAIN_NAME?: string; [key: string]: unknown },
  fetchImpl?: typeof fetch
): Promise<void> {
  const fetcher = fetchImpl || (env?.fetch as typeof fetch) || fetch;
  const caaIssuer = getCaaIssuerDomainName(env as AcmeEnv | undefined);

  for (const domain of domains) {
    const res = await validateCaa(domain, accountUri, fetcher, caaIssuer);
    if (!res.valid) {
      throw AcmeError.caa(
        `CAA verification failed for domain '${domain}': ${res.error || "CAA records forbid issuance by " + caaIssuer}`
      );
    }
  }
}
