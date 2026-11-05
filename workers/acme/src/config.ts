// Configuration constants for CFMS-PKI ACME Server

export interface AcmeEnv {
  DB: D1Database;
  ACME_BASE_URL?: string;
  CERT_VALIDITY_DAYS?: string;
  RENEWAL_WINDOW_DAYS?: string;
  CA_DIR?: string;
  CA_ID?: string;
  PK_ENV_VAR?: string;
  EXCLUDED_CA_IDS?: string; // Comma-separated list of CA identifiers to exclude
  CA_WEIGHTS?: string;      // JSON string of { [caId]: number }
  WEBSITE_URL?: string;
  ARI_EXPLANATION_URL?: string;
  TERMS_OF_SERVICE_URL?: string;
  CAA_IDENTITIES?: string | string[];
  CAA_ISSUER_DOMAIN_NAME?: string;
  EXTERNAL_ACCOUNT_REQUIRED?: string | boolean;
  [key: string]: unknown;
}

// Authoritative Global CAA Issuer Domain Name (RFC 8659)
export const CAA_ISSUER_DOMAIN_NAME = "cfms-pki.crpteam.club";

// Public URLs & Metadata (RFC 8555 & RFC 9773)
export const WEBSITE_URL = `https://${CAA_ISSUER_DOMAIN_NAME}`;
export const ARI_EXPLANATION_URL = `https://${CAA_ISSUER_DOMAIN_NAME}/docs/ari`;
export const TERMS_OF_SERVICE_URL = "";
export const CAA_IDENTITIES: string[] | undefined = [CAA_ISSUER_DOMAIN_NAME];
export const EXTERNAL_ACCOUNT_REQUIRED = false;

/**
 * Resolves the authoritative CAA issuer domain name per RFC 8659.
 * Fallback to CONFIG.CAA_ISSUER_DOMAIN_NAME or default constant if not set.
 */
export function getCaaIssuerDomainName(env?: AcmeEnv): string {
  if (typeof env?.CAA_ISSUER_DOMAIN_NAME === "string" && env.CAA_ISSUER_DOMAIN_NAME.trim()) {
    return env.CAA_ISSUER_DOMAIN_NAME.trim();
  }
  const configVal = typeof CONFIG.CAA_ISSUER_DOMAIN_NAME === "string" ? CONFIG.CAA_ISSUER_DOMAIN_NAME.trim() : "";
  return configVal || CAA_ISSUER_DOMAIN_NAME;
}

/**
 * Resolves the termsOfService URL per RFC 8555 § 7.1.1.
 * If not specified, returns undefined (omitted from response).
 */
export function getTermsOfServiceUrl(env?: AcmeEnv): string | undefined {
  const envVal = typeof env?.TERMS_OF_SERVICE_URL === "string" ? env.TERMS_OF_SERVICE_URL.trim() : "";
  const configVal = typeof CONFIG.TERMS_OF_SERVICE_URL === "string" ? CONFIG.TERMS_OF_SERVICE_URL.trim() : "";
  return envVal || configVal || undefined;
}

/**
 * Resolves the website URL per RFC 8555 § 7.1.1.
 * If not specified or explicitly set to empty, returns undefined.
 */
export function getWebsiteUrl(env?: AcmeEnv): string | undefined {
  if (env?.WEBSITE_URL === "") return undefined;
  const envVal = typeof env?.WEBSITE_URL === "string" ? env.WEBSITE_URL.trim() : "";
  const configVal = typeof CONFIG.WEBSITE_URL === "string" ? CONFIG.WEBSITE_URL.trim() : "";
  return envVal || configVal || undefined;
}

/**
 * Resolves the caaIdentities array per RFC 8555 § 7.1.1.
 * If not specified or empty, returns undefined.
 */
export function getCaaIdentities(env?: AcmeEnv): string[] | undefined {
  if (env?.CAA_IDENTITIES === "") return undefined;
  if (Array.isArray(env?.CAA_IDENTITIES)) {
    const list = env.CAA_IDENTITIES.filter(Boolean);
    return list.length > 0 ? list : undefined;
  }
  if (typeof env?.CAA_IDENTITIES === "string") {
    const list = env.CAA_IDENTITIES.split(",").map((s) => s.trim()).filter(Boolean);
    return list.length > 0 ? list : undefined;
  }
  if (env?.CAA_ISSUER_DOMAIN_NAME !== undefined) {
    const domain = typeof env.CAA_ISSUER_DOMAIN_NAME === "string" ? env.CAA_ISSUER_DOMAIN_NAME.trim() : "";
    return domain ? [domain] : undefined;
  }
  if (Array.isArray(CONFIG.CAA_IDENTITIES)) {
    const list = CONFIG.CAA_IDENTITIES.filter(Boolean);
    return list.length > 0 ? list : undefined;
  }
  if (CONFIG.CAA_ISSUER_DOMAIN_NAME) {
    const domain = CONFIG.CAA_ISSUER_DOMAIN_NAME.trim();
    return domain ? [domain] : undefined;
  }
  return undefined;
}

/**
 * Resolves the externalAccountRequired flag per RFC 8555 § 7.1.1.
 * Returns true only if explicitly set to true. Default is false (omitted from meta).
 */
export function getExternalAccountRequired(env?: AcmeEnv): boolean {
  if (env?.EXTERNAL_ACCOUNT_REQUIRED === true || env?.EXTERNAL_ACCOUNT_REQUIRED === "true") {
    return true;
  }
  if (CONFIG.EXTERNAL_ACCOUNT_REQUIRED === true) {
    return true;
  }
  return false;
}

export const CONFIG = {
  // Authoritative Global CAA Issuer Domain Name
  CAA_ISSUER_DOMAIN_NAME,

  // Public URLs & Metadata
  WEBSITE_URL,
  ARI_EXPLANATION_URL,
  TERMS_OF_SERVICE_URL,
  CAA_IDENTITIES,
  EXTERNAL_ACCOUNT_REQUIRED,

  // RFC 8555 defaults
  DEFAULT_CERT_VALIDITY_DAYS: 90,
  DEFAULT_RENEWAL_WINDOW_DAYS: 30, // ARI suggested window duration (start = notAfter - 30d, end = notAfter)
  NONCE_EXPIRATION_SECONDS: 300,   // 5 minutes
  ORDER_EXPIRATION_SECONDS: 86400 * 7, // 7 days
  AUTHZ_EXPIRATION_SECONDS: 86400 * 3, // 3 days
  ARI_RETRY_AFTER_SECONDS: 21600,      // 6 hours

  // Rate Limits
  RATE_LIMIT_CERTS_PER_DOMAIN: 50,       // 50 certs per registered domain per 7 days
  RATE_LIMIT_DOMAIN_WINDOW_SECONDS: 7 * 86400,

  RATE_LIMIT_DUPLICATE_CERTS: 5,         // 5 duplicate certs per 7 days
  RATE_LIMIT_DUPLICATE_WINDOW_SECONDS: 7 * 86400,

  RATE_LIMIT_NEW_ORDERS_PER_ACCOUNT: 300, // 300 orders per 3 hours
  RATE_LIMIT_NEW_ORDERS_WINDOW_SECONDS: 3 * 3600,

  RATE_LIMIT_FAILED_VALIDATIONS: 5,      // 5 failures per account per hostname per hour
  RATE_LIMIT_FAILED_WINDOW_SECONDS: 3600,

  // Intermediate CA Directory & Selection Configuration
  CA_DIR: "cas",                         // Designated directory for bundled intermediate CA certs

  // Excluded CA identifiers from issuance (configured in config.ts)
  EXCLUDED_CA_IDS: [] as string[],       // e.g. ["legacy-ca"]

  // Relative weights for CA selection (default weight is 1 if unspecified)
  // Higher weight increases probability: P(CA_i) = weight_i / sum(weights)
  CA_WEIGHTS: {} as Record<string, number>, // e.g. { "generic-intermediate": 10, "backup-intermediate": 1 }

  // Default Intermediate CA fallback identifier
  DEFAULT_CA_ID: "generic-intermediate",
  DEFAULT_PK_ENV_VAR: "PK_GENERIC_INTERMEDIATE",
};
