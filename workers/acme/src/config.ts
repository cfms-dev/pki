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
  [key: string]: unknown;
}

// Authoritative Global CAA Issuer Domain Name (RFC 8659)
export const CAA_ISSUER_DOMAIN_NAME = "cfms-pki.crpteam.club";

// Public URLs & Metadata (RFC 8555 & RFC 9773)
export const WEBSITE_URL = `https://${CAA_ISSUER_DOMAIN_NAME}`;
export const ARI_EXPLANATION_URL = `https://${CAA_ISSUER_DOMAIN_NAME}/docs/ari`;
export const TERMS_OF_SERVICE_URL = "";

export const CONFIG = {
  // Authoritative Global CAA Issuer Domain Name
  CAA_ISSUER_DOMAIN_NAME,

  // Public URLs & Metadata
  WEBSITE_URL,
  ARI_EXPLANATION_URL,
  TERMS_OF_SERVICE_URL,

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
