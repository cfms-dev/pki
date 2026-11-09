// Non-sensitive settings are owned here. Environment bindings supply resources and secrets only.
export interface AcmeEnv {
  DB: D1Database;
  fetch?: typeof fetch;
  // Private-key binding names come from registry/ca.json via the bundled manifest.
  [binding: string]: unknown;
}

export const CONFIG = {
  ACME_BASE_URL: "", // Empty: publish URLs using the request origin.
  CAA_ISSUER_DOMAIN_NAME: "cfms-pki.crpteam.club",
  WEBSITE_URL: "https://cfms-pki.crpteam.club",
  ARI_EXPLANATION_URL: "https://www.rfc-editor.org/rfc/rfc9773.html#section-4.2",
  TERMS_OF_SERVICE_URL: "",
  // undefined derives the published identity from CAA_ISSUER_DOMAIN_NAME; [] omits it.
  CAA_IDENTITIES: undefined as string[] | undefined,
  EXTERNAL_ACCOUNT_REQUIRED: false,
  CRL_BASE_URL: "https://cfms-dev.github.io/pki/crl/",

  CERT_VALIDITY_DAYS: 90,
  RENEWAL_WINDOW_DAYS: 30,
  NONCE_EXPIRATION_SECONDS: 300,   // 5 minutes
  ORDER_EXPIRATION_SECONDS: 86400 * 7, // 7 days
  AUTHZ_EXPIRATION_SECONDS: 86400 * 3, // 3 days
  ARI_RETRY_AFTER_SECONDS: 21600,      // 6 hours

  // HTTP-01 validation (RFC 8555 § 8.3)
  HTTP01_MAX_REDIRECTS: 5,
  HTTP01_REQUEST_TIMEOUT_MS: 10000,
  HTTP01_TOTAL_TIMEOUT_MS: 20000,
  HTTP01_MAX_BODY_BYTES: 8192,
  CHALLENGE_PROCESSING_STALE_SECONDS: 60, // allow recovery from an interrupted validation

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
};

export function getCaaIssuerDomainName(): string {
  return CONFIG.CAA_ISSUER_DOMAIN_NAME.trim();
}

export function getTermsOfServiceUrl(): string | undefined {
  return CONFIG.TERMS_OF_SERVICE_URL.trim() || undefined;
}

export function getWebsiteUrl(): string | undefined {
  return CONFIG.WEBSITE_URL.trim() || undefined;
}

export function getCaaIdentities(): string[] | undefined {
  const identities = CONFIG.CAA_IDENTITIES ?? [getCaaIssuerDomainName()];
  const list = identities.map((identity) => identity.trim()).filter(Boolean);
  return list.length ? list : undefined;
}

export function getExternalAccountRequired(): boolean {
  return CONFIG.EXTERNAL_ACCOUNT_REQUIRED;
}

/** Positive whole-day policy; invalid code configuration fails closed. */
export function configuredDays(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error("Invalid day configuration");
  return value;
}
