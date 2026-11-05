// Configuration constants for CFMS-PKI ACME Server

export interface AcmeEnv {
  DB: D1Database;
  ACME_BASE_URL?: string;
  CERT_VALIDITY_DAYS?: string;
  RENEWAL_WINDOW_DAYS?: string;
  CA_ID?: string;
  PK_ENV_VAR?: string;
  [key: string]: unknown;
}

export const CONFIG = {
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

  // Default Intermediate CA identifier matching registry/ca.json
  DEFAULT_CA_ID: "generic-intermediate",
  DEFAULT_PK_ENV_VAR: "PK_GENERIC_INTERMEDIATE",

  // Bundled Generic Intermediate CA Certificate (from certs/generic-intermediate.pem)
  BUNDLED_INTERMEDIATE_CERT_PEM: `-----BEGIN CERTIFICATE-----
MIICazCCAhCgAwIBAgIUMOJM76aCZ/5MXqL3fxaQbPvYJoMwCgYIKoZIzj0EAwIw
ejELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWpp
bmcxJTAjBgNVBAoMHENGTVMgTWFuYWdlbWVudCBPcmdhbml6YXRpb24xIDAeBgNV
BAMMF0NGTVMgVmFsaWRhdGlvbiBSb290IENBMB4XDTI1MDkxOTA0MzQyMFoXDTI4
MDkxODA0MzQyMFowgYcxCzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAw
DgYDVQQHDAdCZWlqaW5nMTUwMwYDVQQKDCxDRk1TIEludGVybWVkaWF0ZSBDQSBN
YW5hZ2VtZW50IE9yZ2FuaXphdGlvbjEdMBsGA1UEAwwUQ0ZNUyBJbnRlcm1lZGlh
dGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARUHTvzub/uwfCcFHZdnliF
IGghm1ZNxdKjYjeYMZs87uu8AjJVtG9MBV0+bnj9uzzYDoQ2+5u2gccB4ETiT6mB
o2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4E
FgQU5YWPQ5jiWFP+M3bAJrk/iGzigeMwHwYDVR0jBBgwFoAUYgHVcHEiM4gP4gSA
oIMUKCQGBv4wCgYIKoZIzj0EAwIDSQAwRgIhALrCHuX8oDwF5GJyekkH3DNdAmVq
d2diSMQPL3P1eKxNAiEA9hIiXGee0/VWU6rchoDpu2Zgfm+O9Qea9w24byIHk4A=
-----END CERTIFICATE-----`.trim(),
};
