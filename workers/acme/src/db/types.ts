// Database row types for Cloudflare D1

export interface AccountRow {
  id: string;
  jwk: string; // JSON string of account JWK
  thumbprint: string; // RFC 7638 SHA-256 base64url thumbprint
  /**
   * base64url(SHA-256(canonical SubjectPublicKeyInfo DER)) of the actual
   * account public key. Unlike `thumbprint`, this is stable across legal JWK
   * encodings and is the identity used by cross-account key-reuse checks.
   * NULL only for legacy rows whose one-time backfill has not completed.
   */
  public_key_fingerprint?: string | null;
  contact: string | null; // JSON string array of contact URLs
  status: "valid" | "deactivated" | "revoked";
  created_at: number; // unix timestamp seconds
  terms_of_service?: string | null; // Agreed terms of service URL
}

/**
 * A legacy account whose public key could not be indexed, or an account that
 * shares an actual public key with another account. These rows are
 * administrator-facing only; they never contain private key material.
 */
export interface AccountKeyConflictRow {
  account_id: string;
  reason: string;
  public_key_fingerprint: string | null;
  conflicting_account_id: string | null;
  detected_at: number;
}

export interface OrderRow {
  id: string;
  account_id: string;
  status: "pending" | "ready" | "processing" | "valid" | "invalid";
  identifiers: string; // JSON array of domain strings e.g. ["example.com"]
  not_before: number | null;
  not_after: number | null;
  replaces_cert_id: string | null; // RFC 9773 predecessor certID
  is_ari_renewal: number; // 0 or 1
  created_at: number;
  expires_at: number;
  certificate_id: string | null;
  processing_started_at?: number | null;
  finalize_generation?: number;
}

export interface AuthorizationRow {
  id: string;
  order_id: string;
  identifier_value: string; // domain name e.g. "example.com"
  status: "pending" | "valid" | "invalid";
  token: string;
  expires_at: number;
  created_at: number;
}

export type ChallengeType = "dns-01" | "http-01";
export type ChallengeStatus = "pending" | "processing" | "valid" | "invalid";

export interface ChallengeRow {
  id: string;
  authorization_id: string;
  type: ChallengeType;
  token: string;
  status: ChallengeStatus;
  error: string | null; // JSON-encoded ACME problem document
  validated_at: number | null;
  processing_started_at: number | null;
  // Incremented atomically by every validation claim. Completion updates are
  // conditional on the generation captured at claim time so a stale attempt
  // whose processing claim was reclaimed cannot overwrite the newer result.
  validation_generation: number;
  created_at: number;
}

export interface CertificateRow {
  ca_id?: string | null;
  id: string;
  cert_id: string; // RFC 9773 certID: Base64URL(AKI) + "." + Base64URL(Serial)
  serial_number: string; // Hex or integer string
  aki: string; // Hex string of Authority Key Identifier
  subject: string;
  san: string; // JSON array of SAN strings
  pem: string;
  not_before: number;
  not_after: number;
  account_id: string;
  created_at: number;
  revoked_at: number | null;
  revocation_reason: string | null;
  replaced_by_cert_id: string | null;
}

export interface NonceRow {
  nonce: string;
  expires_at: number;
}

export interface RateLimitRow {
  key: string;
  counter: number;
  window_start: number;
}
