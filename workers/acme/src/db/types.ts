// Database row types for Cloudflare D1

export interface AccountRow {
  id: string;
  jwk: string; // JSON string of account JWK
  thumbprint: string; // RFC 7638 SHA-256 base64url thumbprint
  contact: string | null; // JSON string array of contact URLs
  status: "valid" | "deactivated" | "revoked";
  created_at: number; // unix timestamp seconds
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

export interface CertificateRow {
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
