import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { AcmeEnv, CONFIG, certificateValiditySeconds } from "../config";
import { AcmeError } from "../errors";
import { AcmeIdentifier, asIdentifiers, identifierKey, isValidDnsIdentifier, validateDnsIdentifier, validateIpIdentifier } from "../acme/identifiers";
import { base64UrlDecode } from "./nonce";
import { derivePublicKeyIdentityFromCryptoKey } from "./jws";
import { bytesToHex, computeCertId } from "../ari/cert-id";
import {
  SelectedIntermediateCa,
  selectIntermediateCa,
} from "./ca";


export interface ParsedCsr {
  csr: x509.Pkcs10CertificateRequest;
  domains: string[]; // DNS-only compatibility view
  identifiers: AcmeIdentifier[];
  publicKey: CryptoKey;
  /** Canonical SubjectPublicKeyInfo DER encoding of the CSR public key. */
  publicKeySpki: Uint8Array;
  /** RFC 7638 SHA-256 JWK thumbprint of the CSR public key. */
  publicKeyThumbprint: string;
  /** base64url(SHA-256(canonical SPKI DER)) — the actual public key identity. */
  publicKeyFingerprint: string;
}

export interface IssuedCertificate {
  leafPem: string;
  chainPem: string;
  serialNumber: string; // hex
  aki: string;          // hex
  certId: string;       // RFC 9773 certID
  notBefore: number;    // unix seconds
  notAfter: number;     // unix seconds
  subject: string;
  san: AcmeIdentifier[];
  caId: string;
  caSerialNumber: string;
}

export interface PublicKeyIdentity {
  publicKey: CryptoKey;
  /** Canonical SubjectPublicKeyInfo DER encoding of the public key. */
  publicKeySpki: Uint8Array;
  /** RFC 7638 SHA-256 JWK thumbprint of the public key. */
  publicKeyThumbprint: string;
  /** base64url(SHA-256(canonical SPKI DER)) — the actual public key identity. */
  publicKeyFingerprint: string;
}

/**
 * Normalises a SubjectPublicKeyInfo public key into a canonical identity.
 *
 * `PublicKey.export()` imports the key through WebCrypto, so re-exporting it
 * produces a canonical SPKI DER (independent of how the client encoded the
 * key) and the JWK that RFC 7638 thumbprints are defined over. A key that
 * cannot be normalised is rejected as badCSR: the finalize-time key-reuse
 * check must never treat an unrepresentable key as a pass.
 */
export async function derivePublicKeyIdentity(
  publicKey: x509.PublicKey
): Promise<PublicKeyIdentity> {
  try {
    const cryptoKey = await publicKey.export();
    const identity = await derivePublicKeyIdentityFromCryptoKey(cryptoKey);
    return {
      publicKey: identity.cryptoKey,
      publicKeySpki: identity.spki,
      publicKeyThumbprint: identity.thumbprint,
      publicKeyFingerprint: identity.fingerprint,
    };
  } catch (error: unknown) {
    throw AcmeError.badCSR(
      `CSR public key is malformed or uses an unsupported algorithm: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
}

/**
 * Parses and verifies a PKCS#10 CSR from base64url or DER
 */
export async function parseAndVerifyCsr(csrBase64Url: string): Promise<ParsedCsr> {
  let derBytes: Uint8Array;
  try {
    derBytes = base64UrlDecode(csrBase64Url);
  } catch {
    throw AcmeError.badCSR("Failed to base64url decode CSR");
  }

  let csr: x509.Pkcs10CertificateRequest;
  try {
    csr = new x509.Pkcs10CertificateRequest(derBytes);
  } catch (err: unknown) {
    throw AcmeError.badCSR(`Failed to parse PKCS#10 CSR: ${err instanceof Error ? err.message : String(err)}`);
  }

  const isValid = await csr.verify();
  if (!isValid) {
    throw AcmeError.badCSR("CSR signature verification failed");
  }

  const identifiers: AcmeIdentifier[] = [];
  for (const ext of csr.extensions) {
    if (ext.type !== "2.5.29.17") continue;
    const sanExt = new x509.SubjectAlternativeNameExtension(ext.rawData);
    for (const item of sanExt.names.items) {
      if (item.type !== "dns" && item.type !== "ip") {
        throw AcmeError.badCSR(`CSR contains unsupported SAN type '${item.type}'`);
      }
      const result = item.type === "ip" ? validateIpIdentifier(item.value) : validateDnsIdentifier(item.value);
      if (!result.ok) throw AcmeError.badCSR(result.detail);
      identifiers.push({ type: item.type, value: result.value });
    }
  }

  // RFC 8555 § 7.4 allows DNS identifiers to be carried in the subject
  // commonName instead of (or in addition to) the SAN extension. Include a
  // commonName only when it is a syntactically valid DNS identifier, so a
  // descriptive CN does not become a phantom identifier. If it is a valid DNS
  // name, it is part of the requested set and is checked against the order.
  for (const cn of csr.subjectName.getField("CN")) {
    const value = cn.trim().toLowerCase();
    if (isValidDnsIdentifier(value)) {
      identifiers.push({ type: "dns", value });
    }
  }

  const uniqueIdentifiers = [...new Map(identifiers.map((item) => [identifierKey(item), item])).values()];
  if (uniqueIdentifiers.length === 0) throw AcmeError.badCSR("CSR contains no authorized identifiers");

  return {
    csr,
    identifiers: uniqueIdentifiers,
    domains: uniqueIdentifiers.filter((item) => item.type === "dns").map((item) => item.value),
    ...(await derivePublicKeyIdentity(csr.publicKey)),
  };
}

/**
 * Generates a random 160-bit serial number as a hex string
 */
export function generateRandomSerialNumberHex(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  bytes[0] &= 0x7f;
  if (bytes.every((byte) => byte === 0)) bytes[19] = 1;
  return bytesToHex(bytes);
}

/**
 * Issues a policy-bounded leaf certificate signed by the intermediate CA
 */
export async function issueCertificateFromCsr(
  csr: x509.Pkcs10CertificateRequest,
  authorizedDomains: (string | AcmeIdentifier)[],
  env: AcmeEnv,
  validityDays = CONFIG.CERT_VALIDITY_DAYS,
  explicitCa?: SelectedIntermediateCa,
  requested?: { notBefore: number | null; notAfter: number | null }
): Promise<IssuedCertificate> {
  const identifiers = asIdentifiers(authorizedDomains);
  const subjectDns = identifiers.find((item) => item.type === "dns");
  const subject = subjectDns ? `CN=${subjectDns.value}` : "";
  const selected = explicitCa || (await selectIntermediateCa(env));
  const caCertPem = selected.certPem;
  const caCert = selected.cert;
  const caPrivateKey = selected.privateKey;

  const now = new Date();
  const notBefore = requested?.notBefore ? new Date(requested.notBefore * 1000) : now;
  const maximumEnd = Math.min(notBefore.getTime() + certificateValiditySeconds(identifiers, validityDays) * 1000, caCert.notAfter.getTime());
  const notAfter = requested?.notAfter ? new Date(requested.notAfter * 1000) : new Date(maximumEnd);
  if (notBefore < caCert.notBefore || notBefore >= caCert.notAfter || notAfter <= notBefore || notAfter.getTime() > maximumEnd || notAfter <= now) {
    throw AcmeError.badCSR("Requested certificate validity exceeds issuer validity or policy");
  }

  const serialHex = generateRandomSerialNumberHex();

  // Create AKI & SKI
  const issuerSki = caCert.getExtension(x509.SubjectKeyIdentifierExtension)?.keyId;
  const akiExt = issuerSki
    ? new x509.AuthorityKeyIdentifierExtension(issuerSki)
    : await x509.AuthorityKeyIdentifierExtension.create(caCert.publicKey);
  const skiExt = await x509.SubjectKeyIdentifierExtension.create(csr.publicKey);

  // SAN entries are built exclusively from the already-authorized order
  // identifiers. CSR-supplied names are only used for the finalize equality
  // check in routes/order.ts; they are never copied into the certificate.
  const sanNames = identifiers.map((item) => ({ type: item.type, value: item.value }));

  const extensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(false, undefined, true),
    new x509.KeyUsagesExtension(
      x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment,
      true
    ),
    new x509.ExtendedKeyUsageExtension(
      [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth],
      false
    ),
    new x509.SubjectAlternativeNameExtension(sanNames, !subjectDns),
    skiExt,
    akiExt,
    new x509.CRLDistributionPointsExtension([
      `${CONFIG.CRL_BASE_URL.trim().replace(/\/$/, "")}/${encodeURIComponent(selected.ca.crlFile || `${selected.ca.id}.crl`)}`,
    ]),
  ];

  const signingAlg =
    caPrivateKey.algorithm.name === "ECDSA"
      ? { name: "ECDSA", hash: "SHA-256" }
      : caPrivateKey.algorithm.name === "RSASSA-PKCS1-v1_5"
      ? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }
      : { name: "Ed25519" };

  const leafCert = await x509.X509CertificateGenerator.create({
    serialNumber: serialHex,
    subject,
    issuer: caCert.subject,
    notBefore,
    notAfter,
    publicKey: csr.publicKey,
    signingKey: caPrivateKey,
    signingAlgorithm: signingAlg,
    extensions,
  });

  const leafPem = leafCert.toString("pem");
  if (!await leafCert.verify({ publicKey: caCert.publicKey, signatureOnly: true })) {
    throw AcmeError.serverInternal("Issued certificate signature verification failed");
  }
  const chainPem = `${leafPem}\n${caCertPem}`;

  const akiHex = akiExt.keyId || "";
  const certId = computeCertId(akiHex, serialHex);

  return {
    leafPem,
    chainPem,
    serialNumber: serialHex,
    aki: akiHex,
    certId,
    notBefore: Math.floor(notBefore.getTime() / 1000),
    notAfter: Math.floor(notAfter.getTime() / 1000),
    subject,
    san: identifiers,
    caId: selected.ca.id,
    caSerialNumber: caCert.serialNumber,
  };
}
