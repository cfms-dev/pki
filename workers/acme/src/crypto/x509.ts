import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { AcmeEnv, CONFIG } from "../config";
import { AcmeError } from "../errors";
import { isValidDnsIdentifier } from "../acme/identifiers";
import { base64UrlDecode } from "./nonce";
import { calculateJwkThumbprint } from "./jws";
import { bytesToHex, computeCertId } from "../ari/cert-id";
import {
  importCaPrivateKey,
  SelectedIntermediateCa,
  selectIntermediateCa,
} from "./ca";

export { importCaPrivateKey };

export interface ParsedCsr {
  csr: x509.Pkcs10CertificateRequest;
  domains: string[];
  publicKey: CryptoKey;
  /** Canonical SubjectPublicKeyInfo DER encoding of the CSR public key. */
  publicKeySpki: Uint8Array;
  /** RFC 7638 SHA-256 JWK thumbprint of the CSR public key. */
  publicKeyThumbprint: string;
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
  san: string[];
  caId: string;
  caSerialNumber: string;
}

export interface PublicKeyIdentity {
  publicKey: CryptoKey;
  /** Canonical SubjectPublicKeyInfo DER encoding of the public key. */
  publicKeySpki: Uint8Array;
  /** RFC 7638 SHA-256 JWK thumbprint of the public key. */
  publicKeyThumbprint: string;
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
    const spki = (await crypto.subtle.exportKey("spki", cryptoKey)) as ArrayBuffer;
    const jwk = (await crypto.subtle.exportKey("jwk", cryptoKey)) as JsonWebKey;
    return {
      publicKey: cryptoKey,
      publicKeySpki: new Uint8Array(spki),
      publicKeyThumbprint: await calculateJwkThumbprint(jwk),
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

  // Extract identifiers from the subjectAltName extension. RFC 8555 § 7.4
  // requires the CSR to request exactly the order's identifiers, and this
  // server only supports "dns", so any other SAN type (notably "ip") is an
  // unauthorized identifier and must be rejected rather than ignored.
  const domains: string[] = [];
  for (const ext of csr.extensions) {
    if (ext.type !== "2.5.29.17") continue;

    const sanExt = new x509.SubjectAlternativeNameExtension(ext.rawData);
    for (const item of sanExt.names.items) {
      if (item.type !== "dns") {
        throw AcmeError.badCSR(
          `CSR subjectAltName contains an unsupported identifier type '${item.type}'; only DNS identifiers are supported`
        );
      }
      const value = item.value?.trim().toLowerCase();
      if (!value) {
        throw AcmeError.badCSR("CSR subjectAltName contains an empty DNS identifier");
      }
      domains.push(value);
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
      domains.push(value);
    }
  }

  const uniqueDomains = Array.from(new Set(domains));
  if (uniqueDomains.length === 0) {
    throw AcmeError.badCSR("CSR contains no DNS Subject Alternative Names or Common Name");
  }

  return {
    csr,
    domains: uniqueDomains,
    ...(await derivePublicKeyIdentity(csr.publicKey)),
  };
}

/**
 * Loads the CA private key from the environment
 */
export async function loadCaPrivateKey(env: AcmeEnv, pkVarName?: string): Promise<CryptoKey> {
  const varName = pkVarName || env.PK_ENV_VAR || CONFIG.DEFAULT_PK_ENV_VAR;
  const pkPem = env[varName] as string | undefined;

  if (!pkPem || typeof pkPem !== "string" || pkPem.trim() === "") {
    throw AcmeError.serverInternal(
      `CA private key missing: environment variable ${varName} is not set or empty`
    );
  }

  return importCaPrivateKey(pkPem);
}

/**
 * Generates a random 160-bit serial number as a hex string
 */
export function generateRandomSerialNumberHex(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  // Ensure the highest bit is not 0 to maintain length
  bytes[0] = bytes[0] | 0x01;
  return bytesToHex(bytes);
}

/**
 * Issues a 90-day leaf certificate signed by the intermediate CA
 */
export async function issueCertificateFromCsr(
  csr: x509.Pkcs10CertificateRequest,
  authorizedDomains: string[],
  env: AcmeEnv,
  validityDays = CONFIG.DEFAULT_CERT_VALIDITY_DAYS,
  explicitCa?: SelectedIntermediateCa
): Promise<IssuedCertificate> {
  const selected = explicitCa || (await selectIntermediateCa(env));
  const caCertPem = selected.certPem;
  const caCert = selected.cert;
  const caPrivateKey = selected.privateKey;

  const now = new Date();
  const notBefore = now;
  const notAfter = new Date(now.getTime() + validityDays * 86400 * 1000);

  const serialHex = generateRandomSerialNumberHex();

  // Create AKI & SKI
  const akiExt = await x509.AuthorityKeyIdentifierExtension.create(caCert.publicKey);
  const skiExt = await x509.SubjectKeyIdentifierExtension.create(csr.publicKey);

  // SAN entries are built exclusively from the already-authorized order
  // identifiers. CSR-supplied names are only used for the finalize equality
  // check in routes/order.ts; they are never copied into the certificate.
  const sanNames = authorizedDomains.map((d) => ({ type: "dns" as const, value: d }));

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
    new x509.SubjectAlternativeNameExtension(sanNames),
    skiExt,
    akiExt,
  ];

  const signingAlg =
    caPrivateKey.algorithm.name === "ECDSA"
      ? { name: "ECDSA", hash: "SHA-256" }
      : caPrivateKey.algorithm.name === "RSASSA-PKCS1-v1_5"
      ? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }
      : { name: "Ed25519" };

  const leafCert = await x509.X509CertificateGenerator.create({
    serialNumber: serialHex,
    subject: `CN=${authorizedDomains[0]}`,
    issuer: caCert.subject,
    notBefore,
    notAfter,
    publicKey: csr.publicKey,
    signingKey: caPrivateKey,
    signingAlgorithm: signingAlg,
    extensions,
  });

  const leafPem = leafCert.toString("pem");
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
    subject: `CN=${authorizedDomains[0]}`,
    san: authorizedDomains,
    caId: selected.ca.id,
    caSerialNumber: caCert.serialNumber,
  };
}
