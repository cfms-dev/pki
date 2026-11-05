import * as x509 from "@peculiar/x509";
import { AcmeEnv, CONFIG } from "../config";
import { AcmeError } from "../errors";
import { base64UrlDecode } from "./nonce";
import { bytesToHex, computeCertId } from "../ari/cert-id";
import {
  importCaPrivateKey,
  pemToDer,
  SelectedIntermediateCa,
  selectIntermediateCa,
} from "./ca";

export { pemToDer, importCaPrivateKey };

export interface ParsedCsr {
  csr: x509.Pkcs10CertificateRequest;
  domains: string[];
  publicKey: CryptoKey;
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
    csr = new x509.Pkcs10CertificateRequest(derBytes.buffer);
  } catch (err: unknown) {
    throw AcmeError.badCSR(`Failed to parse PKCS#10 CSR: ${err instanceof Error ? err.message : String(err)}`);
  }

  const isValid = await csr.verify();
  if (!isValid) {
    throw AcmeError.badCSR("CSR signature verification failed");
  }

  // Extract domains from SAN extension or CommonName
  const domains: string[] = [];
  for (const ext of csr.extensions) {
    if (ext.type === "2.5.29.17") {
      const sanExt = new x509.SubjectAlternativeNameExtension(ext.rawData);
      if (sanExt.names && Array.isArray(sanExt.names.items)) {
        for (const item of sanExt.names.items) {
          if (item.type === "dns" && item.value) {
            domains.push(item.value.toLowerCase());
          }
        }
      }
    }
  }

  if (domains.length === 0) {
    // Check CN in subject
    const cnMatch = csr.subject.match(/CN=([^,]+)/i);
    if (cnMatch && cnMatch[1]) {
      domains.push(cnMatch[1].trim().toLowerCase());
    }
  }

  if (domains.length === 0) {
    throw AcmeError.badCSR("CSR contains no DNS Subject Alternative Names or Common Name");
  }

  return {
    csr,
    domains,
    publicKey: csr.publicKey,
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
  const caCert = new x509.X509Certificate(caCertPem);
  const caPrivateKey = selected.privateKey;

  const now = new Date();
  const notBefore = now;
  const notAfter = new Date(now.getTime() + validityDays * 86400 * 1000);

  const serialHex = generateRandomSerialNumberHex();

  // Create AKI & SKI
  const akiExt = await x509.AuthorityKeyIdentifierExtension.create(caCert.publicKey);
  const skiExt = await x509.SubjectKeyIdentifierExtension.create(csr.publicKey);

  // SAN entries
  const sanNames = authorizedDomains.map((d) => ({ type: "dns" as const, value: d }));

  const extensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(false, true),
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
  };
}
