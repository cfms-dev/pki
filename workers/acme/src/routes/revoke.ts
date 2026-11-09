import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { normalizePublicKey, verifyAcmeJws } from "../crypto/jws";
import { derivePublicKeyIdentity } from "../crypto/x509";
import { computeCertId } from "../ari/cert-id";
import { base64UrlDecode } from "../crypto/nonce";
import { Database } from "../db/queries";
import { AcmeError } from "../errors";

const REASONS: Record<number, string> = {
  0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged",
  4: "superseded", 5: "cessationOfOperation", 6: "certificateHold",
  9: "privilegeWithdrawn", 10: "aACompromise",
};

export async function handleRevokeCert(request: Request, database: Database): Promise<Response> {
  const verified = await verifyAcmeJws<{ certificate: string; reason?: number }>(request, database, "/revoke-cert");
  if (typeof verified.payload.certificate !== "string" || !/^[A-Za-z0-9_-]+$/.test(verified.payload.certificate)) {
    throw AcmeError.malformed("Revoke payload must contain a base64url DER certificate");
  }
  const reason = verified.payload.reason === undefined ? 0 : verified.payload.reason;
  if (!Number.isInteger(reason) || !Object.hasOwn(REASONS, reason)) {
    throw new AcmeError("badRevocationReason", "Unsupported revocation reason");
  }
  let cert: x509.X509Certificate;
  try { cert = new x509.X509Certificate(base64UrlDecode(verified.payload.certificate)); }
  catch { throw AcmeError.malformed("Invalid certificate in revoke payload"); }
  const aki = cert.getExtension(x509.AuthorityKeyIdentifierExtension)?.keyId;
  if (!aki) throw AcmeError.notFound("Certificate not found");
  const row = await database.getCertificateByCertId(computeCertId(aki, cert.serialNumber));
  if (!row) throw AcmeError.notFound("Certificate not found");
  const stored = new x509.X509Certificate(row.pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)?.[0] ?? "");
  const actualBytes = new Uint8Array(cert.rawData);
  const storedBytes = new Uint8Array(stored.rawData);
  if (actualBytes.length !== storedBytes.length || actualBytes.some((byte, i) => byte !== storedBytes[i])) {
    throw AcmeError.notFound("Certificate not found");
  }
  let authorized = false;
  if (verified.account) {
    authorized = row.account_id === verified.account.id;
    if (!authorized) {
      const domains = JSON.parse(row.san) as string[];
      authorized = domains.length > 0 && await database.accountHasValidAuthorizations(
        verified.account.id, domains, Math.floor(Date.now() / 1000)
      );
    }
  } else {
    const signer = await normalizePublicKey(verified.jwk, verified.header.alg);
    authorized = signer.fingerprint === (await derivePublicKeyIdentity(stored.publicKey)).publicKeyFingerprint;
  }
  if (!authorized) throw AcmeError.unauthorized("The signing key is not authorized to revoke this certificate");
  if (!await database.revokeCertificate(row.cert_id, Math.floor(Date.now() / 1000), REASONS[reason])) {
    throw AcmeError.alreadyRevoked();
  }
  return new Response(null, { status: 200 });
}
