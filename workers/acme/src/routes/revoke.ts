import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { verifyAcmeJws } from "../crypto/jws";
import { base64UrlDecode } from "../crypto/nonce";
import { Database } from "../db/queries";
import { AcmeError } from "../errors";

interface RevokePayload {
  certificate: string;
  reason?: number;
}

const REASON_NAMES: Record<number, string> = {
  0: "unspecified",
  1: "keyCompromise",
  2: "cAMultiple",
  3: "affiliationChanged",
  4: "superseded",
  5: "cessationOfOperation",
  6: "certificateHold",
  8: "removeFromCRL",
  9: "privilegeWithdrawn",
  10: "aACompromise",
};

export async function handleRevokeCert(
  request: Request,
  database: Database
): Promise<Response> {
  const verified = await verifyAcmeJws<RevokePayload>(request, database, "/revoke-cert");
  if (!verified.payload.certificate) {
    throw AcmeError.malformed("Revoke payload must contain 'certificate'");
  }

  let derBytes: Uint8Array;
  try {
    derBytes = base64UrlDecode(verified.payload.certificate);
  } catch {
    throw AcmeError.malformed("Failed to base64url decode certificate");
  }

  let cert: x509.X509Certificate;
  try {
    cert = new x509.X509Certificate(derBytes);
  } catch {
    throw AcmeError.malformed("Invalid certificate in revoke payload");
  }

  const certRow = await database.getCertificateBySerial(cert.serialNumber);
  if (!certRow) {
    throw AcmeError.notFound("Certificate not found");
  }

  if (certRow.revoked_at !== null) {
    throw AcmeError.alreadyRevoked();
  }

  const reasonCode = verified.payload.reason ?? 0;
  const reasonText = REASON_NAMES[reasonCode] || "unspecified";
  const now = Math.floor(Date.now() / 1000);

  await database.revokeCertificate(certRow.cert_id, now, reasonText);

  return new Response(null, {
    status: 200,
  });
}
