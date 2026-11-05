import { verifyAcmeJws } from "../crypto/jws";
import { Database } from "../db/queries";
import { AcmeError } from "../errors";

export async function handleGetCertificate(
  request: Request,
  database: Database,
  certId: string
): Promise<Response> {
  // ACME allows GET or POST-as-GET for certificates (RFC 8555 § 7.4.2)
  if (request.method === "POST") {
    await verifyAcmeJws(request, database);
  }

  const cert = await database.getCertificateById(certId);
  if (!cert) {
    throw AcmeError.notFound("Certificate not found");
  }

  return new Response(cert.pem, {
    status: 200,
    headers: {
      "Content-Type": "application/pem-certificate-chain",
      "Cache-Control": "public, max-age=86400",
    },
  });
}
