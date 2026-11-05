import { AcmeEnv } from "../config";

export function handleDirectory(request: Request, env: AcmeEnv, baseUrl: string): Response {
  const directory = {
    newNonce: `${baseUrl}/new-nonce`,
    newAccount: `${baseUrl}/new-account`,
    newOrder: `${baseUrl}/new-order`,
    revokeCert: `${baseUrl}/revoke-cert`,
    keyChange: `${baseUrl}/key-change`,
    renewalInfo: `${baseUrl}/renewal-info`, // RFC 9773 ACME Renewal Information
    meta: {
      termsOfService: `${baseUrl}/terms`,
      website: "https://cfms-pki.example.com",
      caaIdentities: ["cfms-pki.example.com"],
      externalAccountRequired: false,
    },
  };

  return new Response(JSON.stringify(directory, null, 2), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "max-age=86400",
    },
  });
}
