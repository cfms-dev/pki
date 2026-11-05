import { AcmeEnv, CAA_ISSUER_DOMAIN_NAME, CONFIG } from "../config";

export function handleDirectory(request: Request, env: AcmeEnv, baseUrl: string): Response {
  const website = (env.WEBSITE_URL as string) || CONFIG.WEBSITE_URL;
  const termsOfService =
    (env.TERMS_OF_SERVICE_URL as string) ||
    CONFIG.TERMS_OF_SERVICE_URL ||
    `${baseUrl}/terms`;

  const directory = {
    newNonce: `${baseUrl}/new-nonce`,
    newAccount: `${baseUrl}/new-account`,
    newOrder: `${baseUrl}/new-order`,
    revokeCert: `${baseUrl}/revoke-cert`,
    keyChange: `${baseUrl}/key-change`,
    renewalInfo: `${baseUrl}/renewal-info`, // RFC 9773 ACME Renewal Information
    meta: {
      termsOfService,
      website,
      caaIdentities: [CAA_ISSUER_DOMAIN_NAME],
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
