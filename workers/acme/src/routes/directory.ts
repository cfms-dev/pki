import {
  AcmeEnv,
  getCaaIdentities,
  getExternalAccountRequired,
  getTermsOfServiceUrl,
  getWebsiteUrl,
} from "../config";

export function handleDirectory(request: Request, env: AcmeEnv, baseUrl: string): Response {
  const meta: Record<string, unknown> = {};

  const termsOfService = getTermsOfServiceUrl();
  if (termsOfService) {
    meta.termsOfService = termsOfService;
  }

  const website = getWebsiteUrl();
  if (website) {
    meta.website = website;
  }

  const caaIdentities = getCaaIdentities();
  if (caaIdentities && caaIdentities.length > 0) {
    meta.caaIdentities = caaIdentities;
  }

  const externalAccountRequired = getExternalAccountRequired();
  if (externalAccountRequired) {
    meta.externalAccountRequired = true;
  }

  const directory: Record<string, unknown> = {
    newNonce: `${baseUrl}/new-nonce`,
    newAccount: `${baseUrl}/new-account`,
    newOrder: `${baseUrl}/new-order`,
    revokeCert: `${baseUrl}/revoke-cert`,
    keyChange: `${baseUrl}/key-change`,
    renewalInfo: `${baseUrl}/renewal-info`, // RFC 9773 ACME Renewal Information
  };

  if (Object.keys(meta).length > 0) {
    directory.meta = meta;
  }

  return new Response(JSON.stringify(directory, null, 2), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "max-age=86400",
    },
  });
}
