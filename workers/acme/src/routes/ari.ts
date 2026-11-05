import { AcmeEnv, CONFIG } from "../config";
import { Database } from "../db/queries";
import { AcmeError } from "../errors";
import { computeSuggestedWindow } from "../ari/window";

export async function handleRenewalInfo(
  request: Request,
  database: Database,
  certId: string,
  env?: AcmeEnv
): Promise<Response> {
  if (request.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const cert = await database.getCertificateByCertId(certId);
  if (!cert) {
    throw AcmeError.notFound(`Certificate with certID '${certId}' not found`);
  }

  const suggestedWindow = computeSuggestedWindow(
    cert,
    CONFIG.DEFAULT_RENEWAL_WINDOW_DAYS
  );

  const explanationURL =
    (env?.ARI_EXPLANATION_URL as string) || CONFIG.ARI_EXPLANATION_URL;

  const body: { suggestedWindow: typeof suggestedWindow; explanationURL?: string } = {
    suggestedWindow,
  };

  if (explanationURL) {
    body.explanationURL = explanationURL;
  }

  return new Response(JSON.stringify(body, null, 2), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Retry-After": CONFIG.ARI_RETRY_AFTER_SECONDS.toString(),
      "Cache-Control": "max-age=3600",
    },
  });
}
