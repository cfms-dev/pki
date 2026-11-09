import { CONFIG } from "../config";
import { CertificateRow } from "../db/types";

export interface AriSuggestedWindow {
  start: string; // ISO 8601 UTC
  end: string;   // ISO 8601 UTC
}

export interface AriResponse {
  suggestedWindow: AriSuggestedWindow;
  explanationURL?: string;
}

/**
 * Computes suggested renewal window per RFC 9773
 */
export function computeSuggestedWindow(
  cert: CertificateRow,
  renewalWindowDays = CONFIG.DEFAULT_RENEWAL_WINDOW_DAYS,
  now = Math.floor(Date.now() / 1000)
): AriSuggestedWindow {
  // If certificate is revoked or marked for immediate replacement,
  // set window to the past to trigger immediate client renewal
  if (cert.revoked_at !== null || cert.replaced_by_cert_id !== null) {
    const pastStart = new Date((now - 3600) * 1000).toISOString();
    const pastEnd = new Date(now * 1000).toISOString();
    return {
      start: pastStart,
      end: pastEnd,
    };
  }

  // Standard window: duration of 30 days ending at not_after
  // (e.g. For 90-day validity: from day 60 to day 90)
  const windowSeconds = renewalWindowDays * 86400;
  const startSec = Math.max(cert.not_before, cert.not_after - windowSeconds);
  const endSec = cert.not_after;

  return {
    start: new Date(startSec * 1000).toISOString(),
    end: new Date(endSec * 1000).toISOString(),
  };
}

/**
 * Validates whether an incoming renewal order qualifies for ARI Rate Limit Exemption
 */
export function checkAriRenewalEligibility(
  predecessorCert: CertificateRow,
  requestedDomains: string[],
  now = Math.floor(Date.now() / 1000),
  renewalWindowDays = CONFIG.DEFAULT_RENEWAL_WINDOW_DAYS
): { eligible: boolean; reason?: string } {
  // 1. Check if predecessor has already been replaced
  if (predecessorCert.replaced_by_cert_id) {
    return {
      eligible: false,
      reason: `Predecessor certificate ${predecessorCert.cert_id} has already been replaced by ${predecessorCert.replaced_by_cert_id}`,
    };
  }

  // 2. Check identifier overlap (requested domains must be subset or equal to predecessor cert SANs)
  let existingSans: string[] = [];
  try {
    existingSans = JSON.parse(predecessorCert.san) as string[];
  } catch {
    return { eligible: false, reason: "Malformed predecessor SAN metadata" };
  }

  const existingSet = new Set(existingSans.map((d) => d.toLowerCase()));
  for (const domain of requestedDomains) {
    if (!existingSet.has(domain.toLowerCase())) {
      return {
        eligible: false,
        reason: `Requested identifier '${domain}' was not part of predecessor certificate`,
      };
    }
  }

  // 3. Check renewal window timing:
  // If predecessor is revoked, immediate renewal is eligible.
  if (predecessorCert.revoked_at !== null) {
    return { eligible: true };
  }

  // Otherwise, current time must be on or after suggestedWindow.start
  const window = computeSuggestedWindow(predecessorCert, renewalWindowDays, now);
  const windowStartSec = Math.floor(new Date(window.start).getTime() / 1000);

  if (now < windowStartSec) {
    return {
      eligible: false,
      reason: `Current time is before the suggested renewal window (${window.start} to ${window.end})`,
    };
  }

  return { eligible: true };
}
