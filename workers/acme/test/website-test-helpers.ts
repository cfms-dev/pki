/** Protocol tests never use assets; website tests explicitly stub this boundary. */
export const testAssets = {
  async fetch(_input: RequestInfo | URL): Promise<Response> {
    throw new Error("Unexpected asset fetch: use a stub or the real runtime Assets binding");
  },
} as Fetcher;

/** Protocol tests explicitly opt into successful admission; ingress tests exercise rejection. */
export const testRateLimits = {
  API_RATE_LIMITER: { async limit(_options: { key: string }) { return { success: true }; } } as RateLimit,
  ACCOUNT_REGISTRATION_LIMITER: { async limit(_options: { key: string }) { return { success: true }; } } as RateLimit,
};
