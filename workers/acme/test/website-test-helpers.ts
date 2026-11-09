/** Protocol tests never use assets; website tests explicitly stub this boundary. */
export const testAssets = {
  async fetch(_input: RequestInfo | URL): Promise<Response> {
    throw new Error("Unexpected asset fetch: use a stub or the real runtime Assets binding");
  },
} as Fetcher;
