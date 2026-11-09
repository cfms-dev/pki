import { AcmeError } from "../errors";

export interface DnsAnswer { type: number; data: string; name?: string }
export interface DnsResponse { Status: number; Answer: DnsAnswer[] }
export interface DnsBudget { deadline: number }
export const dnsBudget = (): DnsBudget => ({ deadline: Date.now() + 20000 });

export function normalizeDnsTarget(value: string): string {
  const name = value.toLowerCase().replace(/\.$/, "");
  if (name.length > 253 || !name.split(".").every((part) => /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(part))) {
    throw new AcmeError("dns", "Invalid DNS alias target");
  }
  return name;
}

/** Only transport/JSON failures may be retried at another resolver. */
export async function queryDns(
  hostname: string, type: string, fetchImpl: typeof fetch, budget = dnsBudget()
): Promise<DnsResponse> {
  hostname = normalizeDnsTarget(hostname);
  for (const endpoint of ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]) {
    const remaining = budget.deadline - Date.now();
    if (remaining <= 0) break;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const data: unknown = await Promise.race([
        (async () => {
          const response = await fetchImpl(`${endpoint}?name=${encodeURIComponent(hostname)}&type=${type}`, {
            headers: { Accept: "application/dns-json" }, signal: controller.signal,
          });
          if (!response.ok || !response.body) throw new Error("DNS transport failure");
          const reader = response.body.getReader();
          const chunks: Uint8Array[] = [];
          let length = 0;
          try {
            while (true) {
              const { value, done } = await reader.read();
              if (done) break;
              length += value.length;
              if (length > 65536) { await reader.cancel(); throw new AcmeError("dns", "DNS response exceeds 64 KiB"); }
              chunks.push(value);
            }
          } finally { reader.releaseLock(); }
          const bytes = new Uint8Array(length);
          let offset = 0;
          for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
          return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
        })(),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => { controller.abort(); reject(new Error("DNS timeout")); }, Math.min(10000, remaining));
        }),
      ]);
      if (!data || typeof data !== "object" || !Number.isInteger((data as DnsResponse).Status)) {
        throw new AcmeError("dns", "Malformed DNS status");
      }
      const result = data as Partial<DnsResponse>;
      if (result.Status !== 0) throw new AcmeError("dns", `DNS query failed with status ${result.Status}`);
      if (result.Answer !== undefined && (!Array.isArray(result.Answer) || result.Answer.some(
        (answer) => !answer || !Number.isInteger(answer.type) || typeof answer.data !== "string" ||
          (answer.name !== undefined && typeof answer.name !== "string")
      ))) throw new AcmeError("dns", "Malformed DNS answer");
      return { Status: 0, Answer: result.Answer ?? [] };
    } catch (error) {
      if (error instanceof AcmeError) throw error;
    } finally { if (timer !== undefined) clearTimeout(timer); controller.abort(); }
  }
  throw new AcmeError("dns", "DNS lookup could not be completed");
}
