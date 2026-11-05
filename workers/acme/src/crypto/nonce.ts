import { CONFIG } from "../config";
import { Database } from "../db/queries";

export function generateNonceString(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export function base64UrlEncode(buffer: Uint8Array | ArrayBuffer): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function base64UrlDecode(str: string): Uint8Array {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function createAndSaveNonce(database: Database): Promise<string> {
  const nonce = generateNonceString();
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + CONFIG.NONCE_EXPIRATION_SECONDS;
  await database.saveNonce(nonce, expiresAt);
  return nonce;
}

export async function verifyAndConsumeNonce(
  database: Database,
  nonce: string
): Promise<boolean> {
  if (!nonce || typeof nonce !== "string") return false;
  const now = Math.floor(Date.now() / 1000);
  return await database.consumeNonce(nonce, now);
}
