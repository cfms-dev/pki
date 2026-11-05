import { base64UrlEncode } from "../crypto/nonce";

/**
 * Converts a hex string into a Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.replace(/[^0-9a-fA-F]/g, "");
  const bytes = new Uint8Array(Math.ceil(cleanHex.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Converts bytes into a hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Encodes a serial number into DER INTEGER contents octets (excluding tag 0x02 and length).
 * Per RFC 5280, serial numbers are positive integers. In ASN.1 DER, if the most
 * significant bit of the first byte is set, a 0x00 prefix byte is prepended.
 */
export function serialToDerContents(serialHex: string): Uint8Array {
  const rawBytes = hexToBytes(serialHex);
  // Strip any accidental leading zero bytes unless necessary
  let startIdx = 0;
  while (startIdx < rawBytes.length - 1 && rawBytes[startIdx] === 0) {
    startIdx++;
  }
  const significant = rawBytes.slice(startIdx);

  // If MSB is 1, prepend 0x00 so it represents a positive integer in DER
  if (significant.length > 0 && (significant[0] & 0x80) !== 0) {
    const result = new Uint8Array(significant.length + 1);
    result[0] = 0x00;
    result.set(significant, 1);
    return result;
  }
  return significant;
}

/**
 * Derives RFC 9773 certID from AKI (Authority Key Identifier) and Certificate Serial Number:
 * certID = Base64URL(AKI) + "." + Base64URL(DER Serial contents)
 */
export function computeCertId(akiHex: string, serialHex: string): string {
  const akiBytes = hexToBytes(akiHex);
  const derSerial = serialToDerContents(serialHex);

  const encodedAki = base64UrlEncode(akiBytes);
  const encodedSerial = base64UrlEncode(derSerial);

  return `${encodedAki}.${encodedSerial}`;
}
