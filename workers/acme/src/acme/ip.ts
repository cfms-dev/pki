function stripIpv6Brackets(value: string): string {
  return value.startsWith("[") && value.endsWith("]") ? value.slice(1, -1) : value;
}

export function parseIpv4(address: string): number | null {
  const parts = address.split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith("0")) return null;
    const value = Number(part);
    if (!Number.isInteger(value) || value < 0 || value > 255) return null;
    octets.push(value);
  }
  return (
    octets[0] * 0x1000000 +
    octets[1] * 0x10000 +
    octets[2] * 0x100 +
    octets[3]
  ) >>> 0;
}

function isPublicIpv4(value: number): boolean {
  const a = (value >>> 24) & 0xff;
  const b = (value >>> 16) & 0xff;
  const c = (value >>> 8) & 0xff;

  if (a === 0) return false; // "this network"
  if (a === 10) return false; // RFC 1918
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT 100.64/10
  if (a === 127) return false; // loopback
  if (a === 169 && b === 254) return false; // link-local
  if (a === 172 && b >= 16 && b <= 31) return false; // RFC 1918
  if (a === 192 && b === 0 && c === 0) return false; // IETF protocol assignments
  if (a === 192 && b === 0 && c === 2) return false; // TEST-NET-1
  if (a === 192 && b === 88 && c === 99) return false; // 6to4 relay anycast
  if (a === 192 && b === 168) return false; // RFC 1918
  if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
  if (a === 198 && b === 51 && c === 100) return false; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return false; // TEST-NET-3
  if (a >= 224) return false; // multicast and reserved
  return true;
}

export function parseIpv6(address: string): Uint8Array | null {
  let input = stripIpv6Brackets(address);
  if (!input || input.includes("%")) return null;
  if (input.includes(":::")) return null;

  const halves = input.split("::");
  if (halves.length > 2) return null;

  const parseGroups = (part: string): number[] | null => {
    if (part === "") return [];
    const pieces = part.split(":");
    const groups: number[] = [];
    for (let i = 0; i < pieces.length; i++) {
      const piece = pieces[i];
      if (piece.includes(".")) {
        if (i !== pieces.length - 1) return null;
        const v4 = parseIpv4(piece);
        if (v4 === null) return null;
        groups.push((v4 >>> 16) & 0xffff, v4 & 0xffff);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) return null;
        groups.push(parseInt(piece, 16));
      }
    }
    return groups;
  };

  const left = parseGroups(halves[0]);
  const right = halves.length === 2 ? parseGroups(halves[1]) : [];
  if (!left || !right) return null;

  let groups: number[];
  if (halves.length === 2) {
    const missing = 8 - left.length - right.length;
    if (missing < 1) return null;
    groups = [...left, ...new Array<number>(missing).fill(0), ...right];
  } else {
    if (left.length !== 8) return null;
    groups = left;
  }
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < groups.length; i++) {
    bytes[i * 2] = (groups[i] >>> 8) & 0xff;
    bytes[i * 2 + 1] = groups[i] & 0xff;
  }
  return bytes;
}

function isPublicIpv6(bytes: Uint8Array): boolean {
  const allZero = bytes.every((byte) => byte === 0);
  if (allZero) return false; // ::

  const firstFifteenZero = bytes.slice(0, 15).every((byte) => byte === 0);
  if (firstFifteenZero && bytes[15] === 1) return false; // ::1

  // IPv4-mapped (::ffff:a.b.c.d) addresses are only as safe as the embedded
  // IPv4 address. Deprecated IPv4-compatible (::a.b.c.d) addresses are
  // rejected outright because they are not valid globally routable IPv6
  // destinations.
  const firstTenZero = bytes.slice(0, 10).every((byte) => byte === 0);
  if (firstTenZero && bytes[10] === 0xff && bytes[11] === 0xff) {
    const v4 = ((bytes[12] << 24) | (bytes[13] << 16) | (bytes[14] << 8) | bytes[15]) >>> 0;
    return isPublicIpv4(v4);
  }
  const firstTwelveZero = bytes.slice(0, 12).every((byte) => byte === 0);
  if (firstTwelveZero) {
    return false;
  }

  // Only global unicast (2000::/3) is eligible.
  if ((bytes[0] & 0xe0) !== 0x20) return false;

  // 2001:db8::/32 documentation
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0x0d && bytes[3] === 0xb8) {
    return false;
  }
  // 2001::/32 Teredo and 2001:2::/48 benchmarking
  if (
    bytes[0] === 0x20 &&
    bytes[1] === 0x01 &&
    bytes[2] === 0x00 &&
    (bytes[3] === 0x00 || bytes[3] === 0x02)
  ) {
    return false;
  }
  // 2001:10::/28 and 2001:20::/28 ORCHID
  if (
    bytes[0] === 0x20 &&
    bytes[1] === 0x01 &&
    bytes[2] === 0x00 &&
    bytes[3] >= 0x10 &&
    bytes[3] <= 0x2f
  ) {
    return false;
  }
  // 2002::/16 6to4 can embed private IPv4 addresses.
  if (bytes[0] === 0x20 && bytes[1] === 0x02) return false;
  // 3fff::/20 documentation
  if (bytes[0] === 0x3f && (bytes[1] & 0xf0) === 0xf0) return false;

  return true;
}

/** True only for globally routable unicast IPv4/IPv6 addresses. */
export function isPublicIpAddress(address: string): boolean {
  const v4 = parseIpv4(address);
  if (v4 !== null) return isPublicIpv4(v4);
  const v6 = parseIpv6(address);
  if (v6 !== null) return isPublicIpv6(v6);
  return false;
}

