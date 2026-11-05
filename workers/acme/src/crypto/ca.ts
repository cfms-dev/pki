import fs from "node:fs";
import path from "node:path";
import * as x509 from "@peculiar/x509";
import { AcmeEnv, CONFIG } from "../config";
import { AcmeError } from "../errors";

export interface IntermediateCaEntry {
  id: string;
  certFile: string;
  pkEnv: string;
  weight: number;
}

export interface SelectedIntermediateCa {
  ca: IntermediateCaEntry;
  certPem: string;
  privateKey: CryptoKey;
}

/**
 * Converts a PEM string (PKCS#8 / Certificate) to raw DER bytes
 */
export function pemToDer(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----[^-]+-----/g, "")
    .replace(/\s+/g, "");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Imports a CA private key from PEM string (supports ECDSA P-256, RSA, Ed25519)
 */
export async function importCaPrivateKey(pkPem: string): Promise<CryptoKey> {
  const der = pemToDer(pkPem);

  // Try importing as ECDSA P-256 first
  try {
    return await crypto.subtle.importKey(
      "pkcs8",
      der.buffer,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
  } catch {
    // Try RSA
    try {
      return await crypto.subtle.importKey(
        "pkcs8",
        der.buffer,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["sign"]
      );
    } catch {
      // Try Ed25519
      try {
        return await crypto.subtle.importKey(
          "pkcs8",
          der.buffer,
          { name: "Ed25519" },
          false,
          ["sign"]
        );
      } catch (err: unknown) {
        throw AcmeError.serverInternal(
          `Failed to import CA private key: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }
  }
}

/**
 * Attempts to read a CA certificate from the designated directory.
 * Searches candidate locations in order:
 * 1. env.CA_CERT_PEM override (for isolated unit tests)
 * 2. Designated directory path
 * 3. Cloudflare Workers Virtual File System (/bundle/<caDir>/...)
 * 4. Fallback paths (process.cwd, parent directories)
 */
export function readCaCertPem(
  ca: IntermediateCaEntry,
  caDir = CONFIG.CA_DIR,
  env?: AcmeEnv
): string {
  // Allow explicit test override
  if (env?.CA_CERT_PEM && typeof env.CA_CERT_PEM === "string" && env.CA_CERT_PEM.trim()) {
    // If CA_ID matches or only generic intermediate, return test PEM
    if (!env.CA_ID || env.CA_ID === ca.id) {
      return env.CA_CERT_PEM.trim();
    }
  }

  const candidatePaths: string[] = [
    // Direct path in designated directory
    path.resolve(caDir, ca.certFile),
    path.join(caDir, ca.certFile),
    // Cloudflare Workers VFS bundle paths
    `/bundle/${caDir}/${ca.certFile}`,
    `/bundle/${ca.certFile}`,
    // Relative to process working directory
    path.resolve(process.cwd(), caDir, ca.certFile),
    path.resolve(process.cwd(), "cas", ca.certFile),
    path.resolve(process.cwd(), "certs", ca.certFile),
    path.resolve(process.cwd(), "../../certs", ca.certFile),
    // Relative to file directory
    path.resolve(__dirname, "../../cas", ca.certFile),
    path.resolve(__dirname, "../../../certs", ca.certFile),
  ];

  for (const candidate of candidatePaths) {
    try {
      if (fs.existsSync(candidate)) {
        const content = fs.readFileSync(candidate, "utf-8").trim();
        if (content.includes("-----BEGIN CERTIFICATE-----")) {
          return content;
        }
      }
    } catch {
      // Continue checking next candidate
    }
  }

  throw AcmeError.serverInternal(
    `Failed to read Intermediate CA certificate for '${ca.id}' (${ca.certFile}) in designated directory '${caDir}'. Checked paths: ${candidatePaths.slice(0, 4).join(", ")}`
  );
}

/**
 * Loads the registry of intermediate CAs from the designated directory manifest or fallback scanning.
 */
export function loadCaRegistry(caDir = CONFIG.CA_DIR, env?: AcmeEnv): IntermediateCaEntry[] {
  const manifestCandidates: string[] = [
    path.resolve(caDir, "manifest.json"),
    path.join(caDir, "manifest.json"),
    `/bundle/${caDir}/manifest.json`,
    `/bundle/manifest.json`,
    path.resolve(process.cwd(), caDir, "manifest.json"),
    path.resolve(__dirname, "../../cas/manifest.json"),
    path.resolve(process.cwd(), "registry/ca.json"),
    path.resolve(__dirname, "../../../registry/ca.json"),
  ];

  for (const candidate of manifestCandidates) {
    try {
      if (fs.existsSync(candidate)) {
        const parsed = JSON.parse(fs.readFileSync(candidate, "utf-8"));
        const cas = parsed.cas || {};
        const entries: IntermediateCaEntry[] = [];

        for (const [key, value] of Object.entries(cas)) {
          const val = value as Record<string, unknown>;
          const certFile =
            (val.certFile as string) ||
            (val.location ? path.basename(val.location as string) : `${key}.pem`);
          const pkEnv =
            (val.pkEnv as string) ||
            (val.pk_env as string) ||
            `PK_${key.toUpperCase().replace(/-/g, "_")}`;

          entries.push({
            id: key,
            certFile,
            pkEnv,
            weight: 1,
          });
        }

        if (entries.length > 0) {
          return entries;
        }
      }
    } catch {
      // Continue checking next candidate
    }
  }

  // Fallback: Attempt directory listing in caDir
  try {
    const candidateDirs = [
      caDir,
      path.resolve(process.cwd(), caDir),
      `/bundle/${caDir}`,
      path.resolve(__dirname, "../../cas"),
    ];

    for (const dir of candidateDirs) {
      if (fs.existsSync(dir)) {
        const files = fs.readdirSync(dir);
        const pemFiles = files.filter((f) => f.endsWith(".pem"));
        if (pemFiles.length > 0) {
          return pemFiles.map((f) => {
            const id = path.basename(f, ".pem");
            return {
              id,
              certFile: f,
              pkEnv: `PK_${id.toUpperCase().replace(/-/g, "_")}`,
              weight: 1,
            };
          });
        }
      }
    }
  } catch {
    // Ignore and fallback
  }

  // Default fallback if nothing found on disk
  return [
    {
      id: CONFIG.DEFAULT_CA_ID,
      certFile: `${CONFIG.DEFAULT_CA_ID}.pem`,
      pkEnv: CONFIG.DEFAULT_PK_ENV_VAR,
      weight: 1,
    },
  ];
}

/**
 * Validates intermediate CA certificate validity, basic constraints, and key usage.
 * Rejects expired, not-yet-valid, non-CA, or non-certificate-signing CAs.
 */
export function validateIntermediateCaCertificate(
  ca: IntermediateCaEntry,
  certPem: string,
  now = new Date(),
  revokedSerials?: Set<string>
): { eligible: boolean; reason?: string } {
  try {
    const cert = new x509.X509Certificate(certPem);

    // 1. Check validity period (not expired, already active)
    if (cert.notBefore > now) {
      return {
        eligible: false,
        reason: `CA '${ca.id}' certificate is not yet valid (notBefore: ${cert.notBefore.toISOString()})`,
      };
    }
    if (cert.notAfter <= now) {
      return {
        eligible: false,
        reason: `CA '${ca.id}' certificate has expired (notAfter: ${cert.notAfter.toISOString()})`,
      };
    }

    // 2. Check Basic Constraints: must have CA=true
    let isCa = false;
    for (const ext of cert.extensions) {
      if (ext instanceof x509.BasicConstraintsExtension) {
        isCa = ext.ca;
        break;
      }
      if (ext.type === "2.5.29.19") {
        try {
          const bc = new x509.BasicConstraintsExtension(ext.rawData);
          isCa = bc.ca;
          break;
        } catch {
          // continue
        }
      }
    }
    if (!isCa) {
      return {
        eligible: false,
        reason: `CA '${ca.id}' certificate lacks basicConstraints CA=true`,
      };
    }

    // 3. Check Key Usage: if present, must include keyCertSign (bit 32)
    for (const ext of cert.extensions) {
      if (ext instanceof x509.KeyUsagesExtension) {
        if ((ext.usages & x509.KeyUsageFlags.keyCertSign) === 0) {
          return {
            eligible: false,
            reason: `CA '${ca.id}' certificate keyUsage forbids certificate signing`,
          };
        }
      }
      if (ext.type === "2.5.29.15") {
        try {
          const ku = new x509.KeyUsagesExtension(ext.rawData);
          if ((ku.usages & x509.KeyUsageFlags.keyCertSign) === 0) {
            return {
              eligible: false,
              reason: `CA '${ca.id}' certificate keyUsage forbids certificate signing`,
            };
          }
        } catch {
          // continue
        }
      }
    }

    // 4. Revocation check
    if (revokedSerials) {
      const serialNorm = cert.serialNumber.toLowerCase().replace(/^0x/, "");
      if (revokedSerials.has(serialNorm) || revokedSerials.has(ca.id.toLowerCase())) {
        return {
          eligible: false,
          reason: `CA '${ca.id}' certificate is revoked`,
        };
      }
    }

    return { eligible: true };
  } catch (err) {
    return {
      eligible: false,
      reason: `Failed to parse CA '${ca.id}' certificate: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * Generates a cryptographically secure uniform random float in [0, 1)
 */
export function secureRandom(): number {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0] / (0xffffffff + 1);
}

/**
 * Selects an Intermediate CA using weighted random selection,
 * taking into account exclusion lists in config.ts / env and ensuring
 * the required private key is configured in the environment.
 */
export async function selectIntermediateCa(
  env: AcmeEnv,
  options?: {
    candidates?: IntermediateCaEntry[];
    random?: () => number;
    now?: Date;
    revokedSerials?: Set<string>;
  }
): Promise<SelectedIntermediateCa> {
  const caDir = env.CA_DIR || CONFIG.CA_DIR;
  const candidates = options?.candidates || loadCaRegistry(caDir, env);

  // Build exclusion set
  const excludedSet = new Set<string>(CONFIG.EXCLUDED_CA_IDS || []);
  if (env.EXCLUDED_CA_IDS && typeof env.EXCLUDED_CA_IDS === "string") {
    env.EXCLUDED_CA_IDS.split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .forEach((id) => excludedSet.add(id));
  }

  // Parse custom weights
  let customWeights: Record<string, number> = { ...(CONFIG.CA_WEIGHTS || {}) };
  if (env.CA_WEIGHTS) {
    try {
      const parsedWeights =
        typeof env.CA_WEIGHTS === "string"
          ? JSON.parse(env.CA_WEIGHTS)
          : env.CA_WEIGHTS;
      customWeights = { ...customWeights, ...parsedWeights };
    } catch {
      // Ignore malformed env JSON
    }
  }

  // Filter eligible CAs
  const eligible: Array<IntermediateCaEntry & { certPem: string }> = [];
  const now = options?.now || new Date();

  for (const ca of candidates) {
    // 1. Check exclusion
    if (excludedSet.has(ca.id)) {
      continue;
    }

    // 2. Check private key availability in environment
    const pkPem = env[ca.pkEnv] as string | undefined;
    if (!pkPem || typeof pkPem !== "string" || pkPem.trim() === "") {
      // Private key not configured in environment, cannot sign
      continue;
    }

    // 3. Check weight
    const weight = customWeights[ca.id] ?? ca.weight ?? 1;
    if (weight <= 0) {
      continue;
    }

    // 4. Validate intermediate CA certificate validity & constraints
    let certPem: string;
    try {
      certPem = readCaCertPem(ca, caDir, env);
    } catch {
      continue;
    }

    const val = validateIntermediateCaCertificate(ca, certPem, now, options?.revokedSerials);
    if (!val.eligible) {
      continue;
    }

    eligible.push({
      ...ca,
      weight,
      certPem,
    });
  }

  if (eligible.length === 0) {
    throw AcmeError.serverInternal(
      "No eligible Intermediate CA available for certificate issuance (all CAs are excluded or missing private keys in environment)"
    );
  }

  // Weighted Random Selection using secure random generator
  let chosen: (IntermediateCaEntry & { certPem: string });
  if (eligible.length === 1) {
    chosen = eligible[0];
  } else {
    const totalWeight = eligible.reduce((acc, c) => acc + c.weight, 0);
    const rng = options?.random ? options.random() : secureRandom();
    const target = rng * totalWeight;

    let cumulative = 0;
    chosen = eligible[0];
    for (const ca of eligible) {
      cumulative += ca.weight;
      if (target < cumulative) {
        chosen = ca;
        break;
      }
    }
  }

  // Read certificate PEM from designated directory (or already verified certPem)
  const certPem = chosen.certPem;

  // Import private key
  const pkPem = env[chosen.pkEnv] as string;
  const privateKey = await importCaPrivateKey(pkPem);

  return {
    ca: chosen,
    certPem,
    privateKey,
  };
}
