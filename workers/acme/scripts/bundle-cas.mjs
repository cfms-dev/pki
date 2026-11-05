#!/usr/bin/env node

/**
 * Packaging script for Cloudflare Workers ACME server.
 * Bundles Intermediate CA certificates and generates manifest.json
 * into the designated Worker CA directory (workers/acme/cas).
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Root repository directory: cfms-pki
const repoRootDir = path.resolve(__dirname, "../../..");
// Worker directory: workers/acme
const workerDir = path.resolve(__dirname, "..");
// Target CA directory
const targetCaDir = path.resolve(workerDir, "cas");

console.log(`[bundle-cas] Packaging Intermediate CAs into ${targetCaDir}...`);

// Ensure target directory exists
if (!fs.existsSync(targetCaDir)) {
  fs.mkdirSync(targetCaDir, { recursive: true });
}

// Locate registry/ca.json
const caJsonCandidates = [
  path.resolve(repoRootDir, "registry", "ca.json"),
  path.resolve(process.cwd(), "registry", "ca.json"),
  path.resolve(process.cwd(), "../../registry", "ca.json"),
];

let caJsonPath = caJsonCandidates.find((p) => fs.existsSync(p));

const manifest = {
  cas: {},
  bundledAt: new Date().toISOString(),
};

if (caJsonPath) {
  console.log(`[bundle-cas] Reading CA registry from ${caJsonPath}`);
  try {
    const caJsonContent = JSON.parse(fs.readFileSync(caJsonPath, "utf-8"));
    const cas = caJsonContent.cas || {};

    for (const [caId, caInfo] of Object.entries(cas)) {
      if (!caInfo || !caInfo.location) continue;

      const certSrcPath = path.isAbsolute(caInfo.location)
        ? caInfo.location
        : path.resolve(repoRootDir, caInfo.location);

      if (!fs.existsSync(certSrcPath)) {
        console.warn(`[bundle-cas] Warning: Certificate file not found at ${certSrcPath} for CA '${caId}'`);
        continue;
      }

      const certFileName = path.basename(certSrcPath);
      const certDestPath = path.resolve(targetCaDir, certFileName);

      fs.copyFileSync(certSrcPath, certDestPath);
      console.log(`[bundle-cas] Copied ${certSrcPath} -> ${certDestPath}`);

      manifest.cas[caId] = {
        id: caId,
        certFile: certFileName,
        pkEnv: caInfo.pk_env || `PK_${caId.toUpperCase().replace(/-/g, "_")}`,
      };
    }
  } catch (err) {
    console.error(`[bundle-cas] Error parsing ${caJsonPath}:`, err);
  }
} else {
  console.warn("[bundle-cas] Warning: registry/ca.json not found in candidate paths.");
  // Check if any existing .pem files are already present in targetCaDir
  const existingFiles = fs.readdirSync(targetCaDir).filter((f) => f.endsWith(".pem"));
  for (const file of existingFiles) {
    const caId = path.basename(file, ".pem");
    manifest.cas[caId] = {
      id: caId,
      certFile: file,
      pkEnv: `PK_${caId.toUpperCase().replace(/-/g, "_")}`,
    };
  }
}

// Write manifest.json into target directory
const manifestPath = path.resolve(targetCaDir, "manifest.json");
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), "utf-8");
console.log(`[bundle-cas] Successfully generated ${manifestPath} with ${Object.keys(manifest.cas).length} CA(s).`);
