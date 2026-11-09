#!/usr/bin/env node

// Copy public CA certificates and generate the Worker's manifest from registry/ca.json.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));
const targetDir = fileURLToPath(new URL("../cas/", import.meta.url));
const registryPath = path.join(repoRoot, "registry/ca.json");
const { cas } = JSON.parse(fs.readFileSync(registryPath, "utf-8"));

if (!cas || typeof cas !== "object" || Array.isArray(cas) || Object.keys(cas).length === 0) {
  throw new Error(`[bundle-cas] Expected non-empty 'cas' object in ${registryPath}`);
}

function writeIfChanged(filePath, content) {
  if (fs.existsSync(filePath) && fs.readFileSync(filePath, "utf-8") === content) {
    return;
  }
  fs.writeFileSync(filePath, content, "utf-8");
  console.log(`[bundle-cas] Wrote ${filePath}`);
}

fs.mkdirSync(targetDir, { recursive: true });
const manifest = { cas: {} };

for (const [id, ca] of Object.entries(cas)) {
  if (
    !ca ||
    typeof ca.location !== "string" ||
    !ca.location ||
    typeof ca.pk_env !== "string" ||
    !ca.pk_env.trim()
  ) {
    throw new Error(`[bundle-cas] CA '${id}' requires location and pk_env`);
  }

  const sourcePath = path.resolve(repoRoot, ca.location);
  const certFile = path.basename(sourcePath);
  const pem = fs.readFileSync(sourcePath, "utf-8");
  if (!pem.includes("-----BEGIN CERTIFICATE-----") || !pem.includes("-----END CERTIFICATE-----")) {
    throw new Error(`[bundle-cas] Invalid PEM certificate: ${sourcePath}`);
  }
  if (/-----BEGIN [^-]*PRIVATE KEY-----/.test(pem)) {
    throw new Error(`[bundle-cas] Certificate contains private key data: ${sourcePath}`);
  }

  writeIfChanged(path.join(targetDir, certFile), pem);
  const crlFile = path.basename(ca.crl_path || `${id}.crl`);
  if (!/^[a-zA-Z0-9_-][a-zA-Z0-9_.-]*\.crl$/.test(crlFile) || crlFile.includes("..")) throw new Error("Invalid CRL filename");
  manifest.cas[id] = { certFile, pkEnv: ca.pk_env, crlFile };
}

writeIfChanged(path.join(targetDir, "manifest.json"), JSON.stringify(manifest, null, 2));
