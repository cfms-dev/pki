import "reflect-metadata";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import * as x509 from "@peculiar/x509";

// Use the exact runtime selected by Wrangler rather than an older independent
// Miniflare release. All state and generated keys are disposable local fixtures.
const require = createRequire(import.meta.url);
const { Miniflare, convertV4MiniflareOptions } = createRequire(require.resolve("wrangler"))("miniflare");
const directory = await mkdtemp(path.join(tmpdir(), "cfms-pki-smoke-"));
let runtime;
try {
  execFileSync(process.execPath, ["node_modules/wrangler/bin/wrangler.js", "deploy", "--dry-run", "--outdir", directory], { stdio: "pipe", timeout: 60000 });
  const caKeys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const ca = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "1234", name: "CN=Runtime Smoke CA", keys: caKeys,
    notBefore: new Date(Date.now() - 10000), notAfter: new Date(Date.now() + 365 * 86400000),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: [new x509.BasicConstraintsExtension(true, 0, true), await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey)],
  });
  await writeFile(path.join(directory, "generic-intermediate.pem"), ca.toString("pem"));
  await writeFile(path.join(directory, "manifest.json"), JSON.stringify({
    cas: {
      "generic-intermediate": { certFile: "generic-intermediate.pem", pkEnv: "PK_GENERIC_INTERMEDIATE" },
    }
  }));
  const files = await readdir(directory);
  const entry = files.find((file) => file.endsWith(".js") && !file.endsWith(".map"));
  assert.ok(entry, "Wrangler did not emit a Worker");
  const key = Buffer.from(await crypto.subtle.exportKey("pkcs8", caKeys.privateKey)).toString("base64");
  runtime = new Miniflare(convertV4MiniflareOptions({
    modulesRoot: directory,
    modules: [
      { type: "ESModule", path: path.join(directory, entry) },
      { type: "Text", path: path.join(directory, "home.html") },
      { type: "Text", path: path.join(directory, "manifest.json") },
      { type: "Text", path: path.join(directory, "generic-intermediate.pem") },
    ],
    compatibilityDate: "2026-11-05", compatibilityFlags: ["nodejs_compat"],
    d1Databases: ["DB"],
    bindings: { PK_GENERIC_INTERMEDIATE: `-----BEGIN PRIVATE KEY-----\n${key}\n-----END PRIVATE KEY-----` },
    outboundService: async (request) => {
      assert.ok(request.url.includes("type=CAA"), "Unexpected external runtime request");
      return Response.json({ Status: 0, Answer: [] });
    },
  }));
  const base = "https://acme.runtime.test";
  const home = await runtime.dispatchFetch(`${base}/`);
  assert.equal(home.status, 200);
  assert.equal(home.headers.get("Content-Type"), "text/html; charset=utf-8");
  assert.equal(home.headers.get("Link"), `<${base}/directory>;rel="index"`);
  const homeHtml = await home.text();
  assert.ok(homeHtml.includes("Certificate issuance,"));
  assert.ok(homeHtml.includes(`href="${base}/directory"`));
  assert.ok(!homeHtml.includes("{{DIRECTORY_URL}}"));
  const homeHead = await runtime.dispatchFetch(`${base}/`, { method: "HEAD" });
  assert.equal(homeHead.status, 200);
  assert.equal(homeHead.headers.get("Content-Type"), home.headers.get("Content-Type"));
  assert.equal(await homeHead.text(), "");
  const discovery = await runtime.dispatchFetch(`${base}/directory`);
  assert.equal(discovery.status, 200);
  const directoryBody = await discovery.json();
  assert.equal(directoryBody.newAccount, `${base}/new-account`);
  assert.equal(directoryBody.meta.website, "https://cfms-pki.crpteam.club");
  assert.deepEqual(directoryBody.meta.caaIdentities, ["cfms-pki.crpteam.club"]);
  const accountKeys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const accountJwk = await crypto.subtle.exportKey("jwk", accountKeys.publicKey);
  const b64 = (value) => Buffer.from(value).toString("base64url");
  let kid;
  async function post(url, payload, useJwk = false) {
    const nonce = (await runtime.dispatchFetch(`${base}/new-nonce`, { method: "HEAD" })).headers.get("Replay-Nonce");
    assert.ok(nonce, "D1 schema initialization/nonce creation failed");
    const protectedHeader = b64(JSON.stringify({ alg: "ES256", nonce, url, ...(useJwk ? { jwk: accountJwk } : { kid }) }));
    const encoded = payload === "" ? "" : b64(JSON.stringify(payload));
    const signature = b64(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, accountKeys.privateKey, Buffer.from(`${protectedHeader}.${encoded}`)));
    return runtime.dispatchFetch(url, { method: "POST", headers: { "Content-Type": "application/jose+json" }, body: JSON.stringify({ protected: protectedHeader, payload: encoded, signature }) });
  }
  // Begin with a legacy schema to exercise the actual D1 upgrade path.
  const db = await runtime.getD1Database("DB");
  await db.exec("CREATE TABLE accounts (id TEXT PRIMARY KEY, jwk TEXT NOT NULL, thumbprint TEXT UNIQUE NOT NULL, contact TEXT, status TEXT NOT NULL, created_at INTEGER NOT NULL)");
  const account = await post(`${base}/new-account`, {}, true);
  assert.equal(account.status, 201, await account.clone().text());
  kid = account.headers.get("Location");
  const response = await post(`${base}/new-order`, { identifiers: [{ type: "dns", value: "runtime.example.com" }] });
  assert.equal(response.status, 201, await response.clone().text());
  const order = await response.json();
  // DNS/HTTP validation has separate integration coverage. Seed only the
  // authorization result here; signing, filesystem access and D1 run in workerd.
  await db.prepare("UPDATE authorizations SET status = 'valid'").run();
  await db.prepare("UPDATE challenges SET status = 'valid'").run();
  const leafKeys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: "CN=runtime.example.com", keys: leafKeys, signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: [new x509.SubjectAlternativeNameExtension([{ type: "dns", value: "runtime.example.com" }])],
  });
  const finalized = await post(order.finalize, { csr: b64(csr.rawData) });
  assert.equal(finalized.status, 200, await finalized.clone().text());
  const body = await finalized.json();
  assert.equal(body.status, "valid");
  const downloaded = await runtime.dispatchFetch(body.certificate);
  const chain = await downloaded.text();
  const leaf = new x509.X509Certificate(chain.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)[0]);
  assert.equal(await leaf.verify({ publicKey: ca.publicKey, signatureOnly: true }), true);
  assert.equal(leaf.getExtension(x509.CRLDistributionPointsExtension)
    ?.distributionPoints[0].distributionPoint?.fullName?.[0].uniformResourceIdentifier,
    "https://cfms-dev.github.io/pki/crl/generic-intermediate.crl");
  const certificate = await db.prepare("SELECT cert_id FROM certificates").first();
  const renewal = await runtime.dispatchFetch(`${base}/renewal-info/${certificate.cert_id}`);
  assert.equal(renewal.status, 200);
  const renewalBody = await renewal.json();
  assert.equal(renewalBody.explanationURL, "https://www.rfc-editor.org/rfc/rfc9773.html#section-4.2");
  assert.equal(Date.parse(renewalBody.suggestedWindow.end) - Date.parse(renewalBody.suggestedWindow.start), 30 * 86400000);
  assert.equal(leaf.notAfter.getTime() - leaf.notBefore.getTime(), 90 * 86400000);
  assert.equal((await db.prepare("SELECT ca_id FROM certificates").first()).ca_id, "generic-intermediate");
  console.log("Workers runtime smoke passed: legacy D1 migration, bundled CA read, issuance, signature and CRL distribution point");
} finally {
  if (runtime) await runtime.dispose();
  // directory comes exclusively from mkdtemp under the OS temp directory.
  assert.ok(directory.startsWith(path.join(tmpdir(), "cfms-pki-smoke-")));
  await rm(directory, { recursive: true, force: true });
}
