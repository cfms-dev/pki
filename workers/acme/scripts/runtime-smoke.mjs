import "reflect-metadata";
import { build } from "esbuild";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
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
let parserRuntime;
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
    unsafeTriggerHandlers: true,
    modulesRoot: directory,
    modules: [
      { type: "ESModule", path: path.join(directory, entry) },
      { type: "Text", path: path.join(directory, "manifest.json") },
      { type: "Text", path: path.join(directory, "generic-intermediate.pem") },
      ...files.filter((file) => file.endsWith(".wasm")).map((file) => ({ type: "CompiledWasm", path: path.join(directory, file) })),
    ],
    compatibilityDate: "2026-11-05", compatibilityFlags: ["nodejs_compat", "global_fetch_strictly_public"],
    assets: {
      directory: path.resolve("dist/website"), binding: "ASSETS",
      routerConfig: { has_user_worker: true },
      assetConfig: { html_handling: "auto-trailing-slash", not_found_handling: "none" },
    },
    d1Databases: ["DB"],
    ratelimits: {
      API_RATE_LIMITER: { namespace_id: "19472001", simple: { limit: 300, period: 60 } },
      ACCOUNT_REGISTRATION_LIMITER: { namespace_id: "19472002", simple: { limit: 10, period: 60 } },
    },
    bindings: { PK_GENERIC_INTERMEDIATE: `-----BEGIN PRIVATE KEY-----\n${key}\n-----END PRIVATE KEY-----` },
    outboundService: async (request) => {
      assert.ok(request.url.includes("type=CAA"), "Unexpected external runtime request");
      return Response.json({ Status: 0, Answer: [] });
    },
  }));
  const base = "https://acme.runtime.test";
  const home = await runtime.dispatchFetch(`${base}/`);
  assert.equal(home.status, 200, await home.clone().text());
  assert.equal(home.headers.get("Content-Type"), "text/html; charset=utf-8");
  assert.equal(home.headers.get("Link"), null);
  assert.equal(home.headers.get("Access-Control-Allow-Origin"), null);
  const homeHtml = await home.text();
  assert.ok(homeHtml.includes("Certificate issuance,"));
  assert.ok(homeHtml.includes('href="/directory"><code>/directory</code>'));
  assert.ok(!homeHtml.includes("{{CRL_URL}}"));
  const otherOrigin = await runtime.dispatchFetch("https://other.runtime.test/");
  assert.equal(await otherOrigin.text(), homeHtml);
  const etag = home.headers.get("ETag");
  assert.ok(etag, "Static homepage should have an asset validator");
  assert.equal(home.headers.get("Cache-Control"), "public, max-age=0, must-revalidate");
  const cached = await runtime.dispatchFetch(`${base}/`, { headers: { "If-None-Match": etag } });
  assert.equal(cached.status, 304);
  assert.equal(await cached.text(), "");
  assert.ok(!homeHtml.includes("{{DIRECTORY_URL}}"));
  const homeHead = await runtime.dispatchFetch(`${base}/`, { method: "HEAD" });
  assert.equal(homeHead.status, 200);
  assert.equal(homeHead.headers.get("Content-Type"), home.headers.get("Content-Type"));
  assert.equal(await homeHead.text(), "");
  const redirect = await runtime.dispatchFetch(`${base}/index.html`, { redirect: "manual" });
  assert.equal(redirect.status, 307);
  assert.equal(new URL(redirect.headers.get("Location"), base).href, `${base}/`);
  const chineseHome = await runtime.dispatchFetch(`${base}/zh-cn/`);
  assert.equal(chineseHome.status, 200);
  assert.equal(chineseHome.headers.get("Replay-Nonce"), null);
  const chineseHtml = await chineseHome.text();
  assert.ok(chineseHtml.includes('<html lang="zh-CN">'));
  assert.ok(chineseHtml.includes("证书签发，"));
  assert.ok(chineseHtml.includes('href="/directory"><code>/directory</code>'));
  const chineseEtag = chineseHome.headers.get("ETag");
  assert.ok(chineseEtag);
  const chineseCached = await runtime.dispatchFetch(`${base}/zh-cn/`, { headers: { "If-None-Match": chineseEtag } });
  assert.equal(chineseCached.status, 304);
  const chineseAlias = await runtime.dispatchFetch(`${base}/zh-cn/index.html`, { redirect: "manual" });
  assert.equal(chineseAlias.status, 307);
  assert.equal(new URL(chineseAlias.headers.get("Location"), base).pathname, "/zh-cn/");
  for (const page of ["terms", "privacy", "zh-cn/terms", "zh-cn/privacy"]) {
    const alias = await runtime.dispatchFetch(`${base}/${page}.html`, { redirect: "manual" });
    assert.equal(alias.status, 307);
    assert.equal(new URL(alias.headers.get("Location"), base).pathname, `/${page}`);
    const response = await runtime.dispatchFetch(`${base}/${page}`);
    assert.equal(response.status, 200);
    assert.ok(response.headers.get("Content-Type").startsWith("text/html"));
    assert.ok((await response.text()).includes('href="/styles.css"'));
  }
  const css = await runtime.dispatchFetch(`${base}/styles.css`);
  assert.equal(css.status, 200);
  assert.ok(css.headers.get("Content-Type").startsWith("text/css"));
  for (const resource of ["/missing.css", "/images/missing.png", "/zh-cn/missing"]) {
    const missing = await runtime.dispatchFetch(`${base}${resource}`);
    assert.equal(missing.status, 404);
    assert.equal(missing.headers.get("Replay-Nonce"), null);
  }
  for (const page of ["/", "/index.html", "/terms", "/privacy", "/styles.css", "/zh-cn/", "/zh-cn/index.html", "/zh-cn/terms", "/zh-cn/privacy"]) {
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
      const rejected = await runtime.dispatchFetch(`${base}${page}`, { method, redirect: "manual" });
      assert.equal(rejected.status, 405);
      assert.equal(rejected.headers.get("Replay-Nonce"), null);
    }
    const head = await runtime.dispatchFetch(`${base}${page}`, { method: "HEAD", redirect: "manual" });
    assert.equal(await head.text(), "");
  }
  // Website traffic must not initialize the database, even on real workerd.
  const untouchedDb = await runtime.getD1Database("DB");
  const tables = await untouchedDb.prepare("SELECT name FROM sqlite_master WHERE name = 'accounts'").all();
  assert.equal(tables.results.length, 0);
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
  const unknown = await runtime.dispatchFetch(`${base}/unknown-acme-endpoint`);
  assert.equal(unknown.status, 404);
  assert.ok(unknown.headers.get("Content-Type").includes("application/problem+json"));

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
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM issuance_ledger").first()).n, 2);
  // Repeat finalize must neither issue again nor charge the ledger again.
  assert.equal((await post(order.finalize, { csr: b64(csr.rawData) })).status, 200);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM issuance_ledger").first()).n, 2);

  for (const identifiers of [
    [{ type: "ip", value: "93.184.216.34" }],
    [{ type: "ip", value: "2606:4700:4700::1111" }],
    [{ type: "dns", value: "runtime.example.com" }, { type: "ip", value: "93.184.216.34" }],
  ]) {
    const response = await post(`${base}/new-order`, { identifiers });
    assert.equal(response.status, 201, await response.clone().text());
    const ipOrder = await response.json();
    const authz = await post(ipOrder.authorizations[identifiers.length - 1], "");
    assert.deepEqual((await authz.json()).challenges.map((item) => item.type), ["http-01"]);
    await db.prepare("UPDATE authorizations SET status = 'valid'").run();
    await db.prepare("UPDATE challenges SET status = 'valid'").run();
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "", keys: leafKeys, signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [new x509.SubjectAlternativeNameExtension(identifiers)],
    });
    const finalized = await post(ipOrder.finalize, { csr: b64(csr.rawData) });
    assert.equal(finalized.status, 200, await finalized.clone().text());
    const issued = await finalized.json();
    const downloaded = await runtime.dispatchFetch(issued.certificate);
    const leaf = new x509.X509Certificate((await downloaded.text()).match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)[0]);
    assert.equal(leaf.notAfter.getTime() - leaf.notBefore.getTime(), 160 * 3600000);
    assert.deepEqual(leaf.getExtension(x509.SubjectAlternativeNameExtension).names.items.map((item) => item.type), identifiers.map((item) => item.type));
    assert.equal(await leaf.verify({ publicKey: ca.publicKey, signatureOnly: true }), true);
    if (identifiers.every((item) => item.type === "ip")) {
      assert.equal(leaf.subject, "");
      assert.equal(leaf.getExtension(x509.SubjectAlternativeNameExtension).critical, true);
    }
  }

  // Native workerd rate-limit bindings reject registration before D1 writes.
  let limited;
  for (let attempt = 0; attempt < 30; attempt++) {
    const result = await runtime.dispatchFetch(`${base}/new-account`, {
      method: "POST", headers: { "CF-Connecting-IP": "198.51.100.10" }, body: "invalid JWS",
    });
    if (result.status === 429) { limited = result; break; }
    assert.equal(result.status, 415);
  }
  assert.ok(limited, "Native registration limiter did not reject the burst");
  assert.equal(limited.headers.get("Retry-After"), "60");
  assert.equal(limited.headers.get("Replay-Nonce"), null);
  const nonceCount = (await db.prepare("SELECT COUNT(*) AS n FROM nonces").first()).n;
  assert.equal((await runtime.dispatchFetch(`${base}/new-account`, {
    method: "POST", headers: { "CF-Connecting-IP": "198.51.100.10" }, body: "invalid JWS",
  })).status, 429);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM nonces").first()).n, nonceCount);

  await db.prepare("INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)").bind("expired-runtime-nonce", 1).run();
  const scheduled = await runtime.dispatchFetch(`${base}/cdn-cgi/local/scheduled?cron=*/5%20*%20*%20*%20*&format=json`);
  assert.equal(scheduled.status, 200, await scheduled.clone().text());
  assert.equal(await db.prepare("SELECT nonce FROM nonces WHERE nonce = ?").bind("expired-runtime-nonce").first(), null);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM nonces").first()).n, nonceCount);

  // Exercise the real socket adapter and strict parser in workerd, injecting
  // only the TCP peer. No public probe host or production binding is involved.
  const probe = await build({
    absWorkingDir: process.cwd(), bundle: true, write: false, format: "esm", platform: "browser",
    external: ["cloudflare:sockets", "node:net"],
    plugins: [{ name: "runtime-wasm", setup(build) {
      build.onResolve({ filter: /\.wasm$/ }, () => ({ path: "./llhttp.wasm", external: true }));
    } }],
    stdin: { resolveDir: process.cwd(), contents: `
      import { validateHttp01Challenge } from './src/http01/validator';
      export default { async fetch() {
        const token = 'a'.repeat(22), thumbprint = 'b'.repeat(43), body = token + '.' + thumbprint;
        const checks = [];
        for (const ip of ['93.184.216.34', '2606:4700:4700::1111']) {
          for (const valid of [true, false]) {
            let destination, closed = false, request = '';
            const connectImpl = (address) => {
              destination = address;
              const wire = valid ? 'HTTP/1.1 200 OK\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n' + body.length.toString(16) + '\\r\\n' + body + '\\r\\n0\\r\\n\\r\\n' : 'HTTP/1.1 200 OK\\r\\nContent-Length: 999\\r\\n\\r\\nx';
              return {
                opened: Promise.resolve({}), closed: new Promise(() => {}),
                readable: new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode(wire)); c.close(); } }),
                writable: new WritableStream({ write(bytes) { request += new TextDecoder().decode(bytes); } }),
                close() { closed = true; return Promise.resolve(); }
              };
            };
            const result = await validateHttp01Challenge({ type: 'ip', value: ip }, token, thumbprint, { connectImpl, fetchImpl: () => { throw new Error('unexpected fetch'); } });
            checks.push({ ip, expected: valid, result, destination, closed, request });
          }
        }
        return Response.json(checks);
      } };
    ` },
  });
  const wasmFile = files.find((file) => file.endsWith(".wasm"));
  assert.ok(wasmFile, "Wrangler did not bundle llhttp WASM");
  parserRuntime = new Miniflare(convertV4MiniflareOptions({
    modulesRoot: directory,
    modules: [
      { type: "ESModule", path: path.join(directory, "parser-probe.mjs"), contents: probe.outputFiles[0].text },
      { type: "CompiledWasm", path: path.join(directory, "llhttp.wasm"), contents: await readFile(path.join(directory, wasmFile)) },
    ],
    compatibilityDate: "2026-11-05", compatibilityFlags: ["nodejs_compat", "global_fetch_strictly_public"],
  }));
  const checks = await (await parserRuntime.dispatchFetch("https://parser.runtime.test")).json();
  for (const check of checks) {
    assert.equal(check.result.valid, check.expected, JSON.stringify(check));
    assert.equal(check.closed, true);
    const authority = check.ip.includes(":") ? `[${check.ip}]` : check.ip;
    assert.equal(check.destination, `${authority}:80`);
    assert.ok(check.request.includes(`Host: ${authority}\r\n`));
    if (!check.expected) assert.equal(check.result.errorType, "incorrectResponse");
  }
  console.log("Workers runtime smoke passed: Assets, legacy D1 migration, DNS/IPv4/IPv6/mixed issuance, atomic issuance ledger, native ingress limits, scheduled nonce cleanup, signatures, validity, ARI, compiled llhttp WASM and socket parsing");
} finally {
  if (parserRuntime) await parserRuntime.dispose();
  if (runtime) await runtime.dispose();
  // directory comes exclusively from mkdtemp under the OS temp directory.
  assert.ok(directory.startsWith(path.join(tmpdir(), "cfms-pki-smoke-")));
  await rm(directory, { recursive: true, force: true });
}
