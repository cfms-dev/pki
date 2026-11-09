# CFMS-PKI ACME Worker

RFC 8555 / RFC 8738 ACME server deployed on Cloudflare Workers with a D1 database and a
weighted pool of intermediate CAs. Supported validation methods:

- `dns-01` (existing, DNS-over-HTTPS TXT lookup)
- `http-01` (RFC 8555 § 8.3 / RFC 8738, for non-wildcard DNS and public IP identifiers)

The ACME directory is served at `/directory` (for production:
`https://acme.cfms-pki.crpteam.club/directory`).

The root `/` serves an English HTML service overview, independently of D1.
Simplified Chinese versions are available at `/zh-cn/`, `/zh-cn/terms` and
`/zh-cn/privacy`. The globe link switches the current page's language; all
website links preserve it. English remains the default, without browser
scripts, language detection, cookies or preference storage.
Use `/directory`, rather than the homepage, as your ACME client's server URL.
Webpages use native Workers Assets handling for GET, HEAD, unsupported methods,
redirects, caching and conditional requests. They do not receive the ACME API's
Link, CORS or nonce headers, or a custom five-minute cache policy.

Page shells and optional static assets live in `public/`. Shared navigation,
CSS and English/Chinese content live in `../../src/cfms_pki/templates/web/`,
which is also packaged with the Python CRL site generator. Run website builds
from a checkout that contains these shared resources.
`npm run build:website` renders both languages into the ignored `dist/website/`
output, escaping text and URLs before inserting trusted local HTML fragments.
Source templates are never overwritten. `CONFIG.CRL_BASE_URL` supplies the
English CRL directory link; its parent supplies the PKI overview root and
localized browsing links (for example, `/pki/crl/` gives `/pki/` and
`/pki/zh-cn/crl/`). Change that setting and rebuild/redeploy to update links.
`npm run build` creates CA certificates and their manifest in `generated/cas/`,
llhttp WASM and its supporting files in `generated/llhttp/`, and the website in
`dist/website/`. These outputs are ignored by Git and recreated by the build;
no placeholder directories are required. Wrangler runs the build before local
development, type generation and deployment, including dry runs.

The homepage always displays and links `/directory`, resolved by the browser
against the current site. It does not inspect `ACME_BASE_URL` or infer an ACME
hostname. The dynamic ACME API retains its existing behavior: an empty
`ACME_BASE_URL` derives published URLs from the request origin, while a nonempty
value overrides that origin. No nonempty base URL is required to build the site.

Wrangler serves `dist/website/` with asset-first routing and
`html_handling = "auto-trailing-slash"`. Canonical pages are `/`, `/terms` and
`/privacy`, with shared styles at `/styles.css`. `/index.html` and the policy
`.html` aliases, including Chinese page aliases, use Assets' native redirects. There is no SPA fallback or browser
script. Missing CSS/images and website requests that reach the Worker are
forwarded unchanged to `ASSETS.fetch()` without accessing D1, without
ACME nonce generation or template rendering.

Publishing the terms page does not itself enable ACME consent enforcement.
`CONFIG.TERMS_OF_SERVICE_URL` remains empty by default. Set it to the absolute
URL of the applicable terms to advertise it in `/directory` and activate the
existing consent checks for account registration and continued ordering.
Use a new URL when the applicable terms change: consent records identify the
agreed version by URL. Keep previously published versions available if needed.
The policy text describes the current implementation; update it when service
practices change.

## Identifier support

| Identifier | Supported | Notes |
| --- | --- | --- |
| `dns` | Yes | Wildcards receive DNS-01 only |
| `ip` | Yes | Public IPv4/IPv6, HTTP-01 only; mixed DNS/IP orders supported |
| anything else | No | `unsupportedIdentifier` |

IP identifiers use standard dotted-decimal IPv4 or unbracketed IPv6. IPv6 is
canonicalized, and equivalent identifiers are deduplicated by type and value.
Legacy numeric IPv4 (`127.1`, integer, hexadecimal, octal), brackets, zone IDs,
ports, wildcards and non-public addresses are rejected before order state is
written. DNS identifiers continue to reject IP literals, including legacy forms.

IP validation connects directly to the numeric IP using `cloudflare:sockets`,
initially on TCP/80, with the IP in `Host` (bracketed for IPv6). No initial DNS,
IP `fetch()`, alias or external proxy is involved. Cloudflare-owned and other
platform-blocked destinations can still fail with a `connection` problem.

The socket response is parsed by strict llhttp WASM. `build:llhttp` extracts the
unmodified module from the pinned official `undici@8.12.4` build dependency;
Undici's HTTP client and runtime loader are not included. Wrangler statically
imports a precompiled module through a generated shim in `generated/llhttp/`.
Each socket uses its own parser instance. See [provenance and ABI notes](src/http01/LLHTTP.md).

Orders and certificate SAN metadata now store typed identifier arrays.
Historical DNS string arrays remain readable. The idempotent D1 schema upgrade
adds `authorizations.identifier_type TEXT NOT NULL DEFAULT 'dns'`; historical
records are not rewritten. Deploy the schema and this type-aware Worker together.
After typed records have been written, rollback must use a type-aware build;
older DNS-only Workers cannot interpret the new metadata.

Any certificate containing an IP SAN is limited to **160 hours**, additionally
bounded by the global validity policy and issuer expiry. This follows
[Let's Encrypt's IP certificate policy](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability),
not a validity mandate in RFC 8738. Pure DNS certificates retain the existing
policy. IP ARI windows span 2/3 to 5/6 of the actual issued lifetime; renewals
require fresh validation. No ACME Profiles extension is advertised or required.

## HTTP-01 flow

1. `POST /new-order` creates one authorization per unique typed identifier, plus
   `dns-01` and (for non-wildcard DNS identifiers) `http-01` challenge rows.
   IP identifiers receive only `http-01`.
   The `dns-01` challenge deliberately keeps the authorization ID as its
   challenge ID, so existing `/challenge/{authzId}` URLs remain valid.
2. `POST /authz/{id}` (POST-as-GET) returns both challenges with `type`, `url`,
   `status`, and `token`.
3. `POST /challenge/{challengeId}` with `{}` triggers synchronous validation.
4. The server computes the RFC 7638 SHA-256 JWK thumbprint from the account key
   and builds `keyAuthorization = token + "." + base64urlThumbprint`.
5. It requests `http://{identifier}/.well-known/acme-challenge/{token}` on
   HTTP port 80, following at most five redirects.
6. A successful validation requires HTTP 200 and a body that is exactly the key
   authorization, with only trailing whitespace ignored.
7. Success moves the challenge and authorization to `valid`; when every
   authorization is valid the order becomes `ready`.
8. Failure stores an ACME problem document on the challenge, invalidates the
   authorization, other pending challenges, and the order. `finalize` cannot
   issue from an invalid, expired, or incomplete order.

### Redirect and target policy

`global_fetch_strictly_public` keeps hostname validation requests on the public
Internet routing path, including Worker-hosted names in this service's own zone.
This avoids private-origin routing that can bypass the target's Worker/security
settings or produce a self-fetch 522. It does not pin DNS resolution or remove
the DNS-rebinding limitation documented below.

Each hop is checked before any request is made:

- Initial request: `http:` on port 80 only.
- Redirects: `http:`/80 or `https:`/443 only; no credentials, fragments,
  local/special-use hostnames, invalid DNS names, or non-public IPs. IP-origin
  validations allow IP and DNS redirects; existing DNS-origin validations
  continue to reject IP redirect targets. HTTPS always verifies certificates.
- At most five redirects; redirect loops are rejected.
- IP hops use numeric sockets, with native TLS for HTTPS/443. Responses use
  strict llhttp framing, `Connection: close`, and `Accept-Encoding: identity`;
  non-identity content/transfer encodings, upgrades and ambiguous framing fail.
  Cumulative headers, trailers and chunk metadata are bounded to 16 KiB, bodies
  to 8 KiB, and each socket wire response to 64 KiB. All paths close the socket.
- Hostnames are resolved through public DNS-over-HTTPS (`cloudflare-dns.com`
  and `dns.google`) before every request, and the check is fail-closed:
  - Both the A and the AAAA family must produce a definitive answer. A
    confirmed NOERROR/NODATA (no records of that type) is a valid empty
    result, so a dual-stack target may legitimately have only one family.
  - A timeout, transport failure, non-JSON response, missing/invalid DNS
    status, malformed Answer section, invalid A/AAAA record data, NXDOMAIN, or
    any non-NOERROR status makes the check fail closed: the validation is
    aborted before the HTTP request is made. The second DoH provider is only
    used to recover from transport-level failures (timeout, HTTP error,
    unparsable JSON); a definitive DNS answer (including NXDOMAIN or an error
    status) is never reinterpreted by another resolver.
  - At least one confirmed address across both families is required, and every
    returned address must be globally routable unicast. Private, loopback,
    link-local, CGNAT, documentation, multicast, reserved, IPv4-mapped private,
    6to4, Teredo, and similar special-use addresses are rejected.
  - CNAME targets must be valid DNS names (never IP literals). A recursive
    resolver normally returns the alias chain together with the final A/AAAA
    records, all of which are checked; if a response stops at a CNAME, the
    alias target is queried explicitly (bounded, loop-detected) so the final
    address is still checked.
- Requests use `redirect: "manual"`, `cache: "no-store"`, no-cache headers, a
  10s per-request timeout, a 20s total budget, and an 8 KiB response-body
  limit. Every redirect hop repeats the target and DNS checks.
- `cf-cache-status` is not used as an accept/reject signal. RFC 8555 § 8.3
  makes the exact key-authorization body authoritative: a stale cached body
  contains a different token and fails the body comparison, while a HIT
  containing the current key authorization is a valid response. Rejecting all
  HITs would break legitimate Cloudflare-proxied origins that cache
  `.well-known` paths. The request already asks caches to bypass or
  revalidate (`Cache-Control: no-cache`, `Pragma: no-cache`, `cache:
  "no-store"`).

### Concurrency and crash recovery

- `pending -> processing` is claimed with a single conditional `UPDATE` that
  also increments the row's `validation_generation`. Duplicate challenge
  submissions do not run a second validation.
- A stale `processing` claim older than 60 seconds can be reclaimed; the
  reclaim increments the generation again.
- Success/failure writes are conditional on `status = 'processing'` **and**
  the generation captured at claim time. A slow or resumed attempt from a
  reclaimed claim therefore cannot overwrite the result of the newer attempt
  (for example, an old failure cannot invalidate a newer success, and an old
  success cannot resurrect an order that a newer attempt invalidated).
- Invalid state is reconciled when an authorization or order is read
  (`syncAuthorizationState` / `syncOrderState`), so an isolate that dies between
  D1 updates does not leave a challenge permanently `processing`.
- `finalize` claims a `ready` order with a conditional `UPDATE` to prevent two
  concurrent requests from issuing certificates. On failure the order returns to
  `ready`; on success it becomes `valid`.
- Validation runs inline in the request; no Queues binding or `waitUntil()` is
  used.

## Account public key identity

Two different values are stored for every account. They must not be conflated:

| Column | Definition | Purpose |
| --- | --- | --- |
| `accounts.thumbprint` | RFC 7638 SHA-256 JWK thumbprint of the JWK submitted by the client | ACME key authorization (`token + "." + thumbprint`) for http-01/dns-01 |
| `accounts.public_key_fingerprint` | `base64url(SHA-256(canonical SubjectPublicKeyInfo DER))` | Actual-key identity used for account uniqueness, keyChange, and finalize key-reuse checks |

The RFC 7638 thumbprint is a protocol value over the JWK's required members as
supplied. Two legal encodings of one actual key can produce different
thumbprints: for example an RSA `n` with redundant leading zero octets, or EC
`x`/`y` coordinates with redundant leading zero bytes. WebCrypto accepts those
encodings and normalizes them on import. Using the thumbprint as a uniqueness
index therefore allowed the same actual key to be registered more than once
and caused the finalize cross-account lookup to miss a re-used account key.

`normalizePublicKey()` in `src/crypto/jws.ts` is the single identity function
used by account registration, keyChange, CSR parsing/finalize, and migration:

1. Validate `kty`/`crv` for the supported account algorithms (`ES256` P-256,
   `RS256` RSA, `EdDSA` Ed25519).
2. Reject private/symmetric JWK members (`d`, `p`, `q`, `dp`, `dq`, `qi`,
   `oth`, `k`) and invalid/unsupported members.
3. Strip irrelevant optional members (`kid`, `use`, `key_ops`, `alg`, ...) and
   import the minimal public JWK through WebCrypto.
4. Re-export canonical SPKI DER and the canonical public JWK.
5. Return `SHA-256(SPKI DER)` as the stable fingerprint, plus the RFC 7638
   thumbprint of the canonical JWK.

Any key that cannot complete this normalization is rejected (fail closed); it
is never treated as "different" by default.

### newAccount and onlyReturnExisting

A new account is looked up by `public_key_fingerprint`, not by thumbprint. The
database has a `UNIQUE` index on that column, so a concurrent duplicate insert
fails in SQLite/D1; the loser returns the existing account with `200 OK` and
its original `Location` (RFC 8555 § 7.3.1). `onlyReturnExisting` uses the same
lookup and returns the existing account for any equivalent encoding; if no
account exists it returns `400 accountDoesNotExist` without creating one.

For new accounts the exact submitted JWK representation is stored together
with its RFC 7638 thumbprint, so the stored protocol representation and the
thumbprint used for key authorizations are consistent. Existing accounts keep
their original `jwk`/`thumbprint`; migration only adds the fingerprint.

### keyChange (RFC 8555 § 7.3.5)

The directory's `keyChange` URL is implemented at `POST /key-change`:

- The outer JWS is authenticated by the current account key (`kid`).
- The inner JWS must carry the new public key in `jwk`, omit `nonce`, use a
  `url` identical to the outer JWS, and verify with that new key.
- The keyChange object's `account` must be the exact account URL, and `oldKey`
  must normalize to the same actual key as the account's current key.
- The new key is normalized and looked up by fingerprint. If another account
  already owns it, the response is `409 Conflict` with that account's
  `Location` header; the account key is not modified.
- The update is a single compare-and-swap `UPDATE ... WHERE id = ? AND
  thumbprint = ?`, protected by the `UNIQUE` fingerprint index. Concurrent
  rollovers cannot leave a partially updated account, and an identical
  concurrent rollover is idempotent.
- Account ID, URL, status, orders, authorizations, and certificates are not
  modified. A rollover to the same actual key is a no-op so pending challenge
  key authorizations are not rewritten.

### Finalize key selection (RFC 8555 § 11.1)

Finalize re-reads the account row so a concurrent keyChange cannot leave the
comparison using a stale key snapshot. It then:

1. Directly compares the CSR's canonical SPKI DER with the current account
   key's canonical SPKI DER (defensive current-account check).
2. Calls `ensureAccountPublicKeyIndex()`. If any legacy account key is not yet
   indexed, or a conflict is unresolved, the request fails closed with
   `serverInternal` before the order is claimed or a CA is selected.
3. Looks up `public_key_fingerprint` in the UNIQUE account index. A match is
   rejected as `badCSR` and the order stays `ready`; no certificate row is
   written. A CSR key that cannot be normalized is also `badCSR`.

## Database schema and migrations

Drizzle definitions in `src/db/schema.ts` are the source of truth for the ten
application tables. Read and insert types are inferred from those definitions.
JSON remains text, timestamps remain Unix seconds, and flags remain integers.
The Worker requires the latest schema: requests, scheduled jobs, and management
scripts never create tables or upgrade an old database.

Drizzle Kit generates reviewed SQL and snapshots in `drizzle/`; Wrangler applies
that SQL and tracks versions in `d1_migrations`. Do not also run Drizzle's
migrator or use `drizzle-kit push` against production. `security_migrations` is a
separate business readiness marker, not the schema migration history.

```bash
npm run db:generate
npm run db:check
npm run db:migrate:local
```

`db:check` checks migration history and generates into a disposable directory to
verify that the committed snapshots match the schema. Tests initialize their
SQLite fixtures from the same committed SQL. CI also applies migrations to an
empty local D1 database; CI never connects to production.

### Before pushing code that triggers deployment

1. Run `npm run typecheck`, `npm test`, `npm run db:check`,
   `npm run test:runtime`, and `npm audit` with the documented Node/npm versions.
2. Back up the production database with `wrangler d1 export cfms-acme-db --remote
   --output <backup.sql>` outside the repository. Review the pending SQL and
   verify that the existing Worker can still use the migrated schema.
3. Run `npm run db:migrate:remote`, then
   `wrangler d1 migrations list cfms-acme-db --remote`. Verify the required
   columns/indexes, account fingerprints, issuance ledger and readiness marker.
4. Only then push code to trigger the existing automatic deployment.

Neither `npm run deploy` nor CI applies production migrations automatically.
Future changes must remain compatible with the running Worker until the push
is deployed. Roll back Worker code while retaining additive schema changes and
migration history; never remove the fingerprint uniqueness guard or issuance
accounting data to roll back an application release.

### Initial baseline adoption

`0000_baseline.sql` is the only migration using idempotent table/index creation.
An existing database must already have the latest structure before adopting it;
it is not an upgrader for historical schemas. It preserves business rows and
records the baseline through Wrangler. An empty database is initialized by the
same migration. Discardable local D1 state may be removed and recreated with
`npm run db:migrate:local` after stopping local development processes.

Only a database with no certificates receives the initial `issuance-ledger-v1`
readiness marker. A database with existing certificates must retain its original
ledger and readiness marker; baseline adoption must not invent either.

### Account public key fingerprint data backfill

`npm run migrate:account-keys` requires the latest schema and dedicated D1 write
credentials (`CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_D1_DATABASE_ID`, and
`CLOUDFLARE_API_TOKEN`). It performs only the explicit, resumable data backfill,
not schema migrations. Each iteration examines at most 50 accounts missing a
fingerprint and not already listed in `account_key_conflicts`.

The fingerprint is computed from the stored JWK using `normalizePublicKey()`.
Account IDs, URLs, JWK strings, RFC 7638 thumbprints, statuses, contacts, resource
ownership, and existing challenge key authorizations are preserved. Invalid or
duplicate legacy public keys are recorded for administrator review without
silently choosing an account or deleting data. Resolve conflicts through an
audited administrative process, remove the resolved conflict record, and rerun.
Never fabricate fingerprints or remove the UNIQUE fingerprint index.

`ensureAccountPublicKeyIndex()` still verifies the actual UNIQUE index and fails
closed while fingerprints remain unresolved. `newAccount`, `keyChange`, and
`finalize` return HTTP 503 in that state; unrelated authenticated operations can
continue. Inspect readiness without printing public-key material:

```sql
SELECT account_id, reason, public_key_fingerprint, conflicting_account_id, detected_at
FROM account_key_conflicts ORDER BY detected_at;
SELECT COUNT(*) AS unresolved FROM accounts WHERE public_key_fingerprint IS NULL;
```

Historical business data remains readable in the latest schema. Legacy DNS
identifier arrays are accepted; legacy authorizations lazily acquire challenge
rows when needed. Valid authorizations without challenge rows retain the DNS-01
fallback during finalize.

## Configuration

Each setting has one authoritative source. Non-sensitive Worker settings belong
in the exported `CONFIG` object in `src/config.ts`; changing them requires a
build and deployment. Environment variables do not override or merge with them.

| Source | Responsibility |
| --- | --- |
| `src/config.ts` | Certificate policy, renewal window, URLs, directory metadata, CAA issuer, CA exclusions/weights, rate limits and timeouts |
| Worker bindings/secrets | `DB` and private keys whose binding names are declared in the CA registry |
| `registry/ca.json` | CA IDs, public certificate locations, private-key binding names and optional CRL paths; generates the bundled manifest |
| `wrangler.toml` | Deployment, resource bindings and bundling; contains no business configuration in `[vars]` |

`CERT_VALIDITY_DAYS` and `RENEWAL_WINDOW_DAYS` are positive safe integer numbers,
currently `90` and `30`. `ACME_BASE_URL` is empty by default, so published URLs
use the request origin; set it in `CONFIG` to publish a fixed URL.
`CRL_BASE_URL` is `https://cfms-dev.github.io/pki/crl/`, and
`ARI_EXPLANATION_URL` is
`https://www.rfc-editor.org/rfc/rfc9773.html#section-4.2`.

Optional metadata URLs are trimmed and omitted when empty.
`CAA_IDENTITIES: undefined` derives directory identities from
`CAA_ISSUER_DOMAIN_NAME`; an explicit array supplies the published list, and
`[]` omits it. CAA enforcement always uses `CAA_ISSUER_DOMAIN_NAME`.
`EXTERNAL_ACCOUNT_REQUIRED: false` omits that directory flag; this refactor does
not add EAB enforcement. Terms of service are disabled by default with an empty
`TERMS_OF_SERVICE_URL`.

`CA_DIR: "generated/cas"` is the local certificate-read directory and must match
the CA build output and Wrangler's `base_dir`. Wrangler scans only that folder
for additional modules; llhttp WASM is included through its explicit import.
Workers read the manifest and public certificates from the root of `/bundle`.
The manifest is generated, not a second place to edit CA registration.
CA public certificates cannot be replaced by environment bindings.

Removed environment settings (including any dashboard or `.dev.vars` copies):
`ACME_BASE_URL`, `CERT_VALIDITY_DAYS`, `RENEWAL_WINDOW_DAYS`, `CA_DIR`,
`CRL_BASE_URL`, `EXCLUDED_CA_IDS`, `CA_WEIGHTS`, `WEBSITE_URL`,
`ARI_EXPLANATION_URL`, `TERMS_OF_SERVICE_URL`, `CAA_IDENTITIES`,
`CAA_ISSUER_DOMAIN_NAME`, `EXTERNAL_ACCOUNT_REQUIRED`, `CA_CERT_PEM`, `CA_ID`
and `PK_ENV_VAR`. Legacy values have no effect. Before deploying, inspect old
deployment variables and move any intended custom values into `CONFIG`, then
remove those variables. Keep CA registration and key-binding names in the
registry, and key material in secrets. No database migration or changes to
already issued certificates are needed.

HTTP-01 settings in the same `CONFIG` object:

| Constant | Default | Purpose |
| --- | --- | --- |
| `HTTP01_MAX_REDIRECTS` | 5 | Redirect hop limit |
| `HTTP01_REQUEST_TIMEOUT_MS` | 10000 | Per-request timeout |
| `HTTP01_TOTAL_TIMEOUT_MS` | 20000 | Whole-validation budget |
| `HTTP01_MAX_BODY_BYTES` | 8192 | Response body limit |
| `HTTP01_MAX_HEADER_BYTES` | 16384 | Socket headers, trailers and chunk metadata |
| `HTTP01_MAX_WIRE_BYTES` | 65536 | Socket response wire-byte limit |
| `IP_CERT_VALIDITY_HOURS` | 160 | Maximum validity for any certificate containing IPs |
| `CHALLENGE_PROCESSING_STALE_SECONDS` | 60 | Processing-claim recovery |

No new secrets or bindings are required. Undici is a build-only dependency
used to extract llhttp WASM; run the complete build before tests or deployment.

## Tests

```bash
npm test          # build + vitest, includes HTTP-01 unit + integration suites
npm run typecheck # build + wrangler types + tsc --noEmit
npm run build     # generate CA and llhttp assets + build the website
```

Relevant suites: `test/http01-validator.spec.ts` (protocol/SSRF/timeout/redirect/
body/cache handling and fail-closed A/AAAA resolution), `test/http01-flow.spec.ts`
(order, challenge, concurrency, finalize, wildcard, non-public IP rejection, expiry,
per-domain CAA methods, legacy orders), `test/identifiers.spec.ts` (DNS
identifier normalization and IP-literal rejection), `test/finalize-key.spec.ts`
(RFC 8555 § 11.1 CSR/account key separation, including cross-account reuse),
`test/finalize-key-identity.spec.ts` (cross-account rejection under
non-canonical JWK encodings and fail-closed migration/index states),
`test/public-key-identity.spec.ts` (unified SPKI normalization, strict JWK
validation, optional members, RSA/EC/Ed25519), `test/account-key-uniqueness.spec.ts`
(account registration, onlyReturnExisting, equivalent encodings, concurrent
registration), `test/key-change.spec.ts` (RFC 8555 § 7.3.5 rollover, reuse,
concurrency, order ownership), `test/account-key-migration.spec.ts`
(idempotent legacy backfill, duplicate conflicts, invalid JWKs, legacy
authentication, UNIQUE enforcement), `test/challenge-state.spec.ts` (processing
generations and stale-claim fencing), and `test/schema-migration.spec.ts`
(challenges table/column migration and legacy authorization backfill).

## Protocol conformance notes

- **Wildcard authorizations (RFC 8555 § 7.1.4).** The stored authorization
  identifier remains `*.example.com` so DNS-01 and CAA logic can distinguish
  wildcards, but the authorization response removes the `*.` prefix from
  `identifier.value` and sets `wildcard: true`. The order object still lists the
  wildcard identifier, as required by § 7.1.3.
- **Finalize CSR matching (RFC 8555 § 7.4 / RFC 8738).** CSR DNS/IP SANs
  must exactly match the typed order set. A valid DNS CN is also included in
  that comparison; an IP CN cannot replace an IP SAN. Other SAN types are
  rejected. Issued SANs come only from authorized order identifiers, encoded
  as dNSName/iPAddress. Pure IP certificates have an empty subject and critical
  SAN; mixed certificates use the first DNS identifier as their CN.
- **Finalize key selection (RFC 8555 § 11.1).** The CSR public key must not be
  the account key that authenticated the finalize request, and must not reuse a
  key already registered to any other ACME account. Account keys are compared
  through `SHA-256(canonical SPKI DER)` (`public_key_fingerprint`), not through
  the RFC 7638 thumbprint: the thumbprint is a protocol value that differs for
  legal alternate encodings of the same key, and the stored JWK JSON is not
  canonical. The CSR key's SPKI is imported/re-exported through WebCrypto in
  exactly the same way. The cross-account check is a point lookup through the
  accounts table's UNIQUE `public_key_fingerprint` index. A match is rejected
  as `badCSR`, and a CSR key that cannot be normalized is also rejected as
  `badCSR`. The check runs before the order is claimed and before any
  intermediate CA is selected. If a legacy account has not been indexed yet,
  the request fails closed with `serverInternal` instead of assuming the key is
  unused.
- **Account key rollover (RFC 8555 § 7.3.5).** `POST /key-change` verifies the
  nested inner/outer JWS, exact account URL, and `oldKey`, rejects a new key
  already owned by any account (`409` with that account's `Location`), and
  updates the account key, RFC 7638 thumbprint, and SPKI fingerprint atomically
  with a compare-and-swap `UPDATE`. Orders and authorizations are untouched.
- **CAA validationmethods (RFC 8657 § 4).** Finalize collects the challenge
  type that actually succeeded for each authorization and evaluates each
  domain's CAA records against that domain's method(s). A mixed order can use
  dns-01 for one identifier and http-01 for another. A valid legacy
  authorization with no challenge row falls back to dns-01, which is the only
  method that existed before HTTP-01 support. An explicitly empty
  `validationmethods` list authorizes no method, and an `accounturi`-restricted
  property is not accepted when the requesting account URI is unknown
  (RFC 8657 § 3).

## Operational limitations

- **DNS rebinding cannot be fully eliminated.** Workers `fetch()` resolves DNS
  itself and does not allow pinning the connection to a previously resolved IP
  (unlike, for example, Boulder's pre-resolved dialer). The DoH checks are now
  fail-closed — an A or AAAA query that cannot be resolved definitively aborts
  the validation instead of proceeding on partial information — but they remain
  a pre-check, not a proof that the connection used the checked address: an
  attacker-controlled authoritative DNS server can return public addresses to
  the DoH resolvers and a private address to the `fetch()` resolver, or change
  the answer between the pre-check and the request. The fail-closed rule does
  not stop that rebinding. What remains mitigated is the direct case (a name
  that already resolves to a non-public address is rejected before the
  request), plus the fixed GET path/method, the 80/443 port restriction,
  redirect re-checks, the 20s budget, the 8 KiB body limit, the absence of
  credentials/cookies, and error responses that do not echo the target's body.
  See RFC 8555 § 10.4: ACME HTTP validation is inherently a limited SSRF
  surface, and an operator should ensure validation queries can only reach
  public servers. Platform-level egress filtering is not a substitute for
  address pinning and is not assumed by this code.
- **HTTPS redirect targets must present a trusted certificate.** Workers
  `fetch()` verifies TLS certificates and has no supported option to disable
  verification; a self-signed, expired, hostname-mismatched, or incomplete
  chain causes the validation request to fail even if the HTTP-01 body would be
  correct. Cloudflare documents that Workers subrequests to external hostnames
  always use Full (strict) SSL, so this typically surfaces as an error response
  such as 526. Let's Encrypt/Boulder deliberately skip certificate verification
  when following HTTP-01 redirects, because this challenge is used to bootstrap
  a valid certificate. This Worker retains certificate verification for both
  domain fetches and native-TLS IP sockets. The limitation is explicit: redirect from `http://` to `https://` works only when
  the HTTPS origin has a publicly trusted certificate. Plain-HTTP redirects and
  the initial HTTP request are unaffected.
- **Cache status is not authoritative.** A `cf-cache-status: HIT` response is
  accepted if and only if its body exactly matches the current key
  authorization. Stale cached content fails the body check; the request's
  no-cache/no-store headers and the fixed, unguessable token path limit the
  window. Operators should not configure cache rules that serve
  `.well-known/acme-challenge/*` from cache with a long TTL, but a HIT is not
  itself a validation failure.
- **Cloudflare partial (CNAME) zones** can make outbound `fetch()` fail with
  HTTP 530/1016 if the target hostname is not present in Cloudflare DNS. This is
  a platform behavior, not an ACME-specific policy.
- Validation is performed inline; a Worker isolate eviction during validation
  can leave a challenge in `processing` until the stale-claim timeout allows a
  retry. There is no background queue. The generation fence makes the
  post-reclaim state correct even if the evicted request resumes.
- `finalize` performs CAA revalidation and checks authorization expiry again
  immediately before persisting the certificate. CAA `validationmethods` is
  evaluated against the method(s) that actually validated each authorization.

## Security operations

Successful issuance quotas are enforced atomically with certificate persistence
using `issuance_ledger`. Unverified orders consume only their own account's order
budget. Shared quotas count only successful issuance in the previous seven days;
historical order counters are not used. Revocation does not refund capacity.

Native Workers bindings admit approximately 300 API requests/minute/source IP and
ten account registration requests/minute/source IP before D1 access. Shared NATs
share these budgets. Missing or failed bindings reject requests with HTTP 503;
limit rejections return 429 and `Retry-After: 60`. Both bypass nonce generation.
Static pages, directory reads and OPTIONS retain their database-free behavior.
Expired nonces are cleaned every five minutes in bounded batches. Use
`npm run cleanup:nonces` repeatedly to drain a reported backlog.

Use Node.js 26.13.0 and npm 12.2.2. Run `npm ci`, `npm run typecheck`,
`npm test`, `npm run test:runtime`, and `npm audit` before deployment.
The runtime test uses Wrangler's exact bundled workerd/Miniflare version and
applies committed migrations before certificate issuance with disposable CA material.

`CONFIG.CERT_VALIDITY_DAYS` and `CONFIG.RENEWAL_WINDOW_DAYS` must be positive
safe integer day counts. The issuance interval is capped by the selected CA's expiration.
`CONFIG.CRL_BASE_URL` is set to `https://cfms-dev.github.io/pki/crl/`; newly issued
certificates include a per-CA CRL distribution point. No retroactive certificate
extension changes are possible.

JWS requests require `application/jose+json`, a maximum 64 KiB body, and exact
published URL/account URL binding. POST-as-GET payloads must be empty.
DNS TXT and CAA lookups have a 20-second budget, 10-second request limit,
64 KiB response limit and at most eight alias hops. DNS errors block issuance.
HTTP-01 keeps its existing target restrictions; DoH results cannot pin Workers'
independent fetch DNS resolution and do not eliminate DNS rebinding risk.

Back up D1 before operational changes. Preserve issuance-ledger data and its
initialization marker when restoring or moving a database. Use a scoped D1 write
token for management commands and a separate read-only token for verified CRL
revocation export. Keep issuance paused if rolling back to a build without
atomic issuance accounting.


### IP acceptance coverage

`test/llhttp.spec.ts`, `test/ip-http01.spec.ts` and `test/ip-flow.spec.ts` cover
strict framing and fragmentation, bounds, numeric IPv4/IPv6 dial/Host, native
TLS selection, redirect safety, timeout cleanup, typed orders/SAN issuance,
160-hour validity, migration, CAA filtering, limits, ARI and revocation.
`test:runtime` uses the same generated WASM as Node tests and exercises actual
workerd parsing plus DNS/IP/mixed certificate issuance with disposable CA material.
The socket peer is injected locally; this is not a live public-network challenge.
Before production rollout, complete a real deployed-Worker HTTP-01 flow against
controlled public IPv4 and IPv6 origins. The local connectivity experiment is
supporting network-primitive evidence and remains outside the production patch.
