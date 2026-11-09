# CFMS-PKI ACME Worker

RFC 8555 ACME server deployed on Cloudflare Workers with a D1 database and a
weighted pool of intermediate CAs. Supported validation methods:

- `dns-01` (existing, DNS-over-HTTPS TXT lookup)
- `http-01` (RFC 8555 § 8.3, for non-wildcard DNS identifiers)

The ACME directory is served at `/directory` (for production:
`https://acme.cfms-pki.crpteam.club/directory`).

The root `/` serves an English HTML service overview, independently of D1.
Use `/directory`, rather than the homepage, as your ACME client's server URL.
The homepage supports GET and HEAD; other methods return 405, with OPTIONS
retaining the server's CORS preflight behavior.

Web assets live in `public/`: `index.html`, `terms.html`, `privacy.html` and
`styles.css`. Wrangler's `[assets]` configuration binds this directory as
`ASSETS`, with `run_worker_first = true` and `html_handling = "none"`.
`src/routes/website.ts` handles these requests before database initialization;
CSS and image requests (including missing files) also stay independent of D1.

The homepage is read through `ASSETS.fetch()` and rendered with escaped,
runtime-configured directory and CRL links. It retains its five-minute public
cache policy; source asset validators are removed from the rendered response.
`/index.html` redirects to `/`. The policy pages use `/terms.html` and
`/privacy.html`, with shared styles at `/styles.css`. There are no browser
scripts. Website failures do not generate an ACME nonce or access D1.

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
| `dns` | Yes | Includes wildcard `*.example.com` orders |
| `ip` (RFC 8738) | No | `new-order` returns `urn:ietf:params:acme:error:unsupportedIdentifier` |
| anything else | No | Same `unsupportedIdentifier` problem document |

Wildcard identifiers only receive a `dns-01` challenge. HTTP-01 is not offered
and a manually injected HTTP-01 challenge for a wildcard is rejected as
`malformed`.

A `dns` identifier must actually be a DNS name. IPv4 and IPv6 literals are
rejected with `urn:ietf:params:acme:error:rejectedIdentifier`, including the
legacy numeric IPv4 notations that the WHATWG URL parser rewrites into an
address (`127.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`, `127.0.0.1.`).
The check runs in the shared identifier validator before any order or
authorization row is written, so a rejected request leaves no partial state.
Only `type: "dns"` identifiers are supported; `type: "ip"` and unknown types
still return `unsupportedIdentifier`.

### Why IP identifiers are rejected

A correct RFC 8738 HTTP-01 validation must connect directly to the requested IP
address on TCP port 80, send an HTTP request with the IP literal in the `Host`
header, and prove that the response came from that exact address. The current
Cloudflare Workers runtime does not provide a supported way to do this:

- Workers [`fetch()` cannot target IP address literals](https://developers.cloudflare.com/workers/platform/known-issues/#fetch-to-ip-addresses).
  The documented workaround is to create a DNS name that resolves to the IP,
  which would no longer be direct RFC 8738 IP validation.
- The [`connect()` TCP API](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/)
  blocks private, localhost, and Cloudflare-owned destinations, and the runtime
  documentation explicitly directs HTTP traffic on ports 80/443 to `fetch()`.
  Building an ad-hoc HTTP client on raw sockets would not be a documented or
  stable HTTP validation path.
- Using an external proxy/VPS or a temporary DNS alias would violate the
  requirement to validate the requested IP directly.

Because IP validation is not implemented, the RFC 8738 six-day / 160-hour IP
certificate validity limit is intentionally not introduced: there is no code
path that can issue a certificate containing an IP SAN.

## HTTP-01 flow

1. `POST /new-order` creates one authorization per unique DNS identifier, plus
   `dns-01` and (for non-wildcard identifiers) `http-01` challenge rows.
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

Each hop is checked before any request is made:

- Initial request: `http:` on port 80 only.
- Redirects: `http:`/80 or `https:`/443 only; no credentials, fragments, IP
  literals, local/special-use hostnames, or invalid DNS names.
- At most five redirects; redirect loops are rejected.
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

## Database migration

`Database.initSchema()` (run lazily by the Worker) creates the new
`challenges` table and its index with `CREATE TABLE IF NOT EXISTS`. Existing
deployments therefore receive the table automatically on the first request; no
destructive migration or manual column change is required. `schema.sql` contains
the same definitions for fresh databases.

### Account public key fingerprint backfill

`initSchema()` adds `accounts.public_key_fingerprint`, the UNIQUE index
`idx_accounts_public_key_fingerprint`, the partial
`idx_accounts_missing_public_key_fingerprint` index, and the
`account_key_conflicts` table. `ALTER TABLE ... ADD COLUMN` does **not**
compute cryptographic values for existing rows; legacy accounts start with
`public_key_fingerprint IS NULL` by design.

An administrator runs `npm run migrate:account-keys` using a dedicated D1 write token.
The script resumes the idempotent backfill in `src/db/account-keys.ts`:

- Only rows with `public_key_fingerprint IS NULL` and no recorded conflict are
  examined; the check is a cheap indexed existence probe, not an unconditional
  full-table scan on every request.
- The fingerprint is computed from the stored JWK through the same
  `normalizePublicKey()` used everywhere else.
- Each iteration processes at most 50 accounts; the management script resumes
  until completion or reports unresolved conflicts. Public requests never run
  a backfill; key-sensitive operations return HTTP 503 until it is complete.
- Account IDs, URLs, JWK strings, RFC 7638 thumbprints, statuses, contacts, and
  order/authz/certificate ownership are never rewritten. Existing HTTP-01 and
  DNS-01 key authorizations therefore keep working.

If two legacy accounts normalize to the same actual key, or a legacy JWK cannot
be normalized, the migration does not choose a winner or delete anything. It
leaves the row unindexed and records it in `account_key_conflicts` with the
account ID(s), a reason code, the public fingerprint (a public hash), and the
timestamp. The UNIQUE index prevents any later write from silently assigning
the duplicate fingerprint.

`ensureAccountPublicKeyIndex()` fails closed while any account remains
unindexed. In that state `newAccount`, `keyChange`, and `finalize` return
`urn:ietf:params:acme:error:serverInternal`; JWS authentication, account
updates, order reads, and existing challenge validation still work. Resolve the
conflicts manually, then rerun the management script:

```sql
-- Inspect (never contains private key material)
SELECT account_id, reason, public_key_fingerprint, conflicting_account_id, detected_at
FROM account_key_conflicts
ORDER BY detected_at;

-- Verify completeness: must be 0 before certificate issuance is safe
SELECT COUNT(*) AS unresolved FROM accounts WHERE public_key_fingerprint IS NULL;
```

For a duplicate actual key, decide which account is canonical, remove or
re-key the duplicate through an audited administrative process (never delete
silently), delete its `account_key_conflicts` row, and rerun the management script. For an invalid legacy JWK, repair the row's `jwk`/`thumbprint`
through an audited process, delete the conflict row, and rerun the management script. Do not drop
`idx_accounts_public_key_fingerprint` while accounts exist, and do not edit
`public_key_fingerprint` by hand to a fabricated value.

### Deployment order and rollback

1. Back up/inspect the production D1 database.
2. Run `npm run migrate:account-keys` with D1 management credentials; the script
   applies incremental schema changes and backfills public key identities.
3. Run the verification queries above, then deploy the Worker (`npm run deploy`).
   New columns for finalize leases/generations and certificate CA IDs are additive.
4. If conflicts exist, keep the fail-closed state until they are reviewed.
   Certificate issuance remains unavailable, which is intentional.

Operators who prefer to apply schema before deploying traffic can run the same
statements manually and ignore the expected `duplicate column name` error on a
re-run:

```bash
npx wrangler d1 execute cfms-acme-db --remote --command \
  "ALTER TABLE accounts ADD COLUMN public_key_fingerprint TEXT;"
npx wrangler d1 execute cfms-acme-db --remote --command \
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_public_key_fingerprint ON accounts (public_key_fingerprint);"
npx wrangler d1 execute cfms-acme-db --remote --command \
  "CREATE INDEX IF NOT EXISTS idx_accounts_missing_public_key_fingerprint ON accounts (id) WHERE public_key_fingerprint IS NULL;"
npx wrangler d1 execute cfms-acme-db --remote --command \
  "CREATE TABLE IF NOT EXISTS account_key_conflicts (account_id TEXT PRIMARY KEY, reason TEXT NOT NULL, public_key_fingerprint TEXT, conflicting_account_id TEXT, detected_at INTEGER NOT NULL);"
```

Rollback is additive and non-destructive: reverting the Worker code leaves the
new column/table/indexes in place and the previous Worker simply ignores them.
Do not roll back by deleting the fingerprint column or its UNIQUE index while
accounts exist, because that reopens the key-reuse vulnerability.


The `validation_generation` column is part of the `CREATE TABLE` definition.
For a `challenges` table that was created by an earlier deployment without it,
`initSchema()` issues an idempotent
`ALTER TABLE challenges ADD COLUMN validation_generation INTEGER NOT NULL
DEFAULT 0`; the "duplicate column name" error on an already-upgraded table is
intentionally ignored. Existing challenge rows start at generation 0 and are
reclaimed normally.

Legacy orders and authorizations created before the `challenges` table existed
are upgraded lazily by `ensureChallengesForAuthorization()` when the
authorization is read: a pending authorization receives dns-01 plus (for
non-wildcard identifiers) http-01, a valid authorization is represented as a
valid dns-01 challenge, and an invalid authorization as an invalid dns-01
challenge. Finalize also tolerates a valid legacy authorization with no
challenge rows by treating it as the dns-01 method that existed at the time;
it does not need to write challenge rows.

Each challenge row stores its own token, status, error problem document,
`validated_at`, `processing_started_at`, and `validation_generation`.

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

`CA_DIR: "cas"` is the local certificate-read directory and must match the
existing build convention. The bundler writes `cas`, Wrangler bundles that
folder, and Workers read the manifest and public certificates from `/bundle`.
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
| `CHALLENGE_PROCESSING_STALE_SECONDS` | 60 | Processing-claim recovery |

No new secrets, bindings, or third-party dependencies are required.

## Tests

```bash
npm test          # vitest, includes HTTP-01 unit + integration suites
npm run typecheck # wrangler types + tsc --noEmit
npm run build     # bundle CA assets
```

Relevant suites: `test/http01-validator.spec.ts` (protocol/SSRF/timeout/redirect/
body/cache handling and fail-closed A/AAAA resolution), `test/http01-flow.spec.ts`
(order, challenge, concurrency, finalize, wildcard, IP rejection, expiry,
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
- **Finalize CSR matching (RFC 8555 § 7.4).** The CSR's SAN extension may only
  contain dNSName entries, and the resulting set (including a syntactically
  valid commonName) must equal the order identifier set. Non-DNS SAN types
  (notably IP) are rejected as `badCSR`; the issuer also builds the issued SAN
  exclusively from the stored order identifiers, never from CSR-supplied names.
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
  a valid certificate. This Worker cannot safely emulate that: disabling
  verification is impossible, and using raw `connect()` sockets to bypass it
  would replace a documented HTTP transport with an ad hoc one. The limitation
  is therefore explicit: redirect from `http://` to `https://` works only when
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

Use Node.js 26.13.0 and npm 12.2.2. Run `npm ci`, `npm run typecheck`,
`npm test`, `npm run test:runtime`, and `npm audit` before deployment.
The runtime test uses Wrangler's exact bundled workerd/Miniflare version and
performs a local D1 upgrade and certificate issuance with disposable CA material.

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

See [the security rollout runbook](../../docs/security-rollout.md) for D1
backup, migration, Cloudflare credentials, verified revocation export and rollback.
