# CFMS-PKI ACME Worker

RFC 8555 ACME server deployed on Cloudflare Workers with a D1 database and a
weighted pool of intermediate CAs. Supported validation methods:

- `dns-01` (existing, DNS-over-HTTPS TXT lookup)
- `http-01` (RFC 8555 § 8.3, for non-wildcard DNS identifiers)

The ACME directory is served at `/directory` (for production:
`https://acme.cfms-pki.crpteam.club/directory`).

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

## Database migration

`Database.initSchema()` (run lazily by the Worker) creates the new
`challenges` table and its index with `CREATE TABLE IF NOT EXISTS`. Existing
deployments therefore receive the table automatically on the first request; no
destructive migration or manual column change is required. `schema.sql` contains
the same definitions for fresh databases.

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

New constants in `src/config.ts`:

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
`test/challenge-state.spec.ts` (processing generations and stale-claim
fencing), and `test/schema-migration.spec.ts` (challenges table/column
migration and legacy authorization backfill).

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
  key already registered to any other ACME account. Both sides are normalized
  to canonical SubjectPublicKeyInfo DER (the CSR's SPKI is imported and
  re-exported through WebCrypto) before comparison, so JWK field order and key
  encoding do not matter. The CSR key's RFC 7638 thumbprint is then looked up
  through the accounts table's UNIQUE thumbprint index, which keeps the
  cross-account check a point lookup instead of a table scan. A match is
  rejected as `badCSR`, and a CSR key that cannot be normalized is also
  rejected as `badCSR`; the check runs before the order is claimed and before
  any intermediate CA is selected.
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
