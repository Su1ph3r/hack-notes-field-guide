---
tags:
  - hack-notes
  - checklist
  - api
---

# API Security Testing Checklist

> Methodology for testing REST, GraphQL, gRPC, and WebSocket APIs against the OWASP API Security Top 10 (2023). Work top to bottom. The core discipline throughout is two-account differential testing: every authorization claim is proven by replaying one account's request with another account's credentials. Commands and payloads live in the linked cheatsheets; this file is the ordered method.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Discovery and Inventory](#2-discovery-and-inventory)
- [3. Authentication](#3-authentication)
- [4. Object-Level Authorization (BOLA)](#4-object-level-authorization-bola)
- [5. Function-Level Authorization (BFLA)](#5-function-level-authorization-bfla)
- [6. Object Property Level Authorization](#6-object-property-level-authorization)
- [7. Resource Consumption](#7-resource-consumption)
- [8. Business-Flow Abuse and SSRF](#8-business-flow-abuse-and-ssrf)
- [9. GraphQL-Specific Testing](#9-graphql-specific-testing)
- [10. Misconfiguration and Improper Inventory](#10-misconfiguration-and-improper-inventory)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

Get the contract right before touching the API. APIs are easy to over-test (rate limits, billing endpoints, downstream third parties) and easy to under-scope (shadow versions, partner hosts).

### Authorization and Boundaries
- [ ] **Confirm written scope:** Exact base URLs, hostnames, API versions, and whether subdomains/partner gateways are in or out. Get the FQDN allow-list in writing.
- [ ] **Identify environment:** Sandbox vs staging vs production. Prefer a non-prod environment that mirrors prod authz logic. If only prod is available, agree on data-mutation limits and a rollback contact.
- [ ] **Clarify destructive-action policy:** DELETE/PATCH on real records, payment capture, email/SMS triggers, bulk export. Get explicit sign-off or carve-outs.
- [ ] **Map third-party blast radius:** Note any endpoint that proxies to external providers (payments, KYC, mail, webhooks) so SSRF and abuse tests do not hit out-of-scope systems.
- [ ] **Confirm rate-limit and WAF posture:** Ask whether a WAF/API gateway sits in front, whether your tester IPs can be allow-listed, and the acceptable request rate. Get a contact to unban test IPs.

### Documentation and Specs
- [ ] **Request the API spec:** OpenAPI/Swagger (v2/v3), Postman collection, GraphQL SDL, gRPC `.proto` files, AsyncAPI for event/WebSocket. A spec turns blind fuzzing into targeted testing.
- [ ] **Request a data dictionary:** Object models, ID formats (sequential int, UUIDv4, hashid, ULID), and which fields are server-controlled (roles, balances, ownership).
- [ ] **Note auth mechanism up front:** Bearer JWT, opaque token, API key, mTLS, session cookie, HMAC-signed request. Drives the entire Authentication phase.

### Accounts (the core requirement)
- [ ] **Obtain two accounts minimum, same role/tenant:** Account A and Account B at the same privilege level. This is the BOLA/BFLA differential baseline. Without two same-role accounts you cannot prove object-level authorization.
- [ ] **Obtain a privilege ladder:** At least one low-priv and one high-priv (admin) account to test vertical (BFLA) escalation.
- [ ] **Obtain cross-tenant accounts:** For multi-tenant APIs, one account in Org-1 and one in Org-2 to prove tenant isolation. Cross-tenant BOLA is frequently the highest-impact finding.
- [ ] **Establish an unauthenticated baseline:** Keep a no-token client to check which routes are reachable pre-auth.
- [ ] **Record every account's identifiers:** user IDs, org IDs, object IDs created by each, and tokens. Keep a credentials matrix you can reference in every later phase.

```
Account matrix (fill before testing):
  A-low   user_id=___  org=Org1  token=___  owns: obj_A1, obj_A2
  B-low   user_id=___  org=Org1  token=___  owns: obj_B1, obj_B2
  C-low   user_id=___  org=Org2  token=___  owns: obj_C1
  D-admin user_id=___  org=Org1  token=___
```

---

## 2. Discovery and Inventory

You cannot test routes you have not found. Enumerate every host, version, route, method, and parameter, including the ones the spec does not mention (shadow APIs) and the ones that should be dead (zombie APIs). See [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md) for passive host and subdomain discovery.

### Find the Spec and the Surface
- [ ] **Hunt for live documentation:** Probe `/openapi.json`, `/swagger.json`, `/swagger-ui`, `/v3/api-docs`, `/api-docs`, `/redoc`, `/graphql`, `/graphiql`, `/.well-known/`, `/actuator`, `/metrics`. A leaked spec is the fastest path to full coverage.
- [ ] **Diff the spec against reality:** Routes present in traffic but absent from the spec are shadow APIs. Routes in the spec returning 404/410 may be zombie or pre-release. Test both; they are often unguarded.
- [ ] **Enumerate versions:** `/v1`, `/v2`, `/api/v3`, `?version=`, `Accept: application/vnd.api+json;version=1`. Old versions frequently lack fixes present in current ones (downgrade is its own attack, see Phase 5).
- [ ] **Brute-force routes:** Use API-specific wordlists against the base path. Watch for method-specific behavior (a path may 404 on GET but accept POST/PUT).

### Mine the Clients
- [ ] **JS source mining:** Pull and beautify all frontend bundles. Grep for path fragments, full URLs, GraphQL operation names, API keys, and feature flags. Source maps, if present, expose internal route tables.
- [ ] **Mobile app extraction:** Decompile the APK/IPA, extract strings and resources, and pull API hosts, hardcoded keys, certificate pins, and undocumented endpoints. See [Mobile App Testing](../Cheatsheets/Mobile%20App%20Testing.md). Mobile clients routinely call admin/internal endpoints the web app hides.
- [ ] **Capture real traffic:** Proxy the web and mobile clients through Burp/mitmproxy, exercise every feature, and build the endpoint inventory from observed calls. Real traffic reveals parameters and headers no wordlist will.
- [ ] **Inspect WebSocket and gRPC channels:** Find `wss://` upgrades and gRPC endpoints (HTTP/2, `application/grpc`). For gRPC without a `.proto`, attempt server reflection to enumerate services and methods.

### Catalog Per Endpoint
- [ ] **Build a method matrix:** For each path, record which of GET/POST/PUT/PATCH/DELETE/OPTIONS it honors. `OPTIONS` and `Allow:` headers often disclose more methods than the docs.
- [ ] **Record auth requirement per route:** unauth-reachable, any-token, role-gated. This drives Phases 3-5.
- [ ] **Note ID and parameter formats:** Which params carry object references, their format, and whether they appear in path, query, body, or header. Feeds BOLA testing directly.

---

## 3. Authentication

API2:2023 Broken Authentication. Test how tokens are issued, validated, scoped, and revoked. Token forgery or replay collapses every downstream control. JWT-specific attacks and tooling live in [API JWT and GraphQL](../Cheatsheets/API%20JWT%20and%20GraphQL.md).

### Token Issuance and Lifecycle
- [ ] **Map the login/refresh flow:** Where tokens are minted, their TTL, refresh-token rotation, and whether refresh tokens are single-use. Reused or non-rotating refresh tokens enable persistence.
- [ ] **Test logout/revocation:** After logout or password change, replay the old access and refresh tokens. If they still work, session invalidation is broken.
- [ ] **Check token entropy and predictability:** Opaque tokens should be unguessable. Sequential or timestamp-derived tokens are forgeable.
- [ ] **Look for credential-stuffing and brute-force gaps:** No lockout, no rate limit, and verbose login errors (user-enumeration via differing messages or timing). Pair with Phase 7.

### JWT Attacks
- [ ] **Decode and inspect every JWT:** Header `alg`/`kid`/`jku`/`x5u`, claims `iss`/`aud`/`exp`/`sub`/`scope`/`role`/tenant. Note anything authorization-relevant in the claims (see Phase 5).
- [ ] **`alg:none` / unsigned acceptance:** Strip the signature and set `alg` to `none`/`None`/`NONE`. If accepted, total forgery.
- [ ] **HMAC/RSA algorithm confusion:** Re-sign an RS256 token as HS256 using the public key as the HMAC secret. If the server verifies, you mint arbitrary tokens. Test PS256/ES256 cross-acceptance too.
- [ ] **`kid` injection:** Manipulate `kid` for path traversal (`../../dev/null`), SQLi, or command injection in key lookup. A `kid` pointing at a predictable file lets you sign with known key material.
- [ ] **`jku`/`x5u` SSRF and key injection:** Point `jku` at a Collaborator URL to confirm the server fetches it (SSRF), then host your own JWKS there, sign with your private key, and check for acceptance. Verify the server pins `jku` to an allow-list.
- [ ] **Claim tampering:** Modify `exp` (expiry not enforced), `sub`/`user_id` (impersonation), `aud` (cross-service token reuse), and signature-stripping on weak verifiers.
- [ ] **Weak HMAC secret:** Crack HS256 tokens against a wordlist offline. A guessable secret means full forgery.

### API Keys, OAuth/OIDC, mTLS
- [ ] **API key scope and placement:** Test whether one tenant's key works against another's data, whether keys are over-scoped, and whether keys leak in URLs/logs/referrers. Check key rotation and revocation.
- [ ] **OAuth/OIDC flow flaws:** `redirect_uri` validation (open redirect, path/subdomain bypass), `state` for CSRF, PKCE presence on public clients, scope upgrade, and authorization-code reuse/leak. Test implicit-flow token leakage if still enabled.
- [ ] **Token-audience confusion:** A token minted for service X accepted by service Y. Common in microservice meshes sharing a signing key.
- [ ] **mTLS handling:** If client certs gate access, test whether the API also accepts requests without a cert at an alternate port/path, trusts a client-supplied `X-SSL-Client-*` header, or accepts any CA-signed cert. Header-trusted client identity is a frequent bypass.

---

## 4. Object-Level Authorization (BOLA)

API1:2023, the number-one API risk and roughly 40% of API attacks. This is where two accounts earn their keep. The test is mechanical: take a request that works for Account A against A's object, swap in B's object ID while keeping A's token, and see if A reads or mutates B's data.

### Method
- [ ] **Inventory every object reference:** Every ID in path, query, body, header, or GraphQL variable that names a resource. Each is a BOLA candidate.
- [ ] **Differential swap (the core test):** As Account A, request A's own object and confirm 200. Replay with B's object ID and A's token. A 200 with B's data is BOLA. A 403/404 is the expected control.

```http
GET /api/v2/orders/1001 HTTP/1.1   # A's order, A's token -> 200 (baseline)
GET /api/v2/orders/1002 HTTP/1.1   # B's order, A's token -> expect 403/404
Authorization: Bearer <A_token>
```

- [ ] **Test all verbs, not just GET:** Read may be blocked while PUT/PATCH/DELETE on the same object ID is not. Run the swap for every method the route honors.
- [ ] **Cross-tenant swap:** Repeat with C (Org-2). Cross-tenant read/write is typically the highest-severity BOLA. Tenant ID in a header or JWT claim that the server trusts without re-checking ownership is a classic break.

### ID Handling Variations
- [ ] **Sequential and enumerable IDs:** Increment/decrement to find neighbors. Automate the swap across a range and flag any non-403 response. Pair with Indago for breadth.
- [ ] **UUID/hashid/ULID handling:** "Unguessable" IDs are not an authz control. Harvest real IDs from other responses (lists, references, error messages, exports) and replay them under A's token. The ID being opaque does not mean the object is protected.
- [ ] **Nested and indirect IDs:** `/users/{A}/cards/{cardId}` where the server trusts `cardId` and ignores `{A}`. Test mismatched parent/child IDs (A's user path, B's card) and IDs buried in nested JSON bodies or arrays.
- [ ] **Encoded and wrapped references:** Base64, JSON, or composite keys in a single param. Decode, swap the inner ID, re-encode.
- [ ] **Secondary-context BOLA:** IDs in filters, search, export, GraphQL `node(id:)`, and bulk endpoints that bypass the per-object check the single-GET route enforces.

---

## 5. Function-Level Authorization (BFLA)

API5:2023 Broken Function Level Authorization. Vertical access control: can a low-priv user invoke high-priv functions. Where BOLA swaps the object, BFLA swaps the role and the operation.

- [ ] **Map admin and privileged routes:** From the spec, JS, and mobile mining, list `/admin`, `/internal`, `/manage`, user-role-change, billing, and config endpoints. Many are simply hidden, not protected.
- [ ] **Low-priv invokes high-priv:** Replay every admin request using the low-priv token. A 200 is BFLA. Confirm against an admin-token baseline so you know the call is otherwise valid.
- [ ] **HTTP method tampering:** A route may gate GET but not POST/PUT/DELETE, or honor `X-HTTP-Method-Override: PUT` / `_method=DELETE` to reach a privileged verb. Test override headers and params.
- [ ] **Verb-and-path mismatch:** `GET /admin/users` blocked but `POST /admin/users` (create) or `DELETE /admin/users/{id}` open. Enumerate the full verb set per privileged path.
- [ ] **Role claim tampering:** If role/scope lives in a client-readable JWT or body (`"role":"user"` -> `"admin"`, `"isAdmin":false` -> `true`), tamper and replay. Server must re-derive role server-side, not trust the token claim blindly.
- [ ] **Version downgrade:** If `/v2` enforces a control that `/v1` lacks, call the legacy version. Old versions and deprecated routes often miss authorization added later.
- [ ] **Forced browsing of state transitions:** Skip workflow steps (call `/checkout/complete` without `/checkout/pay`, approve your own request). Overlaps with Phase 8.

---

## 6. Object Property Level Authorization

API3:2023 Broken Object Property Level Authorization, which merges mass assignment (write side) and excessive data exposure (read side). The object may be yours, but individual properties have their own authorization.

### Mass Assignment (write side)
- [ ] **Map writable vs server-controlled fields:** From the spec/data dictionary, identify properties the client should never set: `role`, `isAdmin`, `is_verified`, `balance`, `owner_id`, `org_id`, `status`, `price`, `created_at`.
- [ ] **Inject extra properties:** Add those fields to create/update bodies and check whether they take effect. Privilege escalation, price tampering, and ownership reassignment all live here.

```http
PATCH /api/v2/users/me HTTP/1.1
Authorization: Bearer <low_priv_token>
Content-Type: application/json

{"display_name":"x","role":"admin","org_id":"Org2","email_verified":true}
```

- [ ] **Reuse response shapes as request bodies:** GET an object, take the full returned JSON (including read-only fields), and PUT it back modified. APIs that bind the whole body are vulnerable.
- [ ] **Test nested and array mass assignment:** Privileged fields inside nested objects or list items often skip the validation applied to top-level fields.
- [ ] **GraphQL input objects:** Mutations frequently accept input types with more fields than the UI uses. Enumerate input-type fields from the schema and set the privileged ones.

### Excessive Data Exposure (read side)
- [ ] **Inspect full response bodies, not the rendered UI:** APIs commonly return entire objects and rely on the client to hide fields. Look for PII, password hashes, internal flags, tokens, other users' data, and `_internal`/`debug` fields.
- [ ] **Check list and search endpoints:** Collection responses leak more per-item data than the single-object view, and may include records the user should not see at all (overlaps BOLA).
- [ ] **Diff responses across roles:** Compare the same object fetched as low-priv vs admin. Fields visible to low-priv that should be admin-only are property-level read breaks.
- [ ] **GraphQL over-selection:** Request sensitive fields directly even if the UI never asks for them. Field-level authorization is often missing while object-level passes.

---

## 7. Resource Consumption

API4:2023 Unrestricted Resource Consumption. Test rate limiting, pagination, batching, and query-cost controls. Coordinate with the client before load-style tests (see scoping). Confirm, do not flood: a single proof of a missing limit suffices.

- [ ] **Probe rate limits per dimension:** Per-IP, per-token, per-account, per-endpoint. A global IP limit often misses per-account brute force. Note `X-RateLimit-*`/`Retry-After` headers and whether limits reset trivially.
- [ ] **Bypass rate limits:** Rotate `X-Forwarded-For`/`X-Real-IP`, case/encoding variations of the path, append trailing chars, switch API version, or move the call to GraphQL aliasing (Phase 9). If any bypass works, the limit is cosmetic.
- [ ] **Pagination abuse:** Set `limit`/`page_size`/`per_page`/`first` to extreme values (`99999`, `-1`, `0`). Unbounded page sizes enable mass extraction and memory DoS. Test deep `offset` for performance cliffs.
- [ ] **Batching abuse:** Where the API accepts arrays of operations (bulk create, JSON-RPC batch, GraphQL batch), submit oversized batches and many auth attempts in one request to bypass per-request throttling.
- [ ] **Cost-amplification inputs:** Large payloads, deeply nested JSON/XML, expensive regex/search filters, wildcard exports, and file-processing endpoints. Watch for response-time blowup and 5xx.
- [ ] **GraphQL depth and complexity DoS:** Deeply nested and recursive queries (cyclic relationships) can exhaust the server. See Phase 9; confirm query-depth and complexity limits exist.
- [ ] **Resource-creation flooding:** Endpoints that allocate storage, send email/SMS, or trigger paid downstream calls. Unmetered creation is both DoS and a billing-abuse finding.

```
⚠️ Resource-consumption tests can degrade or take down shared environments and can
   incur real cost (SMS, email, compute, third-party API calls). Confirm scope, prefer
   non-prod, throttle, and stop at proof. Have the unban/rollback contact ready.
```

---

## 8. Business-Flow Abuse and SSRF

API6:2023 Unrestricted Access to Sensitive Business Flows and API7:2023 SSRF. These need an understanding of intent, not just the route table.

### Business-Flow Abuse
- [ ] **Model the sensitive flows:** Purchase, transfer, referral/reward, voting, sign-up, coupon redemption, ticket purchase. Ask: what does the business assume a human does here that a script can automate?
- [ ] **Test workflow-step skipping and reordering:** Reach a final-state endpoint without the prerequisite steps, replay a one-time action, or approve/confirm out of order. Overlaps BFLA forced browsing.
- [ ] **Race conditions / TOCTOU:** Fire concurrent requests at balance debits, coupon/voucher redemption, inventory decrement, and withdrawal. Single-use limited to N becomes N+k. Use a high-concurrency client.
- [ ] **Quantity and price manipulation:** Negative quantities, negative/zero/fractional prices, currency swaps, and integer overflow in totals. Pairs with mass assignment.
- [ ] **Anti-automation gaps:** Missing CAPTCHA, device binding, or velocity checks on flows meant to be human-paced. Demonstrate scripted abuse within scope.

### Server-Side Request Forgery
- [ ] **Find URL-accepting parameters:** Webhook registration, `import-from-url`, avatar/image fetch, PDF/screenshot renderers, link unfurl/preview, document converters, and `jku`/`x5u` (Phase 3).
- [ ] **Confirm outbound fetch:** Point the param at a Collaborator/listener URL and watch for the callback. A DNS/HTTP hit confirms SSRF.
- [ ] **Reach internal targets:** `http://127.0.0.1`, `http://169.254.169.254/latest/meta-data/` (cloud metadata/IMDS), internal hostnames, and non-HTTP schemes (`file://`, `gopher://`, `dict://`). Cloud credential theft via IMDS is the high-impact outcome.
- [ ] **Bypass weak SSRF filters:** Decimal/octal/hex IP encodings, IPv6 (`[::1]`, `[::ffff:127.0.0.1]`), DNS rebinding, redirect-based bypass (allow-listed host that 302s to internal), and `@`/`#` URL-parsing tricks. Many 2024-2026 SSRF CVEs are redirect-not-revalidated bypasses of an existing fix.
- [ ] **Blind SSRF impact:** Even without a response body, prove internal reachability via timing or out-of-band, and pivot to internal service interaction where authorized.

---

## 9. GraphQL-Specific Testing

GraphQL collapses many endpoints into one and shifts authorization to the resolver. Discovery, DoS, and brute-force surfaces all differ from REST. See [API JWT and GraphQL](../Cheatsheets/API%20JWT%20and%20GraphQL.md) for query syntax and tooling.

### Schema Discovery
- [ ] **Introspection:** Send the full introspection query against `/graphql` and alternates (`/api/graphql`, `/v1/graphql`, `/query`, `/graphiql`). A complete schema dump maps every type, field, and mutation.
- [ ] **Introspection-disabled bypass:** If introspection is off, enumerate via field suggestions. GraphQL's "Did you mean X?" error on a near-miss field name leaks valid names. Use Clairvoyance-style enumeration to rebuild the schema from suggestions.
- [ ] **Probe alternate methods:** Some servers disable introspection over POST but allow it over GET, or vice versa. Test both and `Content-Type` variants (`application/json` vs `application/graphql`).

### GraphQL Authorization
- [ ] **Per-field and per-type authz:** Object-level pass does not imply field-level pass. Run BOLA/BFLA/property tests (Phases 4-6) through GraphQL queries and mutations, not just REST.
- [ ] **`node(id:)` and global-ID interfaces:** The Relay `node` field can fetch any object by global ID, bypassing the per-type resolver checks. Harvest and replay other accounts' global IDs.
- [ ] **Mutation enumeration:** List every mutation from the schema and test each for missing authorization, especially admin/config/role mutations not exposed in the UI.

### GraphQL Abuse and DoS
- [ ] **Alias-based brute force and rate-limit bypass:** Aliases let you run the same operation many times in one request. Batch hundreds of login/OTP/coupon attempts under different aliases to defeat HTTP-request-count rate limiting.

```graphql
mutation {
  a: login(user:"v", pass:"p1"){ token }
  b: login(user:"v", pass:"p2"){ token }
  c: login(user:"v", pass:"p3"){ token }
  # ... hundreds of aliases in one request
}
```

- [ ] **Query batching:** Send an array of operations in one HTTP request to bypass per-request throttles. Confirm whether the server caps batch size; most cap aliases or batching but not both.
- [ ] **Nested/recursive depth DoS:** Exploit cyclic relationships (`user -> posts -> author -> posts ...`) to build expensive deeply nested queries. Confirm depth-limit and complexity/cost-analysis controls exist.
- [ ] **Field duplication and circular fragments:** Repeating fields or fragment cycles to amplify cost without depth. Check the server rejects duplicated/cyclic selections.
- [ ] **CSRF on GraphQL:** If the endpoint accepts `application/x-www-form-urlencoded` or GET with cookie auth, it may be CSRF-able. Test cross-origin query/mutation.
- [ ] **Injection through arguments:** Resolver arguments flow to SQL/NoSQL/OS sinks like any input. Test injection in GraphQL variables.

---

## 10. Misconfiguration and Improper Inventory

API8:2023 Security Misconfiguration and API9:2023 Improper Inventory Management. The leftover-and-loose category: old versions, debug surfaces, weak transport, and unmanaged hosts.

### Misconfiguration
- [ ] **Transport security:** Enforce TLS; flag plaintext HTTP acceptance, TLS downgrade, and weak ciphers. Confirm HSTS on the API host.
- [ ] **CORS:** Test reflected `Origin`, `null` origin, and wildcard with credentials. `Access-Control-Allow-Origin: <reflected>` + `Allow-Credentials: true` is exploitable cross-origin data theft.
- [ ] **Security headers and verbose errors:** Missing `Content-Type`/`X-Content-Type-Options`; stack traces, framework banners, SQL errors, and internal hostnames in error bodies. Verbose errors feed every other phase.
- [ ] **HTTP method and header hygiene:** `TRACE`, `OPTIONS` over-disclosure, unexpected `PATCH`/`PUT`. Check that `Content-Type` is enforced (JSON endpoint accepting form/multipart can enable CSRF and parser confusion).
- [ ] **Cache and CDN:** Sensitive API responses cached by a CDN, or web-cache deception on API paths. Check `Cache-Control` on authenticated responses.
- [ ] **Debug and management surfaces:** `/actuator`, `/metrics`, `/debug`, `/graphiql`, `/swagger-ui` exposed in production. Each is an info-leak or worse.

### Improper Inventory
- [ ] **Catalog all versions and hosts:** Map every reachable version (Phase 2) and every API host/subdomain (partner, staging, beta, internal-but-exposed). Test the forgotten ones; they skip current controls.
- [ ] **Hunt non-production exposure:** `api-dev.`, `staging-api.`, `uat.`, `internal-api.` reachable from the internet. Non-prod often has weaker auth, debug on, and real data.
- [ ] **Deprecated-endpoint behavior:** Routes marked deprecated may still serve data without the newest authz. Confirm they are actually disabled, not just undocumented.
- [ ] **Third-party data-flow review:** Where the API forwards data to or pulls from external services, confirm the trust and the data minimization. Overlaps SSRF and excessive exposure.

---

## Recent Techniques (2024-2026)

- [ ] **OWASP API Top 10 2023 in practice:** Salt Security 2025 reporting finds the large majority of API attacks come from authenticated sources. Treat authn as table stakes and spend the budget on BOLA/BFLA/BOPLA differential testing with multiple accounts.
- [ ] **BOLA at automation scale:** Build an authorization matrix (account x endpoint x method) and replay programmatically, not by hand. Test for: any non-403 when Account A touches B's object across every verb. Tooling: Autorize/AuthMatrix (Burp), OWASP ZAP access-control scan, and schema-driven fuzzers seeded from OpenAPI.
- [ ] **GraphQL alias rate-limit bypass:** Test for many aliased mutations (login/OTP/coupon) in one request defeating HTTP-count rate limits. Most servers cap batching OR aliases, rarely both. Probe each independently.
- [ ] **GraphQL batching auth bypass + DoS:** Test for batched operation arrays bypassing per-request authz/throttle, and recursive nested queries exhausting CPU where no depth/complexity limit exists.
- [ ] **Introspection-disabled schema recovery:** Test for field-suggestion leakage ("Did you mean") rebuilding the schema via Clairvoyance even with introspection off.
- [ ] **JWT algorithm confusion:** Test for RS256->HS256 re-signing with the public key as HMAC secret, plus PS256/ES256 cross-acceptance on shared keys.
- [ ] **JWKS/`jku`/`x5u` SSRF and key injection:** Test for the server fetching an attacker `jku` URL (Collaborator hit = SSRF), then accepting a token signed by an attacker-hosted JWKS. Confirm `jku` is allow-listed.
- [ ] **CVE-2025-27371 (JWT ECDSA key recovery):** Test for token forgery via public-key recovery in vulnerable ECDSA-based implementations.
- [ ] **CVE-2025-53767 (Azure OpenAI SSRF EoP, CWE-918):** Critical SSRF-to-privilege-escalation pattern in AI/LLM API backends. Test for: URL-fetching params in AI service proxies reaching internal/metadata endpoints.
- [ ] **CVE-2026-33992 class (SSRF fix bypass via redirect):** Test for: an SSRF filter that validates the submitted URL but not the redirect target, letting an allow-listed host 302 to an internal address. Re-test every "fixed" SSRF for redirect revalidation.
- [ ] **BOPLA breadth:** Broken object property authz now spans mass assignment AND excessive exposure. Test for: privileged fields settable on nested/array inputs, and sensitive fields readable via direct GraphQL selection though hidden in the UI.
- [ ] **Mass assignment to admin:** Test for role/owner promotion via extra body fields (Camaleon CMS-style account-to-admin escalations recur across frameworks that bind the whole request body).
- [ ] **gRPC/WebSocket coverage:** Test for gRPC server-reflection enumeration without a `.proto`, and WebSocket messages that skip the per-message authorization the REST layer enforces.

---

## Reporting and Evidence

### Evidence to Capture Per Finding
- [ ] **Raw request/response pairs:** For every finding, save the complete HTTP request and response (headers + body), including the baseline (Account A's own object succeeding) and the break (Account A reaching B's object). The pair IS the proof of authorization findings.
- [ ] **Account and identity context:** Which account/token/role/tenant sent each request and which object/user it targeted. An authz finding without both identities is unproven.
- [ ] **Reproduction steps:** Exact endpoint, method, parameters, and the minimal sequence to reproduce. Note environment (prod vs sandbox) and timestamp.
- [ ] **Impact scope:** Records affected, cross-tenant reach, PII categories exposed, and whether the action is read or write/delete.

### Severity Guidance
| Finding | Typical severity | Driver |
| --- | --- | --- |
| Cross-tenant BOLA write/delete | Critical | Tenant isolation broken, data integrity |
| Cross-tenant BOLA read (PII) | High to Critical | Confidentiality at scale |
| JWT forgery (alg confusion, jku, weak secret) | Critical | Full authentication bypass |
| BFLA to admin function | High to Critical | Vertical privilege escalation |
| Mass assignment to privileged field | High | Privilege/ownership/price tampering |
| SSRF to cloud metadata | High to Critical | Credential theft, internal pivot |
| Same-tenant BOLA read | Medium to High | Scoped data exposure |
| Excessive data exposure | Medium to High | Depends on field sensitivity |
| Rate-limit/alias bypass enabling brute force | Medium to High | Amplifies authn attacks |
| Verbose errors, missing headers, CORS misconfig | Low to Medium | Info leak or conditional impact |

### False Positives to Rule Out
- [ ] **404 vs 403 on BOLA:** A 404 may be correct authorization (object hidden) rather than a leak. Confirm by checking whether the same ID is reachable by its true owner; only a 200 with another user's data is BOLA.
- [ ] **Reflected but unused mass-assignment fields:** A field accepted in the body but ignored server-side is not a finding. Verify the value actually changed state via a follow-up read.
- [ ] **Introspection on a public/intentional API:** Confirm the schema is meant to be private before reporting introspection exposure.
- [ ] **Rate limit enforced elsewhere:** A missing app-layer limit may be covered by an upstream gateway/WAF. Validate end-to-end before claiming no limit.
- [ ] **SSRF that only reaches the internet:** Outbound fetch with no internal reach is lower impact; demonstrate internal/metadata reachability for high severity.
- [ ] **Self-XSS / self-only access:** Accessing your own data via an "unusual" path is not BOLA. Always prove with a second account.

---

## Tools and References

| Tool | Use |
| --- | --- |
| Burp Suite + Autorize / AuthMatrix | Differential BOLA/BFLA replay across account contexts |
| Burp + InQL / GraphQL Raider | GraphQL introspection, query building, batching |
| Indago | Spec-driven API fuzzing, BOLA range sweeps, parameter discovery |
| BypassBurrito | WAF/filter bypass payloads for blocked API requests |
| [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md) | Templated checks for exposed specs, debug surfaces, known API CVEs |
| OWASP ZAP | Access-control scan, automated authz differential |
| jwt_tool / jwt.io | JWT decode, alg-confusion, jku/kid, secret cracking |
| Clairvoyance | GraphQL schema recovery via field suggestions (introspection off) |
| mitmproxy / Burp proxy | Capture web and mobile traffic to build endpoint inventory |
| ffuf / kiterunner | Route and method brute-forcing with API wordlists |
| grpcurl | gRPC enumeration via server reflection |

References:
- OWASP API Security Top 10 (2023): owasp.org/API-Security
- OWASP WSTG, Section 4.12 API Testing
- OWASP GraphQL Cheat Sheet and JWT/REST/Authorization Cheat Sheets
- OWASP API Security Testing Framework (ASTF)
- OWASP ASVS (auth, access-control, and session requirements)

---

## Related

- Playbooks: [Blind SSRF to Cloud Metadata RCE](../Playbooks/Blind%20SSRF%20to%20Cloud%20Metadata%20RCE.md), [Insecure Deserialization to RCE](../Playbooks/Insecure%20Deserialization%20to%20RCE.md)
- [API JWT and GraphQL](../Cheatsheets/API%20JWT%20and%20GraphQL.md)
- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)
- [Web Application](Web%20Application.md)
- [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md)
- [Mobile App Testing](../Cheatsheets/Mobile%20App%20Testing.md)
- Indago
- BypassBurrito
- [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
