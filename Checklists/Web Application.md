---
tags:
  - hack-notes
  - checklist
  - web
---

# Web Application Testing Checklist

> Methodology-first web app pentest checklist built on OWASP WSTG. Use top to bottom for a black/grey-box engagement against a web application. Commands and payloads live in the linked cheatsheets; this is the ordered method, the pass/fail signals, and the evidence to bank.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Information Gathering](#2-information-gathering)
- [3. Configuration and Deployment Management](#3-configuration-and-deployment-management)
- [4. Identity and Authentication](#4-identity-and-authentication)
- [5. Session Management](#5-session-management)
- [6. Authorization](#6-authorization)
- [7. Input Validation and Injection](#7-input-validation-and-injection)
- [8. Business Logic](#8-business-logic)
- [9. Client-Side](#9-client-side)
- [10. Server-Side Request Forgery and File Handling](#10-server-side-request-forgery-and-file-handling)
- [11. WAF Evasion Handoff](#11-waf-evasion-handoff)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

Lock scope and rules of engagement before sending a single request. A finding outside scope is wasted work at best and an incident at worst.

### Scope and Authorization
- [ ] **In-scope domains and IPs:** Get the exact apex domains, subdomains, API hosts, and IP ranges in writing. Confirm whether wildcard subdomains are in scope or only named hosts.
- [ ] **Out-of-scope carve-outs:** Record third-party SaaS, shared CDNs, payment processors, and any host you must not touch. Re-read this list before every new target you discover.
- [ ] **Authorization window:** Confirm the test dates, allowed hours, and the named point of contact for emergencies. Keep the signed authorization reachable during the test.
- [ ] **Allowed actions:** Confirm whether exploitation, data exfiltration proof, lateral movement, and DoS-adjacent testing (fuzzing, brute force) are permitted or off-limits.

### Test Accounts and Environment
- [ ] **Multiple privilege levels:** Obtain at least two accounts per role (admin, manager, standard user, read-only, unauthenticated). Two accounts at the same level are required to test horizontal access control.
- [ ] **Cross-tenant accounts:** For multi-tenant apps, get accounts in two separate tenants/orgs to test tenant isolation.
- [ ] **Credential hygiene:** Store test creds in the engagement vault, not in notes that ship in the report. Note any SSO/IdP path used to log in.
- [ ] **Prod vs staging:** Confirm which environment you are hitting. Staging may carry debug endpoints and weaker data; prod carries real users. Tag every finding with the environment it was proven on.
- [ ] **Data safety:** Agree on test-data markers (a recognizable prefix) so created records are easy to identify and purge. Never test destructive actions against records you do not own.

### Rate-Limit and WAF Awareness
- [ ] **WAF/CDN identification:** Fingerprint the edge (Cloudflare, Akamai, AWS WAF, Imperva) before fuzzing. A 403/429 may be the WAF, not the app. See BypassBurrito.
- [ ] **Allowlist coordination:** Ask whether the client can allowlist your source IP or a custom header so the WAF does not skew results. Document whichever path was chosen.
- [ ] **Rate-limit baseline:** Probe a benign endpoint to learn throttle thresholds before launching tooling. Throttle scanners to avoid tripping lockouts and incident response.
- [ ] **Detection awareness:** Confirm whether the test is announced (blue team aware) or blind. Adjust noise accordingly.

```
⚠️ Do not run automated scanners, brute force, or fuzzing against production until rate-limit
and WAF behavior is understood and the client has confirmed it is safe. A lockout of a real
user account or a flooded SOC is an incident you caused.
```

---

## 2. Information Gathering

Map the application before attacking it. The goal is a complete picture of hosts, technologies, and reachable entry points.

### Fingerprinting and Tech Stack
- [ ] **Server and framework fingerprint:** Identify web server, app framework, language, and version from headers, error pages, cookie names (e.g. `JSESSIONID`, `connect.sid`, `csrftoken`), and favicon hash.
- [ ] **WAF/CDN and edge stack:** Confirm the CDN, load balancer, and any reverse proxy chain. Proxy chains matter for desync (see Recent Techniques).
- [ ] **Third-party components:** Catalog JS libraries, analytics, tag managers, and embedded SaaS widgets with versions. Cross-check versions against known CVEs.
- [ ] **Passive recon first:** Pull subdomains, historical URLs, and tech from passive sources before active probing. See [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md).

### Spidering and Content Discovery
- [ ] **Authenticated and unauthenticated crawl:** Spider the app once logged out and once per role. Compare the surface each role can reach.
- [ ] **Forced browsing / dir brute:** Brute-force directories and files with role-appropriate wordlists. Flag anything returning 200/403 that the UI never links.
- [ ] **Hidden parameters:** Fuzz for unlinked GET/POST parameters on key endpoints (param mining). Hidden params often gate debug or admin behavior.
- [ ] **HTTP method sweep:** Test `OPTIONS`, `PUT`, `DELETE`, `PATCH`, `TRACE` on key paths. Note any method the app honors that the UI does not use.

### JavaScript and Client Asset Analysis
- [ ] **JS endpoint extraction:** Pull all script bundles and extract URLs, API paths, parameter names, and feature flags. Front-end routing tables reveal hidden views.
- [ ] **Source maps:** Look for `.map` files (`//# sourceMappingURL=`). If present, reconstruct original source for comments, internal API routes, and secrets.
- [ ] **Hardcoded secrets:** Grep bundles for API keys, tokens, cloud bucket names, internal hostnames, and `Authorization` literals.
- [ ] **Client-side feature flags:** Identify role gates enforced only in JS. Anything hidden by a flag but not server-enforced is an authz test target.

```bash
# Pull a bundle and mine for endpoints/secrets (anchor only; full tooling in cheatsheet)
curl -s https://target/static/main.js | grep -oE '"/[a-zA-Z0-9_/.-]+"' | sort -u
```

### Comments, Metafiles, and Entry Points
- [ ] **HTML/JS comments:** Read comments in markup and bundles for TODOs, credentials, internal URLs, and disabled features.
- [ ] **Metafiles:** Review `robots.txt`, `sitemap.xml`, `security.txt`, `humans.txt`, `.well-known/`. Disallowed paths are a hint list, not a barrier.
- [ ] **Error and debug pages:** Trigger 404/500 and malformed input to surface stack traces, framework banners, and debug consoles.
- [ ] **Entry-point map:** Build a single table of every request the app makes: method, path, params, auth requirement, and content type. This map drives every later phase.

---

## 3. Configuration and Deployment Management

Test how the app is deployed and exposed, independent of its own code.

### Transport and TLS
- [ ] **TLS version and ciphers:** Confirm TLS 1.2+ only, no SSLv3/TLS 1.0/1.1, no weak/export ciphers, strong key exchange. Flag expired or mismatched certs.
- [ ] **HSTS:** Confirm `Strict-Transport-Security` with a sane max-age and `includeSubDomains`. Note absence of preload where relevant.
- [ ] **Mixed content and redirects:** Confirm HTTP redirects to HTTPS site-wide and no sensitive content is served over plaintext.

### Security Headers
- [ ] **Header baseline:** Check `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options`/CSP `frame-ancestors`, `Referrer-Policy`, `Permissions-Policy`. Record each as present/weak/absent.
- [ ] **CSP quality:** Do not just check for presence. Look for `unsafe-inline`, `unsafe-eval`, wildcard sources, and missing `object-src`/`base-uri`. A weak CSP is a real finding, not a pass.
- [ ] **Information leakage headers:** Flag verbose `Server`, `X-Powered-By`, `X-AspNet-Version`, and similar version banners.

### Exposed Surfaces and Files
- [ ] **HTTP methods and TRACE:** Confirm dangerous methods are disabled. `TRACE` enabled may allow Cross-Site Tracing.
- [ ] **Admin and management interfaces:** Look for `/admin`, `/manager`, `/actuator`, `/console`, `/phpmyadmin`, framework dashboards. Test for default creds and missing auth.
- [ ] **Default and sample files:** Probe for shipped sample apps, install scripts, setup wizards, and framework demo pages left deployed.
- [ ] **Source control and env exposure:** Probe `/.git/HEAD`, `/.git/config`, `/.env`, `/.svn/`, `/.DS_Store`, backup suffixes (`.bak`, `~`, `.old`). A reachable `.git` often means full source recovery.

```bash
# .git exposure quick check (anchor)
curl -s -o /dev/null -w "%{http_code}\n" https://target/.git/HEAD
```

- [ ] **Cloud storage exposure:** Identify referenced S3/GCS/Azure buckets in markup and JS. Test for public listing, unauthenticated read, and writable buckets. See [AWS Pentest](../Cheatsheets/AWS%20Pentest.md) and [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md).
- [ ] **Subdomain takeover:** For every CNAME pointing at a third-party service, confirm the backing resource still exists. Dangling records are takeover candidates.
- [ ] **Verbose errors in prod:** Confirm stack traces, SQL errors, and debug toolbars are disabled in production.

---

## 4. Identity and Authentication

Test every way a principal proves who they are. Pair this phase with [API JWT and GraphQL](../Cheatsheets/API%20JWT%20and%20GraphQL.md) for token and API auth depth.

### Registration and Provisioning
- [ ] **Registration abuse:** Test for duplicate-account creation, role assignment via hidden fields (mass assignment into `role`/`isAdmin`), and email/identifier normalization tricks.
- [ ] **Email verification bypass:** Confirm unverified accounts cannot reach privileged functionality. Test whether verification tokens are guessable or reusable.
- [ ] **Provisioning side channels:** Test invite flows, SSO JIT provisioning, and admin-create paths for privilege injection.

### Account Enumeration
- [ ] **Username/email enumeration:** Compare responses, timing, and status codes for valid vs invalid identifiers across login, registration, and password reset. Any observable difference is enumeration.
- [ ] **Consistent-response check:** Confirm the app returns identical generic messages for "user not found" and "wrong password".

### Password Policy and Credential Attacks
- [ ] **Password policy:** Test minimum length, complexity, breached-password rejection, and whether trivial passwords (`Password1`) are accepted.
- [ ] **Brute force and lockout:** Confirm account lockout or progressive delay exists. Test whether lockout can be evaded by varying casing, IP, or `X-Forwarded-For`.
- [ ] **Credential stuffing exposure:** Confirm there is rate limiting and bot mitigation on login. Test the login API directly, bypassing any client-side throttle.
- [ ] **Default and weak creds:** Try documented defaults on any admin or device interface found in phase 3.

### MFA
- [ ] **MFA enforcement:** Confirm MFA cannot be skipped by direct-navigating past the MFA step to an authenticated route.
- [ ] **MFA brute force:** Test OTP endpoints for rate limiting. GraphQL aliasing/batching and array batching can multiply attempts in one request (see Recent Techniques).
- [ ] **MFA bypass via flow swap:** Test logging in with a partially authenticated session token against endpoints that should require full MFA.
- [ ] **Remember-device abuse:** Confirm "remember this device" tokens are bound to the user and cannot be transplanted.

### Password Reset
- [ ] **Reset token strength:** Confirm tokens are long, random, single-use, and short-lived. Test for sequential or timestamp-derived tokens.
- [ ] **Host header poisoning of reset links:** Inject `Host`/`X-Forwarded-Host` and check whether the reset email link points at the attacker host. See input injection phase.
- [ ] **Reset response leakage:** Confirm the reset response and email do not leak the token or whether the account exists.
- [ ] **Reset to takeover:** Test whether the reset flow lets you change another user's password (parameter swap, token reuse across accounts).

### JWT and Session Tokens
- [ ] **JWT algorithm and signature:** Test `alg:none`, algorithm confusion (RS256 to HS256 using the public key as HMAC secret), and weak HMAC secrets. Full JWT method in [API JWT and GraphQL](../Cheatsheets/API%20JWT%20and%20GraphQL.md).
- [ ] **Token claim trust:** Test whether the server trusts client-supplied claims (`role`, `tenant`, `sub`) without revalidation.
- [ ] **Token lifetime and revocation:** Confirm tokens expire and that logout/disable actually invalidates them server-side.

---

## 5. Session Management

Test how the authenticated state is carried, refreshed, and torn down.

### Cookie and Token Handling
- [ ] **Cookie attributes:** Confirm session cookies set `HttpOnly`, `Secure`, and an appropriate `SameSite` (`Lax`/`Strict`). Flag any session cookie missing these.
- [ ] **Scope and path:** Confirm cookies are scoped to the correct domain and path, not over-broad to a shared parent domain.
- [ ] **Token storage (SPA):** For token-in-localStorage apps, note the XSS-to-token-theft exposure and confirm there is no refresh token in JS-readable storage.

### Lifecycle
- [ ] **Session fixation:** Confirm the session identifier is regenerated on privilege change (login, role elevation). A pre-auth ID that survives login is fixation.
- [ ] **Logout:** Confirm logout invalidates the session server-side, not just client-side. Replay the old cookie after logout; it must fail.
- [ ] **Idle and absolute timeout:** Confirm sessions expire after inactivity and after an absolute maximum age.
- [ ] **Concurrent sessions:** Test whether multiple simultaneous sessions are allowed and whether a password change revokes other sessions.

### CSRF
- [ ] **State-changing request protection:** Confirm anti-CSRF tokens (or SameSite + origin checks) protect every state-changing action. Test by stripping/replaying the token.
- [ ] **Token binding:** Confirm the CSRF token is bound to the session and not globally valid or predictable.
- [ ] **Method and content-type bypass:** Test whether changing method (`POST` to `GET`) or content type (`application/json` to `text/plain`/form) bypasses CSRF defenses.
- [ ] **JSON CSRF and CORS interplay:** Confirm a permissive CORS policy does not enable cross-origin reads of CSRF tokens.

---

## 6. Authorization

Test what an authenticated principal is allowed to do. This is the highest-yield phase in most modern apps. You need at least two same-level accounts and accounts at different levels.

### Object-Level (IDOR/BOLA)
- [ ] **Direct object reference swap:** For every endpoint that takes an ID (numeric, UUID, slug, filename), replay it as another user and confirm the server denies access. Cross-account read or write is IDOR/BOLA.
- [ ] **Unpredictable-ID is not access control:** Even UUIDs leak via referers, logs, and shared links. Test access enforcement, not just guessability.
- [ ] **Tenant isolation:** From tenant A, attempt to read/modify tenant B objects by ID. Confirm the org/tenant boundary is enforced server-side.

### Function-Level (Vertical Privesc)
- [ ] **Forced browsing to admin functions:** As a low-priv user, request admin endpoints discovered in phase 2. Confirm a 403, not a 200.
- [ ] **Hidden-method privesc:** Test admin actions via API even when the UI hides the button. UI hiding is not authorization.
- [ ] **Role tampering:** Replay requests with modified role/claim values (cookie, JWT, body field) and confirm the server reauthorizes.

### Horizontal Privesc
- [ ] **Same-role cross-user:** With two same-level accounts, confirm user A cannot act on user B's resources through any endpoint.
- [ ] **Workflow step skipping:** Confirm a user cannot reach a later resource by skipping an ownership-establishing step.

### Mass Assignment and Parameter Pollution
- [ ] **Mass assignment:** Add unexpected fields (`role`, `isAdmin`, `verified`, `balance`, `ownerId`) to create/update requests and confirm the server ignores them.
- [ ] **HTTP parameter pollution:** Send duplicate parameters and confirm consistent, safe handling across the proxy/app boundary.

---

## 7. Input Validation and Injection

Test every place untrusted input reaches an interpreter or sink. Payload depth lives in [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md); this phase is the coverage map and the pass/fail signal.

### SQL and NoSQL Injection
- [ ] **SQLi sweep:** Test all parameters (query, body, headers, cookies) for error-based, boolean-blind, time-blind, and UNION SQLi. Confirm with a controlled time delay before claiming blind SQLi.
- [ ] **NoSQLi:** For Mongo/document stores, test operator injection (`{"$ne":null}`, `{"$gt":""}`) in JSON bodies and query strings.
- [ ] **ORM and second-order:** Test stored values that later feed a query (second-order injection) and ORM raw-query escapes.

### Command and Code Injection
- [ ] **OS command injection:** Test parameters that may reach shell calls with separators (`;`, `|`, `$()`, backticks) and confirm via out-of-band callback or time delay.
- [ ] **Code/expression injection:** Test for language eval sinks where user input reaches `eval`, `Function`, ognl, SpEL, or similar.

### Template Injection (SSTI)
- [ ] **SSTI detection:** Inject polyglot probes (`${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`) into reflected values and rendered fields (names, subjects, templates). A `49` confirms evaluation.
- [ ] **Engine identification and escalation:** Once confirmed, fingerprint the engine (Jinja2, Twig, Freemarker, Velocity, ERB) and walk to RCE via the known gadget chain. See Recent Techniques for current gadgets.

### XXE and Structured-Data Injection
- [ ] **XXE:** For any XML, SVG, DOCX, or SOAP intake, test external entity injection for file read and SSRF. Test both classic and blind (out-of-band DTD) variants.
- [ ] **LDAP injection:** Test auth and search fields that reach LDAP with `*`, `)(`, and filter-breaking payloads.
- [ ] **Deserialization:** Identify serialized blobs (Java, .NET, PHP, Python pickle, Ruby) in cookies/params and test for insecure deserialization to RCE. See Recent Techniques for current gadgets.

### Cross-Site Scripting (XSS)
- [ ] **Reflected XSS:** Test every reflected parameter and header across HTML, attribute, JS, and URL contexts. Confirm execution, not just reflection.
- [ ] **Stored XSS:** Test every field that is later rendered to another user (profiles, comments, filenames, support tickets, admin views). Stored XSS into an admin panel is high impact.
- [ ] **DOM XSS:** Trace client-side sinks (`innerHTML`, `document.write`, `eval`, `location`, `setAttribute`) fed by sources (`location.hash`, `postMessage`, `referrer`). Covered further in phase 9.
- [ ] **Context and filter bypass:** For each near-miss, identify the encoding/filter and attempt a context-appropriate bypass before calling it safe. Do not stop at the first blocked payload.

### Header, Host, and Redirect Injection
- [ ] **Host header injection:** Inject `Host`/`X-Forwarded-Host` and observe reflection in links, password-reset emails, and cache keys.
- [ ] **CRLF / response splitting:** Test for `%0d%0a` injection into headers and logs.
- [ ] **Open redirect:** Test redirect parameters (`return`, `next`, `url`, `redirect`) for arbitrary external destinations and for use as an OAuth `redirect_uri` lever.

---

## 8. Business Logic

Test the rules of the application, not the syntax of its inputs. These bugs are invisible to scanners and require understanding the workflow.

- [ ] **Workflow sequencing:** Map each multi-step flow (checkout, KYC, onboarding) and attempt to skip, reorder, or repeat steps. Confirm the server enforces order and prerequisites.
- [ ] **Price and quantity tampering:** Modify price, quantity, currency, discount, and total fields client-side and confirm the server recomputes authoritatively. Test negative quantities and integer overflow.
- [ ] **Coupon and reward abuse:** Test coupon stacking, reuse of single-use codes, and refund/credit loops that create value.
- [ ] **Race conditions:** Fire concurrent requests at limited-resource actions (redeem, withdraw, apply-once) to test for double-spend. Use single-packet/parallel techniques. See Recent Techniques.
- [ ] **Replay and idempotency:** Replay state-changing requests (payments, transfers, votes) and confirm idempotency keys or nonces prevent duplication.
- [ ] **Quota and limit bypass:** Test whether plan limits, upload caps, and usage quotas can be exceeded via concurrency or alternate endpoints.
- [ ] **Trust-boundary assumptions:** Identify any value the app assumes is server-controlled but actually accepts from the client (status, role, verified, ownerId).

---

## 9. Client-Side

Test code that runs in the victim's browser and the cross-origin relationships around it.

### DOM and Script Execution
- [ ] **DOM XSS:** Confirm sink/source chains from phase 7 with a working browser payload. Pay attention to SPA framework sinks and template bindings.
- [ ] **Prototype pollution (client):** Test query/JSON inputs for `__proto__`/`constructor.prototype` pollution and trace to a DOM XSS or logic gadget. See Recent Techniques.
- [ ] **CSPT (client-side path traversal):** Test client-built fetch URLs for `../` injection that redirects the request to attacker-chosen endpoints, then chain to CSRF or XSS. See Recent Techniques.

### Cross-Origin Mechanisms
- [ ] **postMessage:** Audit `message` event handlers for missing `origin` checks and for passing data into dangerous sinks. A handler that trusts any origin is exploitable.
- [ ] **CORS:** Test `Access-Control-Allow-Origin` reflection, `null` origin acceptance, and `Allow-Credentials: true` with a wildcard or reflected origin. A credentialed reflected origin leaks authenticated data.
- [ ] **Clickjacking:** Confirm `frame-ancestors`/`X-Frame-Options` protect sensitive actions. Build a framing PoC for any unprotected state-changing page.
- [ ] **WebSockets:** Test the WS handshake for missing origin validation (cross-site WebSocket hijacking) and test message handlers for injection and authz gaps.

### CSP and Supply Chain
- [ ] **CSP bypass:** For apps relying on CSP, look for bypass gadgets: permissive sources, JSONP endpoints, unsafe-eval, and trusted-CDN script gadgets.
- [ ] **Third-party script risk:** Confirm Subresource Integrity on critical external scripts. Note any script load from a host the app does not control.

---

## 10. Server-Side Request Forgery and File Handling

Test where the server fetches, parses, or stores attacker-influenced data.

### SSRF
- [ ] **SSRF surface:** Test every server-fetch feature (URL preview, webhook, import-from-URL, PDF/screenshot generation, avatar-from-URL) for outbound requests to attacker-chosen hosts. Confirm with an out-of-band callback.
- [ ] **Cloud metadata:** From a confirmed SSRF, attempt to reach `169.254.169.254` (AWS IMDS), GCP/Azure metadata endpoints, and internal services. IMDSv1 reachability is critical. See [AWS Pentest](../Cheatsheets/AWS%20Pentest.md).
- [ ] **Filter bypass:** Test SSRF allowlist/denylist bypasses: alternate IP encodings, `[::]`, DNS rebinding, redirect-based, and `@`-trick URLs.
- [ ] **Blind SSRF impact:** Even without response reflection, prove internal port scanning or internal service interaction via timing and callbacks.

### File Upload and Handling
- [ ] **Upload validation:** Test extension, content-type, and magic-byte checks independently. Confirm validation is by content, not just extension.
- [ ] **Dangerous-type upload:** Attempt to upload executable/server-interpretable files (`.php`, `.jsp`, `.aspx`, `.svg`, `.html`) and reach them via a web-accessible path.
- [ ] **Path traversal in filename/path:** Test `../` and absolute paths in upload filenames and download parameters for arbitrary read/write.
- [ ] **Archive and parser abuse:** Test zip-slip on archive uploads and parser exploits (image/PDF/XML libraries) for RCE or SSRF.
- [ ] **Download/IDOR on files:** Confirm uploaded files are not readable cross-user by guessable path or ID.

### Path Traversal and LFI/RFI
- [ ] **Local file inclusion:** Test path parameters for `../../etc/passwd` and wrappers. Confirm read of files outside the web root.
- [ ] **Remote file inclusion / include-by-URL:** Test include parameters that may fetch remote content.

---

## 11. WAF Evasion Handoff

When a payload class is blocked at the edge rather than by the app, treat the block as a vuln class to bypass, not a negative result.

- [ ] **Confirm it is the WAF, not the app:** Compare the blocked response to the app's own validation errors. A generic 403/406/429 at the edge usually means the WAF.
- [ ] **Characterize the rule:** Identify which token in the payload triggers the block by bisecting the request.
- [ ] **Generate bypass candidates:** Apply encoding, casing, comment-insertion, chunking, and parameter-pollution transforms appropriate to the sink. Hand the blocked request to BypassBurrito for payload generation.
- [ ] **Re-test the full class:** After a bypass works, re-run the entire affected payload class through it before concluding the underlying app is or is not vulnerable.

```
⚠️ Bypassing a WAF can dramatically increase the blast radius of a live payload. Re-confirm
the action is in scope and non-destructive before firing a bypassed exploit at production.
```

---

## Recent Techniques (2024-2026)

Run these against modern targets in addition to the WSTG core. Each item is a named technique or CVE with a one-line test-for.

### HTTP Desync and Request Smuggling (Kettle, 2024-2025)
- [ ] **CL.0 desync:** Server ignores `Content-Length` on certain paths so the body is parsed as a new request. Test for paths/handlers that respond before reading the body.
- [ ] **0.CL desync:** Front-end sees no body, back-end expects one. On IIS/Windows, probe special device paths (`/con`, `/aux`, `/nul`) that make the origin respond immediately.
- [ ] **Browser-powered / client-side desync:** Trigger desync using only a victim's browser against a vulnerable front-end. Test connection-locked request injection from a normal browser flow.
- [ ] **"HTTP/1.1 must die" upstream check:** Desync persists when the proxy-to-origin hop still speaks HTTP/1.1 even if the edge is HTTP/2. Confirm whether upstream is HTTP/1.1 and test the proxy chain end to end.

### Web Cache Attacks (2024)
- [ ] **"Gotta cache 'em all" parser discrepancies:** URL-parsing differences between cache and origin enable arbitrary cache poisoning/deception. Test path-delimiter and normalization discrepancies (`;`, `%2f`, `..%2f`) across the cache boundary.
- [ ] **Wildcard web cache deception (ChatGPT-class ATO):** Inconsistent decoding plus a cacheable static-extension suffix causes the cache to store a victim's authenticated response. Append `/nonexistent.css`-style suffixes to sensitive endpoints and check for a cache HIT serving private data.
- [ ] **Cache key normalization poisoning:** Unkeyed input (headers, casing) influences the response but not the cache key. Test unkeyed-header injection that persists in cached responses.

### Client-Side Path Traversal (Doyensec, 2024-2025)
- [ ] **CSPT2CSRF (CVE-class, Mattermost/Rocket.Chat):** Front-end builds a fetch path from user input; `../` reroutes the authenticated request to an attacker-chosen sink, defeating CSRF tokens because the front-end still attaches them. Test client-controlled path segments in API calls.

### Prototype Pollution and Gadgets (2024-2025)
- [ ] **Server-side prototype pollution (Dasty gadgets):** Pollute `Object.prototype` via JSON body and reach a sink in ejs/nodemailer/workerpool-style gadgets to DoS or RCE. Test `__proto__`/`constructor.prototype` keys in JSON.
- [ ] **CVE-2024-21505 (web3-utils), CVE-2024-21529 (dset), CVE-2024-57075 (eazy-logger), CVE-2025-64718 (js-yaml):** Known prototype-pollution sinks in popular libs. Fingerprint dependency versions and test for the polluted-property effect.

### SSTI and Deserialization (2024-2025)
- [ ] **CVE-2025-66436 (Frappe/ERPNext Jinja2):** `render_template` over attacker-controlled context. Test template-rendered fields with `{{ }}` probes.
- [ ] **CVE-2024-28118 / CVE-2024-56085 / CVE-2024-56087 (SSTI in app dashboards):** Authenticated template injection in search/dashboard features. Test any user-defined template or report field.
- [ ] **Nested/encoded SSTI payloads (CVE-2024-28254-style):** Multi-stage base64-wrapped payloads evade naive filters. Re-test blocked SSTI with layered encoding.

### GraphQL (2024-2025)
- [ ] **Introspection exposure:** Confirm introspection is disabled in prod; if enabled, dump the full schema for hidden mutations and admin types.
- [ ] **Aliasing/batching rate-limit and 2FA bypass:** Send N aliased copies of a sensitive resolver (OTP check, login) in one operation to multiply attempts past per-request throttling.
- [ ] **Deep-nesting DoS:** Submit recursive nested queries on cyclic types and confirm a depth/cost limit exists.
- [ ] **CVE-2024-54147 (Altair client TLS):** Client tools that skip cert validation on WS. Relevant when assessing GraphQL tooling in scope.
- [ ] **Full method:** See [API JWT and GraphQL](../Cheatsheets/API%20JWT%20and%20GraphQL.md) and [API Security](API%20Security.md) for the complete GraphQL flow.

### OAuth / OIDC (2024-2025)
- [ ] **Redirect URI bypass:** Test loose `redirect_uri` matching (path append, subdomain, open-redirect chain) to steal `code`/`token`.
- [ ] **State / PKCE absence:** Confirm `state` (CSRF) and PKCE are present and enforced. Missing PKCE on a public client is a finding.
- [ ] **Cookie tossing into OAuth flow (2024):** A subdomain XSS or cookie write hijacks the OAuth flow via tossed cookies. Test cookie precedence across subdomains.
- [ ] **Device-flow phishing (ShinyHunters/UNC6040 wave):** Abuse of device authorization grant for consent phishing. Confirm device-code flows have user-verification and short lifetimes where in scope.
- [ ] **CVE-2025-54576 (oauth2-proxy):** Auth bypass via regex match over the full URI including query. Test query-string smuggling against proxy auth.
- [ ] **CVE-2024-45409 (Ruby-SAML / GitLab):** XPath-based SAML signature bypass. Test SAML response tampering where SAML SSO is in scope.

### Single-Packet Race Conditions (2023-2024, still high-yield)
- [ ] **Single-packet attack:** Use HTTP/2 single-packet or last-byte-sync to fire many requests with near-zero jitter at limited-once actions. Test coupon, withdrawal, and apply-once flows for double-processing.

---

## Reporting and Evidence

### Evidence to Capture per Finding
- [ ] **Raw request/response pair:** Save the full HTTP request and response (or a screenshot) for every finding and PoC, captured at test time. This is mandatory, not optional.
- [ ] **Reproduction steps:** Numbered, minimal steps from a clean session, including the account/role used and the environment (prod/staging).
- [ ] **Impact proof:** Demonstrate the actual effect (cross-account data, code execution marker, cache HIT serving private data), not just the trigger. Use a benign marker; never exfiltrate real user data.
- [ ] **Scope and account tagging:** Record which host, which account, and which privilege level proved the issue.

### Severity Guidance
| Severity | Typical web examples |
|---|---|
| Critical | Pre-auth RCE, SQLi to data dump, auth bypass to admin, SSRF to cloud metadata + creds |
| High | Stored XSS hitting admins, IDOR/BOLA exposing PII at scale, account takeover chain, request smuggling |
| Medium | Reflected XSS, CSRF on sensitive action, weak session handling, SSTI requiring auth |
| Low | Verbose errors, missing security headers, weak TLS config, autocomplete on password fields |
| Info | Version banners, robots.txt disclosure, best-practice deviations with no direct impact |

Let the impact and the CVSS vector set the label. Topology/metadata exposure is usually `C:L`, not `C:H`. Default to the lower band on a Medium/High boundary.

### Common False Positives to Rule Out
- [ ] **Reflected != executed:** A reflected payload is not XSS until it executes in the intended context. Confirm execution.
- [ ] **Self-XSS:** Input only attacker controls in their own session is not a finding without a delivery vector (cookie tossing, CSPT).
- [ ] **WAF block != not vulnerable:** A blocked payload proves the WAF works, not that the app is safe. Confirm app behavior behind the WAF (see phase 11).
- [ ] **Unpredictable ID != access control:** A hard-to-guess ID is not authorization. Prove the server actually enforces ownership.
- [ ] **Out-of-scope CDN/SaaS behavior:** Confirm a header or config finding belongs to the target, not a shared third-party edge.
- [ ] **Login enumeration via rate limiting:** Distinguish a true response/timing oracle from generic throttling noise.

---

## Tools and References

| Tool | Use |
|---|---|
| Burp Suite (Pro) | Intercept proxy, Repeater, Intruder, scanner, smuggling/desync and param-mining extensions |
| OWASP ZAP | Open-source proxy and scanner alternative |
| ffuf / feroxbuster | Content discovery and forced browsing |
| sqlmap | SQLi confirmation and exploitation |
| nuclei | Templated CVE and misconfig checks (see [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md)) |
| Param Miner / Arjun | Hidden parameter discovery |
| jwt_tool | JWT algorithm and signature attacks |
| trufflehog / gitleaks | Secret discovery in exposed source and bundles |
| Collaborator / interactsh | Out-of-band confirmation for SSRF, blind injection, XXE |

Authoritative references:
- OWASP Web Security Testing Guide (WSTG) latest: the canonical phase-by-phase method.
- OWASP Application Security Verification Standard (ASVS): control requirements to test against.
- OWASP Top 10 and OWASP Cheat Sheet Series (CSP, GraphQL, SSRF, Auth).
- PortSwigger Web Security Academy and annual Top 10 Web Hacking Techniques.

---

## Related

- Playbooks: [SQL Injection to RCE to Pivot](../Playbooks/SQL%20Injection%20to%20RCE%20to%20Pivot.md), [File Upload to Web Shell to Foothold](../Playbooks/File%20Upload%20to%20Web%20Shell%20to%20Foothold.md), [Insecure Deserialization to RCE](../Playbooks/Insecure%20Deserialization%20to%20RCE.md), [Blind SSRF to Cloud Metadata RCE](../Playbooks/Blind%20SSRF%20to%20Cloud%20Metadata%20RCE.md)
- [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md)
- [API JWT and GraphQL](../Cheatsheets/API%20JWT%20and%20GraphQL.md)
- [API Security](API%20Security.md)
- BypassBurrito
- Indago
- [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md)
- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)
- [AWS Pentest](../Cheatsheets/AWS%20Pentest.md)
- [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md)
