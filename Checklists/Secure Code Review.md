---
tags:
  - hack-notes
  - checklist
  - code-review
---

# Secure Code Review Checklist

> Source-driven review method for grey-box and white-box engagements where you have the code. Read it top to bottom when you hold a repo, a build, and ideally a running instance to confirm against. The commands here are anchors only; grep/semgrep recipes and full tooling live in the linked cheatsheets. This file is the ordered method, the sinks to chase, and the bar for calling a finding real rather than a SAST hit.

## Table of Contents
- [1. Pre-Engagement and Access](#1-pre-engagement-and-access)
- [2. Codebase Recon and Mapping](#2-codebase-recon-and-mapping)
- [3. Authentication and Session Code](#3-authentication-and-session-code)
- [4. Authorization Code](#4-authorization-code)
- [5. Injection Sinks](#5-injection-sinks)
- [6. Cryptography Usage](#6-cryptography-usage)
- [7. Secrets and Git History](#7-secrets-and-git-history)
- [8. Input Validation and Output Encoding](#8-input-validation-and-output-encoding)
- [9. Error Handling, Logging, and Sensitive Data](#9-error-handling-logging-and-sensitive-data)
- [10. Dependencies and Supply Chain](#10-dependencies-and-supply-chain)
- [11. Business Logic in Code](#11-business-logic-in-code)
- [12. Framework-Specific Sinks](#12-framework-specific-sinks)
- [13. SAST Tooling and Triage](#13-sast-tooling-and-triage)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Access

Code review fails quietly when you start reading without the pieces that make a finding provable. Get the source, the history, and a way to run the thing before you open the first file. A sink you cannot reach at runtime is a lead, not a finding, and the engagement needs to agree up front on which of those you report.

### Source and Build Access
- [ ] **Full source, not a snapshot zip:** Get a clone with history, submodules, and generated code. A flat export hides the `.git` log, vendored dependencies, and build-time code generation where real sinks live.
- [ ] **Buildable tree:** Confirm you can build and run it. A review you cannot compile is a review you cannot verify, and dead-code branches look identical to live ones in a text editor.
- [ ] **Branch and tag discipline:** Review the branch that ships. Pin the exact commit in your notes. Fixes land on `main` while the release tag lags, and the reverse happens too.
- [ ] **Grey-box pairing:** Ask for a running instance (staging or local) alongside the source. The highest-value mode is reading the code to find the candidate, then firing the request to prove it. Static-only review inflates severity because you cannot see what the framework or a proxy strips.

### SCM and History
- [ ] **Commit history access:** Confirm you can read the full log, not a squashed import. Secrets, removed debug endpoints, and the "temporary" auth bypass that never left all live in history (Phase 7).
- [ ] **Issue and PR context:** Where available, skim merged PRs and open issues for known-weak areas the team already argued about. A closed "we'll fix the authz later" issue is a map.

### Inventory and Threat Model
- [ ] **Language and framework census:** List every language, framework, and major library with versions before reading logic. The sink set for Spring differs from Express differs from Rails; you test what the stack can actually do (Phase 12).
- [ ] **Trust boundaries:** Mark where data crosses from untrusted to trusted: HTTP handlers, queue consumers, webhook receivers, file importers, CLI args, inter-service calls. Every boundary is a source for the data-flow pass (Phase 2).
- [ ] **Define "done":** Agree on coverage. Full review of auth/authz/injection paths, or a time-boxed pass over the highest-risk modules. Record which files you did not reach. An unreviewed module is a gap you name, not a gap you hide.
- [ ] **Agree the reporting bar:** Static-reachable vs runtime-proven. State in the SOW whether an unreachable-at-runtime sink is reported as a finding or an observation. This prevents a report full of SAST noise the client cannot action.

---

## 2. Codebase Recon and Mapping

Read the shape before the details. You are building the same entry-point map a black-box tester builds by crawling, except you can read it directly from the route table and the framework config. Trace from where untrusted data enters to where it reaches a dangerous call. That source-to-sink path is the unit of work for the rest of this checklist.

### Entrypoints and Routes
- [ ] **Enumerate the route table:** Find every controller, handler, resolver, and route decorator. This is the attack surface, same as the black-box entry-point map but authoritative. Coverage is the fraction of these you actually traced.
- [ ] **Non-HTTP entrypoints:** Message consumers, cron jobs, webhook receivers, gRPC services, GraphQL resolvers, file/upload processors, and deserialization endpoints. These skip the web middleware that guards the HTTP paths and are routinely less defended.
- [ ] **Middleware and filter order:** Read the request pipeline. Auth middleware applied globally vs per-route decides whether a new handler is protected by default or exposed by default. A route registered outside the auth group is unauthenticated whatever the function body assumes.

### Data Flow, Sources to Sinks
- [ ] **Identify sources:** Request params, bodies, headers, cookies, path segments, uploaded files, env-influenced config, and values read back from the database that originated with a user (second-order).
- [ ] **Identify sinks:** Query builders, shell exec, template render, file path operations, deserializers, redirects, HTML output. Phases 5 and 8 enumerate these per class.
- [ ] **Trace the taint:** For each source, follow the value to a sink without an intervening parameterization, encoding, or validation step. An unbroken path is the finding; a path that passes through the ORM's parameter binding is not.

### Dependency and Framework Identification
- [ ] **SBOM from the lockfile:** Parse `package-lock.json`, `yarn.lock`, `poetry.lock`, `go.sum`, `Gemfile.lock`, `pom.xml` for the real resolved versions. The manifest range lies; the lockfile is what ships (Phase 10).
- [ ] **Framework version and its defaults:** The version decides which auto-escaping, which deserialization behavior, and which known CVEs apply. A sink that is safe on the framework's current default can be live on the pinned older version.

```bash
# Build the route inventory for an Express/Fastify app (anchor only; full tooling in cheatsheet)
rg -n "\.(get|post|put|patch|delete)\(['\"]" --type js
```

---

## 3. Authentication and Session Code

Read how a principal is proven, not how the login page looks. The bugs are in verification, not the happy path: a token accepted when it should be rejected, a password compared in a way that leaks, a session that outlives its revocation. Pair with [API JWT and GraphQL](../Cheatsheets/API%20JWT%20and%20GraphQL.md) for token specifics.

### Credential Handling
- [ ] **Password comparison:** Confirm the code uses a constant-time verify against a slow hash, not `==` on a plaintext or a fast digest. A `password == stored` on a reversible value is both a storage and a timing finding.
- [ ] **Password storage algorithm:** The algorithm is the finding. Confirm bcrypt, scrypt, argon2id, or PBKDF2 with a sane cost. Flag MD5, SHA-1, SHA-256, or any unsalted fast hash for passwords. Read the actual cost/work-factor constant, not just the function name.
- [ ] **Credential logging:** Grep the auth path for logging of passwords, tokens, and reset codes. A `logger.debug(req.body)` on the login handler ships credentials to the log sink (Phase 9).

### Token Issuance and Verification
- [ ] **JWT verification call:** Read the verify call, not the sign call. Confirm the algorithm is pinned server-side and the library is not asked to trust the token's own `alg` header. A `verify(token, key)` that honors `alg:none` or accepts HS256 against an RSA public key is total forgery.
- [ ] **Signature actually checked:** Confirm the decode path verifies the signature rather than decoding claims and trusting them. A `jwt.decode()` used where `jwt.verify()` belongs is an unauthenticated claim read.
- [ ] **Claim trust:** Confirm `exp`, `iss`, and `aud` are enforced, and that `role`/`tenant`/`sub` claims are re-checked against the server's own records rather than trusted from the token (Phase 4).
- [ ] **Secret source:** Trace the HMAC secret or signing key. A hardcoded or short default secret means offline forgery (Phase 7).

### SSO and OIDC Code
- [ ] **redirect_uri validation:** Read the match logic. Prefix/`startsWith` or substring matching lets an attacker append a path or a subdomain and steal the code. Confirm exact-match against a registered allowlist.
- [ ] **state and PKCE:** Confirm `state` is generated, stored, and compared on callback, and PKCE is enforced for public clients. A callback handler that ignores `state` is CSRF-able into the auth flow.
- [ ] **SAML signature:** Where SAML is handled in code, confirm the assertion signature is validated over the whole assertion and that XML canonicalization/comment handling cannot split the signed content (the Ruby-SAML/XPath class, 2024).
- [ ] **ID-token signature and nonce:** Confirm the OIDC `id_token` is verified against the provider JWKS and the `nonce` is bound to the session.

### Session Lifecycle
- [ ] **Session regeneration on login:** Confirm the session identifier is rotated at privilege change. A pre-auth ID that survives login is fixation.
- [ ] **Server-side revocation:** Confirm logout, password change, and account disable invalidate server-side, not just clear a cookie. Stateless JWTs with no deny-list cannot be revoked; call that out where sessions must be killable.
- [ ] **Cookie flags set in code:** Read where the session cookie is written and confirm `HttpOnly`, `Secure`, and `SameSite` are set there, not left to a default. A cookie assembled by hand usually misses one.

---

## 4. Authorization Code

The highest-yield phase. Authorization bugs do not look like bugs in a diff: the code reads cleanly, it just never checks ownership. You are hunting for the check that is missing, enforced in the wrong layer, or applied to one route and forgotten on its sibling. Sweep by capability, not by the one function you just read. Copies of a handler are found by name; parallel routes that do the same thing are found only by walking the route table.

### Where Authz Is Enforced
- [ ] **Enforcement layer:** Confirm authorization runs server-side in the handler or a middleware that covers the route, not in the client or a UI guard. A hidden button is not a control; the endpoint behind it is what you test.
- [ ] **Enforced vs assumed:** For each privileged handler, find the explicit check. Absence is the finding. A handler that trusts an earlier step established ownership, without re-checking, is broken when the step is skipped.
- [ ] **Middleware coverage gaps:** Diff the set of routes against the set the auth middleware actually wraps. A route registered on a different router, or after the guard, is exposed. This is the sibling-route sweep: one guarded, one not.

### Object-Level (IDOR/BOLA in Code)
- [ ] **Owner check in the query:** Read the data-access call. `findById(id)` with no `AND owner_id = :currentUser` is IDOR regardless of how unguessable the ID is. The filter in the WHERE clause is the control; its absence is the bug.
- [ ] **Tenant scoping:** Confirm every query in a multi-tenant app filters by tenant/org derived from the session, not from a client-supplied field. A `tenant_id` read from the request body and used in the filter is attacker-controlled scoping.
- [ ] **Trusted client-supplied scope:** Flag any query that scopes by an ID taken from the request when it should come from the authenticated principal.

### Function-Level and Roles
- [ ] **Role check location:** Confirm role checks sit in the server handler, not only in a template conditional or a frontend route guard. A `{% if user.is_admin %}` hiding a form while the POST handler has no check is vertical privesc.
- [ ] **Role re-derivation:** Confirm the role is read from the server's record, not trusted from a request field or a client-readable token claim.

### Mass Assignment
- [ ] **Whole-body binding:** Find model binds that accept the full request body (`Model(**request.json)`, `update(req.body)`, strong-params gaps, `BindJSON` onto the DB struct). Unlisted fields like `role`, `is_admin`, `owner_id`, `balance`, `verified` become settable.
- [ ] **Allowlist vs blocklist on binding:** Confirm writable fields are explicitly allowlisted. A blocklist misses the next field someone adds to the model.

```
⚠️ A structural grep for "the authz check is present" proves nothing until you mutate it.
Delete the check, re-run the test that is supposed to fail, and confirm it now passes.
A guard that still passes with the check removed is decoration, not enforcement.
```

---

## 5. Injection Sinks

Every injection class is the same shape in code: untrusted data reaches an interpreter without the data and the code being separated. You are looking for string-built commands where a parameterized API exists and was not used. Payload depth lives in [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md); here you find the sink and prove the source reaches it.

### SQL and ORM
- [ ] **String-built queries:** Grep for concatenation and interpolation into query strings: `"SELECT ... WHERE id = " + id`, f-strings in `cursor.execute`, template literals in a raw query. A parameter placeholder was available and skipped.
- [ ] **ORM raw escapes:** The ORM is safe until someone drops to `raw()`, `extra()`, `whereRaw`, `@Query` with string concat, or `sequelize.query` with interpolation. Read every raw-query escape hatch; that is where ORM-backed apps get SQLi.
- [ ] **Second-order:** A value stored safely and later concatenated into a query on read. The write looks clean; the read is the sink.

```bash
# Find raw-query escape hatches across an ORM codebase (anchor only; full tooling in cheatsheet)
rg -n "raw\(|whereRaw|extra\(|execute\(.*(\+|%|format|f['\"])" 
```

### Command and Code Execution
- [ ] **Shell exec with untrusted input:** Find `exec`, `system`, `popen`, `child_process.exec`, `Runtime.exec`, `os.system`, `subprocess` with `shell=True` where an argument carries user input. The shell metacharacters are the vector; the array-argument form is the fix.
- [ ] **Eval-class sinks:** `eval`, `Function()`, `setTimeout(string)`, `vm.runInContext`, Python `eval/exec`, Ruby `instance_eval`. Any user value reaching these is code injection.

### Template Injection
- [ ] **Render over user-controlled template:** Flag `render_template_string`, `Template(user_input)`, string-concatenated templates, and user-editable template fields. The data belongs in the context, never in the template string. A `render_template_string(f"Hello {name}")` is SSTI.
- [ ] **Confirm the engine:** Once found, identify the engine (Jinja2, Twig, Freemarker, Velocity, ERB) to know the escalation path to RCE (Recent Techniques).

### Deserialization
- [ ] **Untrusted deserialization:** Find `pickle.loads`, Java `ObjectInputStream.readObject`, `ObjectMapper` with default typing enabled, PHP `unserialize`, Ruby `Marshal.load`, YAML full-load on attacker data. Each is RCE if a gadget chain exists in the classpath.
- [ ] **YAML load mode:** Confirm `yaml.safe_load`, not `yaml.load` with a full loader. The difference is arbitrary object construction.

### Path, LDAP, XXE
- [ ] **Path traversal:** Find file operations that join a user segment into a path without canonicalizing and confirming it stays under the intended root. `open(base + userfile)` with no normalization is traversal.
- [ ] **LDAP filters:** Find search filters built by concatenation. User input with `*`, `)(`, and filter-breaking chars is LDAP injection.
- [ ] **XML parser config:** Read the parser setup. External entity resolution enabled (no `disallow-doctype`/`FEATURE_SECURE_PROCESSING`, or `resolve_entities=True`) is XXE for any XML/SVG/DOCX/SOAP intake.
- [ ] **Open redirect:** Find redirect calls that take their destination from a request parameter (`redirect(request.args["next"])`, `res.redirect(req.query.url)`). An unvalidated external destination is a redirect finding and an OAuth `redirect_uri` lever.

---

## 6. Cryptography Usage

Crypto findings are read directly off the constants: the algorithm name, the mode, the key, the IV, the random source. You do not need to break anything, you need to read the value and recognize it. The constant is the finding.

- [ ] **Weak or deprecated algorithms:** Flag DES, 3DES, RC4, MD5, SHA-1 used for a security purpose. Read the cipher/digest constant, not the surrounding comment.
- [ ] **ECB mode:** Any `AES/ECB`, `MODE_ECB`, or a block cipher with no mode specified where the default is ECB. ECB leaks structure and is a finding on its own.
- [ ] **Hardcoded keys and IVs:** Grep for key and IV literals in source and config. A fixed IV defeats the mode; a hardcoded key is game over (Phase 7).
- [ ] **IV/nonce reuse:** For CTR, GCM, and stream ciphers, confirm the nonce is unique per encryption. A static or counter-from-zero nonce with a reused key breaks confidentiality and, for GCM, authentication.
- [ ] **Weak randomness for secrets:** Flag `Math.random`, `rand()`, `java.util.Random`, Python `random` used to generate tokens, session IDs, keys, or password-reset values. These are predictable; the code needs the CSPRNG (`secrets`, `crypto.randomBytes`, `SecureRandom`).
- [ ] **Certificate validation disabled:** Grep for TLS verification turned off: `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`, a trust-all `HostnameVerifier` or `X509TrustManager`. A "temporary" disable in prod code is a MITM finding.
- [ ] **Missing authenticated encryption:** Confirm encrypt-then-MAC or an AEAD mode where integrity matters. Raw CBC with no MAC on a value the attacker can tamper is a padding-oracle candidate.

---

## 7. Secrets and Git History

Secrets in the working tree are the easy half. The committed-then-deleted secret is still in the history and still valid until rotated. Scan both, and treat the finding as live until the client confirms rotation.

- [ ] **Hardcoded credentials in source:** Grep for API keys, passwords, tokens, private keys, and connection strings in code and config. A `password = "..."` or an `Authorization: Bearer` literal in source is a finding even if it is "only staging".
- [ ] **Committed .env and config:** Confirm `.env`, `*.pem`, `credentials.json`, and cloud config are gitignored and absent from the tree. A committed `.env` is the fastest full compromise in a code review.
- [ ] **Secrets in git history:** Run a history scanner, not just a working-tree grep. A secret removed in a later commit is still recoverable and usually still active.
- [ ] **High-entropy and known-format detection:** Use rule-based scanning (AWS keys, Google API keys, Stripe, GitHub PATs, private key headers) across all history, not just regex on `HEAD`.
- [ ] **Confirm, do not assume, rotation:** A found secret is live until proven otherwise. Report it as active and let the client rotate; never test a real third-party credential beyond confirming its format.

```bash
# Scan full history, not just the working tree (anchor only; full tooling in cheatsheet)
gitleaks detect --source . --log-opts="--all"
```

---

## 8. Input Validation and Output Encoding

Validation and encoding are defense in depth, and the pattern that matters is whether they are centralized or scattered. One sanitizer everyone calls is auditable. Fifty hand-rolled checks guarantee one is wrong. Read for the gap, not the presence.

- [ ] **Centralized vs scattered validation:** Confirm there is a single validation layer, not per-handler ad hoc checks. Scattered validation means the next handler forgets; that handler is your finding.
- [ ] **Encoding at the sink, context-correct:** Confirm output is encoded for its context (HTML body, attribute, JS, URL, CSS) at the point of output. Encoding on input is the wrong layer and breaks under a second context.
- [ ] **Auto-escaping assumptions:** Confirm the template engine's auto-escaping is on and not bypassed. A `|safe`, `{{{ }}}`, `mark_safe`, `dangerouslySetInnerHTML`, `v-html`, or `[innerHTML]` on user data is XSS straight through the framework's protection.
- [ ] **Deny-list where allow-list belongs:** Flag validation that blocks known-bad instead of permitting known-good. A blocklist is bypassed by the input nobody thought of; close the class with an allowlist (shape beats a blocklist).
- [ ] **Validation on the server, not just the client:** Client-side validation is UX. Confirm the server re-validates everything. A field validated only in JS is unvalidated.
- [ ] **Canonicalize before validate:** Confirm decoding/normalization happens before the check, not after. Validating then decoding lets `%2e%2e%2f` pass the check and traverse at the sink.

---

## 9. Error Handling, Logging, and Sensitive Data

Two failure modes live here and they pull in opposite directions: too much detail to the user, and too much detail to the logs. A stack trace to the browser leaks internals; a request body in the log leaks the password. Read both the error path and the log sink.

- [ ] **Stack traces to users:** Confirm production does not return stack traces, SQL errors, or framework banners in responses. A global debug flag left on, or a catch that echoes the exception message, is the leak.
- [ ] **Debug flags in shipped config:** Grep for `DEBUG = True`, `app.debug`, `NODE_ENV` not pinned to production, and verbose-error toggles in deployed config. Django's debug page is a full environment and settings dump.
- [ ] **Secrets and PII in logs:** Read what reaches the logger. Logging whole request/response objects, tokens, passwords, card numbers, or full PII is a finding; the log store is rarely as protected as the database.
- [ ] **Swallowed exceptions hiding security failures:** Flag empty catches and broad `except:`/`catch(e){}` that discard errors on a security-relevant path. A signature-verification failure silently swallowed becomes an auth bypass.
- [ ] **Error-driven user enumeration:** Confirm auth and reset flows return a generic message and consistent timing, with the branch difference not visible in the response or the logs either.

---

## 10. Dependencies and Supply Chain

The lockfile is the source of truth and the attack surface at once. Read the resolved versions, not the declared ranges, and check what runs at install time. A postinstall script runs with your build's privileges before a line of your code executes.

- [ ] **SCA against resolved versions:** Run the composition analysis on the lockfile. Confirm the pinned version, not the manifest range. A `^4.17.0` that resolved to a patched build is fine; the lockfile tells you which.
- [ ] **Known-vuln pinned versions:** Cross-check direct and transitive dependencies against advisories. A single vulnerable transitive dep pulled by three packages is still one finding with the real version cited.
- [ ] **Lockfile integrity:** Confirm the lockfile is committed and integrity hashes are present. A missing or mutable lockfile means the build is not reproducible and a registry swap goes unnoticed.
- [ ] **Typosquats and suspicious names:** Scan dependency names for near-misses on popular packages and recently published low-reputation packages. A `requsts` or a lookalike scoped package is a supply-chain plant.
- [ ] **Install-time scripts:** Read `postinstall`/`preinstall` hooks and `setup.py` code in dependencies where feasible. Install scripts execute in your pipeline; a malicious one does not wait for your app to run.
- [ ] **Unpinned or Git/URL dependencies:** Flag dependencies pulled from a branch, a tag that can move, or an arbitrary URL. Anything not content-pinned can change under you.

---

## 11. Business Logic in Code

Logic flaws survive every scanner because the code is syntactically correct; it just trusts the wrong actor or races itself. Read the rules of the application and ask which invariant the server assumes but never enforces.

- [ ] **Server-authoritative checks:** Confirm price, quantity, discount, balance, status, and role are recomputed or revalidated server-side, never trusted from the request. A total taken from the client body is price tampering by design.
- [ ] **Race conditions and TOCTOU:** Find check-then-act gaps on shared state: balance debits, coupon redemption, inventory decrement, apply-once actions. A read, a decision, and a write with no lock or atomic update is a double-spend under concurrency.
- [ ] **Idempotency on sensitive actions:** Confirm payments, transfers, and one-time actions use an idempotency key or a nonce. Replay of a clean request is a logic finding, not an injection.
- [ ] **Workflow-step enforcement:** Confirm each step in a multi-step flow verifies its prerequisites server-side. A `/checkout/complete` that does not confirm `/checkout/pay` ran is step-skipping.
- [ ] **Trust-boundary assumptions in state:** Identify any value the code treats as server-controlled that actually arrives from the client (`verified`, `ownerId`, `status`, `isAdmin`). Overlaps mass assignment (Phase 4); here you are reading the assumption, not the bind.

---

## 12. Framework-Specific Sinks

Each stack has a short list of calls that are its usual way to get owned. Identify the framework in Phase 2, then grep its danger list. These are the sinks worth a targeted pass before anything generic.

### Spring / Java
- [ ] **SpEL and expression eval:** `@Value("#{...}")` over user input, `SpelExpressionParser` on request data, Thymeleaf `${...}` inline expressions. SpEL evaluates to arbitrary Java.
- [ ] **Deserialization and type handling:** Jackson `enableDefaultTyping`/polymorphic typing, `ObjectInputStream`, and SnakeYAML full-load. Classpath gadgets turn these into RCE.

### Django / Flask / Python
- [ ] **Template injection:** Flask `render_template_string`, Jinja2 `Template()` on user data, Django `|safe`/`mark_safe` and `format_html` misuse.
- [ ] **ORM raw and extra:** Django `.raw()`, `.extra()`, `RawSQL`; SQLAlchemy `text()` with interpolation. Also `pickle` and `yaml.load` on untrusted input.

### Rails / Ruby
- [ ] **Mass assignment and raw SQL:** Missing strong parameters, `where("... #{params}")` string interpolation, `find_by_sql`. And `send`/`constantize`/`to_sym` on user input (object injection, DoS).
- [ ] **Render and redirect:** `render inline:` with user data, `redirect_to params[:url]` (open redirect), and ERB over user content.

### Express / Node
- [ ] **Exec and eval:** `child_process.exec` with concatenated input, `vm` module on user data, and `Function()`/`eval`. Plus `res.redirect(req.query.url)` and template engines with interpolation off the auto-escape path.
- [ ] **Prototype pollution sinks:** Recursive merge/extend/`set` helpers reached by a JSON body with `__proto__` (Recent Techniques).

### .NET
- [ ] **Deserialization and injection:** `BinaryFormatter`, `LosFormatter`, `JavaScriptSerializer` with type handling, XML `XmlSerializer`/`DataContractSerializer` on untrusted data, and `SqlCommand` with string-built text.
- [ ] **Razor and path:** `@Html.Raw` on user data and `Path.Combine` with a user segment reaching file I/O.

### PHP
- [ ] **Classic sinks:** `eval`, `system`/`exec`/`passthru`/`shell_exec`, `unserialize` on user data, `include`/`require` with a user path (LFI/RFI), and `preg_replace` with the `/e` modifier on legacy code.

---

## 13. SAST Tooling and Triage

A scanner finds candidates, not findings. Its job is to point you at the source-to-sink path; your job is to confirm the path is reachable and the data is actually tainted. Report what you have verified, never the raw scanner output. An unreviewed scanner hit in a report is how a review loses the client's trust.

- [ ] **Run Semgrep with a real ruleset:** Use the registry rules plus any stack-specific set, and write a targeted rule for a sink you find by hand. Semgrep is best for pattern sinks; tune out the auto-escaped and the test-only paths.
- [ ] **Run CodeQL for data-flow depth:** Where taint has to cross functions and files, CodeQL's data-flow queries trace further than a pattern match. Worth the setup on a large codebase where the source and sink are far apart.
- [ ] **Triage every hit to reachable or not:** For each candidate, confirm a real untrusted source reaches the sink without an intervening sanitizer. Unreachable sinks and framework-auto-escaped output are the two biggest false-positive buckets.
- [ ] **Prove exploitability where you can:** On the grey-box instance, fire the request that reaches the sink. A runtime confirmation turns a "potential" into a finding and sets the severity honestly.
- [ ] **Deduplicate the same root cause:** One shared helper with a sink, called from forty sites, is one finding about the helper, not forty. Fix and report the family, not each call site.
- [ ] **Diff the scanner against the stack:** A rule written for one framework fires noisily on another. Scope the ruleset to the languages and frameworks actually present before reading the output, or the triage drowns in cross-stack noise.

```
⚠️ A green SAST run is not a clean codebase. Scanners miss authorization gaps, logic
flaws, and anything that needs cross-function reasoning they are not configured for.
Absence of a hit is a statement about your rules, not about the code.
```

---

## Recent Techniques (2024-2026)

Each item is a named technique or a real library CVE with a one-line test-for in source. Fingerprint the dependency version before claiming a library CVE applies.

### Server-Side Prototype Pollution
- [ ] **SSPP gadget chains:** A JSON body with `__proto__`/`constructor.prototype` keys pollutes `Object.prototype`, then a downstream library (ejs, nodemailer, workerpool style) reads the polluted property and reaches a sink. Grep for recursive merge/clone/`set` helpers and check whether they guard `__proto__`.
- [ ] **CVE-2025-64718 (js-yaml prototype pollution):** Prototype pollution in js-yaml. Pin the version from the lockfile and test for the polluted-property effect through any YAML-parsing path.

### SSTI via render over user data
- [ ] **render_template_string / Template() on user input:** The recurring SSTI shape in Python web apps: user data reaching the template string rather than the context. Grep the render calls, then confirm the engine for the escalation path. A `{{7*7}}` yielding `49` at runtime confirms it.
- [ ] **Jinja2 context injection (Frappe/ERPNext class, 2024-2025):** `render_template` over attacker-controlled context in app dashboards and report fields. Test any user-defined template, report, or print-format field.

### Insecure Deserialization Gadget Chains
- [ ] **Classpath gadget reachability:** `pickle.loads`, Java `readObject` with a gadget library (Commons-Collections, etc.) on the classpath, Jackson default-typing, PHP `unserialize` with a POP chain. The sink plus a present gadget library is the finding; confirm the chain, do not assume it. See [Insecure Deserialization to RCE](../Playbooks/Insecure%20Deserialization%20to%20RCE.md).

### Known Library Sinks (verify the pinned version)
- [ ] **Lodash-family and merge-util pollution:** Prototype-pollution sinks in merge/set utilities recur across the ecosystem. Fingerprint the resolved version and trace a JSON source to the merge sink rather than trusting the advisory alone.
- [ ] **XML parser defaults (XXE):** Older parser versions resolve external entities by default. Read the parser construction; the default, not the app code, is the bug.

### SSRF Fix Bypass via Redirect
- [ ] **Validated URL, unvalidated redirect:** Many 2024-2026 SSRF fixes check the submitted URL but not the redirect target, so an allowlisted host 302s to internal. Re-read every "fixed" SSRF sink for whether it revalidates after following redirects.

---

## Reporting and Evidence

### Evidence to Capture per Finding
- [ ] **file:path:line provenance:** Every finding cites the exact file and line of the sink and, where it matters, the source. A finding without a line reference is an assertion. Give the reader the path to the code, not a paraphrase.
- [ ] **Source-to-sink trace:** Show the path from the untrusted input to the dangerous call, including the files it crosses. This is what separates a real finding from a pattern match.
- [ ] **Exploitability proof, not just the pattern:** Where you have the running instance, capture the request/response that reaches the sink. Pattern-matched-only findings must be labelled as such; do not imply runtime confirmation you did not do.
- [ ] **Mutation check for guards:** For any "control is present" claim, record that you removed the guard and the protected behavior broke. A guard you never tested both directions is unverified.
- [ ] **Affected scope:** Note whether the sink is one site or a shared helper called from many, and cite the count.

### Severity Guidance
| Severity | Typical code-review examples |
|---|---|
| Critical | Untrusted deserialization to RCE, SQLi via string-built query on a reachable route, hardcoded signing key enabling token forgery, auth bypass in verify logic |
| High | Stored XSS via `dangerouslySetInnerHTML` on user data, IDOR from a missing owner filter, SSRF reachable from a handler, command injection behind auth |
| Medium | Reflected XSS requiring a specific context, weak password hash (fast digest), mass assignment to a non-critical field, CSRF gap on a sensitive action |
| Low | Missing security header set in code, verbose error handler, weak randomness for a non-secret value, deprecated-but-unreachable crypto call |
| Info | A SAST hit on an auto-escaped output, a sink with no reachable untrusted source, a best-practice deviation with no demonstrated impact |

Let reachability and the data's sensitivity set the label. A sink with no untrusted source is Info, not the scanner's default High. Default to the lower band on a boundary and say why.

### Common False Positives to Rule Out
- [ ] **Auto-escaped output read as XSS:** A value rendered through the framework's default escaping is not XSS. Confirm the escape is actually bypassed (`|safe`, raw-HTML sink) before reporting.
- [ ] **Unreachable sink:** A dangerous call in dead code, a test fixture, or a path no untrusted source reaches is not a finding. Trace the source first.
- [ ] **Parameterized query flagged by a pattern:** A query built with placeholders is safe even if it matches a "SQL + variable" rule. Read the binding.
- [ ] **Sanitized-upstream input:** A sink fed by a value that passed a real validator or canonicalizer is not live. Confirm the sanitizer is correct and not bypassable, then stand down.
- [ ] **Library CVE on a non-vulnerable pinned version:** Confirm the resolved lockfile version is in the affected range before citing the advisory.
- [ ] **Framework default already mitigating:** Some sinks are guarded by a secure framework default. Confirm the default is on in the shipped config, then clear it.

---

## Tools and References

| Tool | Use |
|---|---|
| Semgrep | Pattern-based sink detection and custom rules for a sink found by hand |
| CodeQL | Cross-function data-flow/taint queries on large codebases |
| gitleaks / trufflehog | Secret discovery across the working tree and full git history |
| OWASP Dependency-Check / Grype / Trivy | SCA against the lockfile for known-vuln dependencies |
| npm audit / pip-audit / bundler-audit / govulncheck | Ecosystem-native advisory checks |
| ripgrep (rg) | Fast grep for sinks, raw-query hatches, and dangerous calls |
| jwt_tool | Confirm JWT verify weaknesses found in code against the running instance |
| Burp Suite / mitmproxy | Fire the request that proves a static finding reaches its sink at runtime |
| ysoserial / ysoserial.net | Confirm a deserialization gadget chain against the classpath |

Authoritative references:
- OWASP Code Review Guide: the phase-by-phase manual-review method.
- OWASP Application Security Verification Standard (ASVS): the control requirements each finding maps to.
- OWASP Top 10 and the CWE list: classification for findings.
- Semgrep and CodeQL rule registries: the baseline rulesets to run and extend.

---

## Related

- Checklists: [Web Application](Web%20Application.md), [API Security](API%20Security.md), [CICD Pipeline](CICD%20Pipeline.md)
- Cheatsheets: [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md), [API JWT and GraphQL](../Cheatsheets/API%20JWT%20and%20GraphQL.md), [CICD and Supply Chain](../Cheatsheets/CICD%20and%20Supply%20Chain.md)
- Playbooks: [Insecure Deserialization to RCE](../Playbooks/Insecure%20Deserialization%20to%20RCE.md), [SQL Injection to RCE to Pivot](../Playbooks/SQL%20Injection%20to%20RCE%20to%20Pivot.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
