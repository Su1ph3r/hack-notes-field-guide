---
tags:
  - hack-notes
  - checklist
  - kubernetes
  - cloud
---

# Kubernetes and Containers Testing Checklist

> Phased methodology for assessing Kubernetes clusters and container runtimes: external exposure, in-cluster enumeration from a foothold pod, container breakout, RBAC privilege escalation, lateral movement, supply chain, and cloud integration. Methodology-first. For long commands and breakout payloads see [Kubernetes and Container Breakout](../Cheatsheets/Kubernetes%20and%20Container%20Breakout.md) and Container.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. External and Recon](#2-external-and-recon)
- [3. In-Cluster Enumeration from a Pod](#3-in-cluster-enumeration-from-a-pod)
- [4. Container Breakout](#4-container-breakout)
- [5. RBAC and Privilege Escalation](#5-rbac-and-privilege-escalation)
- [6. Lateral Movement and Pivot](#6-lateral-movement-and-pivot)
- [7. Supply Chain and Images](#7-supply-chain-and-images)
- [8. Cloud Integration](#8-cloud-integration)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

### Scope definition
- [ ] **Cluster inventory:** Confirm in writing every cluster in scope (name, API server endpoint, environment) and that out-of-scope clusters sharing a control plane or registry are explicitly excluded.
- [ ] **Managed vs self-hosted:** Identify the distribution and hosting model. Each changes the attack surface and what you may touch.

| Distribution | Control plane | Notes for testing |
|---|---|---|
| EKS (AWS) | Managed by cloud | Node IAM + IRSA / Pod Identity; etcd not reachable |
| GKE (Google) | Managed by cloud | Workload Identity; metadata server v1 vs v2 |
| AKS (Azure) | Managed by cloud | Managed Identity / Workload Identity federation |
| kubeadm / self-hosted | You own it | etcd, kubelet, control-plane nodes all in scope |
| k3s / RKE2 / OpenShift | Mixed | Bundled components, embedded etcd, SCCs (OpenShift) |

- [ ] **Foothold model:** Agree the starting position: fully external, a low-priv service account token, a shell in an application pod, or a node. Most realistic engagements start from a compromised pod (post-RCE assumption).
- [ ] **RBAC context provided:** Record exactly which credentials/kubeconfigs were issued and their intended privilege. You will validate the real privilege against the intended privilege.
- [ ] **Namespaces in scope:** Confirm which namespaces are fair game. `kube-system` and other operators are usually the crown jewels; confirm before touching.

### Safety and rules of engagement
- [ ] **Production safety:** Confirm whether the target is production. If so, forbid pod-killing, node-draining, resource-exhaustion, and admission-bypass tests that could trigger reconciliation storms.

```
⚠️ DESTRUCTIVE OPERATIONS - get explicit written approval before any of:
  - Creating privileged / hostPath pods on production nodes
  - Reading or exfiltrating real Secrets (request synthetic secrets instead)
  - Deleting or evicting workloads, draining nodes, scaling deployments
  - Assuming cloud IAM roles via node IMDS (can touch prod cloud resources)
  - Writing to etcd directly (bypasses admission and audit, no rollback)
```

- [ ] **Audit-log awareness:** Confirm whether API-server audit logging, Falco/runtime detection, and cloud trail (CloudTrail/Cloud Audit Logs) are active. Note that direct etcd and kubelet access bypass API-server audit; flag this as both a finding and a stealth caveat.
- [ ] **Blast radius for breakout:** A container escape lands you on a node shared by other tenants' pods. Agree node-level actions are constrained and reversible.
- [ ] **Evidence handling:** Agree how stolen tokens/Secrets are stored and destroyed. Treat any extracted service-account token as a live credential.
- [ ] **Cleanup contract:** Track every object you create (pods, roles, bindings, serviceaccounts) for teardown. Label them with an engagement tag for easy cleanup.

---

## 2. External and Recon

### Identify exposed control-plane and node ports
- [ ] **Port sweep:** From the external position, scan the known Kubernetes ports. Exposure of any to the internet is a finding on its own.

| Port | Component | Risk if exposed |
|---|---|---|
| 6443 / 8443 | kube-apiserver | Anonymous/over-permissive access = cluster takeover |
| 10250 | kubelet (read-write) | `/exec`, `/run` = RCE in pods; `/pods` = inventory |
| 10255 | kubelet (read-only) | Pod specs, env vars, tokens (deprecated, often on) |
| 2379 / 2380 | etcd | Full cluster state incl. all Secrets if no mTLS |
| 10257 / 10259 | controller-manager / scheduler | Metrics, profiling |
| 30000-32767 | NodePort services | Directly exposed workloads |

```bash
# anchor only - see cheatsheet for full sweep
nmap -Pn -p 6443,8443,10250,10255,2379,2380,30000-32767 <node-ips>
```

### API server probing
- [ ] **Anonymous access:** Hit the API server unauthenticated and check whether `system:anonymous` has any rights.

```bash
curl -sk https://<api>:6443/version
curl -sk https://<api>:6443/api/v1/namespaces/default/pods   # 403 = good, 200 = finding
```

- [ ] **Anonymous self-review:** If anonymous is bound to anything, enumerate it with `kubectl auth can-i --list` using no credentials.
- [ ] **TLS and version:** Capture the server version from `/version`; map it to known CVEs (see Recent Techniques). Note expired/self-signed certs.

### Kubelet exposure
- [ ] **Read-only port:** GET `http://<node>:10255/pods` and `/metrics`. Pod specs leak env vars, mounted secret names, and sometimes tokens.
- [ ] **Read-write port:** Probe `https://<node>:10250/pods`. If reachable unauthenticated, test command execution via the `/run` or `/exec` endpoint with `kubeletctl`. RCE in any pod is the impact.

```bash
kubeletctl -i --server <node> pods
kubeletctl -i --server <node> exec "id" -p <pod> -c <container> -n <ns>
```

### etcd exposure
- [ ] **Unauthenticated etcd:** Test `etcdctl` against 2379 without a client cert. A readable etcd dumps every Secret, token, and the full cluster state, and bypasses audit. Treat as critical.

### Dashboard and add-ons
- [ ] **Kubernetes Dashboard:** Look for an exposed dashboard. Pre-1.7-style skip-login or an over-privileged dashboard service account is a takeover path.
- [ ] **Other operator UIs:** Argo CD, Rancher, Portainer, Kubeflow, Prometheus, Grafana, Kiali. Default creds and unauth access are common.

### Cloud-managed control planes
- [ ] **Managed endpoint posture:** For EKS/GKE/AKS, check whether the API endpoint is public, has authorized-CIDR restrictions, and whether legacy/anonymous auth modes are on.
- [ ] **OIDC issuer exposure:** Note the cluster OIDC issuer URL (used for IRSA/Workload Identity); it is informative for cloud-side trust analysis later.

### Container registry exposure
- [ ] **Registry reachability:** Enumerate the registries images are pulled from. Test for anonymous pull/push and catalog listing.

```bash
curl -s https://<registry>/v2/_catalog
curl -s https://<registry>/v2/<image>/tags/list
```

- [ ] **Leaked image tags:** Pull accessible images and inspect layers for baked-in secrets, kubeconfigs, and cloud keys (see [7. Supply Chain and Images](#7-supply-chain-and-images)).
- [ ] **Internet exposure baseline:** Cross-check Shodan/Censys for the target ASN on the ports above to confirm what an external attacker already sees.

---

## 3. In-Cluster Enumeration from a Pod

> Assume a shell in an application pod. Goal: understand what this identity and this pod can reach. Breakout-specific posture checks live in [4. Container Breakout](#4-container-breakout) and the full command set in [Kubernetes and Container Breakout](../Cheatsheets/Kubernetes%20and%20Container%20Breakout.md).

### Confirm you are in a pod and grab the token
- [ ] **Environment fingerprint:** Confirm container context via `KUBERNETES_SERVICE_HOST`, `/var/run/secrets/kubernetes.io`, and `/.dockerenv` or cgroup contents.
- [ ] **Service account token:** Read the mounted projected token and CA.

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT
```

- [ ] **Token decode:** Decode the JWT to read the bound service account, namespace, audience, and expiry. Projected short-lived tokens vs legacy non-expiring tokens matters for persistence.
- [ ] **automountServiceAccountToken:** Note whether the token is mounted at all. If mounted and unused by the app, that is a hardening finding.

### API server reachability and self-review
- [ ] **API reachability:** Confirm the in-cluster API server answers with the token.

```bash
curl -sk -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/$NS/pods
```

- [ ] **RBAC self-review:** Enumerate every permission this identity holds. This is the single most important enumeration step.

```bash
kubectl auth can-i --list                       # all verbs/resources for me
kubectl auth can-i create pods
kubectl auth can-i '*' '*'                       # cluster-admin check
kubectl auth can-i create pods --all-namespaces
```

- [ ] **High-value verbs:** Specifically test for the escalation primitives: `create/patch pods`, `pods/exec`, `pods/attach`, `pods/portforward`, `get/list secrets`, `create serviceaccounts/tokenrequest`, `escalate`/`bind` on roles, `impersonate`, and `create` on `validatingwebhookconfigurations`. Carry hits into [5. RBAC and Privilege Escalation](#5-rbac-and-privilege-escalation).
- [ ] **Bypass without kubectl:** If `kubectl` is absent, drive the REST API directly with curl, or drop a static `kubectl`/`peirates` binary. `peirates` automates this whole enumeration.

### Namespace, workload, and secret enumeration
- [ ] **Namespace map:** List namespaces you can see. Note which are operators (`kube-system`, ingress, cert-manager, CI controllers).
- [ ] **Workload recon:** List pods, deployments, daemonsets, cronjobs. Read pod specs for mounted secrets, env vars, sidecars, and privileged settings on neighbors.
- [ ] **Secret enumeration:** If you can list/get Secrets, enumerate them. Look for service-account tokens of more powerful accounts, cloud keys, registry pull creds (`.dockerconfigjson`), TLS keys, and DB passwords.
- [ ] **ConfigMap mining:** ConfigMaps frequently hold connection strings, internal URLs, and the occasional secret-by-mistake.
- [ ] **Service and endpoint map:** List services and endpoints to chart internal reachability (databases, internal APIs, the metadata server).

### Network policy and segmentation mapping
- [ ] **NetworkPolicy inventory:** List NetworkPolicies in reachable namespaces. Absence of any policy means flat pod-to-pod networking, a finding and a movement enabler.
- [ ] **Reachability probing:** From the pod, test connectivity to the API server, other pods, node IP, kubelet (10250), the cloud metadata IP (169.254.169.254), and external egress. Build the actual reachable graph.
- [ ] **DNS enumeration:** Use CoreDNS to enumerate services cluster-wide (`*.svc.cluster.local`) even where listing is denied.
- [ ] **Pod Security context of self:** Capture your own securityContext, capabilities, seccomp/AppArmor profile, and mounts. These feed the breakout decision in the next phase.

---

## 4. Container Breakout

> Escape from the container onto the node. Run posture checks first, pick the matching escape. Full command-by-command payloads in [Kubernetes and Container Breakout](../Cheatsheets/Kubernetes%20and%20Container%20Breakout.md) and Container; node-side privesc continues in Cepheus and [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md).

### Posture assessment (decide the path before acting)
- [ ] **Privileged flag:** Check `securityContext.privileged`. A privileged container has all capabilities and device access; escape is trivial (mount host disk, nsenter into PID 1).
- [ ] **Capabilities:** Dump effective caps (`capsh --print`, `/proc/self/status` CapEff). Flag `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_DAC_READ_SEARCH`, `CAP_NET_RAW`.
- [ ] **Host namespaces:** Check `hostPID`, `hostNetwork`, `hostIPC` on the pod spec.
  - `hostPID` lets you see and `nsenter` host processes.
  - `hostNetwork` puts you on the node network (reach kubelet, metadata, node-local services).
- [ ] **Host mounts:** Inspect mounts for `hostPath` volumes, especially `/`, `/var/run/docker.sock`, `/var/run/containerd`, `/var/lib/kubelet`, `/etc`, and host `/proc`.
- [ ] **Automated triage:** Run `deepce`, `BOtB` (Break out the Box), `CDK`, or `kdigger` to enumerate every escape primitive at once, then confirm by hand.

### Escape techniques
- [ ] **Privileged escape:** In a privileged container, mount the host root device and chroot, or `nsenter -t 1 -m -u -i -n -p` into the host. Confirm by reading a host-only file.
- [ ] **hostPath abuse:** With a writable host mount, write to host paths: drop a cron job, an SSH key in a host user's `authorized_keys`, or a kubelet static-pod manifest under `/etc/kubernetes/manifests` for a privileged pod on the node.
- [ ] **Docker / containerd socket:** A mounted `docker.sock` or containerd socket is full node compromise: launch a new privileged container mounting host `/`.

```bash
# anchor - socket present == game over
docker -H unix:///var/run/docker.sock run -it -v /:/host --privileged alpine chroot /host sh
```

- [ ] **CAP_SYS_ADMIN escapes:** With `CAP_SYS_ADMIN` test the cgroup-v1 `release_agent` notify-on-release escape and core_pattern abuse to execute a payload on the host.
- [ ] **/proc and cgroup escapes:** Test writable `/proc/sys/kernel/core_pattern`, writable host `/proc`, and cgroup `release_agent` paths. These are the same primitives the 2025 runc CVEs reach via mount tricks.
- [ ] **runc / containerd CVE escapes:** Where the runtime is outdated, test the known runtime escapes (Leaky Vessels CVE-2024-21626 and the 2025 runc trio). See Recent Techniques for versions and tests.
- [ ] **Kernel exploits:** As a last resort on an unpatched node, identify the kernel version and test a matching LPE (Dirty Pipe CVE-2022-0847, Dirty COW, OverlayFS, nf_tables). Coordinate closely; kernel exploits can panic the node.
- [ ] **Confirm node identity:** After any escape, prove it: read `/etc/kubernetes` files, the kubelet kubeconfig, node-local Secrets, or run `id` in PID 1's namespace. Capture a host-only artifact as evidence.

### Post-escape on the node
- [ ] **Steal node credentials:** Read the kubelet client cert/kubeconfig (`/var/lib/kubelet`, `/etc/kubernetes/kubelet.conf`) to act as `system:node`.
- [ ] **Harvest neighbor secrets:** Read other pods' projected tokens from `/var/lib/kubelet/pods/*/volumes/.../token` to impersonate every workload scheduled on the node.
- [ ] **Reach the node IMDS:** From the node, hit the cloud metadata service for IAM credentials. Hand off to [8. Cloud Integration](#8-cloud-integration).

---

## 5. RBAC and Privilege Escalation

> Turn the foothold identity into cluster-admin or a powerful cloud identity using legitimate API verbs. Most cluster takeovers are RBAC, not kernel.

### Token and identity abuse
- [ ] **Powerful tokens found:** For any service-account token harvested in Phase 3/4, decode and self-review it. A token bound to `cluster-admin`, `edit` in `kube-system`, or a CI controller account is the prize.
- [ ] **TokenRequest abuse:** If you can `create serviceaccounts/token` (TokenRequest) for a more powerful SA, mint a token for it and use it directly.
- [ ] **Long-lived token theft:** Legacy non-expiring SA token Secrets persist after pod death; flag them as both an escalation path and a persistence risk.

### Pod-creation escalation
- [ ] **pods/exec into privileged pods:** With `pods/exec` you can enter a neighbor pod that holds a stronger token or runs privileged. Enumerate neighbor SAs first.
- [ ] **create-pod-with-hostPath:** If you can `create pods` (directly or via a controller), schedule a pod that mounts host `/` via `hostPath`, or runs `privileged: true`, then read the node filesystem and all node-local tokens. This is the canonical `create pods` -> node -> cluster-admin path.

```yaml
# anchor - hostPath read of node root
volumes: [{name: h, hostPath: {path: /}}]
containers: [{name: c, image: alpine, command: ["sleep","1d"],
  volumeMounts: [{name: h, mountPath: /host}]}]
```

- [ ] **Workload controllers as a proxy:** No direct `create pods`? Check `create/patch` on deployments, daemonsets, statefulsets, jobs, cronjobs, replicasets. Creating a workload makes the controller create the pod for you, often with a more powerful SA.
- [ ] **Node selection:** Where it matters, pin the malicious pod to a control-plane node via `nodeSelector`/tolerations to land next to the API server and etcd.

### Verb-based escalation
- [ ] **escalate verb:** If you hold `escalate` on roles/clusterroles, you can grant yourself permissions beyond your own. Test creating a role with higher rights.
- [ ] **bind verb:** With `bind` you can bind yourself (or your SA) to an existing powerful ClusterRole such as `cluster-admin`.
- [ ] **impersonate verb:** With `impersonate` you can act as another user, group, or service account, including `system:masters`. Test `kubectl --as` / `--as-group`.

```bash
kubectl auth can-i '*' '*' --as system:admin
kubectl get secrets -n kube-system --as=system:serviceaccount:kube-system:clusterrole-aggregation-controller
```

- [ ] **Wildcard / over-broad roles:** Flag any Role/ClusterRole granting `*` verbs or `*` resources, or access to `secrets`, `pods/exec`, or the `*` API group. These are the recurring 2024-2026 escalation roots.

### Secret theft and downstream
- [ ] **Secret sweep:** Where `get/list secrets` is granted (any namespace), enumerate and triage: cloud keys, kubeconfigs, registry creds, signing keys, DB creds, TLS private keys.
- [ ] **Workload identity to cloud:** Map service accounts annotated for IRSA / GKE Workload Identity / AKS Workload Identity. Controlling such an SA (or scheduling a pod as it) yields a cloud IAM role. Hand off to [8. Cloud Integration](#8-cloud-integration) and [AWS Cloud Penetration Test](AWS%20Cloud%20Penetration%20Test.md).
- [ ] **CertificateSigningRequest abuse:** If you can `create` and `approve` CSRs, mint a client cert for a privileged user/group (e.g. `system:masters`).
- [ ] **Webhook abuse:** If you can `create` validating/mutating webhook configurations, you can mutate or intercept admission cluster-wide (inject sidecars, exfiltrate Secrets at admission time).

---

## 6. Lateral Movement and Pivot

> Move across pods, nodes, namespaces, and out to the cloud account. Tunneling and proxy mechanics in [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md).

### Pod-to-pod and namespace
- [ ] **Flat-network reach:** Where NetworkPolicy is absent, sweep reachable pod IPs for unauthenticated internal services (databases, Redis, internal admin APIs, message queues).
- [ ] **Service mesh abuse:** In Istio/Linkerd meshes, test whether mTLS is enforced (PeerAuthentication PERMISSIVE = plaintext accepted), whether sidecar bypass is possible via direct pod IP, and whether the mesh control plane (istiod) is reachable.
- [ ] **Cross-namespace via tokens:** Use stolen tokens to access namespaces the original identity could not, repeating the Phase 3 enumeration as each new identity.
- [ ] **portforward pivot:** With `pods/portforward`, reach internal-only services through the API server without a network route.

### Node-to-node and control plane
- [ ] **system:node reach:** With a stolen kubelet credential, enumerate what `system:node:<name>` can read (the Secrets and configmaps for pods on that node).
- [ ] **Kubelet-to-kubelet:** From one compromised node, probe other nodes' kubelet 10250 for exec/run.
- [ ] **etcd from a control node:** On a control-plane node, read etcd directly (client certs are local) to dump all Secrets and cluster state, bypassing audit.
- [ ] **API server as a pivot:** Use `kubectl proxy`, `exec`, and `portforward` to reach otherwise-unroutable internal targets through the control plane (API-server bypass risk).

### Cluster to cloud
- [ ] **Node IMDS pivot:** From any pod on `hostNetwork` or from the node, reach 169.254.169.254 for the node instance role. Node roles are frequently over-permissioned (ECR pull, EC2, S3, sometimes `eks:*`).
- [ ] **Metadata to cloud lateral:** Use the assumed cloud role to move laterally in the cloud account, then potentially back into other clusters. Continue in [AWS Cloud Penetration Test](AWS%20Cloud%20Penetration%20Test.md).
- [ ] **Cross-cluster:** Look for kubeconfigs/tokens to other clusters in Secrets, CI configs, and node files. A CI/management SA often controls many clusters.

---

## 7. Supply Chain and Images

> The build-and-deploy pipeline is often the softest path in. Pipeline-specific testing in [CICD and Supply Chain](../Cheatsheets/CICD%20and%20Supply%20Chain.md).

### Image inspection
- [ ] **Pull and dissect:** Pull in-scope images and inspect every layer history and filesystem for baked-in secrets, tokens, private keys, kubeconfigs, and `.npmrc`/`.git-credentials`.
- [ ] **Tag and digest hygiene:** Flag deployments pinned to mutable tags (`latest`) rather than digests; a registry-write attacker can swap the image under a mutable tag.
- [ ] **Vulnerability scan:** Scan images (Trivy/Grype) for vulnerable base images and known-vuln packages that enable in-pod escalation or breakout.
- [ ] **Provenance / SBOM:** Check for image provenance and SBOM attestations; absence weakens any signing story.

### Registry and pull security
- [ ] **Registry auth:** Re-test the registry from Phase 2 for anonymous push. Push access = trojaned images into the cluster.
- [ ] **Pull secret theft:** Harvest `.dockerconfigjson` pull secrets from namespaces; they often grant registry write, not just read.

### Admission control and signing
- [ ] **Admission posture:** Enumerate Validating/MutatingWebhookConfigurations, Pod Security Admission level (privileged/baseline/restricted), and any policy engine (OPA Gatekeeper, Kyverno, sigstore policy-controller).
- [ ] **Signed-image enforcement:** Where cosign/sigstore is in use, confirm enforcement is actually on. Common gaps: namespaces not opted in (`policy.sigstore.dev/include` label missing), `no-match-policy: allow`, or warn-only mode. Test by deploying an unsigned image.
- [ ] **Admission bypass:** Test the standard bypasses: namespaces excluded by webhook `namespaceSelector`/`objectSelector`, `failurePolicy: Ignore` (kill or DoS the webhook then deploy), creating workloads via controllers the policy does not gate, and direct etcd/static-pod writes that never hit admission.
- [ ] **Malicious image deploy:** With sufficient rights, deploy a benign-but-marked test image proving an attacker image would run; do not deploy real malware on a live cluster.
- [ ] **Mutating-webhook injection:** Re-check (from Phase 5) whether you can create a mutating webhook to inject sidecars or env into every new pod cluster-wide.

---

## 8. Cloud Integration

> Convert cluster access into cloud-account access and vice versa. Cloud-side exploitation continues in [AWS Cloud Penetration Test](AWS%20Cloud%20Penetration%20Test.md).

### Workload identity mapping
- [ ] **IRSA / Workload Identity inventory:** List service accounts annotated for cloud identity:
  - EKS IRSA: `eks.amazonaws.com/role-arn`
  - EKS Pod Identity: association objects
  - GKE: `iam.gke.io/gcp-service-account`
  - AKS: workload-identity federation annotations / client-id labels
- [ ] **SA-to-role mapping:** For each, resolve the bound cloud role and its policy. Over-scoped trust (role assumable by `*` SA, or a broad namespace pattern) is a finding.
- [ ] **Assume and enumerate:** Where authorized, schedule/exec as the annotated SA, obtain the federated cloud token, and enumerate the role's permissions read-only first.

```bash
# in a pod with IRSA - token is auto-injected
aws sts get-caller-identity
cat $AWS_WEB_IDENTITY_TOKEN_FILE   # projected OIDC token
```

### Metadata service from pods
- [ ] **IMDS reachability:** From a pod, test 169.254.169.254. If reachable and IMDSv1 is allowed (or hop-limit permits pod access), the pod can steal the node instance role, bypassing IRSA scoping entirely. This is a top finding.
- [ ] **Metadata hardening check:** Confirm whether IMDS access from pods is blocked (network policy, hop limit 1, or a metadata proxy). GKE metadata concealment and `GKE_METADATA` mode should hide the node SA.
- [ ] **Node role over-permission:** Enumerate the node instance role. Look for `eks:*`, `iam:PassRole`, `s3:*`, `secretsmanager:*`, or anything enabling cloud-account escalation.

### Cluster to cloud account takeover
- [ ] **Privilege chain:** Chain pod SA / node role into broader cloud access (IAM privesc, assume other roles, read cloud Secrets/KMS). Document the full path: pod -> token/role -> cloud privesc -> account-wide impact.
- [ ] **Control-plane via cloud:** Test the reverse: a cloud IAM principal with `eks:AccessKubernetesApi`, aws-auth ConfigMap edit, or GKE `container.clusters.getCredentials` grants cluster-admin from the cloud side. Map who in the cloud account can become cluster-admin.
- [ ] **Secrets backends:** Check External Secrets Operator / CSI Secrets Store bindings; a compromised pod SA may read the cloud Secrets backend directly.

---

## Recent Techniques (2024-2026)

- [ ] **runc CVE-2025-31133 (masked-path / /dev/null symlink):** runc bind-mounts `/dev/null` to mask host files; a symlink swap redirects the mount read-write into the container, enabling a `/proc` write and escape. Test for: runc older than 1.2.8 / 1.3.3 / 1.4.0-rc.3; missing user-namespace remap.
- [ ] **runc CVE-2025-52565 (/dev/console bind race):** Race/symlink on the `/dev/console` bind mount writes attacker-controlled targets before protections apply, granting procfs write. Test for: same outdated runc versions.
- [ ] **runc CVE-2025-52881 (arbitrary write redirect):** Writes intended for `/proc` are redirected to attacker-controlled locations, enabling escape and DoS. Test for: outdated runc; verify user namespaces are in use as the primary mitigation.
- [ ] **Leaky Vessels CVE-2024-21626 (runc WORKDIR fd leak):** A leaked file descriptor lets a container's working directory resolve to the host filesystem, giving build-time and run-time escape. Test for: runc < 1.1.12; malicious `WORKDIR`/Dockerfile in build pipelines.
- [ ] **IngressNightmare CVE-2025-1974 (ingress-nginx admission RCE, CVSS 9.8):** Unauthenticated RCE by sending a crafted AdmissionReview to the ingress-nginx admission controller, injecting NGINX config (`ssl_engine`/load_module) to load a body-buffered shared library. Leads to reading all cluster Secrets. Test for: ingress-nginx < 1.11.5 / < 1.12.1; admission webhook reachable on the pod network.
- [ ] **Kubelet nodes/proxy and exposed 10250:** Permissive kubelet `/exec` and `/run`, plus `nodes/proxy` GET RBAC, yield silent in-pod RCE that bypasses API audit. Test for: anonymous kubelet auth, `system:anonymous` or broad accounts holding `nodes/proxy`.
- [ ] **etcd without mTLS (2379):** Direct etcd read dumps all Secrets and bypasses admission and audit entirely. Test for: client-cert auth disabled, etcd reachable off the control-plane host.
- [ ] **Mass internet exposure:** Hundreds of thousands of API servers, kubelets, and thousands of etcd instances remain internet-exposed. Always validate external exposure first via Shodan/Censys on 6443/10250/2379.
- [ ] **Long-lived SA token theft and cross-cluster pivot:** Suspected SA token theft seen in ~22% of cloud environments. Test for non-expiring legacy token Secrets and tokens for CI/management SAs that control multiple clusters.
- [ ] **Sigstore policy-controller enforcement gaps:** Signed-image policy not opt-in per namespace, `no-match-policy: allow`, or warn-mode lets unsigned images run. Test by deploying an unsigned image into each namespace.
- [ ] **Admission bypass via failurePolicy/selectors:** `failurePolicy: Ignore` plus a DoS of the webhook, or `namespaceSelector`/`objectSelector` exclusions, lets non-compliant pods through. Map every webhook's failurePolicy and selectors.

---

## Reporting and Evidence

### Evidence to capture per finding
- [ ] **Identity and context:** The credential used (SA name, namespace, token audience/expiry), the cluster, and the API endpoint.
- [ ] **Proof command and output:** The exact `kubectl auth can-i` / curl / kubeletctl call and its response. For breakout, a host-only artifact (node hostname, `/etc/kubernetes` file, neighbor token).
- [ ] **Object manifests:** Any pod/role/binding you created, plus confirmation of teardown.
- [ ] **Path narrative:** For escalation and pivot, the ordered chain from foothold to impact (pod -> verb -> node -> cloud), framed as a defect chain.

### Severity guidance

| Impact | Typical severity |
|---|---|
| Anonymous API/etcd/kubelet exposure, cluster-admin path, container escape to node, cluster-to-cloud account takeover | Critical |
| Cross-namespace secret read, single-namespace privesc, IMDS theft of node role, IngressNightmare-class RCE | High |
| Over-broad RBAC without a proven chain, missing NetworkPolicy, unsigned-image enforcement gap | Medium |
| automount on unused SA, verbose pod env, deprecated read-only kubelet port | Low / Informational |

### Common false positives to rule out
- [ ] **403 is not always safe:** Confirm the 403 is RBAC denial, not an auth-proxy in front; re-test with the real in-cluster token.
- [ ] **can-i says yes, API says no:** `auth can-i` reflects RBAC only; admission webhooks or Pod Security Admission may still block the action. Always attempt the action to confirm.
- [ ] **Capability present but namespaced:** A capability in CapEff may be neutralized by user namespaces, seccomp, or AppArmor. Confirm the escape actually works before rating it.
- [ ] **hostPath without write:** A read-only host mount is lower impact than a writable one; verify the mount mode.
- [ ] **IMDS reachable but no role:** A reachable metadata IP with no useful instance role attached is informational, not High. Enumerate the role before rating.
- [ ] **Managed-control-plane non-issues:** etcd/control-plane components you "cannot reach" on EKS/GKE/AKS are by design; do not report the managed boundary as a finding.

---

## Tools and References

| Tool | Use |
|---|---|
| `kubectl auth can-i` | RBAC self-review, the core enumeration primitive |
| kube-hunter | Remote recon: exposed API server, kubelet, dashboard, etcd |
| kubeletctl | Kubelet 10250 enumeration and exec/run RCE |
| Peirates | In-cluster exploitation, token harvest, escalation, cloud pivot |
| kube-bench | CIS benchmark posture (control-plane and node config) |
| deepce / BOtB / CDK / kdigger | Container breakout enumeration and escape primitives |
| Trivy / Grype | Image and config vulnerability scanning |
| MTKPI | Bundled multi-tool pentest image (botb, kubeletctl, peirates, kube-hunter, kube-bench, etc.) |
| cosign / sigstore policy-controller | Image signature verification and policy enforcement testing |

References:
- Kubernetes RBAC Good Practices and API Server Bypass Risks (kubernetes.io/docs/concepts/security)
- CIS Kubernetes Benchmark
- NSA/CISA Kubernetes Hardening Guidance
- MITRE ATT&CK for Containers
- OWASP Kubernetes Top Ten
- Vendor advisories: opencontainers/runc security advisories; Wiz IngressNightmare disclosure

---

## Related

- Playbooks: [Kubernetes Pod to Cluster to Cloud](../Playbooks/Kubernetes%20Pod%20to%20Cluster%20to%20Cloud.md)
- [Kubernetes and Container Breakout](../Cheatsheets/Kubernetes%20and%20Container%20Breakout.md)
- Container
- Cepheus
- [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md)
- [AWS Cloud Penetration Test](AWS%20Cloud%20Penetration%20Test.md)
- [CICD and Supply Chain](../Cheatsheets/CICD%20and%20Supply%20Chain.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md)
- Caminus
