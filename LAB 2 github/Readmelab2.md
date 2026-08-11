# IKB42603 Cloud Computing Security Essentials

## Lab 2: Secure Isolation & Multi-Tenancy

**Name:** UZAIR BIN SAMSUDIN

**ID:** 52215124300

---

## 1. Objective

This lab demonstrates how to securely isolate multiple tenants on a shared Kubernetes cluster. The core goal is to move from a default-open, shared infrastructure (which exposes cross-tenant risk) to a hardened, properly segmented environment using Kubernetes namespaces, NetworkPolicies, RBAC-enforced secret isolation, and secure data deletion techniques.

## 2. Learning Outcomes

Upon completion of this lab, the student will be able to:

1. Demonstrate compute isolation by separating tenants into containers and Kubernetes namespaces.
2. Observe the default-open behaviour of shared infrastructure and explain why it is a security risk.
3. Implement network isolation with a default-deny NetworkPolicy and prove that cross-tenant traffic is effectively blocked.
4. Enforce storage isolation ensuring one tenant cannot read another tenant's data or secrets.
5. Explain data remanence concerns and demonstrate secure deletion techniques within Docker volumes.

## 3. Environment

| Component | Detail |
|-----------|--------|
| OS | Linux (Ubuntu) |
| Container Runtime | Docker Engine |
| Cluster Tool | kind (Kubernetes IN Docker) — cluster name: ccse-lab2 |
| CNI Plugin | Calico v3.27.0 (required to enforce NetworkPolicy) |
| CLI Tools | kubectl, docker |
| Network Plugin | Default kind CNI disabled; Calico installed manually |
| Pod Subnet | 192.168.0.0/16 |
| Session A Focus | Compute isolation (Tasks 1–3) |
| Session B Focus | Network & storage isolation (Tasks 4–6) |

**Note:** The default kind network driver does not enforce NetworkPolicy rules. Calico must be installed as the CNI to make isolation policies take actual effect.

## 4. Step-by-Step Implementation

### Session A (Week 3) — Compute Isolation & the Default-Open Risk

#### Setup — Cluster with Policy Enforcement

A `kind` cluster was created with the default CNI disabled so that Calico could be installed as the enforcing CNI plugin.

```bash
# Create a cluster with the default CNI disabled
cat <<EOF | kind create cluster --name ccse-lab2 --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
 disableDefaultCNI: true
 podSubnet: 192.168.0.0/16
EOF

# Install Calico as the CNI
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml

# Wait for Calico to be ready
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
```

**Note:** If there is no internet in the lab room, your instructor can provide the `calico.yaml` file locally — apply it with `kubectl apply -f calico.yaml`.

#### Task 1 — Two Tenants on One Cluster

Two Kubernetes namespaces were created to model two separate cloud tenants (`tenant-a` and `tenant-b`). An nginx web server deployment and ClusterIP service were created for each tenant to simulate a real workload.

```bash
# Create namespaces
kubectl create namespace tenant-a
kubectl create namespace tenant-b

# Deploy a web server for each tenant
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx

# Expose each deployment on port 80
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80

# Verify pods and services
kubectl get pods,svc -n tenant-a
kubectl get pods,svc -n tenant-b
```

**Result:** Both namespaces had their nginx pods starting (`ContainerCreating`) and their respective `ClusterIP` services assigned — `10.96.131.74` for `tenant-a` and `10.96.89.109` for `tenant-b`.

#### Task 2 — Observe the Default-Open Risk

A temporary `curl` probe pod was launched inside `tenant-a` and directed to `tenant-b`'s service ClusterIP. This test demonstrates that by default, there is no network isolation between namespaces on a Kubernetes cluster.

```bash
# Get tenant-b's ClusterIP
kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'; echo

# Launch a probe from tenant-a targeting tenant-b's IP
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
 -- curl -s -m 5 http://<B_IP> -o /dev/null -w 'HTTP %{http_code}\n'
```

**Result:** HTTP 200 — `tenant-a` successfully reached `tenant-b`'s web server with no restrictions. This is the multi-tenancy risk: without explicit isolation controls, any pod can reach any other pod across namespace boundaries.

#### Task 3 — Contain the Noisy Neighbor (Resource Quotas)

A `ResourceQuota` was applied to `tenant-a` to ensure it cannot monopolise the shared cluster's CPU, memory, or pod capacity.

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
 name: tenant-a-quota
 namespace: tenant-a
spec:
 hard:
 requests.cpu: "1"
 requests.memory: 512Mi
 pods: "5"
EOF

# Verify the quota
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

**Result:** The quota was applied, capping `tenant-a` to a maximum of 5 pods, 1 CPU core, and 512 MiB of memory. This addresses the noisy-neighbour problem in multi-tenant environments.

### Session B (Week 4) — Network & Storage Isolation

#### Task 4 — Default-Deny Network Isolation

A `NetworkPolicy` of type `default-deny-ingress` was applied to `tenant-b`. This policy selects all pods in the namespace and denies all incoming traffic by default — implementing the deny-by-default, permit-by-exception principle.

```bash
# Apply default-deny NetworkPolicy to tenant-b
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
 name: default-deny-ingress
 namespace: tenant-b
spec:
 podSelector: {}
 policyTypes: [Ingress]
EOF

# Re-run the SAME probe from Task 2 — it should now TIME OUT / fail
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
 -- curl -s -m 5 http://<B_IP> -o /dev/null -w 'HTTP %{http_code}\n'
```

**Result:** HTTP 000 — the connection timed out and returned no HTTP response. The probe pod also terminated with an error status, confirming that the network path was now fully blocked by the policy.

**Security tip:** Capture both results side by side: HTTP 200 (before) and timeout (after). This single before/after is the strongest evidence of enforced network isolation.

#### Task 5 — Storage & Secret Isolation

Per-tenant Kubernetes `secret` objects were created. A `serviceaccount`, `Role`, and `RoleBinding` were configured to scope `tenant-a`'s application identity strictly to its own namespace. The `kubectl auth can-i` command was used to verify that cross-namespace secret access is denied.

```bash
# Create a secret in each tenant
kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B

# Create a service account and RBAC role scoped to tenant-a only
kubectl -n tenant-a create serviceaccount app-a
kubectl -n tenant-a create role reader --verb=get --resource=secrets
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a

# Test authorization
SA=system:serviceaccount:tenant-a:app-a
kubectl auth can-i get secrets -n tenant-a --as=$SA    # Expected: yes
kubectl auth can-i get secrets -n tenant-b --as=$SA    # Expected: no
```

**Result:**

- `kubectl auth can-i get secrets -n tenant-a --as=$SA` → yes
- `kubectl auth can-i get secrets -n tenant-b --as=$SA` → no

Storage isolation was confirmed. The `Role` and `RoleBinding` are namespace-scoped, so `app-a`'s permissions do not extend beyond `tenant-a`.

#### Task 6 — Data Remanence & Secure Deletion

Data remanence was demonstrated by creating a file, deleting it normally, and showing that its contents may persist on disk. A `grep` scan after deletion was used to check for remnant bytes. A second pass used `dd` to overwrite the file with zeros before deletion — a simple form of secure erasure.

```bash
# Step 1: Write, delete normally, then scan for remnant data
docker run --rm -v ccse-vol:/data alpine sh -c \
 'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
 grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'

# Step 2: Write, overwrite with zeros, then delete (secure wipe)
docker run --rm -v ccse-vol:/data alpine sh -c \
 'echo SENSITIVE > /data/phi2.txt; sync; \
 dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; \
 echo wiped'
```

**Result:**

- After normal `rm`, the scan completed with `scan-done` (no recoverable bytes found at the filesystem layer in this run, though physical media remanence remains a concern at lower layers).
- After `dd` overwrite, the output confirmed `1+0 records in, 1+0 records out, 1024 bytes (1.0kB)` copied at 33.7 MB/s, followed by `wiped`. This demonstrates that overwriting before deletion is the correct mitigation.

**Note:** In cloud storage you rarely control physical blocks, so the practical answer to remanence is cryptographic erasure (destroy the key). You will do exactly that in Lab 3.

## 5. Commands Used

| Command | Task | Purpose |
|---------|------|---------|
| `kind create cluster --name ccse-lab2 --config=-` | Setup | Create kind cluster with Calico CNI |
| `kubectl apply -f calico.yaml` | Setup | Install Calico as CNI plugin |
| `kubectl create namespace tenant-a/b` | Task 1 | Create tenant namespaces |
| `kubectl -n <ns> create deployment web --image=nginx` | Task 1 | Deploy nginx per tenant |
| `kubectl -n <ns> expose deployment web --port=80` | Task 1 | Expose web service |
| `kubectl get pods,svc -n <ns>` | Task 1 | Verify pods and services |
| `kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'` | Task 2 | Get tenant-b's ClusterIP |
| `kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never -- curl -s -m 5 http://<B_IP> -o /dev/null -w 'HTTP %{http_code}\n'` | Task 2 & 4 | Run cross-tenant HTTP probe |
| `kubectl apply -f <ResourceQuota YAML>` | Task 3 | Apply resource quota |
| `kubectl describe resourcequota tenant-a-quota -n tenant-a` | Task 3 | Verify quota |
| `kubectl apply -f <NetworkPolicy YAML>` | Task 4 | Apply default-deny ingress policy |
| `kubectl get networkpolicy -A` | Task 4 | Verify all network policies |
| `kubectl -n <ns> create secret generic data --from-literal=value=<value>` | Task 5 | Create tenant secrets |
| `kubectl -n tenant-a create serviceaccount app-a` | Task 5 | Create scoped service account |
| `kubectl -n tenant-a create role reader --verb=get --resource=secrets` | Task 5 | Create RBAC role |
| `kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a` | Task 5 | Bind role to service account |
| `kubectl auth can-i get secrets -n <ns> --as=$SA` | Task 5 | Verify RBAC enforcement |
| `docker run --rm -v ccse-vol:/data alpine sh -c '...'` | Task 6 | Data remanence & secure wipe |
| `kind delete cluster --name ccse-lab2` | Cleanup | Tear down the cluster |
| `docker volume rm ccse-vol` | Cleanup | Remove Docker volume |

## 6. Screenshots

### Screenshot 1 — Task 1: Two Tenants on One Cluster

Namespaces created, nginx deployments and services deployed for `tenant-a` and `tenant-b`.

![Task 1 Screenshot](Task%201%20Two%20Tenants%20on%20One%20Cluster.png)

**Findings:**
- Both pods were in `ContainerCreating` state immediately after deployment.
- `tenant-a`'s service was assigned ClusterIP `10.96.131.74`
- `tenant-b`'s service was assigned ClusterIP `10.96.89.109`
- Both tenants share the same cluster infrastructure, demonstrating compute isolation via namespaces.

### Screenshot 2 — Task 2: Observe the Default-Open Risk

HTTP probe from `tenant-a` successfully reached `tenant-b`'s web server.

![Task 2 Screenshot](Task%202%20Observe%20the%20Default-Open%20Risk.png)

**Result:** HTTP 200 — Cross-tenant traffic is unrestricted by default. This demonstrates the multi-tenancy risk.

### Screenshot 3 — Task 3: Contain the Noisy Neighbor (Resource Quotas)

ResourceQuota applied to `tenant-a` limiting pods, CPU, and memory.

![Task 3 Screenshot](Task%203%20Contain%20the%20Noisy%20Neighbour%20(Resource%20Quotas).png)

**Result:** Quota enforced successfully, capping `tenant-a` to 5 pods, 1 CPU core, and 512 MiB of memory.

### Screenshot 4 — Task 4: Default-Deny Network Isolation

NetworkPolicy applied to `tenant-b`; same probe now times out.

![Task 4 Screenshot](Task%204%20—%20Default-Deny%20Network%20Isolation.png)

**Result:** HTTP 000 (timeout) — Network path is now blocked by the policy.

### Screenshot 5 — Task 5: Storage & Secret Isolation

RBAC authorization test showing `tenant-a` can read its own secrets but not `tenant-b`'s.

![Task 5 Screenshot](Task%205%20(Storage%20&%20Secret%20Isolation).png)

**Result:**
- `kubectl auth can-i get secrets -n tenant-a --as=$SA` → **yes**
- `kubectl auth can-i get secrets -n tenant-b --as=$SA` → **no**

Storage isolation confirmed via RBAC enforcement.

### Screenshot 6 — Task 6: Data Remanence & Secure Deletion

Docker volume demonstrating normal deletion vs. secure wipe with `dd`.

![Task 6 Screenshot](Task%206%20(Data%20Remanence%20&%20Secure%20Deletion).png)

**Result:**
- Normal `rm`: `scan-done` (no remnant bytes at filesystem layer in this run).
- Secure `dd` overwrite: `1+0 records in, 1+0 records out, 1024 bytes (1.0kB)` — demonstrating effective data destruction.

## 7. Short-Answer Questions

### Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?

By default, Kubernetes uses a **flat networking model** where every pod receives a unique IP address and can route traffic to any other pod across all namespaces. Namespaces function primarily as **administrative and logical containers** (providing independent resource names and RBAC boundaries) rather than security firewalls. In a multi-tenant cloud setting, this flat network posture introduces severe risks: a compromised pod in one tenant's namespace can freely perform network discovery, attempt lateral movement, or directly interact with services hosted in another tenant's namespace. Without active `NetworkPolicy` enforcement, tenant isolation is compromised at the network layer.

---

### Q2. Explain the default-deny principle and how your NetworkPolicy implements it.

The **default-deny principle** is a fundamental Zero-Trust posture specifying that *all traffic is implicitly blocked unless explicitly authorized by an ingress or egress rule*. This prevents security gaps caused by forgotten or misconfigured permissions, ensuring that unhandled traffic fails safely.

In this lab, the posture was declared using the following `NetworkPolicy` definition:

```yaml
spec:
  podSelector: {}         # Applies rule to all pods in tenant-b
  policyTypes: [Ingress] # Targets inbound network traffic
# Absence of 'ingress:' block enforces an absolute deny-all rule
```

Setting `podSelector: {}` targets every pod residing in the `tenant-b` namespace. Paired with `policyTypes: [Ingress]` and omitting any allowed `ingress` rules, Kubernetes instructs the CNI (Calico) to drop all incoming packets across the namespace boundary unless a supplementary policy explicitly grants entry.

---

### Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?

| Comparison Feature | Containers (Containerization) | Virtual Machines (Virtualization) |
|---|---|---|
| **Kernel Architecture** | Shared host OS kernel | Independent guest OS kernel per VM |
| **Isolation Primitive** | Kernel primitives (Linux Namespaces, cgroups, seccomp) | Hardware-assisted hypervisor (Type-1/Type-2) |
| **Attack Vector** | System call interface to host kernel | Hypervisor interface & virtualized device drivers |
| **Blast Radius of Breach** | Kernel exploit leads to full host compromise | Hypervisor escape limited to virtual machine boundary |
| **Performance & Resource Cost** | Minimal overhead, instant startup | Higher RAM/CPU overhead, full OS boot time |

A **Virtual Machine (VM) boundary** is necessary under the following conditions:

- **Multi-Tenant Public Clouds:** Running workloads from untrusted or competing third parties on shared hardware.
- **Strict Regulatory Standards:** Compliance frameworks (e.g., PCI-DSS, HIPAA) requiring hard, hardware-enforced hypervisor boundaries.
- **Kernel Diversity Requirements:** Workloads needing custom kernel modules or distinct operating system instances.
- **High-Risk Workload Execution:** Running arbitrary or unvetted code where kernel exploits could lead to container breakouts.

*Note:* Modern cloud architectures frequently combine both approaches (e.g., AWS Kata Containers or Firecracker microVMs), wrapping containerized applications inside lightweight isolated VMs.

---

### Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?

**Data remanence** refers to physical or magnetic traces of data that remain on storage media following standard deletion commands. Standard OS commands like `rm` only unlink directory indices (inodes) while leaving raw data blocks untouched until overwritten by future disk operations.

**Cryptographic erasure** (or *crypto-shredding*) is the standard approach for cloud data sanitization for the following reasons:

1. **Lack of Physical Access:** Tenants in cloud environments do not possess physical access to underlying server drives to perform degaussing or mechanical shredding.
2. **Instant & Irreversible:** Deleting the master encryption key renders the stored ciphertext mathematically impossible to decrypt, completing data destruction instantly.
3. **Storage Abstraction:** It functions uniformly across object storage, block storage, and ephemeral disks regardless of capacity (gigabytes to petabytes).
4. **Regulatory Auditability:** Key destruction events are logged via KMS audit trails, providing verifiable proof of compliance.

The core workflow relies on encrypting data at rest with unique tenant keys and destroying the key lifecycle object when deletion is requested.

---

### Q5. Which of the three isolation dimensions (compute, network, storage) did each task exercise?

| Lab Exercise | Primary Isolation Dimension | Practical Demonstration & Control Applied |
|---|---|---|
| **Task 1** | Compute | Isolated tenant workloads into distinct `tenant-a` and `tenant-b` namespaces |
| **Task 2** | Network (Vulnerability) | Observed flat network routing allowing cross-tenant curl probes (HTTP 200) |
| **Task 3** | Compute | Enforced CPU, memory, and pod constraints via `ResourceQuota` to stop noisy neighbors |
| **Task 4** | Network (Remediation) | Configured default-deny `NetworkPolicy` in `tenant-b`, blocking cross-tenant probes (HTTP 000) |
| **Task 5** | Storage | Restricted secret access to namespace bounds using RBAC `Role` and `RoleBinding` (`can-i` check) |
| **Task 6** | Storage | Verified data remanence risks on storage volumes and performed zero-fill (`dd`) data wiping |


## 8. Challenges Encountered

| Challenge | Resolution |
|---|---|
| **Calico installation requires internet access** | The lab manual notes that an instructor can provide `calico.yaml` locally. Internet was available during this lab session, so the manifest was fetched directly. |
| **Default kind CNI does not enforce NetworkPolicy** | Understood from the lab notes — the cluster was created with `disableDefaultCNI: true` and Calico installed before any policy tests to ensure policies were actually enforced. |
| **Probe pod terminates with `Error` after HTTP 000** | This is expected behaviour — `curl` exits with a non-zero code when the connection fails, causing the pod's exit code to be non-zero. The `HTTP 000` output itself was the meaningful result. |
| **Service account naming consistency** | The rolebinding command in the lab sheet used `app-a` but the SA reference used `appa` in one place. Careful cross-checking of names was required to ensure the RBAC binding matched the service account. |
| **Data remanence scan returning no results** | The `grep` scan on the Docker volume returned no recoverable SENSITIVE data, which may be due to the ext4 filesystem behaviour on the volume driver. The concept of remanence was still demonstrated conceptually; in practice, lower-level tools or forensic carving tools would be needed to recover overwritten blocks. |

---

## 9. Lessons Learned

1. **Logical Segmentation vs. Network Boundaries:** Through this hands-on lab, I realized that Kubernetes namespaces only offer organizational and RBAC partition capabilities. Without an underlying CNI enforcing `NetworkPolicy` rules, the cluster network remains flat, allowing unrestricted inter-tenant routing. Logical grouping alone does not equal secure isolation.

2. **Practical Value of Zero-Trust (Default-Deny):** Observing the contrast between the initial HTTP 200 connection and the subsequent connection timeout (HTTP 000) highlighted why a zero-trust posture is essential. Operating on an explicit whitelist model guarantees that unapproved traffic paths are blocked automatically, protecting cluster workloads against unauthorized lateral movement.

3. **Availability & Resource Governance in Multi-Tenancy:** I learned that cloud isolation extends beyond preventing unauthorized data access to preserving performance stability. Applying `ResourceQuota` objects successfully mitigates "noisy neighbor" scenarios by restricting tenant resource consumption (CPU, memory, and pod count), ensuring fair cluster resource distribution.

4. **Least-Privilege Authorization with Namespace-Scoped RBAC:** Scoping authorization via Kubernetes `Role` and `RoleBinding` objects demonstrated how to prevent privilege creep. By limiting service accounts strictly to their respective namespace resources, cross-tenant secret harvesting is blocked, reinforcing confidentiality across tenant environments.

5. **Data Remanence and Modern Cloud Erasure:** The data remanence experiment clarified why traditional file deletion (`rm`) is insufficient for cloud security. Because underlying storage blocks retain data fragments after directory pointers are unlinked, cryptographic erasure (destroying encryption keys) serves as the primary, compliant defense when physical media access is unavailable.

6. **Infrastructure Dependencies in Security Enforcement:** Installing Calico emphasized that security policy controls depend heavily on the underlying infrastructure plugin. Using the default `kind` CNI would have silently ignored NetworkPolicies; selecting a network driver with active filtering capabilities is a critical prerequisite for production Kubernetes security.


---

## 10. References

1. **Kubernetes Documentation** — *Network Policies*: [kubernetes.io/docs/concepts/services-networking/network-policies](https://kubernetes.io/docs/concepts/services-networking/network-policies)
2. **Calico Documentation** — *Getting Started with Calico on kind*: [docs.tigera.io](https://docs.tigera.io)
3. **Cloud Security Alliance (CSA)** — *Security Guidance for Critical Areas of Focus in Cloud Computing v5 — Infrastructure & Networking Domain.*
4. **IKB42603 Course Lecture** — *Week 3: Secure Isolation of Physical & Logical Infrastructure*, UniKL MIIT, Prof. Dr. Shahrulniza Musa.
5. **Kubernetes Documentation** — *Resource Quotas*: [kubernetes.io/docs/concepts/policy/resource-quotas](https://kubernetes.io/docs/concepts/policy/resource-quotas)
6. **Kubernetes Documentation** — *Using RBAC Authorization*: [kubernetes.io/docs/reference/access-authn-authz/rbac](https://kubernetes.io/docs/reference/access-authn-authz/rbac)
7. **NIST SP 800-88 Rev. 1** — *Guidelines for Media Sanitization*, National Institute of Standards and Technology.
8. **kind Documentation** — *Configuring Your kind Cluster*: [kind.sigs.k8s.io/docs/user/configuration](https://kind.sigs.k8s.io/docs/user/configuration)


