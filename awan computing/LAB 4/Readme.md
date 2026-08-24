# IKB42603 Cloud Computing Security Essentials

### Lab 4: Access Control & Network Security

**Name:** UZAIR BIN SAMSUDIN  
**ID:** 52215124300  

---

## 1. Objective

This lab explores and implements defense-in-depth security mechanisms spanning identity verification, authorization controls, network segmentation, and host/container hardening within cloud and container environments. The primary goal is to distinguish and configure authentication (AuthN) using HTTP Basic Auth and Time-Based One-Time Passwords (TOTP / MFA); enforce the principle of least privilege using Kubernetes Role-Based Access Control (RBAC); isolate multi-tier application architectures via software-defined network segmentation; implement default-deny host firewall rulesets; and harden container runtimes by dropping kernel capabilities, enforcing non-root users, applying read-only filesystems, and scanning images for known vulnerabilities.

---

## 2. Learning Outcomes

Upon completion of this lab, the student will be able to:
* Distinguish and implement authentication (identity verification) and authorization (access control).
* Configure and validate a Time-Based One-Time Password (TOTP / MFA) code to enforce multi-factor authentication.
* Configure network access control and segmentation so services reach only required dependencies.
* Harden a container image profile: non-root execution, dropped Linux capabilities, and read-only filesystems.
* Scan a container image for vulnerabilities (CVEs) and apply least privilege across compute, network, and storage.

---

## 3. Environment

| Component | Detail |
| :--- | :--- |
| **OS** | Kali Linux (`amd64`, kernel 6.16.8) |
| **Container Runtime** | Docker Engine v28.5.2 |
| **Kubernetes Engine** | kind (Kubernetes in Docker) with `kubectl` CLI |
| **MFA Tool** | `oathtool` (OATH TOTP CLI utility) |
| **Vulnerability Scanner** | Aqua Security Trivy CLI (`aquasec/trivy:latest`) |
| **CLI & Network Utilities** | `curl`, `htpasswd` (`httpd:alpine`), `iptables`, `nc` (`netcat-openbsd`), `python3` |
| **Session A Focus** | Authentication vs. authorization, MFA (TOTP), and Kubernetes RBAC enforcement (Tasks 1–3) |
| **Session B Focus** | Network segmentation, firewall default-deny rules, container hardening, and image scanning (Tasks 4–6) |

> [!TIP]
> **Security Tip:** Identity is the perimeter. Notice that almost every control in this lab ultimately asks the same two questions: are you who you claim, and are you allowed to do this?

---

## 4. Step-by-Step Implementation

### Session A (Week 7) — Authentication & Authorization

#### Task 1 — Authentication: A Password-Protected Service

An Nginx web service was deployed behind HTTP Basic authentication requiring valid credentials managed via a hashed `htpasswd` credential store.

```bash
# 1. Generate htpasswd credential file using bcrypt hashing
docker run --rm httpd:alpine htpasswd -nbB student 'P@ssword!' > htpasswd.txt

# 2. Create web content
echo 'Authenticated OK' > index.html

# 3. Create Nginx basic auth configuration
cat > default.conf <<'EOF'
server {
    listen 80;
    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        root /usr/share/nginx/html;
        index index.html;
    }
}
EOF

# 4. Deploy Nginx container with volume mounts
docker run --rm -d --name authsvc -p 8080:80 \
  -v "$PWD/default.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$PWD/htpasswd.txt:/etc/nginx/.htpasswd:ro" \
  -v "$PWD/index.html:/usr/share/nginx/html/index.html:ro" \
  nginx

# 5. Verify unauthenticated and authenticated requests
curl -s -o /dev/null -w 'no-creds: %{http_code}\n' http://localhost:8080
curl -s -u student:'P@ssword!' http://localhost:8080
```

* **Result:** Sending an unauthenticated request returned `no-creds: 401`, while authenticating with `student:P@ssword!` returned HTTP 200 with `Authenticated OK`, verifying access enforcement at the ingress layer.

---

#### Task 2 — Add a Second Factor (MFA / TOTP)

A base32-encoded shared secret was generated to create and validate rolling Time-Based One-Time Password (TOTP) codes.

```bash
# 1. Generate base32 secret
SECRET=$(python3 -c 'import os, base64; print(base64.b32encode(os.urandom(20)).decode().rstrip("="))')
echo "Enrol this secret in an authenticator app: $SECRET"

# 2. Compute TOTP token and validate
CODE=$(oathtool --totp -b "$SECRET")
echo "Current code: $CODE"
[ "$CODE" = "$(oathtool --totp -b "$SECRET")" ] && echo 'MFA OK' || echo 'MFA FAILED'
```

* **Result:** The system generated secret `LREW3TUG707JHK7NUB3IDQM5BX4X6VGV` and dynamic code `405103`, verifying valid token alignment and outputting `MFA OK`.

---

#### Task 3 — Authorization: Kubernetes RBAC Roles

A `kind` Kubernetes cluster was provisioned, and RBAC rules were configured to limit a developer service account strictly to read-only pod operations.

```bash
# 1. Provision cluster
kind create cluster --name ccse-lab4

# 2. Configure namespace, service account, role, and rolebinding
kubectl create namespace app
kubectl create serviceaccount dev -n app
kubectl create role dev-role -n app --verb=get,list --resource=pods
kubectl create rolebinding dev-rb -n app --role=dev-role --serviceaccount=app:dev

# 3. Test authorization boundaries
SA="system:serviceaccount:app:dev"
kubectl auth can-i list pods -n app --as=$SA
kubectl auth can-i create deploy -n app --as=$SA
kubectl auth can-i delete pods -n app --as=$SA

# 4. Cleanup auth container
docker stop authsvc
```

* **Result:** `kubectl auth can-i list pods` returned `yes`, while unauthorized actions (`create deploy` and `delete pods`) returned `no`, validating RBAC least-privilege enforcement.

---

### Session B (Week 8) — Network Security & Container Hardening

#### Task 4 — Network Segmentation (Three-Tier Architecture)

Two separate Docker bridge networks (`frontend-net` and `backend-net`) were created to isolate web, app, and db tiers.

```bash
# 1. Create bridge networks
docker network create frontend-net
docker network create backend-net

# 2. Deploy segmented containers
docker run -d --name db --network backend-net redis:alpine
docker run -d --name app --network backend-net nginx
docker network connect frontend-net app
docker run -d --name web --network frontend-net nginx

# 3. Test web -> db isolation (Expected: BLOCKED)
docker exec web sh -c 'apk add -q curl; curl -m 3 db:6379 || echo BLOCKED'

# 4. Test app -> db connectivity (Expected: REACHABLE)
docker exec app sh -c 'apt-get update -qq && apt-get install -y -qq netcat-openbsd && nc -z -w3 db 6379 && echo REACHABLE'
```

* **Result:** Connection from `web` to `db:6379` timed out and outputted `BLOCKED`, whereas the multi-homed `app` tier successfully connected to `db:6379` and outputted `REACHABLE`.

---

#### Task 5 — Firewall Rules (Default-Deny Policy)

Host-level packet filtering was implemented inside a container using `iptables` to enforce a default-deny policy mirroring cloud security groups.

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c '
apk add -q iptables
iptables -P INPUT DROP
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -L INPUT -n
'
```

* **Result:** `iptables -L INPUT -n` confirmed `Chain INPUT (policy DROP)` with explicit ACCEPT rules for port 443/tcp and the loopback interface (`lo`).

---

#### Task 6 — Container / Host Hardening & Vulnerability Scanning

A hardened container profile was deployed applying unprivileged user execution, read-only root filesystems, dropped Linux kernel capabilities, and privilege escalation prevention. A vulnerability assessment was executed using Trivy.

```bash
# 1. Run hardened container
docker run -d --name hardened \
  --user 1000:1000 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp \
  nginxinc/nginx-unprivileged

# 2. Inspect container properties
docker inspect hardened --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}}'

# 3. Run Trivy vulnerability scan
docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:alpine | head -20
```

* **Result:** `docker inspect` confirmed `User=1000:1000` and `ReadOnly=true`. Trivy evaluated `nginx:alpine` and returned the vulnerability summary report.

---

## 5. Commands Used

| Command | Task | Purpose |
| :--- | :--- | :--- |
| `docker run ... htpasswd -nbB ...` | Task 1 | Generate bcrypt password hash for HTTP Basic Auth |
| `curl -s -o /dev/null -w '%{http_code}' ...` | Task 1 | Verify HTTP 401 response for unauthenticated calls |
| `curl -s -u student:... http://...` | Task 1 | Verify HTTP 200 response with valid credentials |
| `oathtool --totp -b "$SECRET"` | Task 2 | Generate and validate rolling TOTP 6-digit MFA tokens |
| `kind create cluster --name ccse-lab4` | Task 3 | Provision local Kubernetes cluster |
| `kubectl create role ... --verb=get,list` | Task 3 | Define RBAC role with pod read permissions |
| `kubectl create rolebinding ...` | Task 3 | Bind RBAC role to `dev` ServiceAccount |
| `kubectl auth can-i ... --as=$SA` | Task 3 | Query RBAC authorization boundaries |
| `docker network create ...` | Task 4 | Provision isolated bridge networks (`frontend-net`, `backend-net`) |
| `docker network connect ...` | Task 4 | Attach application container to multiple networks |
| `iptables -P INPUT DROP` | Task 5 | Set default firewall ingress policy to DROP |
| `iptables -A INPUT -p tcp --dport 443 -j ACCEPT` | Task 5 | Whitelist inbound HTTPS traffic |
| `docker run --user 1000:1000 --read-only ...` | Task 6 | Deploy container with dropped capabilities and immutable root |
| `docker run ... aquasec/trivy image ...` | Task 6 | Scan base container image for HIGH and CRITICAL CVEs |
| `kubectl get rolebinding ... -o yaml` | Deliverables | Verify active Kubernetes RBAC role binding |
| `docker inspect hardened --format '{{json .HostConfig.CapDrop}}'` | Deliverables | Inspect dropped Linux kernel capabilities |
| `docker rm -f ... / kind delete cluster ...` | Teardown | Terminate containers and delete `kind` cluster |

---

## 6. Screenshots

### Screenshot 1 — Task 1: Authentication (HTTP Basic Auth)

![Screenshot 1 — Task 1 Authentication (HTTP Basic Auth)](./Screenshot%201%20—%20Task%201%20Authentication%20(HTTP%20Basic%20Auth)..png)

**Findings:**
* Requests sent without credentials returned `no-creds: 401`, proving unauthenticated access is denied.
* Requests authenticated with user `student` returned HTTP 200 with `Authenticated OK`, validating credentials against `htpasswd`.

---

### Screenshot 2 — Task 2: Multi-Factor Authentication (TOTP)

![Screenshot 2 — Task 2 Multi-Factor Authentication (TOTP)](./Screenshot%202%20—%20Task%202%20Multi-Factor%20Authentication%20(TOTP).png)

**Findings:**
* A 20-byte base32 secret (`LREW3TUG707JHK7NUB3IDQM5BX4X6VGV`) was generated.
* `oathtool` computed the 6-digit rolling passcode (`405103`), and comparison against the secret validated successfully with `MFA OK`.

---

### Screenshot 3 — Task 3: Authorization (Kubernetes RBAC)

![Screenshot 3 — Task 3 Authorization (Kubernetes RBAC)](./Screenshot%203%20—%20Task%203%20Authorization%20(Kubernetes%20RBAC).png)

**Findings:**
* `kubectl auth can-i list pods` returned `yes` under the `app:dev` ServiceAccount context.
* Privileged requests (`create deploy` and `delete pods`) returned `no`, confirming least-privilege boundary enforcement.

---

### Screenshot 4 — Task 4: Network Segmentation (Three-Tier)

![Screenshot 4 — Task 4 Network Segmentation (Three-Tier)](./Screenshot%204%20—%20Task%204%20Network%20Segmentation%20(Three-Tier).png)

**Findings:**
* The `web` container on `frontend-net` timed out resolving `db:6379` (`BLOCKED`), verifying isolation from the database tier.
* The `app` container attached to both networks successfully connected to `db:6379` (`REACHABLE`).

---

### Screenshot 5 — Task 5: Firewall Rules (Default-Deny)

![Screenshot 5 — Task 5 Firewall Rules (Default-Deny)](./Screenshot%205%20—%20Task%205%20Firewall%20Rules%20(Default-Deny).png)

**Findings:**
* `iptables` configured with default policy `Chain INPUT (policy DROP)`.
* Ingress traffic is dropped except for explicitly allowed port 443/tcp and the loopback interface.

---

### Screenshot 6 — Task 6: Container Hardening & Vulnerability Scanning

![Screenshot 6 — Task 6 Container Hardening & Vulnerability Scanning](./Screenshot%206%20—%20Task%206%20Container%20Hardening%20&%20Vulnerability%20Scanning.png)

**Findings:**
* `docker inspect` verified runtime hardening parameters: `User=1000:1000` and `ReadOnly=true`.
* Trivy scan assessed `nginx:alpine` and returned the vulnerability summary report.

---

### Screenshot 7 — Deliverables: Verification Commands

![Screenshot 7 — Deliverables: Verification Commands](./Screenshot%207%20—%20Deliverables%20Verification%20Commands.png)

**Findings:**
* `kubectl get rolebinding dev-rb -n app -o yaml` displayed the active binding connecting `dev-role` to `ServiceAccount: dev` in namespace `app`.
* `docker inspect hardened --format '{{json .HostConfig.CapDrop}}'` returned `["ALL"]`, confirming complete removal of kernel capabilities.

---

## 7. Short-Answer Questions

### Q1. Explain the difference between authentication and authorization using Tasks 1 and 3.

| Dimension | Authentication (AuthN) — Task 1 | Authorization (AuthZ) — Task 3 |
| :--- | :--- | :--- |
| **Core Question** | "Who are you?" (Proving identity) | "What are you allowed to do?" (Enforcing permissions) |
| **Lab Implementation** | HTTP Basic Auth verified that the client provided the correct passphrase for user `student`. | Kubernetes RBAC evaluated whether the authenticated `dev` identity was permitted to perform API actions. |
| **Enforcement Layer** | Reverse proxy / Web server ingress (`nginx`). | Kubernetes API Server (`rbac.authorization.k8s.io`). |
| **Outcome** | Valid identity allowed access (HTTP 200); invalid credentials rejected (HTTP 401). | Allowed `list pods` (`yes`); denied `create deploy` and `delete pods` (`no`). |

Authentication validates credentials to establish an identity. Authorization enforces permissions defining what an authenticated identity is permitted to execute.

---

### Q2. Why is MFA so effective, and which attacks does it defeat?

Multi-Factor Authentication (MFA) requires presenting factors across independent categories: Knowledge (something you know, e.g., passwords), Possession (something you have, e.g., TOTP authenticator device), and Inherence (something you are, e.g., biometrics).

**Attacks Defeated:**
* **Credential Stuffing & Password Reuse:** Compromised passwords from third-party data breaches cannot grant access without the rolling TOTP secret.
* **Brute-Force / Dictionary Attacks:** Guessing static credentials fails because the dynamic TOTP token changes every 30 seconds.
* **Phishing & Keylogging:** Intercepted passwords are insufficient to establish a session once the 30-second TOTP token expires.

---

### Q3. How does network segmentation limit the damage of a compromised web server?

Network segmentation creates isolated Layer 3 boundaries to restrict communication to necessary paths:

```
+---------------------+         +---------------------+         +---------------------+
|   Web Tier (DMZ)    |         |      App Tier       |         |    Database Tier    |
|   (frontend-net)    | ======> | (front/backend-net) | ======> |    (backend-net)    |
+---------------------+         +---------------------+         +---------------------+
           |                                                               ^
           + - - - - - - - - [ DIRECT ACCESS BLOCKED ] - - - - - - - - - - +
```

* **Containment:** An attacker who compromises the public-facing web container is confined to `frontend-net`.
* **Lateral Movement Prevention:** Because `db` exists exclusively on `backend-net`, there is no IP route or network visibility between `web` and `db`. Direct reconnaissance, exploitation, and data exfiltration from the database are blocked.

---

### Q4. What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?

A default-deny policy sets the default packet filter action to `DROP`, rejecting all inbound and forwarded packets unless explicitly permitted by an allowlist rule.

* **Objective:** Minimizes exposure by closing unused ports, preventing unmanaged service exposure, and mitigating internal port scans.
* **Relation to Cloud Security Groups:** Cloud firewalls (AWS Security Groups, Azure Network Security Groups, GCP Firewall Rules) operate on the default-deny principle. Inbound traffic is blocked by default until explicit inbound rules (such as allowing TCP 443) are provisioned.

---

### Q5. List the hardening measures you applied and the attack surface each one removes.

| Hardening Flag / Directive | Attack Surface Removed / Threat Mitigated |
| :--- | :--- |
| `--user 1000:1000` | **Container Escape to Host Root:** Runs processes without root privileges. If a container breakout occurs, the attacker lands on the host OS as an unprivileged user. |
| `--read-only` | **Malware Persistence & File Modification:** Makes the root filesystem immutable. Attackers cannot install backdoors, write web shells, or alter application binaries on disk. |
| `--cap-drop ALL` | **Kernel Exploits & Privilege Escalation:** Strips Linux kernel capabilities (e.g., `CAP_NET_RAW`, `CAP_SYS_ADMIN`), preventing raw network manipulation, kernel module modifications, and host interference. |
| `--security-opt no-new-privileges` | **SetUID Escalation:** Prevents child processes from acquiring higher execution privileges via setuid/setgid binaries. |
| `aquasec/trivy` Scanning | **Known Vulnerabilities (CVEs):** Identifies vulnerable dependencies and packages before runtime deployment. |

---

## 8. Challenges Encountered

| Challenge | Resolution |
| :--- | :--- |
| **Nginx return 200 Bypassing Basic Auth** | The `return 200` directive executes during Nginx's rewrite phase before `auth_basic` evaluation, causing unauthorized 200 responses. Resolved by serving `Authenticated OK` via a static document root (`index.html`) mounted alongside the configuration. |
| **Container Startup Latency in Sequential Scripts** | Running `curl` commands immediately following container launch caused connection failures (`no-creds: 000`). Resolved by ensuring container sockets were bound before initiating test requests. |
| **Missing Netcat Utility in Alpine/Debian Images** | Standard minimal images lack testing utilities. Resolved by installing `netcat-openbsd` within the `app` container (`apt-get install -y netcat-openbsd`) to verify port reachability on port 6379. |
| **Read-Only Root Filesystem Failures** | Standard Nginx writes temporary files to `/var/run` and crashes on read-only filesystems. Resolved by using `nginxinc/nginx-unprivileged` with a `--tmpfs /tmp` scratch volume. |

---

## 9. Lessons Learned

* **Defense in Depth Across Layers:** Cloud workload protection requires layered security controls: identity verification (AuthN), permission boundaries (AuthZ), network segmentation, and runtime container immutability.
* **Least Privilege Enforcement:** The principle of least privilege must be applied across API access (Kubernetes RBAC), network connectivity (segmented subnets and default-deny firewalls), and process execution (non-root UID, dropped Linux capabilities).
* **Blast Radius Reduction via Segmentation:** Isolating workloads into dedicated tiers limits the impact of remote code execution vulnerabilities by blocking direct lateral network paths.
* **Shift-Left Vulnerability Management:** Scanning container base images for known CVEs with Trivy before runtime deployment reduces exposures in production.

---

## 10. References

1. Docker Security Documentation: Runtime Privilege and Linux Capabilities, [docs.docker.com/engine/security](https://docs.docker.com/engine/security)
2. Kubernetes Documentation: Using RBAC Authorization, [kubernetes.io/docs/reference/access-authn-authz/rbac](https://kubernetes.io/docs/reference/access-authn-authz/rbac)
3. Aqua Security Trivy Documentation: Container Vulnerability Scanner, [aquasecurity.github.io/trivy](https://aquasecurity.github.io/trivy)
4. CIS Docker Benchmark & CIS Kubernetes Benchmark v1.8, Center for Internet Security, [www.cisecurity.org](https://www.cisecurity.org)
5. Cloud Security Alliance (CSA): Security Guidance for Critical Areas of Focus in Cloud Computing v5 — Infrastructure & Networking; IAM.
6. IKB42603 Course Lectures: Week 5 (Access Control) & Week 9 (Network Security Patterns), UniKL MIIT, Prof. Dr. Shahrulniza Musa.
