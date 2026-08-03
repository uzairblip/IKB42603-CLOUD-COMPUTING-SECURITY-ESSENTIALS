<div align="left">

<sup>IKB42603 Cloud Computing Security Essentials</sup>

</div>

<div align="center">

## LAB 1 · WEEKS 1–2

# Cloud Account Security, Identity & Access Management

| Item | Details |
|---|---|
| Lab | Lab 1 - AWS IAM and LocalStack |
| Session | A |
| Student | UZAIR BIN SAMSUDIN |
| Student ID | 52215124300 |

</div>

## Session A

### Objective
Set up a local AWS environment with LocalStack and perform IAM user, access key, group, and policy tasks using the AWS CLI.

### Environment

![LocalStack Environment](LAB1%20PIC/ONETIME%20ENVIROMENT.png)

This lab uses LocalStack to simulate AWS services locally. The environment was configured so that the AWS CLI communicates with LocalStack using the local endpoint.

- LocalStack running on `http://localhost:4566`.
- AWS CLI configured with dummy credentials and region `us-east-1`.
- Verified LocalStack health with `/localstack/health` and AWS endpoint connectivity using `sts get-caller-identity`.

| Step | Description | Result |
|------|-------------|--------|
| 1 | Start LocalStack container and confirm service is running | LocalStack started and health endpoint accessible |
| 2 | Configure AWS CLI credentials and default region | `aws configure set aws_access_key_id test`, `aws configure set aws_secret_access_key test`, `aws configure set region us-east-1` |
| 3 | Verify AWS CLI can connect to LocalStack using STS | `aws --endpoint-url=http://localhost:4566 sts get-caller-identity` returned identity information |

### Task 1 — Map the Cloud Identity Landscape
Complete the following table by matching each cloud identity concept to the AWS term and its purpose.

| Concept | AWS term | Purpose |
|---|---|---|
| All-powerful owner | Root user | The account owner with full administrative control over the entire AWS account |
| Human/app identity | IAM User | A specific person or application identity that can sign in and make API requests |
| Permission bundle | IAM Policy | A set of permissions that allow or deny actions against AWS resources |
| Collection of users | IAM Group | A grouping of users to simplify assigning the same permissions to multiple identities |
| Temporary identity | IAM Role | A temporary security identity that can be assumed to gain short-term access to AWS resources |

### Task 2 — Create a Least-Privilege Admin (Stop Using Root)
The root user is a liability. Create a dedicated admin identity and grant permissions through a group rather than directly to the user.

- Set the LocalStack endpoint variable: `EP='--endpoint-url=http://localhost:4566'`
- Create the Admins group: `aws $EP iam create-group --group-name Admins`
- Attach the AdministratorAccess policy to the Admins group: `aws $EP iam attach-group-policy --group-name Admins --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`
- Create the admin user `CloudAdmin_Ichigo`: `aws $EP iam create-user --user-name CloudAdmin_Ichigo`
- Add the user to the Admins group: `aws $EP iam add-user-to-group --group-name Admins --user-name CloudAdmin_Ichigo`
- Verify the group membership: `aws $EP iam get-group --group-name Admins`

This approach keeps permissions manageable and auditable. By assigning policies to a group and then adding the user to that group, the user inherits the admin permissions without being granted them directly.

![Task 2 Evidence](LAB1%20PIC/TASK2.png)

### Task 3 — Enforce Least Privilege with a Scoped Policy
Now create a read-only user for a teammate who should never modify data. This demonstrates fine-grained authorization.

- Create a read-only user: `aws $EP iam create-user --user-name Analyst_Ichigo`
- Attach a scoped read-only policy (S3 read only): `aws $EP iam attach-user-policy --user-name Analyst_Ichigo --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess`
- Check what the user can do: `aws $EP iam list-attached-user-policies --user-name Analyst_Ichigo`

If the Analyst account were stolen, the damage is limited compared to a stolen admin account. The Analyst user only has read-only access, so they cannot modify or delete data. This reduces the blast radius of a compromised account.

![Task 3 Evidence](LAB1%20PIC/TASK3.png)

### Task 4 — Credential Hygiene & Access Keys
Programmatic access uses access keys. Create one, then reason about the risk of long-lived keys.

- Create an access key for `Analyst_Ichigo`: `aws $EP iam create-access-key --user-name Analyst_Ichigo`
- List access keys to show the `AccessKeyId` and current `Status`: `aws $EP iam list-access-keys --user-name Analyst_Ichigo`
- Rotate the old key by deactivating it: `aws $EP iam update-access-key --user-name Analyst_Ichigo --access-key-id LKIAQAAAAAAFKA8XD47 --status Inactive`
- Confirm the updated status with `aws $EP iam list-access-keys --user-name Analyst_Ichigo`

This task demonstrates credential hygiene. Creating and then rotating access keys reduces the risk of long-lived credentials being compromised. If a key is stolen, deactivating it quickly limits the damage because the stolen key can no longer be used.

![Task 4 Evidence - Create and List](LAB1%20PIC/TASK4(PART1).png)

![Task 4 Evidence - Rotate Key](LAB1%20PIC/TASK%204(PART2).png)

## Summary
This lab demonstrated AWS IAM identity management and LocalStack integration by:

- Mapping cloud identity concepts like Root user, IAM user, IAM policy, IAM group, and IAM role.
- Creating a least-privilege admin account through an IAM group and attaching administrator access to the group.
- Enforcing least privilege by creating a scoped read-only user with AmazonS3ReadOnlyAccess.
- Practicing credential hygiene by creating and rotating access keys for programmatic access.

Overall, the lab highlights the importance of secure account structure, group-based permission management, and reducing blast radius through least privilege and key rotation.

## Session B

### Objective
Set up a local Kubernetes cluster with `kind`, create separate namespaces for development and production, and use Kubernetes RBAC to enforce least-privilege access for a service account.

### Environment

![Setup — Create a Local Kubernetes Cluster](LAB1%20PIC/Setup%20%E2%80%94%20Create%20a%20Local%20Kubernetes%20Cluster.png)

This session uses a local `kind` cluster named `ccse-lab1`. The cluster was verified with `kubectl cluster-info --context kind-ccse-lab1`, and the control plane was confirmed as running.

- Kubernetes cluster created with `kind create cluster --name ccse-lab1`
- Verified cluster status with `kubectl cluster-info --context kind-ccse-lab1`
- Confirmed node readiness using `kubectl get nodes`

### Task 5 — Separate Environments with Namespaces

Create distinct namespaces for development and production to isolate resources and access scopes.

- Create `dev`: `kubectl create namespace dev`
- Create `prod`: `kubectl create namespace prod`
- Confirm namespaces: `kubectl get namespaces`

![Task 5 — Separate Environments with Namespaces](LAB1%20PIC/Task%205%20%E2%80%94%20Separate%20Environments%20with%20Namespaces.png)

### Task 6 — Define a Role and Bind It (Least Privilege)

Create a service account and assign it a role that allows only read-only access to pods in the `dev` namespace.

- Create service account: `kubectl create serviceaccount dev-user -n dev`
- Create role `pod-reader` in `dev` with permissions to `get`, `watch`, and `list` pods
- Bind the role to the service account with `RoleBinding`

![Task 6 — Define a Role and Bind It (Least Privilege)](LAB1%20PIC/Task%206%20%E2%80%94%20Define%20a%20Role%20and%20Bind%20It%20(Least%20Privilege).png)

### Task 7 — Test That Access Control Works

Verify the service account can only perform the allowed actions in the `dev` namespace and cannot access resources outside its scope.

- Allowed: `kubectl auth can-i list pods -n dev --as=system:serviceaccount:dev:dev-user`
- Denied: `kubectl auth can-i delete pods -n dev --as=system:serviceaccount:dev:dev-user`
- Denied: `kubectl auth can-i list pods -n prod --as=system:serviceaccount:dev:dev-user`

![Task 7 — Test That Access Control Works](LAB1%20PIC/Task%207%20%E2%80%94%20Test%20That%20Access%20Control%20Works.png)

### Session B Summary
Session B demonstrated Kubernetes namespace isolation and RBAC by granting a service account only the precise permissions it needed in the `dev` namespace while denying destructive actions and cross-namespace access.

Relate the three can-i results to authentication versus authorization: which step is the service account passing, and which step is blocking the delete and the prod access?

`kubectl auth can-i` demonstrates how Kubernetes handles access control in two separate steps:

- **`kubectl auth can-i list pods -n dev --as=$SA` → `yes`**
  - **Authentication:** **PASSED.** The cluster successfully verified the service account identity (`system:serviceaccount:dev:dev-user`).
  - **Authorization:** **PASSED.** The `pod-reader` role explicitly gives this service account permission to `list` pods in the `dev` namespace.

- **`kubectl auth can-i delete pods -n dev --as=$SA` → `no`**
  - **Authentication:** **PASSED.** The cluster knows who the service account is.
  - **Authorization:** **FAILED.** The authorization engine blocked the action. Because Kubernetes uses least privilege, everything is denied by default unless explicitly allowed. The `pod-reader` role only includes `get`, `list`, and `watch` permissions, so `delete` is blocked.

- **`kubectl auth can-i list pods -n prod --as=$SA` → `no`**
  - **Authentication:** **PASSED.** The identity is still valid and verified.
  - **Authorization:** **FAILED.** The request was blocked because roles in Kubernetes are restricted to their specific namespace. Since the `RoleBinding` was created only in `dev`, the service account has zero permissions in `prod`.

## Deliverables & Assessment

1. Screenshots (label each clearly)
   - ✅ Output of `sts get-caller-identity` showing your operating identity.
   - ✅ `get-group Admins` output showing your `CloudAdmin` user as a member.
   - ✅ `list-attached-user-policies` output for the Analyst showing only the read-only policy.
   - ✅ The three `kubectl auth can-i` results (`yes`, `no`, `no`).

2. Short-Answer Questions
   - Q1. Why is attaching policies to groups better than attaching them directly to users?
     > Attaching policies to **IAM Groups** makes permission management much easier and cleaner to maintain as an organization grows. Instead of manually configuring and tracking policies for every single user, you assign permissions to a group (like `Admins` or `Developers`). When a new employee joins or leaves, you simply add or remove them from the group, ensuring consistent access control and reducing the chance of misconfiguration.
   - Q2. What is the difference between an IAM User and an IAM Role?
     > An **IAM User** represents a long-term identity (usually a real person or a permanent application) that comes with permanent credentials like passwords or long-lived access keys.
     >
     > An **IAM Role**, on the other hand, is a temporary identity without permanent credentials. Users, applications, or cloud services temporarily *assume* a role to receive short-lived, auto-expiring security tokens to perform specific tasks.
   - Q3. Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.
     > The **Principle of Least Privilege** means giving an account only the exact minimum permissions needed to do its job, and nothing more. The `Analyst` account was given `AmazonS3ReadOnlyAccess`, meaning it can only view S3 data.
     >
     > If an attacker steals the `Analyst` credentials, the **blast radius** (potential damage) is kept tiny. The attacker can only read S3 files—they cannot delete buckets, modify configuration files, spin up expensive server resources, or steal admin controls.
   - Q4. In Kubernetes, what is the difference between a Role and a RoleBinding?
     > - A **Role** defines **WHAT** actions are permitted inside a specific namespace. It holds rules listing resources (like `pods`) and allowed actions/verbs (like `get`, `list`, `watch`).
     > - A **RoleBinding** connects **WHO** gets those permissions. It links the `Role` to a specific identity, such as a `ServiceAccount` or `User`.
   - Q5. Why did the developer service account fail to access prod, and which security principle does that demonstrate?
     > The developer service account failed to access `prod` because Kubernetes RBAC operates on an **implicit deny** model—permissions granted in one namespace do not cross over to another unless explicitly defined. Since the `pod-reader` role and binding were created only inside the `dev` namespace, the service account had zero permissions in `prod`.
     >
     > This demonstrates the principle of **Least Privilege** and **Namespace Isolation / Blast Radius Containment**, ensuring low-privilege environments (`dev`) cannot access or disrupt critical production workloads (`prod`).

3. Verification Command
   - Paste the output of the following to prove your cluster RBAC is in place:
     `kubectl get rolebinding dev-user-binding -n dev -o yaml`

   Example output (rolebinding YAML):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: "2026-08-03T11:15:07Z"
  name: dev-user-binding
  namespace: dev
  resourceVersion: "726"
  uid: f594ef04-cad8-4576-abea-51e0bc4b6ba1
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: dev-user
  namespace: dev
```

![Verification — rolebinding YAML output](LAB1%20PIC/Task%206%20%E2%80%94%20Define%20a%20Role%20and%20Bind%20It%20(Least%20Privilege).png)

Security Best-Practices Checklist
- ✅ Root user is not used for daily tasks (a dedicated admin identity exists).
- ✅ Permissions are granted via groups/roles, not directly to individual users.
- ✅ At least one least-privilege (read-only) identity was created and tested.
- ✅ Access keys were listed and a rotation (deactivate) was demonstrated.
- ✅ Kubernetes RBAC blocks an unauthorised action (delete / cross-namespace).

## Cleanup & Teardown

Remove resources created for the lab when you are finished.

```bash
# Remove the Kubernetes cluster
kind delete cluster --name ccse-lab1

# Stop and remove LocalStack
docker stop localstack && docker rm localstack
```

![Cleanup & Teardown evidence](LAB1%20PIC/Setup%20%E2%80%94%20Create%20a%20Local%20Kubernetes%20Cluster.png)

