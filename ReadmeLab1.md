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

### Learning Outcomes
After completing this lab, the following learning outcomes were achieved:

- Understand the purpose of cloud identities and Identity & Access Management (IAM).
- Apply the principle of least privilege using IAM users, groups, and policies.
- Create administrative and read-only IAM users.
- Configure and manage access keys securely.
- Understand credential hygiene and key rotation.
- Create Kubernetes namespaces, roles, and role bindings.
- Verify authorization using Kubernetes RBAC.
- Differentiate between authentication and authorization in cloud environments.

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
A dedicated administrator account was created instead of using the root account. An `Admins` group was created and the `AdministratorAccess` policy was attached to the group. The `CloudAdmin_Ichigo` user was then added to the group so permissions were inherited through group membership.

#### Commands Used
```bash
aws $EP iam create-group --group-name Admins
aws $EP iam attach-group-policy --group-name Admins --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws $EP iam create-user --user-name CloudAdmin_Ichigo
aws $EP iam add-user-to-group --group-name Admins --user-name CloudAdmin_Ichigo
aws $EP iam get-group --group-name Admins
```

#### Explanation
Using groups instead of assigning permissions directly to users simplifies administration and follows security best practices. Future permission changes only need to be applied once to the group rather than individually to each user.

#### Evidence
![Task 2 Evidence](LAB1%20PIC/TASK2.png)

### Task 3 — Enforce Least Privilege with a Scoped Policy
Create a read-only user for a teammate who should never modify data. This demonstrates fine-grained authorization.

#### Commands Used
```bash
aws $EP iam create-user --user-name Analyst_Ichigo
aws $EP iam attach-user-policy --user-name Analyst_Ichigo --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
aws $EP iam list-attached-user-policies --user-name Analyst_Ichigo
```

#### Explanation
The Analyst user receives only read-only permissions. Because the user is limited to inspection actions, they cannot modify or delete data, which reduces the blast radius if the account is ever compromised.

#### Evidence
![Task 3 Evidence](LAB1%20PIC/TASK3.png)

### Task 4 — Credential Hygiene & Access Keys
Programmatic access uses access keys. Create one, then reason about the risk of long-lived keys.

#### Commands Used
```bash
aws $EP iam create-access-key --user-name Analyst_Ichigo
aws $EP iam list-access-keys --user-name Analyst_Ichigo
aws $EP iam update-access-key --user-name Analyst_Ichigo --access-key-id LKIAQAAAAAAFKA8XD47 --status Inactive
aws $EP iam list-access-keys --user-name Analyst_Ichigo
```

#### Explanation
Creating and rotating API keys demonstrates credential hygiene. Rotating or deactivating old keys helps prevent long-lived credentials from being abused if they are exposed.

#### Evidence
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

#### Commands Used
```bash
kubectl create namespace dev
kubectl create namespace prod
kubectl get namespaces
```

#### Explanation
Namespace separation creates a logical boundary between environments. This reduces the chance that a user or workload in development can accidentally or intentionally impact production resources.

#### Evidence
![Task 5 — Separate Environments with Namespaces](LAB1%20PIC/Task%205%20%E2%80%94%20Separate%20Environments%20with%20Namespaces.png)

### Task 6 — Define a Role and Bind It (Least Privilege)
Create a service account and assign it a role that allows only read-only access to pods in the `dev` namespace.

#### Commands Used
```bash
kubectl create serviceaccount dev-user -n dev
kubectl create role pod-reader -n dev --verb=get,list,watch --resource=pods
kubectl create rolebinding dev-user-binding --role=pod-reader --serviceaccount=dev:dev-user -n dev
```

#### Explanation
The `pod-reader` role grants just enough permissions to inspect pods without allowing modification. Binding that role to the service account enforces least privilege by giving only the required actions in a single namespace.

#### Evidence
![Task 6 — Define a Role and Bind It (Least Privilege)](LAB1%20PIC/Task%206%20%E2%80%94%20Define%20a%20Role%20and%20Bind%20It%20(Least%20Privilege).png)

### Task 7 — Test That Access Control Works
Verify the service account can only perform the allowed actions in the `dev` namespace and cannot access resources outside its scope.

#### Commands Used
```bash
kubectl auth can-i list pods -n dev --as=system:serviceaccount:dev:dev-user
kubectl auth can-i delete pods -n dev --as=system:serviceaccount:dev:dev-user
kubectl auth can-i list pods -n prod --as=system:serviceaccount:dev:dev-user
```

#### Explanation
A successful `list` in `dev` proves the service account has the required read-only access. The denied `delete` and denied `prod` checks show that Kubernetes RBAC is enforcing both action-based and namespace-based restrictions.

#### Evidence
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

### Challenges Encountered
One challenge during this lab was making sure LocalStack and the Kubernetes cluster were both up before running IAM and RBAC commands. Another issue was copying access key IDs carefully during key rotation to avoid typo-related failures. After double-checking the environment and following each command step-by-step, all tasks were completed successfully.

### Lessons Learned
This lab gave hands-on experience with real cloud access control workflows. I learned how IAM users, groups, and policies work together to enforce least privilege, and how Kubernetes RBAC can restrict actions to exactly what a service account needs. The lab also reinforced that secure cloud operations depend on small details like correct namespace scope and safe key handling.

### References
- IKB42603 Cloud Computing Security Essentials – Lab 1 Manual
- AWS IAM Documentation
- AWS CLI Documentation
- Kubernetes Documentation
- Kubernetes RBAC Documentation
- LocalStack Documentation
- Docker Documentation

### Conclusion
Lab 1 was completed successfully and the main goals were met. Cloud identities were created and managed in LocalStack IAM, with group-based admin access and a scoped read-only user showing least-privilege practice. Kubernetes RBAC was also configured correctly using namespaces, roles, and bindings, and the authorization checks confirmed that restricted actions were blocked. Overall, this lab strengthened practical skills in cloud identity management and access control, while giving a solid foundation for the next cloud security exercises.

