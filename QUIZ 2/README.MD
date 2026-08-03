![UniKL Logo](unikl-logo.png)

# Cloud Computing & Kubernetes - Quiz Q&A Guide

**Student:** UZAIR BIN SAMSUDIN  
**Student ID:** 52215124300

A comprehensive study guide containing 30 fundamental questions on AWS IAM, Cloud Architecture, Docker, and Kubernetes with detailed student-friendly explanations.

---

## 📄 Questions, Answers & Explanations

### 1. Which account should never have access keys created for routine use?
- [ ] IAM Role
- [ ] IAM User
- [x] **Root User**
- [ ] Analyst User

> **Explanation:** The **Root User** has unrestricted administrative access to all resources and billing in your AWS account. Creating access keys for routine tasks is a severe security risk. If compromised, an attacker gains complete control over your account.

---

### 2. Which ARN component identifies the AWS account that owns the resource?
- [ ] Region
- [ ] Resource ID
- [ ] Service
- [x] **Account ID**

> **Explanation:** The standard AWS ARN format is `arn:partition:service:region:account-id:resource`. The **Account ID** (a 12-digit number) explicitly identifies which AWS account owns the resource. *(Note: Some automated quizzes mistakenly mark Resource ID, but Account ID is technically the correct answer).*

---

### 3. For easier permission management, policies should preferably be attached to:
- [ ] Access keys
- [ ] Individual users
- [x] **IAM Groups**
- [ ] The Root User

> **Explanation:** Attaching policies directly to individual users is hard to maintain at scale. Assigning policies to **IAM Groups** (e.g., *Developers*, *Admins*) allows you to manage permissions centrally by adding or removing users from those groups.

---

### 4. Which endpoint is commonly used with LocalStack?
- [ ] http://localhost:22
- [ ] http://localhost:3389
- [x] **http://localhost:4566**
- [ ] http://localhost:80

> **Explanation:** **LocalStack** emulates AWS cloud services locally. Port `4566` is the default edge port used to route API requests to all simulated AWS services (S3, DynamoDB, Lambda, etc.).

---

### 5. Which security principle gives users only the permissions required to perform their tasks?
- [ ] Defense in Depth
- [ ] Confidentiality
- [ ] Zero Trust
- [x] **Principle of Least Privilege**

> **Explanation:** The **Principle of Least Privilege** dictates that users and system components should only be granted the minimum necessary permissions required to fulfill their specific role—nothing more.

---

### 6. Google Docs is an example of:
- [ ] PaaS
- [x] **SaaS**
- [ ] Virtual Machine
- [ ] IaaS

> **Explanation:** **Software as a Service (SaaS)** provides complete, ready-to-use software applications hosted over the internet. Users access Google Docs via a browser without managing underlying servers or software maintenance.

---

### 7. Which service model provides virtual machines?
- [ ] PaaS
- [ ] SaaS
- [x] **IaaS**
- [ ] DBaaS

> **Explanation:** **Infrastructure as a Service (IaaS)** provides raw compute, networking, and storage resources in the form of virtual machines (e.g., AWS EC2, Google Compute Engine), giving users full control over the OS and runtime environment.

---

### 8. Which AWS identity has unlimited privileges?
- [x] **Root User**
- [ ] IAM Group
- [ ] IAM Role
- [ ] IAM User

> **Explanation:** The **Root User** is created when the AWS account is registered. It possesses absolute, non-restrictable permission over every resource and setting in the account.

---

### 9. If an access key is compromised, what should be done first?
- [x] **Deactivate or rotate the key**
- [ ] Delete the IAM user immediately
- [ ] Restart Docker
- [ ] Ignore it

> **Explanation:** The immediate priority during a security leak is to revoke access. **Deactivating or rotating the key** prevents the attacker from making further API requests while allowing you time to investigate and remediate.

---

### 10. Which deployment model combines private and public cloud?
- [ ] Multi-cloud
- [ ] Public Cloud
- [x] **Hybrid Cloud**
- [ ] Community Cloud

> **Explanation:** A **Hybrid Cloud** environment integrates private infrastructure (on-premises servers) with public cloud services (like AWS or Azure), allowing workload and data sharing across both environments.

---

### 11. In the ARN `arn:aws:s3:::my-bucket`, which component represents the AWS service?
- [ ] aws
- [ ] my-bucket
- [ ] arn
- [x] **s3**

> **Explanation:** Following the standard ARN layout (`arn:aws:service:region:account:resource`), the 3rd element specifies the AWS service—in this case, **s3** (Simple Storage Service). S3 bucket names are globally unique, so region and account fields are omitted.

---

### 12. Access keys are mainly used for:
- [ ] Docker login
- [ ] AWS Management Console login
- [x] **Programmatic access**
- [ ] Kubernetes dashboard login

> **Explanation:** Access keys (Access Key ID & Secret Access Key) allow applications, scripts, continuous integration tools, and the AWS CLI to make **programmatic API calls** to AWS.

---

### 13. Docker is mainly used to:
- [ ] Create databases
- [ ] Manage IAM
- [x] **Run containers**
- [ ] Create AWS accounts

> **Explanation:** **Docker** is a containerization platform used to package applications and all their dependencies into lightweight, portable containers that run consistently across any environment.

---

### 14. Which IAM component contains permissions?
- [x] **IAM Policy**
- [ ] IAM Group
- [ ] IAM User
- [ ] IAM Role

> **Explanation:** An **IAM Policy** is a JSON document that defines explicit `Allow` or `Deny` rules for actions on AWS resources. Policies are attached to users, groups, or roles.

---

### 15. Which command lists Kubernetes nodes?
- [ ] aws iam list-users
- [x] **kubectl get nodes**
- [ ] docker ps
- [ ] kubectl get buckets

> **Explanation:** `kubectl` is the Kubernetes CLI. Running **`kubectl get nodes`** fetches and outputs a list of all active worker and control-plane machines in the connected cluster.

---

### 16. LocalStack is used because it:
- [ ] Installs Kubernetes
- [ ] Creates AWS accounts
- [x] **Simulates AWS services locally**
- [ ] Replaces Docker

> **Explanation:** **LocalStack** spins up local mock implementations of AWS APIs on your local workstation, enabling fast, offline testing without incurring cloud charges.

---

### 17. A node is:
- [x] **A worker machine**
- [ ] A Docker image
- [ ] A database
- [ ] A storage bucket

> **Explanation:** In Kubernetes, a **node** is a worker machine (either a physical machine or a virtual machine) that runs application workloads inside containers.

---

### 18. A Kubernetes cluster consists of:
- [x] **Multiple nodes**
- [ ] Containers only
- [ ] Access keys
- [ ] Multiple policies

> **Explanation:** A Kubernetes cluster comprises a control plane along with **multiple worker nodes** that collectively execute, scale, and manage containerized applications.

---

### 19. Which is NOT an essential characteristic of cloud computing?
- [x] **Manual Provisioning**
- [ ] Rapid Elasticity
- [ ] Measured Service
- [ ] Resource Pooling

> **Explanation:** Cloud computing relies on *automated, self-service provisioning*. **Manual Provisioning** is slow and defeats the core efficiency benefits defined by standard NIST cloud benchmarks.

---

### 20. What does ARN stand for?
- [ ] AWS Resource Namespace
- [ ] Amazon Registry Name
- [x] **Amazon Resource Name**
- [ ] Amazon Resource Number

> **Explanation:** **ARN (Amazon Resource Name)** is the standardized identifier used across AWS to uniquely reference any specific resource (e.g., EC2 instances, S3 buckets, IAM roles).

---

### 21. The smallest deployable unit in Kubernetes is:
- [x] **Pod**
- [ ] Virtual Machine
- [ ] Node
- [ ] Cluster

> **Explanation:** A **Pod** is the basic unit of deployment in Kubernetes. It encapsulates one or more co-located containers that share network IP and storage resources.

---

### 22. Which IAM identity is normally used as a temporary identity?
- [ ] Root User
- [x] **IAM Role**
- [ ] IAM User
- [ ] IAM Group

> **Explanation:** Unlike IAM Users with permanent credentials, an **IAM Role** generates short-lived, temporary security credentials that are assumed by users, applications, or services for specific tasks.

---

### 23. Which deployment model provides the MOST control?
- [x] **Private Cloud**
- [ ] Public Cloud
- [ ] Community Cloud
- [ ] Hybrid Cloud

> **Explanation:** A **Private Cloud** is dedicated exclusively to one organization. Because the organization controls or owns the physical infrastructure, network, and software stack, it offers maximum control and security customization.

---

### 24. A collection of IAM users is called:
- [ ] S3 Bucket
- [ ] IAM Role
- [ ] IAM Policy
- [x] **IAM Group**

> **Explanation:** An **IAM Group** is a collection of IAM users. Using groups simplifies managing authorization rules for multiple team members simultaneously.

---

### 25. Which tool creates a local Kubernetes cluster?
- [x] **kind**
- [ ] Docker Desktop
- [ ] LocalStack
- [ ] Amazon EC2

> **Explanation:** **kind (Kubernetes IN Docker)** is a tool designed specifically to run lightweight local Kubernetes clusters using Docker container nodes for testing and development.

---

### 26. Which characteristic allows cloud resources to automatically grow or shrink?
- [ ] On-demand Self-Service
- [ ] Resource Pooling
- [ ] Broad Network Access
- [x] **Rapid Elasticity**

> **Explanation:** **Rapid Elasticity** allows cloud compute and storage capacities to automatically expand (scale up/out) during demand spikes and shrink (scale down/in) when usage drops.

---

### 27. Which service model requires customers to manage the operating system?
- [x] **IaaS**
- [ ] SaaS
- [ ] FaaS
- [ ] PaaS

> **Explanation:** Under the Cloud Shared Responsibility Model for **IaaS**, the cloud provider handles hardware and hypervisors, while the **customer** is responsible for managing, patching, and securing the OS.

---

### 28. Which AWS-managed policy provides full administrative access?
- [ ] RootPolicy
- [ ] AmazonS3ReadOnlyAccess
- [ ] IAMReadOnlyAccess
- [x] **AdministratorAccess**

> **Explanation:** `AdministratorAccess` is an AWS-managed policy that grants full permissions (`"Effect": "Allow", "Action": "*", "Resource": "*"`) to execute any operation across AWS resources.

---

### 29. Cloud computing refers to:
- [ ] Installing software locally
- [ ] Running applications only on Windows
- [ ] Buying more physical servers
- [x] **Delivering computing resources over the Internet**

> **Explanation:** Cloud computing is the on-demand delivery of IT infrastructure services—including compute power, databases, storage, and networking—over the internet with pay-as-you-go pricing. *(Note: Some automated quizzes mistakenly mark "Buying more physical servers", which is the exact opposite of cloud computing).*

---

### 30. Which AWS CLI command verifies the current identity?
- [ ] aws iam whoami
- [x] **aws sts get-caller-identity**
- [ ] aws identity
- [ ] aws login

> **Explanation:** The **`aws sts get-caller-identity`** command queries the AWS Security Token Service (STS) and returns details about the IAM identity currently active in your command line environment (Account ID, User ID, and ARN).