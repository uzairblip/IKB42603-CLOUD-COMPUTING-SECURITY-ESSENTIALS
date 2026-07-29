# Environment Setup Report

This report summarizes the environment setup guide and places each available screenshot beside the corresponding step. Steps 7 and 9 are text-only because no screenshot was available for those exact steps.

## Step 1: Install Docker
- Verified Docker installation using `docker --version`.
- Confirmed Docker runtime with `docker run --rm hello-world`.

![Docker Installed](<awan computing/1.docker installed.png>)

## Step 2: Install AWS CLI
- Verified AWS CLI installation with `aws --version`.
- Confirmed AWS CLI readiness for AWS and LocalStack use.

![AWS CLI Installed](<awan computing/2.aws installed.png>)

## Step 3: Install kind and kubectl
- Verified installation of `kind` and `kubectl`.
- Confirmed cluster tooling readiness for Kubernetes local clusters.

![kind and kubectl Installed](<awan computing/3.Installed kind & kubectl.png>)

## Step 4: Install Helper Tools
- Verified installation of helper tools including OpenSSL, `oathtool`, and Trivy.
- These tools support certificate handling, one-time password generation, and container/image security scanning.

![Helper Tools Installed](<awan computing/4. Helper Tools (OpenSSL, oathtool, Trivy).png>)

## Step 5: LocalStack Health Check
- Checked LocalStack service status via `http://localhost:4566/_localstack/health`.
- Verified that LocalStack services such as `iam`, `s3`, `lambda`, `kinesis`, and more are available.

![LocalStack Health Check](<awan computing/5.(PART1)LOCALSTACK HEALTH CHECK.png>)

## Step 6: One-Time AWS CLI Configuration
- Configured the AWS CLI with `aws_access_key_id`, `aws_secret_access_key`, and default region.
- Verified the LocalStack endpoint by using `aws sts get-caller-identity --endpoint-url=http://localhost:4566`.

![AWS CLI Configuration](<awan computing/6. One-Time AWS CLI Configuration.png>)

## Step 7: Create Kubernetes Cluster with kind
- Create the Kubernetes cluster using:

```bash
kind create cluster --name ccse
```

- This step prepares a local Kubernetes control plane for testing and deployment.

> Note: No screenshot is available for step 7.

## Step 8: Verify Kubernetes Cluster Info
- Confirm the cluster context and Kubernetes control plane with:

```bash
kubectl cluster-info --context kind-ccse
kubectl get nodes
```

- Check node status to ensure the control plane is ready.

![Kubernetes Cluster Info](<awan computing/5.PART 2 KUBE.png>)

## Step 9: Final Validation
- Perform final validation of the environment and tools.
- Ensure that LocalStack, AWS CLI, Docker, kind, and Kubernetes are working together correctly.

Recommended validation commands:

```bash
kubectl cluster-info --context kind-ccse
kubectl get nodes
aws --endpoint-url=http://localhost:4566 sts get-caller-identity
```

> Note: No screenshot is available for step 9.

## Notes
- Steps 1 through 6 are documented with available screenshots from the workspace.
- Step 8 also includes a Kubernetes screenshot from the workspace.
- Steps 7 and 9 are included as report text because the corresponding screenshot files were not present.
