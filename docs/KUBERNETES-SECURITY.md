# Santet DevSecOps Kubernetes Security

The three tools answer different questions and should not be treated as
interchangeable scanners.

| Tool | Stage | Purpose | Default behavior in this kit |
|---|---|---|---|
| KubeLinter | Pull request | Find unsafe manifests, Helm charts, and Kustomize resources | Blocking CI gate |
| KubeHound | Cluster assessment | Build attack paths from Kubernetes resources and identities | Manual, read-only collection |
| KubeArmor | Runtime | Observe or enforce process, file, network, and capability policy | Audit-first policy |

## KubeLinter

The default target checks `k8s/`, `kubernetes/`, `manifests/`, `deploy/`, and
`charts/` when they exist:

```bash
make kube-lint
```

For a different location, pass repository-relative paths separated by spaces:

```bash
K8S_PATHS="platform/base platform/overlays/production" make kube-lint
```

Configuration lives in `.kube-linter.yaml`. It enables a curated set of
security and production-readiness checks while excluding organization-specific
style rules. Suppress a finding only on the affected object using
`ignore-check.kube-linter.io/<check>` and put an approved exception ID and expiry
in the annotation value.

## KubeArmor

KubeArmor requires compatible Linux Security Modules on cluster nodes. Installing
the controller successfully does not prove that runtime enforcement works.
Docker Desktop on macOS and Windows is explicitly unsupported upstream; Santet's
install command detects Docker Desktop/LinuxKit and exits before changing it.

1. Verify the target context and tools:

   ```bash
   kubectl config current-context
   make cluster-doctor
   ```

2. Render and inspect the pinned operator release:

   ```bash
   helm repo add kubearmor https://kubearmor.github.io/charts
   helm repo update kubearmor
   make kubearmor-render
   ```

   Review `artifacts/security/kubearmor-rendered.yaml`, especially RBAC,
   DaemonSet privileges, image tags, resources, host mounts, and tolerations.

3. Install only after confirming the exact context:

   ```bash
   SANTET_CONTEXT=my-cluster ALLOW_CLUSTER_WRITE=true make kubearmor-install
   ```

4. Confirm actual node enforcement support:

   ```bash
   SANTET_CONTEXT=my-cluster ALLOW_CLUSTER_READ=true make kubearmor-probe
   SANTET_CONTEXT=my-cluster ALLOW_CLUSTER_READ=true make kubearmor-status
   ```

5. Review `kubernetes/kubearmor/audit-sensitive-runtime.yaml`. It is a cluster
   policy, but only selects workloads explicitly labeled
   `santet.devsecops/profile=hardened`. Validate against the installed CRD
   without persisting it:

   ```bash
   SANTET_CONTEXT=my-cluster ALLOW_CLUSTER_READ=true make kubearmor-policy-check
   ```

6. Label only a test workload with `santet.devsecops/profile=hardened`, then
   apply the audit policy:

   ```bash
   SANTET_CONTEXT=my-cluster ALLOW_CLUSTER_WRITE=true make kubearmor-policy-apply
   ```

   Exercise normal traffic and observe events with `karmor logs`.

7. Keep the policy at `Audit` until telemetry proves it will not interrupt valid
   behavior. Promote individual rules to `Block` through review, canary rollout,
   and a documented rollback.

The example audits package-manager/downloader execution and service-account-token
access. Those operations may be legitimate for some workloads; do not switch the
example globally to `Block`.

## KubeHound

KubeHound reads cluster objects and starts local Docker Compose services for its
graph database and UI. Its dataset contains sensitive topology, RBAC, workload,
and attack-path information. Run it from a secured workstation and do not upload
the dump or database as an ordinary CI artifact.

Install the pinned/approved KubeHound binary, then:

```bash
kubectl config current-context
make cluster-doctor
SANTET_CONTEXT=my-cluster ALLOW_CLUSTER_READ=true make kubehound
```

Approved client versions are recorded centrally in `.santet/policy.env`.
Upgrade them through review instead of relying on mutable `latest` downloads.

Use a dedicated read-only assessment identity where possible. Review at least:

- paths from externally reachable workloads to privileged identities;
- paths to cluster-admin or node compromise;
- container escape opportunities;
- cross-namespace lateral movement; and
- overly broad service-account or workload-identity permissions.

Record findings and remediation evidence, then remove local KubeHound data using
its documented backend lifecycle commands. Do not automate destructive backend
cleanup against an unverified Docker context.

## Recommended cadence

- KubeLinter: every pull request.
- KubeHound: monthly and after RBAC, identity, network, or cluster architecture
  changes.
- KubeArmor: continuously, with policy and telemetry reviewed as part of normal
  operations.
