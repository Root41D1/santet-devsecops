# Santet DevSecOps

> Free, open-source security automation for code, containers, Kubernetes, and
> AWS, Azure, Google Cloud, and Alibaba Cloud—from pull request to runtime.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Shell: POSIX](https://img.shields.io/badge/shell-POSIX-4EAA25.svg)](scripts/santet.sh)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-security-326CE5.svg)](docs/KUBERNETES-SECURITY.md)

Santet DevSecOps is an opinionated, vendor-neutral toolkit that composes proven
open-source security tools behind one small command surface. It provides useful
defaults, machine-readable evidence, GitHub Actions integration, and explicit
safety controls for live-cluster operations.

The name is Indonesian; here it is a playful metaphor for finding hidden attack
paths before they become real incidents.

## Why Santet?

- **Useful on day one:** scanners run in pinned containers; no local package
  soup is required for repository scans.
- **Defense across the lifecycle:** secrets, SAST, dependencies, IaC,
  Kubernetes manifests, container images, SBOMs, attack paths, and runtime
  enforcement.
- **One multi-cloud control plane:** pinned, read-only assessment for AWS,
  Azure, GCP, and Alibaba Cloud with consistent evidence and failure policy.
- **Reduced cloud runtime:** provider-irrelevant PowerShell, embedded image
  scanning, and test credentials are removed before vulnerability gating.
- **Safe cluster access:** every live-cluster command requires an exact context
  name and an explicit read or write opt-in.
- **Low-noise defaults:** KubeLinter uses a curated security profile instead of
  organization-specific style rules.
- **Reproducible evidence:** SARIF, JSON, CycloneDX, and SPDX reports are kept
  under `artifacts/` and excluded from source control.
- **Free and open source:** Santet is Apache-2.0 licensed and orchestrates tools
  with their own open-source licenses.

## Security coverage

| Control | Tool | Stage | Output |
|---|---|---|---|
| Secret detection (history + files) | Gitleaks | Local + CI | SARIF |
| Static application security testing | Semgrep | Local + CI | SARIF |
| Dependency vulnerability analysis | OSV-Scanner | Local + CI | JSON |
| Vulnerability, IaC, and config scanning | Trivy | Local + CI | SARIF |
| Kubernetes manifest and Helm linting | KubeLinter | Local + CI | JSON |
| Software bill of materials | Syft | Local + CI | CycloneDX + SPDX |
| Kubernetes attack-path analysis | KubeHound | Controlled cluster assessment | Local graph |
| Runtime security enforcement | KubeArmor | Kubernetes runtime | Alerts + policy enforcement |
| Multi-cloud posture and compliance | Prowler | AWS, Azure, GCP, Alibaba Cloud | CSV + JSON-OCSF + HTML + SARIF |

## Installation

### Prerequisites

Choose one of the installation methods below. Docker is recommended for most
users because scanner versions and their dependencies are already pinned in the
published image.

The recommended Docker installation requires Docker Engine or Docker Desktop
with a running daemon, plus `curl`. The source installation additionally
requires Git and Make.

Cluster assessment additionally requires:

- `kubectl`
- Helm 3
- KubeHound 1.6.7
- `karmor` CLI 1.4.7
- Docker Compose v2 for KubeHound

Windows users should run the Docker workflow from WSL2. The lightweight wrapper
currently supports macOS and Linux shells.

### Option A: install with Docker (recommended)

This method does not require cloning the Santet repository. It installs a small
wrapper that mounts the current project and the active Docker socket into the
versioned Santet container.

1. Confirm that Docker is running:

   ```bash
   docker version
   ```

2. Pull the versioned release image:

   ```bash
   docker pull ghcr.io/root41d1/santet-devsecops:0.3.0
   ```

3. Download and inspect the matching wrapper:

   ```bash
   curl -fsSLo santet-docker \
     https://raw.githubusercontent.com/Root41D1/santet-devsecops/v0.3.0/docker/santet
   less santet-docker
   chmod 0755 santet-docker
   ```

4. Install it on your local path:

   ```bash
   mkdir -p "$HOME/.local/bin"
   install -m 0755 santet-docker "$HOME/.local/bin/santet"
   export PATH="$HOME/.local/bin:$PATH"
   ```

5. Pin the container version and verify the installation:

   ```bash
   export SANTET_IMAGE=ghcr.io/root41d1/santet-devsecops:0.3.0
   santet help
   santet doctor
   ```

   Set `SANTET_IMAGE` in CI or your shell profile if you want the selection to
   persist. Keep the wrapper and image on the same release version.

6. Enter the project you want to assess and run the baseline:

   ```bash
   cd /absolute/path/to/your-project
   santet scan
   ```

Reports are written to `artifacts/security/` in the assessed project. The
wrapper always scans the current directory unless `SANTET_TARGET_DIR` is set.

> [!WARNING]
> The wrapper mounts the Docker daemon socket. Access to that socket is
> security-sensitive and effectively has high privilege on the Docker host.
> Use only trusted, version-pinned Santet images and inspect the wrapper before
> installing it.

### Option B: clone and run from source

Repository scans are containerized, so cloning Santet is enough when Git,
Docker, and Make are already available:

```bash
git clone --branch v0.3.0 --depth 1 \
  https://github.com/Root41D1/santet-devsecops.git
cd santet-devsecops
make doctor
make scan
```

For cluster features, install the exact approved versions from the official
[KubeHound v1.6.7 release](https://github.com/DataDog/KubeHound/releases/tag/v1.6.7)
and [karmor v1.4.7 release](https://github.com/kubearmor/kubearmor-client/releases/tag/v1.4.7),
then run `make cluster-doctor`. On macOS, KubeHound is also available with
`brew install kubehound`.

### Option C: build the container locally

Use this path when developing Santet or reviewing changes before publication:

```bash
git clone https://github.com/Root41D1/santet-devsecops.git
cd santet-devsecops
make docker-smoke
SANTET_IMAGE=santet-devsecops:local ./docker/santet scan
```

### Docker Compose

Docker Compose is intended for contributors:

```bash
export SANTET_UID="$(id -u)"
export SANTET_GID="$(id -g)"
export SANTET_DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)" # Linux
docker compose run --rm santet scan
```

On Docker Desktop, use `SANTET_DOCKER_GID=0`, or prefer the wrapper because it
detects the active Unix socket automatically.

## Local Web UI (R&D)

Santet includes an optional Web UI with a Python standard-library backend and a
dependency-free frontend for local security work. It does not replace the CLI:
every action delegates to an allowlisted Santet command, and all evidence stays
under the target project's `artifacts/security/` directory.

From a source checkout, run:

```bash
make web
```

Open <http://127.0.0.1:7777>. The dashboard provides:

- security posture and finding summaries from existing evidence;
- full and focused repository scans with live output;
- container image scanning and SBOM visibility;
- AWS, Azure, GCP, and Alibaba Cloud inventory/gate workflows; and
- searchable, downloadable local evidence.

Authentication is intentionally disabled during local R&D. The server binds to
loopback by default and must not be exposed through a public interface, tunnel,
reverse proxy, or shared load balancer. See the [Web UI Guide](docs/WEB-UI.md)
for the security model, custom targets, ports, and cloud credential setup.

To assess another local project:

```bash
python3 web/server.py --target /absolute/path/to/project
```

## First scans

### Scan a repository

With the Docker installation:

```bash
cd /absolute/path/to/your-project
santet doctor
santet scan
```

With a source checkout:

```bash
make doctor
make scan
```

Both commands generate reports under `artifacts/security/`.

### Scan a cloud environment

Cloud assessment is read-only and intentionally separate from pull-request
scanning. Start by checking the selected provider and credential source:

With the Docker installation and a local AWS profile:

```bash
export SANTET_CLOUD_CREDENTIAL_DIR="$HOME/.aws"
export SANTET_AWS_PROFILE=audit
export SANTET_CLOUD_TARGET=production

santet cloud-validate
santet cloud-doctor aws
santet cloud-inventory aws
santet cloud-scan aws
```

The credential directory is mounted read-only. Use an audit-only profile and
prefer temporary workload identity over long-lived keys.

With a source checkout:

```bash
make cloud-validate
make cloud-doctor CLOUD_PROVIDER=aws
SANTET_CLOUD_TARGET=production make cloud-inventory CLOUD_PROVIDER=aws
SANTET_CLOUD_TARGET=production make cloud-scan CLOUD_PROVIDER=aws
```

`cloud-inventory` always produces a non-blocking all-severity report;
`cloud-scan` returns a failure when critical/high checks fail. Replace `aws`
with `azure`, `gcp`, `alibabacloud`, or `all`. See the
[Multi-cloud Security Guide](docs/MULTICLOUD.md) for temporary identity,
multi-account targeting, compliance frameworks, Docker credential profiles,
and CI safety.

You can also invoke the CLI directly:

```bash
./santet help
./santet kube-lint
IMAGE=example/app:local ./santet image-scan
```

### Scan a container image

From a source checkout:

```bash
docker build -t example/app:local .
IMAGE=example/app:local make image-scan
```

With the Docker installation:

```bash
docker build -t example/app:local .
IMAGE=example/app:local santet image-scan
```

The wrapper supports macOS and Linux, mounts the current project at the same
absolute path, runs Santet as the current user, and discovers the active Unix
Docker socket. Set `SANTET_TARGET_DIR`, `SANTET_DOCKER_SOCKET`, or
`SANTET_IMAGE` only when overriding those defaults.

Docker mode supports repository scans, Kubernetes manifest linting, source
SBOMs, local image scans, and multi-cloud assessment. Run KubeHound and
KubeArmor cluster operations from the host installation because those commands
require locally reviewed kubeconfig and dedicated cluster clients.

## Commands

```text
make doctor                   Check repository-scan prerequisites
make test                     Test CLI safety and argument contracts
make web                      Start the local Web UI on 127.0.0.1:7777
make web-test                 Test Web UI API and safety contracts
make secrets                  Scan Git history and files for secrets
make sast                     Run static application security testing
make dependencies             Scan dependency manifests and lockfiles
make filesystem               Scan source, IaC, config, and vulnerabilities
make kube-lint                Lint Kubernetes manifests and Helm charts
make sbom                     Generate CycloneDX and SPDX SBOMs
make scan                     Run the complete pull-request baseline
make image-scan               Scan IMAGE and generate its SBOM
make docker-build             Build the local Santet container image
make docker-smoke             Build and smoke-test Docker distribution
make prowler-build            Build the hardened four-cloud Prowler runtime
make prowler-smoke            Validate the hardened Prowler runtime offline
make cluster-doctor           Check Kubernetes tools, versions, and context
make cloud-validate           Validate pinned multi-cloud policy
make cloud-doctor             Check CLOUD_PROVIDER credentials and runtime
make cloud-list               List checks/services/compliance for a provider
make cloud-scan               Gate critical/high live-cloud findings
make cloud-inventory          Generate non-blocking all-severity cloud evidence
make kubearmor-render         Render the pinned KubeArmor chart locally
make kubearmor-install        Install KubeArmor into the confirmed context
make kubearmor-status         Show KubeArmor runtime health
make kubearmor-probe          Verify actual runtime-enforcement support
make kubearmor-policy-check   Server-side dry-run the audit policy
make kubearmor-policy-apply   Apply the audit-only runtime policy
make kubehound                Build and open a local attack graph
make kubehound-dump           Create a sensitive offline cluster dump
make clean                    Remove generated security reports
```

Set `PROJECT_NAME` and `PROJECT_VERSION` when you want explicit source identity
inside generated SBOMs; otherwise Santet uses the directory name and Git SHA.

## Kubernetes safety model

Santet refuses live-cluster operations unless the active context exactly matches
`SANTET_CONTEXT`.

Read-only assessment:

```bash
kubectl config current-context
SANTET_CONTEXT=my-dev-cluster ALLOW_CLUSTER_READ=true make kubearmor-probe
SANTET_CONTEXT=my-dev-cluster ALLOW_CLUSTER_READ=true make kubehound
```

Cluster-changing operation:

```bash
kubectl config current-context
make kubearmor-render
SANTET_CONTEXT=my-dev-cluster ALLOW_CLUSTER_WRITE=true make kubearmor-install
SANTET_CONTEXT=my-dev-cluster ALLOW_CLUSTER_WRITE=true make kubearmor-policy-apply
```

Never set these flags globally in a shell profile or CI secret. Supply them only
for the command being reviewed.

### KubeArmor rollout

The included operator chart and every KubeArmor component are pinned to version
1.7.1. Runtime posture and the example policy begin in `Audit` mode. A safe
production rollout is:

1. Render and review RBAC and DaemonSet privileges with `make kubearmor-render`.
2. Install into a non-production cluster.
3. Run `make kubearmor-probe` and confirm an actual LSM enforcer is available.
4. Apply the audit policy and label only a canary workload with
   `santet.devsecops/profile=hardened`.
5. Exercise expected workload behavior and inspect `karmor logs`.
6. Promote narrow, proven rules from `Audit` to `Block` through code review.

Installing the operator does not guarantee enforcement; kernel and node support
must be confirmed by the probe. Santet rejects KubeArmor installation on Docker
Desktop/LinuxKit because KubeArmor requires Linux kernel security modules that
are not exposed by Docker Desktop on macOS or Windows. Use a supported Linux
cluster such as a compatible kubeadm, k3s, GKE, AKS, or EKS environment.

### KubeHound profile

Santet uses a checked-in KubeHound configuration with:

- interactive context confirmation;
- 100 Kubernetes API requests/second;
- page size 500 and a ten-page buffer;
- bounded graph writer concurrency;
- clean logical ingestion to avoid stale paths; and
- telemetry disabled.

For very large clusters, tune API rate and writer concurrency gradually while
watching API-server throttling, backend health, memory, and disk. A large local
graph can require several gigabytes.

KubeHound dumps contain sensitive topology and RBAC information. They are
excluded from Git and must be handled as security evidence.

## GitHub Actions

The workflow at `.github/workflows/santet-devsecops.yml` runs the baseline on
pull requests, pushes to `main`, and manual dispatches. It uploads evidence for
30 days and publishes SARIF to GitHub code scanning when available.

Before enabling branch protection:

1. Run the workflow and resolve any repository-specific baseline findings.
2. Require the `Santet DevSecOps / baseline` check on the default branch.
3. Add your application build and test workflow as a separate required check.
4. Review `.santet/policy.env` and `.kube-linter.yaml` through pull requests.
5. Keep kubeconfig and cluster credentials out of pull-request workflows.

Live KubeHound and KubeArmor operations are intentionally not part of PR CI.

## Configuration

| Path | Purpose |
|---|---|
| `.santet/policy.env` | Approved versions and severity thresholds |
| `.santet/kubehound.yaml` | KubeHound collection and graph-performance profile |
| `.santet/cloud.env.example` | Non-secret multi-cloud selection template |
| `.santet/.gitleaks.toml` | Secret-scanning policy |
| `.kube-linter.yaml` | Curated Kubernetes security checks |
| `.semgrep.yml` | Repository-specific static-analysis rules |
| `Dockerfile` | Reproducible, non-root Santet distribution image |
| `docker/santet` | macOS/Linux Docker wrapper |
| `compose.yaml` | Contributor-oriented Docker Compose runner |
| `web/server.py` | Local-only, allowlisted Web UI API and job runner |
| `web/static/` | Dependency-free dark-mode dashboard |
| `kubernetes/kubearmor/values.yaml` | Pinned KubeArmor operator deployment |
| `kubernetes/kubearmor/config.yaml` | Audit-first runtime and pinned engine images |
| `kubernetes/kubearmor/audit-sensitive-runtime.yaml` | Audit-first runtime policy |

To scan manifests outside the conventional directories:

```bash
K8S_PATHS="platform/base platform/overlays/prod" make kube-lint
```

## Architecture

```text
Developer / CI
      |
      +-- browser --> localhost Web UI -- allowlist --+
      |                                             |
      v                                             v
  ./santet --------------------------------> artifacts/security/
      |                                  |
      +-- source and dependency scans    +-- SARIF / JSON
      +-- Kubernetes lint                +-- CycloneDX / SPDX
      +-- image scan
      |
      +-- explicit context gate --> Kubernetes API
                                      |          |
                                      v          v
                                  KubeHound   KubeArmor
                                  attack graph runtime audit/block
      |
      +-- read-only identity ----> AWS / Azure / GCP / Alibaba
                                      |
                                      v
                               Prowler evidence
```

See [Architecture](docs/ARCHITECTURE.md), [Web UI](docs/WEB-UI.md),
[Multi-cloud Security](docs/MULTICLOUD.md),
[Kubernetes Security](docs/KUBERNETES-SECURITY.md), and the
[Operating Guide](docs/OPERATING-GUIDE.md) for deeper guidance. Maintainers can
use the [Publishing Guide](docs/PUBLISHING.md) for the first GitHub release.

## Design principles

- Build once and promote immutable artifacts.
- Prefer short-lived identity over stored deployment credentials.
- Pin automation and scanner versions; review upgrades.
- Block new high-confidence risk while giving legacy findings owners and dates.
- Use severity together with reachability, exposure, exploitability, and blast
  radius.
- Start runtime controls in audit mode and enforce only observed, tested rules.
- Never treat scanner output as executable input.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md), open an issue,
and keep changes small, testable, and documented. Security vulnerabilities must
follow [SECURITY.md](SECURITY.md), not public issues.

## Project status

Santet DevSecOps is an early-stage community toolkit. Review every policy against
your threat model, platform, and compliance obligations before production use.
It does not replace security engineering judgment, penetration testing, or an
incident-response program.

## License and upstream projects

Santet DevSecOps is licensed under [Apache License 2.0](LICENSE). Gitleaks,
Semgrep, OSV-Scanner, Trivy, Syft, KubeLinter, KubeHound, KubeArmor, and Prowler are
independent upstream projects governed by their own licenses and maintainers.
Santet is not an official distribution of those projects.
