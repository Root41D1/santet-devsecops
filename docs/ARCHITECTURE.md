# Santet DevSecOps Architecture

## Components

Santet is a small POSIX shell orchestrator. It does not replace or fork upstream
security engines. Repository scanners run in pinned containers and mount the
repository at `/src`. Live-cluster tools run as local clients because they need
the user's selected kubeconfig and, for KubeHound, Docker Compose orchestration.

The optional Santet distribution image contains only the orchestrator, Git, and
Docker CLI. It runs as a non-root user and delegates scans to the same pinned
scanner images through the host Docker socket. The target project is mounted at
the same absolute host/container path so nested scanner bind mounts resolve
correctly with Docker-outside-of-Docker.

Live cloud assessment delegates to a digest-pinned Prowler container. Provider
credentials or CLI profiles are mounted only for that child container, and the
repository is read-only. Santet controls target selection, severity gates, and
the writable evidence directory; it does not expose Prowler fixers.

The optional local Web UI is a dependency-free Python HTTP service with a
static browser client. It reads normalized summaries from existing evidence and
delegates requested work to a fixed CLI allowlist. It never invokes a shell,
permits only one job at a time, and does not expose cluster-changing commands.
The UI is a presentation and orchestration layer; CLI policy remains the source
of truth.

## Trust boundaries

1. **Repository:** potentially untrusted source and scanner input.
2. **Docker daemon:** privileged local service used to run scanners and inspect
   local images.
3. **CI runner:** ephemeral environment that receives source but no cluster
   credentials.
4. **Kubernetes API:** sensitive live environment protected by context and
   explicit read/write gates.
5. **Evidence directory:** reports and cluster dumps that may reveal code,
   packages, vulnerabilities, topology, and identities.
6. **Cloud control plane:** sensitive provider APIs accessed through a dedicated
   read-only workload identity and explicit target selection.
7. **Local browser:** unauthenticated R&D interface constrained to loopback,
   same-origin requests, a per-process mutation token, validated command
   parameters, and evidence-directory path confinement.

## Data flow

Repository scans send only required traffic to rule or vulnerability services.
Gitleaks, KubeLinter, and Syft run with container networking disabled. Semgrep,
OSV-Scanner, and Trivy require network access for rules or vulnerability data.

KubeHound reads Kubernetes and RBAC resources and writes a local attack graph.
KubeArmor runs on cluster nodes and emits runtime telemetry through its relay.
Neither is invoked by pull-request CI.

Cloud scans query live provider APIs and write CSV, JSON-OCSF, HTML, and SARIF
under a provider/target boundary. They are scheduled or manually dispatched and
must never receive credentials in untrusted pull-request jobs.

## Failure behavior

- Scanner findings produce a non-zero exit according to policy.
- `make scan` stops on the first local failure; CI uses independent steps with
  `always()` so later evidence is still collected.
- Cluster access fails closed when context or confirmation variables are absent.
- KubeArmor installation fails closed on Docker Desktop/LinuxKit, where the
  required Linux kernel security modules are not available to KubeArmor.
- KubeArmor installation uses Helm `--atomic` and `--wait` to roll back a failed
  release.
- Cloud fixers are unavailable; critical/high failed checks return a blocking
  status while inventory mode remains non-blocking.
- The local Web UI refuses non-loopback binding and non-local Host headers,
  rejects concurrent jobs, and excludes destructive or cluster-changing
  commands from its API.

## Performance model

- Static tools operate on one repository mount and avoid local installation.
- Networkless tools eliminate update latency and reduce exfiltration surface.
- Trivy reuses a dedicated `santet-trivy-cache` Docker volume for vulnerability
  databases and checks bundles.
- Release images are built for `linux/amd64` and `linux/arm64`, include SBOM and
  provenance attestations, and are published only from semantic-version tags.
- KubeHound uses bounded API rate, buffered pages, batched vertices/edges, and a
  fixed worker pool.
- KubeArmor alert throttling limits event storms while keeping enforcement in
  the kernel through supported LSMs.

Performance settings are starting points, not universal maxima. Benchmark with
representative repositories and clusters before raising concurrency.
