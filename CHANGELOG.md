# Changelog

All notable changes to Santet DevSecOps are documented here.

## [Unreleased]

## [0.2.1] - 2026-09-17

### Fixed

- Mount the selected cloud credential directory read-only in the Docker wrapper.
- Forward image-scan, SBOM identity, Kubernetes path, and Trivy policy variables
  through the Docker wrapper.
- Add step-by-step Docker, source, local-build, Compose, repository, image, and
  multi-cloud installation instructions to the GitHub README.

## [0.2.0] - 2026-09-17

### Added

- Read-only AWS, Azure, Google Cloud, and Alibaba Cloud assessment through a
  digest-pinned and minimized Prowler 5.42.0 runtime.
- Blocking critical/high cloud security gate and non-blocking full inventory.
- CSV, JSON-OCSF, HTML, and SARIF evidence partitioned by provider and target.
- Credential-source doctor, provider catalog commands, temporary-identity
  support, metadata opt-in, and Docker credential forwarding.
- Multi-cloud architecture, authentication, CI, baseline, and operating guide.

## [0.1.0] - 2026-09-17

### Added

- Unified `santet` CLI and Make targets.
- Gitleaks, Semgrep, OSV-Scanner, Trivy, Syft, and KubeLinter baseline.
- KubeHound 1.6.7 cluster attack-path workflow and tuned configuration.
- KubeArmor 1.7.1 pinned operator values and audit-first policy.
- GitHub Actions evidence and SARIF workflow.
- Threat-model, incident-response, exception, and operating guides.
- Explicit Kubernetes context and read/write safety gates.
- Docker Desktop/LinuxKit guard for unsupported KubeArmor enforcement.
- Immutable GitHub Actions SHAs, dependency cooldown, and persistent Trivy cache.
- Secret scanning for both Git history and uncommitted working-tree files.
- Non-root Docker distribution with macOS/Linux wrapper and Compose support.
- Multi-architecture GHCR release workflow with SBOM and provenance.
