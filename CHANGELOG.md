# Changelog

All notable changes to Santet DevSecOps are documented here.

## [Unreleased]

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
