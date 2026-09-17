# DevSecOps Starter Kit

An opinionated, stack-neutral security baseline for software repositories. It puts
fast checks on every change, deeper checks on the default branch, and release
provenance around deployable artifacts.

## What this kit covers

| Risk | Control | Tool |
|---|---|---|
| Leaked credentials | Secret scanning | Gitleaks |
| Vulnerable dependencies | SCA | OSV-Scanner |
| Unsafe code patterns | SAST | Semgrep |
| Vulnerable packages and IaC mistakes | Repository/image scan | Trivy |
| Unknown release contents | SBOM | Syft |
| Untrusted release artifacts | Signing/attestation hook | Cosign |

The tools are controls, not the operating model. Ownership, triage deadlines,
exceptions, and evidence retention are documented in [`docs/`](docs/).

## Quick start

Prerequisites: Git, Docker, and Make.

```bash
git init                    # only if this is a new repository
make doctor
make scan
```

Reports are written to `artifacts/security/` and intentionally excluded from
Git. To scan a built image:

```bash
IMAGE=ghcr.io/example/app:commit-sha make image-scan
```

## Commands

```text
make doctor       Check local prerequisites
make secrets      Scan Git history and working tree for secrets
make sast         Run static analysis
make dependencies Scan lockfiles and manifests for known vulnerabilities
make filesystem   Scan source, dependencies, secrets, and IaC
make sbom         Generate CycloneDX and SPDX SBOMs
make scan         Run the pull-request security baseline
make image-scan   Scan IMAGE and generate its SBOM
make clean        Remove generated security reports
```

## CI setup

The GitHub Actions workflow in `.github/workflows/devsecops.yml` runs on pull
requests, pushes to the default branch, and manual dispatches. Before enforcing
it:

1. Replace the example build/test hook with the application's real commands.
2. Protect the default branch and require the `security / baseline` check.
3. Configure dependency updates and GitHub secret scanning where available.
4. Set `IMAGE` in CI only after an image build is added.
5. Review severity thresholds in `.devsecops/policy.env`.
6. Have Dependabot replace major action tags with reviewed updates, or pin action
   commits according to your organization's supply-chain policy.

Start in audit mode for one or two weeks, resolve the baseline, then make the
gates blocking. Do not permanently suppress findings just to turn CI green.

## Repository map

```text
.devsecops/                 Security policy and scanner configuration
.github/workflows/          CI security gates
docs/                       Operating guide, threat model, exceptions, response
scripts/devsecops.sh        Reproducible local/CI command runner
Makefile                    Developer-friendly entry points
```

## Security principles

- Prevent secrets from reaching Git; rotate them if they do.
- Fail on exploitable high/critical findings, with a time-bound exception path.
- Build once, promote the same immutable artifact, and retain its SBOM.
- Use short-lived workload identity instead of long-lived deployment keys.
- Keep CI permissions minimal and pin third-party automation before production.
- Treat scanner output as untrusted data; never execute content from reports.

See [the operating guide](docs/OPERATING-GUIDE.md) for implementation details.
