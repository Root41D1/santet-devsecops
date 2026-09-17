# Santet DevSecOps Operating Guide

## 1. Security lifecycle

### Plan

- Name a service owner and security contact.
- Record sensitive data, trust boundaries, internet-facing entry points, and
  privileged operations in `docs/THREAT-MODEL.md`.
- Define availability, recovery, retention, and regulatory requirements.

### Develop

- Use protected branches, peer review, signed commits where appropriate, and
  least-privilege repository access.
- Keep secrets in an approved secret manager. Commit only variable names and
  safe examples.
- Lock dependencies and review new direct dependencies for maintenance,
  provenance, license, and necessity.
- Run `make scan` before opening a pull request.

### Build and verify

- Build in an ephemeral runner from a reviewed definition.
- Permit outbound scanner traffic only to required registries/advisory services;
  secret scans and SBOM generation in this kit run without network access.
- Do not expose deployment credentials to pull requests or untrusted forks.
- Generate an SBOM for the release artifact, not only the source tree.
- Use immutable image references and record source revision, builder identity,
  test results, and SBOM together.

### Release and deploy

- Sign artifacts with short-lived workload identity and verify signatures before
  deployment.
- Separate build and deploy permissions. Production deployment requires an
  environment approval when risk warrants it.
- Promote the same digest across environments; never rebuild for production.
- Use gradual rollout, health checks, and an exercised rollback procedure.

### Operate and respond

- Centralize security, authentication, administrative, and deployment logs.
- Alert on meaningful behavior and test alert delivery.
- Patch according to the triage SLA below; re-scan continuously because known
  vulnerability data changes after release.
- Follow `docs/INCIDENT-RESPONSE.md` for suspected compromise.

## 2. Required gates

| Gate | Pull request | Default branch/release | Blocks when |
|---|---:|---:|---|
| Unit/integration tests | Yes | Yes | Tests fail |
| Secret scan | Yes | Yes | Verified secret or high-confidence match |
| SAST | Yes | Yes | New high-confidence error |
| Dependency scan | Yes | Yes | Fixable high/critical risk violates policy |
| IaC/config scan | Yes | Yes | High/critical production exposure |
| Kubernetes lint | If Kubernetes exists | Yes | Invalid or unsafe manifest/chart |
| SBOM | Optional | Required | Missing or malformed for release |
| Image scan | If built | Required | Policy threshold exceeded |
| Signature/provenance | No | Required | Missing or unverifiable |
| DAST | Preview/staging | Required for exposed apps | Confirmed high/critical issue |

Live-cluster controls are deliberately separate from pull-request CI. Run
KubeHound on a scheduled assessment cadence and continuously operate KubeArmor
with audit-first, canary-tested enforcement. See `docs/KUBERNETES-SECURITY.md`.

Apply gates to new findings first. Baseline legacy findings with owners and due
dates instead of hiding them.

## 3. Triage SLA

| Severity | Initial triage | Target remediation |
|---|---:|---:|
| Critical, exploitable | Same business day | 24–72 hours |
| High | 2 business days | 14 days |
| Medium | 5 business days | 30–60 days |
| Low | Backlog review | Risk-based |

Severity alone is insufficient. Raise priority for internet exposure, reachable
code, sensitive data, known exploitation, weak compensating controls, or a large
blast radius. Lower priority only with documented evidence.

## 4. Finding workflow

1. Validate the finding and preserve evidence without copying secrets.
2. Determine reachability, exploitability, affected versions, and exposure.
3. Assign an owner, severity, due date, and tracking issue.
4. Fix and test, or request a time-bound exception.
5. Verify the fix independently and close with evidence.

## 5. Metrics that resist gaming

- Median time to remediate by risk class.
- Percentage of production artifacts with a verified SBOM and signature.
- Percentage of repositories covered by required gates.
- Age and count of expired or soon-to-expire exceptions.
- Mean time to rotate a leaked credential.
- Change failure and rollback rates after security changes.

Do not use raw finding count or scanner pass rate as the sole measure of program
quality.
