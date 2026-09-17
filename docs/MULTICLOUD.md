# Multi-cloud security

Santet DevSecOps provides a read-only cloud security assessment layer for AWS,
Microsoft Azure, Google Cloud, and Alibaba Cloud. It orchestrates a pinned
Prowler image and adds a smaller, safety-oriented command surface around cloud
credentials, target selection, evidence, and CI failure behavior.

## Security model

Cloud assessment crosses a high-value trust boundary. The scanner can read
security configuration, identities, resource metadata, network exposure, and
logging posture. Treat its output as confidential security evidence.

Santet applies these defaults:

- the scanner container is immutable, capability-free, and protected with
  `no-new-privileges`;
- only the target repository and provider credential directory are mounted
  read-only;
- only the provider-specific evidence directory is writable;
- the upstream Prowler image is pinned by version and multi-architecture
  digest, then reduced to a dedicated four-cloud runtime whose published manifest is
  also pinned by digest in the Santet policy;
- fixers and automatic remediation are not exposed;
- metadata-based identity requires `SANTET_CLOUD_ALLOW_METADATA=true`;
- `cloud-scan` blocks on failed critical/high checks; and
- `cloud-inventory` records all severities without acting as a gate.

The cloud scanner requires outbound network access to provider APIs. Do not run
it against untrusted configuration or in a network that gives the container
access to unrelated internal services.

## Commands

```bash
make cloud-validate
make cloud-doctor CLOUD_PROVIDER=aws
make cloud-list CLOUD_PROVIDER=aws CLOUD_LIST=compliance
make cloud-scan CLOUD_PROVIDER=aws
make cloud-inventory CLOUD_PROVIDER=aws
```

The direct CLI equivalents are:

```bash
./santet cloud-doctor aws
./santet cloud-list aws checks
./santet cloud-scan aws
./santet cloud-inventory aws
./santet cloud-scan all
```

`all` runs providers sequentially so that API bursts and local memory use stay
bounded. A failure in one provider does not suppress evidence collection from
the others, but the aggregate command returns a failure.

Evidence is stored under:

```text
artifacts/security/cloud/<provider>/<target>/
```

Each run generates CSV, JSON-OCSF, HTML, and SARIF. Never commit this directory.

The runtime removes PowerShell, embedded Trivy, and test credentials that are
not needed for AWS, Azure, GCP, or Alibaba Cloud. Debian security packages are
upgraded to reviewed fixed versions, and the result is blocked from publication
when Trivy finds a fixable HIGH or CRITICAL vulnerability.

## Shared selection controls

Copy `.santet/cloud.env.example` into a local, ignored environment file or set
the variables only for a single command. Do not store credentials in it.

| Variable | Purpose |
|---|---|
| `SANTET_CLOUD_TARGET` | Safe evidence label such as `prod` or `sandbox` |
| `SANTET_CLOUD_SEVERITIES` | Blocking scan severities; defaults to `critical high` |
| `SANTET_CLOUD_REGIONS` | Space-separated AWS or Alibaba regions |
| `SANTET_CLOUD_SERVICES` | Space-separated Prowler services |
| `SANTET_CLOUD_CHECKS` | Space-separated check IDs |
| `SANTET_CLOUD_COMPLIANCE` | Space-separated framework IDs |
| `SANTET_CLOUD_CREDENTIAL_DIR` | Absolute provider CLI profile directory |

Selection values are validated and passed as argument tokens; they are never
evaluated as shell commands.

## Authentication

Prefer temporary workload identity. Long-lived access keys should be a local
fallback, not the production CI design.

### AWS

Recommended CI flow: OIDC federation into a dedicated read-only IAM role.

```bash
export AWS_ROLE_ARN=arn:aws:iam::123456789012:role/SantetAuditRole
export AWS_WEB_IDENTITY_TOKEN_FILE=/absolute/path/to/oidc-token
export AWS_REGION=ap-southeast-1
SANTET_CLOUD_TARGET=prod ./santet cloud-scan aws
```

For a local named profile:

```bash
SANTET_CLOUD_CREDENTIAL_DIR="$HOME/.aws" \
SANTET_AWS_PROFILE=audit \
SANTET_CLOUD_TARGET=prod \
  ./santet cloud-scan aws
```

To assume a second role, set `SANTET_AWS_ROLE_ARN`. Set
`SANTET_AWS_EXTERNAL_ID` where the role trust policy requires it.

### Microsoft Azure

Service-principal environment authentication is the default:

```bash
export AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000
export AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000
export AZURE_CLIENT_SECRET='retrieve-from-a-secret-manager'
export SANTET_AZURE_SUBSCRIPTION_IDS='subscription-id'
SANTET_CLOUD_TARGET=prod ./santet cloud-scan azure
```

For a local Azure CLI login, mount the profile and select CLI auth:

```bash
SANTET_CLOUD_CREDENTIAL_DIR="$HOME/.azure" \
SANTET_AZURE_AUTH=cli \
SANTET_CLOUD_TARGET=prod \
  ./santet cloud-scan azure
```

Managed identity requires `SANTET_AZURE_AUTH=managed` and the explicit metadata
opt-in. Use `SANTET_AZURE_REGION` when limiting Azure regional checks.

For GitHub Actions OIDC, authenticate with the official Azure login action,
select CLI auth, and expose its Azure CLI profile through
`SANTET_CLOUD_CREDENTIAL_DIR`. Santet does not convert an OIDC token into a
client secret.

### Google Cloud

Prefer Workload Identity Federation or service-account impersonation. A local
Application Default Credentials profile can be mounted read-only:

```bash
SANTET_CLOUD_CREDENTIAL_DIR="$HOME/.config/gcloud" \
SANTET_GCP_PROJECT_IDS='project-one project-two' \
SANTET_CLOUD_TARGET=prod \
  ./santet cloud-scan gcp
```

For a credential file, use an absolute `GOOGLE_APPLICATION_CREDENTIALS` path.
For impersonation, set `GOOGLE_IMPERSONATE_SERVICE_ACCOUNT`. Organization-wide
assessment uses `SANTET_GCP_ORGANIZATION_ID`.

### Alibaba Cloud

Prefer a RAM role with STS or OIDC/RRSA. Do not use the root account AccessKey.

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID='temporary-or-source-id'
export ALIBABA_CLOUD_ACCESS_KEY_SECRET='retrieve-from-a-secret-manager'
export SANTET_ALIBABA_ROLE_ARN='acs:ram::123456789012:role/SantetAuditRole'
SANTET_CLOUD_REGIONS='ap-southeast-5' \
SANTET_CLOUD_TARGET=prod \
  ./santet cloud-scan alibabacloud
```

ACK OIDC uses `ALIBABA_CLOUD_OIDC_PROVIDER_ARN`, an absolute
`ALIBABA_CLOUD_OIDC_TOKEN_FILE`, and `SANTET_ALIBABA_OIDC_ROLE_ARN`. ECS RAM
role mode requires `SANTET_ALIBABA_ECS_RAM_ROLE` plus the metadata opt-in.

## Baselines and exceptions

Use Prowler mutelists only for reviewed, resource-specific exceptions. Every
exception needs an owner, reason, expiry date, and compensating control. Santet
does not enable an unrestricted pass-through argument because it could expose
Prowler fixer or external publishing options.

For broad initial adoption:

1. run `cloud-inventory` and store the artifact in restricted CI storage;
2. triage internet exposure, identity, logging, encryption, and critical data;
3. fix critical/high risks or document time-bound exceptions;
4. enable `cloud-scan` as a scheduled and release gate; and
5. gradually add medium severity and organization-specific checks.

## CI guidance

- Never provide cloud credentials to pull requests from forks.
- Use one protected environment per provider and production boundary.
- Use OIDC claims restricted to the exact repository, branch, workflow, and
  environment.
- Grant read-only permissions to the scan identity.
- Upload evidence with short retention and restricted access.
- Schedule live cloud scans; keep repository-only scanning on every pull
  request.
- Constrain concurrent runs to avoid provider API throttling.

Cloud findings are point-in-time observations. Combine scheduled Santet scans
with provider-native continuous controls such as AWS Config, Azure Policy, GCP
Organization Policy/Security Command Center, and Alibaba Cloud Config when the
associated service cost and data handling are acceptable.

## Scope compared with commercial CNAPP products

Santet covers reproducible assessment, compliance evidence, IaC, containers,
Kubernetes, attack-path inputs, and runtime policy. It does not currently claim
agentless disk snapshots, managed data classification, a hosted multi-tenant
graph, 24/7 threat research, or vendor-supported remediation. Those are explicit
roadmap areas, not hidden limitations.
