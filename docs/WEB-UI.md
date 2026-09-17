# Santet DevSecOps Web UI

The Santet Web UI is a local-only R&D console layered on top of the existing
CLI. It does not replace or reimplement scanner behavior: every security action
delegates to an allowlisted `./santet` command, so CLI policy and evidence remain
the source of truth.

## Start locally

Requirements:

- Python 3.10 or newer;
- the same Git and Docker requirements as the Santet CLI; and
- a local checkout of this repository.

Run:

```bash
make web
```

Then open <http://127.0.0.1:7777>.

To assess a different local repository without moving the Santet checkout:

```bash
python3 web/server.py --target /absolute/path/to/project
```

Use a different loopback port when necessary:

```bash
python3 web/server.py --port 8787 --target /absolute/path/to/project
```

## Current capabilities

- overview of local SARIF, OSV, KubeLinter, and CycloneDX evidence;
- full or focused repository scans;
- local container image scanning;
- AWS, Azure, Google Cloud, and Alibaba Cloud doctor/inventory/gate actions;
- evidence search and download;
- live command output, job state, and cancellation; and
- read-only KubeArmor checks through the backend API contract.

Cluster-changing commands, arbitrary CLI arguments, shell execution, cleanup,
and KubeHound's interactive backend are intentionally not exposed in this R&D
UI. They remain available through the original CLI with their existing explicit
safety gates.

## Local security model

Authentication is intentionally disabled for the R&D phase. The server therefore:

- binds to `127.0.0.1` by default;
- refuses every non-loopback bind and rejects non-local Host headers;
- generates a per-process request token for state-changing API calls;
- accepts only a fixed command allowlist and validated provider/image labels;
- uses direct process arguments and never invokes a shell;
- runs only one security job at a time to protect evidence consistency;
- does not expose cluster-changing operations; and
- confines artifact downloads to the target's `artifacts/security/` directory.

Do not expose this R&D server through a reverse proxy, public tunnel, shared
network interface, or cloud load balancer. Authentication, authorization,
durable job isolation, audit identity, TLS, and multi-user storage are required
before any non-local deployment.

## Cloud credentials

Start the Web UI from a terminal that already has the intended read-only cloud
identity. The backend inherits that process environment and the CLI applies the
same provider validation documented in [MULTICLOUD.md](MULTICLOUD.md).

Examples:

```bash
AWS_PROFILE=audit make web
```

```bash
AZURE_CLIENT_ID=... \
AZURE_TENANT_ID=... \
AZURE_CLIENT_SECRET=... \
SANTET_AZURE_SUBSCRIPTION_IDS=... \
  make web
```

Never place credentials in frontend fields, source files, or browser storage.

## Validation

Run the backend and security-contract tests with:

```bash
make web-test
```

The normal `make test` target includes these tests as well.
