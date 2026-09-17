# Contributing to Santet DevSecOps

Thank you for helping make practical security automation easier to adopt.

## Before opening a pull request

1. Open an issue for substantial behavior, policy, dependency, or architecture
   changes.
2. Keep changes focused and avoid unrelated formatting rewrites.
3. Never commit credentials, kubeconfigs, cluster dumps, customer data, or raw
   vulnerability evidence.
4. Add or update documentation for user-visible behavior.
5. Run:

   ```bash
   make doctor
   make kube-lint
   sh -n scripts/santet.sh
   make scan
   ```

## Policy changes

Security-policy changes need a clear threat, expected signal, false-positive
analysis, performance impact, rollout plan, and rollback plan. KubeArmor changes
must begin in `Audit` unless the pull request demonstrates a safe test fixture.

Suppressions must be narrow and reference an approved, expiring exception. A
repository-wide suppression added only to make CI green will not be accepted.

## Tool upgrades

When changing `.santet/policy.env`:

- use a stable upstream release;
- review breaking changes and licenses;
- update image digests where used;
- run the relevant command end to end; and
- record the change in `CHANGELOG.md`.

## Pull requests

Describe what changed, why, how it was tested, security implications, and any
remaining risks. By contributing, you agree that your contribution is licensed
under Apache License 2.0.
