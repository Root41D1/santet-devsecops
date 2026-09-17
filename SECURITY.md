# Santet DevSecOps Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private
vulnerability reporting for this repository and include:

- the affected component and version or commit;
- reproduction steps or a minimal proof of concept;
- potential impact and required preconditions; and
- any suggested mitigation.

Never submit live credentials, kubeconfigs, personal data, production cluster
dumps, or destructive payloads. Redact proof-of-concept output to the minimum
needed to reproduce the issue.

## Response targets

The team should acknowledge a report within two business days, provide an initial
assessment within five business days, and coordinate disclosure after a fix is
available. These are targets, not promises of eligibility or payment.

## Supported versions

Until version 1.0, only the latest tagged release is supported. Pinning an older
scanner version may leave known issues unresolved; upgrade through a reviewed
pull request.
