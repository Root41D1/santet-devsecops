# Lightweight Threat Model

Complete this for each service and review it after architectural or trust-boundary
changes.

## Scope

- Service/repository:
- Owner and security contact:
- Business purpose:
- Production URL and environments:
- Data classification and retention:
- Dependencies and external providers:

## Architecture and trust boundaries

Add a diagram showing users, services, data stores, queues, third parties,
administrative paths, protocols, and where identity or privilege changes.

## Entry points and assets

| Entry point or asset | Authentication | Authorization | Sensitive data | Logging |
|---|---|---|---|---|
| Example: public API | OIDC | tenant + role | customer profile | request/audit ID |

## Abuse cases

| Abuse case | Preconditions | Impact | Existing controls | Gap/owner/date |
|---|---|---|---|---|
| Credential stuffing | Reused password | Account takeover | Rate limit, MFA | Add risk scoring |
| Cross-tenant access | Broken object check | Data disclosure | Tenant-scoped policy | Add negative tests |
| CI dependency takeover | Compromised package/action | Build compromise | Lockfile, review | Verify provenance |
| Cloud scan identity theft | Exposed runner token or profile | Cross-account discovery or data disclosure | Short-lived read-only identity, protected environment, no fork credentials | Review provider audit logs |
| Scanner credential exfiltration | Compromised scanner image or untrusted config | Cloud account compromise | Digest pin, read-only mounts, restricted CLI, isolated runner | Verify upstream provenance and rotate identity |
| Wrong cloud target | Ambiguous account or subscription selection | Sensitive evidence from unintended environment | Explicit target label and provider scope | Require environment approval for production |
| Unsafe auto-remediation | Excessive write privilege or incorrect policy | Outage or destructive configuration change | No cloud fixer exposure; assessment-only identity | Keep remediation in reviewed deployment workflows |

Consider spoofing, tampering, repudiation, disclosure, denial of service,
privilege escalation, business-logic abuse, supply-chain compromise, and operator
error.

## Decisions

- Accepted risks:
- Required security tests:
- Monitoring and response assumptions:
- Reviewer and review date:
