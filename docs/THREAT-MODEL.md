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

Consider spoofing, tampering, repudiation, disclosure, denial of service,
privilege escalation, business-logic abuse, supply-chain compromise, and operator
error.

## Decisions

- Accepted risks:
- Required security tests:
- Monitoring and response assumptions:
- Reviewer and review date:

