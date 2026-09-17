# Security Incident Quick Guide

## First response

1. Declare an incident, name an incident lead, start a timestamped log, and use
   the approved out-of-band channel if collaboration systems may be affected.
2. Preserve volatile evidence and relevant logs. Avoid destructive cleanup before
   capture.
3. Contain the smallest safe scope: revoke exposed credentials, isolate affected
   workloads, or stop a compromised deployment.
4. Identify affected identities, systems, data, artifacts, and time window.
5. Notify legal, privacy, customers, regulators, or law enforcement according to
   the organization's obligations—do not improvise commitments.

## Recovery

- Remove persistence and the root cause, rotate trust material, and rebuild from
  known-good sources.
- Verify artifact signatures, dependencies, CI history, audit trails, and access
  paths before restoring service.
- Increase monitoring during staged recovery and maintain a rollback point.

## Afterward

- Publish a blameless timeline and root-cause analysis.
- Track corrective actions with owners and dates.
- Update detections, threat models, tests, runbooks, and access controls.
- Test that each corrective action would have prevented or detected recurrence.

