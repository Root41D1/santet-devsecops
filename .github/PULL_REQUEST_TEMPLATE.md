## Summary

Describe the problem and the focused change.

## Validation

- [ ] `sh -n scripts/santet.sh`
- [ ] `make kube-lint`
- [ ] Relevant scanner or cluster command tested
- [ ] Documentation updated

## Security and performance

Describe permissions, data exposure, false positives, runtime cost, rollout, and
rollback implications. Confirm that no secrets, kubeconfigs, cluster dumps, or
customer data are included.
