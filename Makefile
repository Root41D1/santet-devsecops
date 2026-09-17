SHELL := /bin/sh

.PHONY: help doctor secrets sast dependencies filesystem sbom scan image-scan clean

help:
	@./scripts/devsecops.sh help

doctor:
	@./scripts/devsecops.sh doctor

secrets:
	@./scripts/devsecops.sh secrets

sast:
	@./scripts/devsecops.sh sast

dependencies:
	@./scripts/devsecops.sh dependencies

filesystem:
	@./scripts/devsecops.sh filesystem

sbom:
	@./scripts/devsecops.sh sbom

scan:
	@./scripts/devsecops.sh scan

image-scan:
	@./scripts/devsecops.sh image-scan

clean:
	@./scripts/devsecops.sh clean

