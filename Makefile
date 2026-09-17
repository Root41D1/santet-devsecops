SHELL := /bin/sh

.PHONY: help test doctor secrets sast dependencies filesystem sbom kube-lint scan image-scan \
	docker-build docker-smoke \
	prowler-build prowler-smoke \
	cluster-doctor kubearmor-probe kubearmor-policy-check kubearmor-render \
	kubearmor-install kubearmor-status kubearmor-policy-apply kubehound kubehound-dump \
	cloud-validate cloud-doctor cloud-scan cloud-inventory cloud-list clean

CLOUD_PROVIDER ?= aws
CLOUD_LIST ?= checks
PROWLER_RUNTIME_IMAGE ?= santet-prowler:5.42.0-r1

help:
	@./santet help

test:
	@tests/test-cloud-cli.sh

doctor:
	@./santet doctor

secrets:
	@./santet secrets

sast:
	@./santet sast

dependencies:
	@./santet dependencies

filesystem:
	@./santet filesystem

sbom:
	@./santet sbom

kube-lint:
	@./santet kube-lint

scan:
	@./santet scan

image-scan:
	@./santet image-scan

docker-build:
	@docker build --tag santet-devsecops:local .

docker-smoke: docker-build
	@SANTET_IMAGE=santet-devsecops:local ./docker/santet help
	@SANTET_IMAGE=santet-devsecops:local ./docker/santet doctor

prowler-build:
	@docker build --file docker/prowler/Dockerfile --tag "$(PROWLER_RUNTIME_IMAGE)" .

prowler-smoke: prowler-build
	@docker run --rm --network=none --read-only --security-opt=no-new-privileges \
		--cap-drop=ALL --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=256m \
		"$(PROWLER_RUNTIME_IMAGE)" --version
	@docker run --rm --network=none --read-only --security-opt=no-new-privileges \
		--cap-drop=ALL --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=256m \
		"$(PROWLER_RUNTIME_IMAGE)" alibabacloud --no-banner --no-color --list-services

cluster-doctor:
	@./santet cluster-doctor

cloud-validate:
	@./santet cloud-validate

cloud-doctor:
	@./santet cloud-doctor "$(CLOUD_PROVIDER)"

cloud-scan:
	@./santet cloud-scan "$(CLOUD_PROVIDER)"

cloud-inventory:
	@./santet cloud-inventory "$(CLOUD_PROVIDER)"

cloud-list:
	@./santet cloud-list "$(CLOUD_PROVIDER)" "$(CLOUD_LIST)"

kubearmor-probe:
	@./santet kubearmor-probe

kubearmor-policy-check:
	@./santet kubearmor-policy-check

kubearmor-render:
	@./santet kubearmor-render

kubearmor-install:
	@./santet kubearmor-install

kubearmor-status:
	@./santet kubearmor-status

kubearmor-policy-apply:
	@./santet kubearmor-policy-apply

kubehound:
	@./santet kubehound

kubehound-dump:
	@./santet kubehound-dump

clean:
	@./santet clean
