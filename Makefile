SHELL := /bin/sh

.PHONY: help doctor secrets sast dependencies filesystem sbom kube-lint scan image-scan \
	docker-build docker-smoke \
	cluster-doctor kubearmor-probe kubearmor-policy-check kubearmor-render \
	kubearmor-install kubearmor-status kubearmor-policy-apply kubehound kubehound-dump clean

help:
	@./santet help

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

cluster-doctor:
	@./santet cluster-doctor

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
