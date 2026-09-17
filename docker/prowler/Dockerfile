FROM docker.io/prowlercloud/prowler:5.42.0@sha256:bd2a26224b0d0983580b0e22b0e3368d012da234d1f2e9597fa336f67d2c9fad

USER root

# This runtime intentionally supports only Santet's AWS, Azure, GCP, and
# Alibaba Cloud adapters. PowerShell (M365) and embedded Trivy (Prowler IaC and
# image providers) are removed because Santet supplies separate pinned engines
# for those domains. Versions below are fixed Debian 13 security updates.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade \
      gzip=1.13-1+deb13u1 \
      libpcre2-8-0=10.46-1~deb13u2 \
      libsqlite3-0=3.46.1-7+deb13u2 \
      libssh2-1t64=1.11.1-1+deb13u2 \
      perl-base=5.40.1-6+deb13u1 \
    && rm -rf /var/lib/apt/lists/* \
      /opt/microsoft/powershell \
      /usr/bin/pwsh \
      /usr/local/bin/trivy \
      /home/prowler/.local/share/powershell \
      /home/prowler/.venv/lib/python3.12/site-packages/moto/moto_proxy/cert.key

LABEL org.opencontainers.image.title="Santet Prowler Runtime" \
      org.opencontainers.image.description="Hardened four-cloud Prowler runtime for Santet DevSecOps" \
      org.opencontainers.image.source="https://github.com/Root41D1/santet-devsecops" \
      org.opencontainers.image.version="5.42.0-r1" \
      org.opencontainers.image.licenses="Apache-2.0"

USER prowler
