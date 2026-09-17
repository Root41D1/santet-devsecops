FROM docker.io/library/docker:29.8.1-cli-alpine3.24@sha256:9f36dfce2d1fd053d700a4eca00c358df79bf7d8cb69d4a9e8d9981af18834ea

ARG SANTET_VERSION=0.1.0

LABEL org.opencontainers.image.title="Santet DevSecOps" \
      org.opencontainers.image.description="Open-source DevSecOps security automation for source code, containers, and Kubernetes" \
      org.opencontainers.image.source="https://github.com/Root41D1/santet-devsecops" \
      org.opencontainers.image.version="${SANTET_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV SANTET_TARGET_DIR=/workspace \
    HOME=/tmp

WORKDIR /opt/santet

COPY santet README.md LICENSE ./
COPY scripts ./scripts
COPY .santet ./.santet
COPY .kube-linter.yaml .semgrep.yml ./
COPY kubernetes ./kubernetes

RUN apk add --no-cache libcrypto3=3.5.8-r0 libssl3=3.5.8-r0 \
    && chmod 0555 /opt/santet/santet /opt/santet/scripts/santet.sh \
    && rm -rf /usr/local/libexec/docker/cli-plugins /usr/local/lib/docker/cli-plugins

WORKDIR /workspace

USER 65532:65532

ENTRYPOINT ["/opt/santet/santet"]
CMD ["help"]
