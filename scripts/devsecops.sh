#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
POLICY_FILE="$ROOT_DIR/.devsecops/policy.env"
REPORT_DIR="$ROOT_DIR/artifacts/security"

if [ ! -f "$POLICY_FILE" ]; then
  echo "Missing policy file: $POLICY_FILE" >&2
  exit 2
fi

# shellcheck disable=SC1090
. "$POLICY_FILE"

docker_run_offline() {
  image=$1
  shift
  docker run --rm \
    --network=none \
    --security-opt=no-new-privileges \
    --cap-drop=ALL \
    -v "$ROOT_DIR:/src" \
    -w /src \
    "$image" "$@"
}

docker_run_online() {
  image=$1
  shift
  docker run --rm \
    --security-opt=no-new-privileges \
    --cap-drop=ALL \
    -v "$ROOT_DIR:/src" \
    -w /src \
    "$image" "$@"
}

prepare() {
  mkdir -p "$REPORT_DIR"
}

doctor() {
  failed=0
  for command_name in git docker; do
    if command -v "$command_name" >/dev/null 2>&1; then
      echo "ok: $command_name"
    else
      echo "missing: $command_name" >&2
      failed=1
    fi
  done
  if command -v git >/dev/null 2>&1 && ! git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "unavailable: $ROOT_DIR is not initialized as a Git repository" >&2
    failed=1
  fi
  if command -v docker >/dev/null 2>&1 && ! docker info >/dev/null 2>&1; then
    echo "unavailable: Docker daemon is not running or is inaccessible" >&2
    failed=1
  fi
  return "$failed"
}

secrets() {
  prepare
  docker_run_offline "zricethezav/gitleaks:v${GITLEAKS_VERSION}" detect \
    --source=/src --config=/src/.devsecops/.gitleaks.toml \
    --report-format=sarif --report-path=/src/artifacts/security/gitleaks.sarif \
    --redact --verbose
}

sast() {
  prepare
  docker_run_online "semgrep/semgrep:${SEMGREP_VERSION}" semgrep scan \
    --config=p/default --config=/src/.semgrep.yml \
    --error --metrics=off --sarif --output=/src/artifacts/security/semgrep.sarif /src
}

dependencies() {
  prepare
  docker_run_online "ghcr.io/google/osv-scanner:v${OSV_SCANNER_VERSION}" scan source \
    --recursive --format json --output-file /src/artifacts/security/osv.json /src
}

filesystem() {
  prepare
  docker_run_online "aquasec/trivy:${TRIVY_VERSION}" filesystem \
    --scanners vuln,misconfig,secret --severity "$TRIVY_SEVERITY" \
    --exit-code "$TRIVY_EXIT_CODE" --format sarif \
    --skip-dirs /src/.git --skip-dirs /src/artifacts \
    --output /src/artifacts/security/trivy-filesystem.sarif /src
}

sbom() {
  prepare
  docker_run_offline "anchore/syft:v${SYFT_VERSION}" scan dir:/src \
    --exclude /src/.git --exclude /src/artifacts \
    -o cyclonedx-json=/src/artifacts/security/sbom.cdx.json \
    -o spdx-json=/src/artifacts/security/sbom.spdx.json
}

image_scan() {
  prepare
  if [ -z "${IMAGE:-}" ]; then
    echo "IMAGE is required, for example: IMAGE=app:local make image-scan" >&2
    exit 2
  fi
  docker run --rm --security-opt=no-new-privileges --cap-drop=ALL \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$REPORT_DIR:/reports" \
    "aquasec/trivy:${TRIVY_VERSION}" image \
    --severity "$TRIVY_SEVERITY" --exit-code "$TRIVY_EXIT_CODE" \
    --format sarif --output /reports/trivy-image.sarif "$IMAGE"
  docker run --rm --security-opt=no-new-privileges --cap-drop=ALL \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$REPORT_DIR:/reports" \
    "anchore/syft:v${SYFT_VERSION}" scan "$IMAGE" \
    -o cyclonedx-json=/reports/image-sbom.cdx.json
}

scan() {
  doctor
  secrets
  sast
  dependencies
  filesystem
  sbom
}

clean() {
  if [ -d "$REPORT_DIR" ]; then
    rm -rf "$REPORT_DIR"
  fi
}

help() {
  sed -n '/^## Commands$/,/^## /p' "$ROOT_DIR/README.md" | sed '$d'
}

case "${1:-help}" in
  doctor) doctor ;;
  secrets) secrets ;;
  sast) sast ;;
  dependencies) dependencies ;;
  filesystem) filesystem ;;
  sbom) sbom ;;
  image-scan) image_scan ;;
  scan) scan ;;
  clean) clean ;;
  help|-h|--help) help ;;
  *) echo "Unknown command: $1" >&2; help; exit 2 ;;
esac
