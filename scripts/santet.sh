#!/bin/sh
set -eu

TOOL_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ROOT_DIR=${SANTET_TARGET_DIR:-$TOOL_DIR}
ROOT_DIR=$(CDPATH= cd -- "$ROOT_DIR" && pwd)

resolve_config() {
  relative_path=$1
  if [ -f "$ROOT_DIR/$relative_path" ]; then
    printf '%s\n' "$ROOT_DIR/$relative_path"
  else
    printf '%s\n' "$TOOL_DIR/$relative_path"
  fi
}

POLICY_FILE=$(resolve_config .santet/policy.env)
REPORT_DIR="$ROOT_DIR/artifacts/security"
GITLEAKS_CONFIG=$(resolve_config .santet/.gitleaks.toml)
SEMGREP_CONFIG=$(resolve_config .semgrep.yml)
KUBELINTER_CONFIG=$(resolve_config .kube-linter.yaml)
KUBEHOUND_CONFIG=$(resolve_config .santet/kubehound.yaml)
KUBEARMOR_VALUES=$(resolve_config kubernetes/kubearmor/values.yaml)
KUBEARMOR_CONFIG=$(resolve_config kubernetes/kubearmor/config.yaml)
KUBEARMOR_POLICY=$(resolve_config kubernetes/kubearmor/audit-sensitive-runtime.yaml)

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
  # Scanner images use different non-root UIDs. A sticky report directory lets
  # each container write its own result without granting write access elsewhere.
  chmod 1777 "$REPORT_DIR"
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
  cp "$GITLEAKS_CONFIG" "$REPORT_DIR/.gitleaks.toml"
  failed=0
  docker_run_offline "zricethezav/gitleaks:v${GITLEAKS_VERSION}" git /src \
    --config=/src/artifacts/security/.gitleaks.toml \
    --report-format=sarif --report-path=/src/artifacts/security/gitleaks-history.sarif \
    --redact --verbose || failed=1
  docker_run_offline "zricethezav/gitleaks:v${GITLEAKS_VERSION}" dir /src \
    --config=/src/artifacts/security/.gitleaks.toml \
    --report-format=sarif --report-path=/src/artifacts/security/gitleaks-files.sarif \
    --redact --verbose || failed=1
  return "$failed"
}

sast() {
  prepare
  cp "$SEMGREP_CONFIG" "$REPORT_DIR/.semgrep.yml"
  docker_run_online "semgrep/semgrep:${SEMGREP_VERSION}" semgrep scan \
    --config=p/default --config=/src/artifacts/security/.semgrep.yml \
    --error --metrics=off --no-git-ignore \
    --exclude=.git --exclude=artifacts \
    --sarif --output=/src/artifacts/security/semgrep.sarif /src
}

dependencies() {
  prepare
  docker_run_online "ghcr.io/google/osv-scanner:v${OSV_SCANNER_VERSION}" scan source \
    --recursive --allow-no-lockfiles \
    --format json --output /src/artifacts/security/osv.json /src
}

filesystem() {
  prepare
  docker run --rm \
    --security-opt=no-new-privileges --cap-drop=ALL \
    -v santet-trivy-cache:/root/.cache/trivy \
    -v "$ROOT_DIR:/src" -w /src \
    "aquasec/trivy:${TRIVY_VERSION}" filesystem \
    --scanners vuln,misconfig,secret --severity "$TRIVY_SEVERITY" \
    --exit-code "$TRIVY_EXIT_CODE" --format sarif \
    --skip-dirs /src/.git --skip-dirs /src/artifacts \
    --output /src/artifacts/security/trivy-filesystem.sarif /src
}

sbom() {
  prepare
  source_name=${PROJECT_NAME:-$(basename "$ROOT_DIR")}
  source_version=${PROJECT_VERSION:-$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || printf 'unknown')}
  docker run --rm --network=none \
    --security-opt=no-new-privileges --cap-drop=ALL \
    -e SYFT_CHECK_FOR_APP_UPDATE=false \
    -v "$ROOT_DIR:/src" -w /src \
    "anchore/syft:v${SYFT_VERSION}" scan dir:/src \
    --source-name "$source_name" --source-version "$source_version" \
    --exclude './.git' --exclude './artifacts' \
    -o cyclonedx-json=/src/artifacts/security/sbom.cdx.json \
    -o spdx-json=/src/artifacts/security/sbom.spdx.json
}

kube_lint() {
  prepare
  cp "$KUBELINTER_CONFIG" "$REPORT_DIR/.kube-linter.yaml"
  set --

  if [ -n "${K8S_PATHS:-}" ]; then
    for candidate in $K8S_PATHS; do
      if [ ! -e "$ROOT_DIR/$candidate" ]; then
        echo "Kubernetes path does not exist: $candidate" >&2
        return 2
      fi
      set -- "$@" "/src/$candidate"
    done
  else
    for candidate in k8s kubernetes manifests deploy charts; do
      if [ -e "$ROOT_DIR/$candidate" ]; then
        set -- "$@" "/src/$candidate"
      fi
    done
  fi

  if [ "$#" -eq 0 ]; then
    echo "skip: no Kubernetes manifests or charts found"
    return 0
  fi

  docker_run_offline "$KUBELINTER_IMAGE" lint \
    "$@" --config /src/artifacts/security/.kube-linter.yaml \
    --format json --output /src/artifacts/security/kube-linter.json
}

cluster_doctor() {
  failed=0
  echo "Santet DevSecOps ${SANTET_VERSION}"
  echo "approved versions: KubeHound ${KUBEHOUND_VERSION}, karmor CLI ${KARMOR_CLIENT_VERSION}"
  for command_name in docker kubectl helm karmor kubehound; do
    if command -v "$command_name" >/dev/null 2>&1; then
      echo "ok: $command_name"
    else
      echo "missing: $command_name" >&2
      failed=1
    fi
  done

  if command -v docker >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
    echo "missing: Docker Compose v2" >&2
    failed=1
  fi

  if command -v kubectl >/dev/null 2>&1; then
    context=$(kubectl config current-context 2>/dev/null || true)
    if [ -n "$context" ]; then
      echo "kubernetes context: $context"
    else
      echo "missing: active Kubernetes context" >&2
      failed=1
    fi
  fi

  if command -v kubehound >/dev/null 2>&1; then
    actual_kubehound=$(kubehound version 2>/dev/null | sed -n 's/.*v\([0-9][^ ]*\).*/\1/p')
    if [ "$actual_kubehound" != "$KUBEHOUND_VERSION" ]; then
      echo "version mismatch: kubehound=${actual_kubehound:-unknown}, expected=$KUBEHOUND_VERSION" >&2
      failed=1
    fi
  fi

  if command -v karmor >/dev/null 2>&1; then
    actual_karmor=$(karmor version 2>/dev/null | sed -n 's/^karmor version \([^ ]*\).*/\1/p')
    if [ "$actual_karmor" != "$KARMOR_CLIENT_VERSION" ]; then
      echo "version mismatch: karmor=${actual_karmor:-unknown}, expected=$KARMOR_CLIENT_VERSION" >&2
      failed=1
    fi
  fi
  return "$failed"
}

require_cluster_context() {
  command -v kubectl >/dev/null 2>&1 || {
    echo "missing: kubectl" >&2
    return 2
  }
  if [ -z "${SANTET_CONTEXT:-}" ]; then
    echo "Set SANTET_CONTEXT to the exact Kubernetes context you intend to assess." >&2
    echo "Current context: $(kubectl config current-context 2>/dev/null || echo unavailable)" >&2
    return 2
  fi
  active_context=$(kubectl config current-context 2>/dev/null || true)
  if [ "$active_context" != "$SANTET_CONTEXT" ]; then
    echo "Context mismatch: active='$active_context', requested='$SANTET_CONTEXT'." >&2
    return 2
  fi
}

require_cluster_read() {
  require_cluster_context
  if [ "${ALLOW_CLUSTER_READ:-}" != "true" ]; then
    echo "Refusing to access a live cluster without ALLOW_CLUSTER_READ=true." >&2
    return 2
  fi
}

require_cluster_write() {
  require_cluster_context
  if [ "${ALLOW_CLUSTER_WRITE:-}" != "true" ]; then
    echo "Refusing to modify a live cluster without ALLOW_CLUSTER_WRITE=true." >&2
    return 2
  fi
}

kubearmor_probe() {
  require_cluster_read
  command -v karmor >/dev/null 2>&1 || {
    echo "missing: karmor CLI" >&2
    return 2
  }
  karmor --context "$SANTET_CONTEXT" probe
}

kubearmor_policy_check() {
  require_cluster_read
  kubectl --context "$SANTET_CONTEXT" apply --dry-run=server -f "$KUBEARMOR_CONFIG"
  kubectl --context "$SANTET_CONTEXT" apply --dry-run=server -f "$KUBEARMOR_POLICY"
}

require_supported_kubearmor_platform() {
  node_platforms=$(kubectl --context "$SANTET_CONTEXT" get nodes \
    -o jsonpath='{range .items[*]}{.status.nodeInfo.osImage}{"\n"}{end}')
  if printf '%s\n' "$node_platforms" | grep -Eiq 'docker desktop|linuxkit'; then
    echo "Refusing KubeArmor installation: Docker Desktop/LinuxKit is not a supported enforcement platform." >&2
    echo "Use a supported Linux cluster and run 'make kubearmor-probe' after installation." >&2
    return 2
  fi
}

kubearmor_render() {
  command -v helm >/dev/null 2>&1 || {
    echo "missing: helm" >&2
    return 2
  }
  prepare
  helm template kubearmor-operator kubearmor/kubearmor-operator \
    --version "$KUBEARMOR_CHART_VERSION" --namespace kubearmor \
    --values "$KUBEARMOR_VALUES" > "$REPORT_DIR/kubearmor-rendered.yaml"
  echo "Rendered: $REPORT_DIR/kubearmor-rendered.yaml"
}

kubearmor_install() {
  require_cluster_write
  require_supported_kubearmor_platform
  command -v helm >/dev/null 2>&1 || {
    echo "missing: helm" >&2
    return 2
  }
  helm upgrade --install kubearmor-operator kubearmor/kubearmor-operator \
    --version "$KUBEARMOR_CHART_VERSION" --namespace kubearmor \
    --create-namespace --values "$KUBEARMOR_VALUES" --atomic --wait \
    --timeout 10m --kube-context "$SANTET_CONTEXT"
  kubectl --context "$SANTET_CONTEXT" apply -f "$KUBEARMOR_CONFIG"
}

kubearmor_status() {
  require_cluster_read
  kubectl --context "$SANTET_CONTEXT" -n kubearmor get \
    kubearmorconfig,daemonset,deployment,pod
  not_ready=$(kubectl --context "$SANTET_CONTEXT" -n kubearmor get daemonset \
    -o go-template='{{range .items}}{{if ne .status.desiredNumberScheduled .status.numberReady}}{{printf "%s desired=%d ready=%d\n" .metadata.name .status.desiredNumberScheduled .status.numberReady}}{{end}}{{end}}')
  if [ -n "$not_ready" ]; then
    echo "unhealthy: KubeArmor DaemonSet readiness check failed:" >&2
    printf '%s\n' "$not_ready" >&2
    return 1
  fi
  echo "healthy: all scheduled KubeArmor DaemonSets are ready"
}

kubearmor_policy_apply() {
  require_cluster_write
  kubectl --context "$SANTET_CONTEXT" apply -f "$KUBEARMOR_POLICY"
}

kubehound_scan() {
  require_cluster_read
  command -v kubehound >/dev/null 2>&1 || {
    echo "missing: kubehound CLI" >&2
    return 2
  }
  echo "KubeHound will read the active cluster and start a local analysis backend."
  kubehound --config "$KUBEHOUND_CONFIG"
}

kubehound_dump() {
  require_cluster_read
  command -v kubehound >/dev/null 2>&1 || {
    echo "missing: kubehound CLI" >&2
    return 2
  }
  dump_dir="$ROOT_DIR/artifacts/kubehound"
  mkdir -p "$dump_dir"
  kubehound --config "$KUBEHOUND_CONFIG" dump local "$dump_dir"
  echo "Sensitive cluster dump written under: $dump_dir"
}

image_scan() {
  prepare
  if [ -z "${IMAGE:-}" ]; then
    echo "IMAGE is required, for example: IMAGE=app:local make image-scan" >&2
    exit 2
  fi
  docker run --rm --security-opt=no-new-privileges --cap-drop=ALL \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v santet-trivy-cache:/root/.cache/trivy \
    -v "$REPORT_DIR:/reports" \
    "aquasec/trivy:${TRIVY_VERSION}" image \
    --severity "$TRIVY_SEVERITY" --exit-code "$TRIVY_EXIT_CODE" \
    --format sarif --output /reports/trivy-image.sarif "$IMAGE"
  docker run --rm --security-opt=no-new-privileges --cap-drop=ALL \
    -e SYFT_CHECK_FOR_APP_UPDATE=false \
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
  kube_lint
  sbom
}

clean() {
  if [ -d "$REPORT_DIR" ]; then
    rm -rf "$REPORT_DIR"
  fi
}

help() {
  sed -n '/^## Commands$/,/^## /p' "$TOOL_DIR/README.md" | sed '$d'
}

case "${1:-help}" in
  doctor) doctor ;;
  secrets) secrets ;;
  sast) sast ;;
  dependencies) dependencies ;;
  filesystem) filesystem ;;
  sbom) sbom ;;
  kube-lint) kube_lint ;;
  cluster-doctor) cluster_doctor ;;
  kubearmor-probe) kubearmor_probe ;;
  kubearmor-policy-check) kubearmor_policy_check ;;
  kubearmor-render) kubearmor_render ;;
  kubearmor-install) kubearmor_install ;;
  kubearmor-status) kubearmor_status ;;
  kubearmor-policy-apply) kubearmor_policy_apply ;;
  kubehound) kubehound_scan ;;
  kubehound-dump) kubehound_dump ;;
  image-scan) image_scan ;;
  scan) scan ;;
  clean) clean ;;
  help|-h|--help) help ;;
  *) echo "Unknown command: $1" >&2; help; exit 2 ;;
esac
