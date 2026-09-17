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
CLOUD_GUIDE=$(resolve_config docs/MULTICLOUD.md)

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

cloud_validate_provider() {
  case "${1:-}" in
    aws|azure|gcp|alibabacloud) ;;
    *)
      echo "Unsupported cloud provider: ${1:-missing}" >&2
      echo "Supported providers: aws, azure, gcp, alibabacloud" >&2
      return 2
      ;;
  esac
}

cloud_validate_token() {
  token_name=$1
  token_value=$2
  case "$token_value" in
    ''|*[!A-Za-z0-9._:/=@,+-]*)
      echo "Invalid $token_name value: use only identifiers, ARNs, paths, or region names." >&2
      return 2
      ;;
  esac
}

cloud_validate_label() {
  label_name=$1
  label_value=$2
  case "$label_value" in
    ''|.|..|*[!A-Za-z0-9._-]*)
      echo "Invalid $label_name value: use a simple name containing letters, numbers, dot, underscore, or dash." >&2
      return 2
      ;;
  esac
}

cloud_validate_list() {
  list_name=$1
  list_value=$2
  for list_item in $list_value; do
    cloud_validate_token "$list_name" "$list_item"
  done
}

cloud_validate() {
  failed=0
  echo "Santet DevSecOps ${SANTET_VERSION} multi-cloud policy"
  echo "Prowler upstream ${PROWLER_VERSION}@${PROWLER_DIGEST}"
  echo "runtime: ${SANTET_PROWLER_IMAGE:-$PROWLER_RUNTIME_IMAGE}"
  echo "blocking severities: ${CLOUD_GATE_SEVERITIES}"
  case "$PROWLER_DIGEST" in
    sha256:????????????????????????????????????????????????????????????????) ;;
    *) echo "invalid: PROWLER_DIGEST must be a complete sha256 digest" >&2; failed=1 ;;
  esac
  [ -f "$CLOUD_GUIDE" ] || {
    echo "missing: $CLOUD_GUIDE" >&2
    failed=1
  }
  return "$failed"
}

cloud_auth_ready() {
  provider=$1
  host_home=${SANTET_HOST_HOME:-${HOME:-}}
  credential_dir=${SANTET_CLOUD_CREDENTIAL_DIR:-}
  if [ -n "$credential_dir" ]; then
    if [ "$provider" != azure ]; then
      return 0
    fi
    if [ "${SANTET_AZURE_AUTH:-sp}" = cli ]; then
      return 0
    fi
  fi

  case "$provider" in
    aws)
      if [ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ]; then
        return 0
      fi
      if [ -n "${AWS_WEB_IDENTITY_TOKEN_FILE:-}" ] && [ -n "${AWS_ROLE_ARN:-}" ]; then
        return 0
      fi
      if [ -n "${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:-}${AWS_CONTAINER_CREDENTIALS_FULL_URI:-}" ]; then
        return 0
      fi
      [ "${SANTET_CLOUD_ALLOW_METADATA:-false}" = "true" ] && return 0
      [ -n "$host_home" ] && [ -d "$host_home/.aws" ]
      ;;
    azure)
      case "${SANTET_AZURE_AUTH:-sp}" in
        sp)
          [ -n "${AZURE_CLIENT_ID:-}" ] && [ -n "${AZURE_TENANT_ID:-}" ] && \
            { [ -n "${AZURE_CLIENT_SECRET:-}" ] || [ -n "${AZURE_CLIENT_CERTIFICATE_PATH:-}" ]; }
          ;;
        cli) [ -n "$host_home" ] && [ -d "$host_home/.azure" ] ;;
        managed) [ "${SANTET_CLOUD_ALLOW_METADATA:-false}" = "true" ] ;;
        *) return 1 ;;
      esac
      ;;
    gcp)
      if [ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]; then
        return 0
      fi
      [ "${SANTET_CLOUD_ALLOW_METADATA:-false}" = "true" ] && return 0
      [ -n "$host_home" ] && [ -d "$host_home/.config/gcloud" ]
      ;;
    alibabacloud)
      if [ -n "${ALIBABA_CLOUD_ACCESS_KEY_ID:-}" ] && [ -n "${ALIBABA_CLOUD_ACCESS_KEY_SECRET:-}" ]; then
        return 0
      fi
      if [ -n "${ALIBABA_CLOUD_OIDC_TOKEN_FILE:-}" ] && [ -n "${ALIBABA_CLOUD_OIDC_PROVIDER_ARN:-}" ] && \
        [ -n "${SANTET_ALIBABA_OIDC_ROLE_ARN:-}${ALIBABA_CLOUD_ROLE_ARN:-}" ]; then
        return 0
      fi
      if [ -n "${ALIBABA_CLOUD_CREDENTIALS_URI:-}" ]; then
        return 0
      fi
      if [ "${SANTET_CLOUD_ALLOW_METADATA:-false}" = "true" ] && \
        [ -n "${SANTET_ALIBABA_ECS_RAM_ROLE:-}${ALIBABA_CLOUD_ECS_METADATA:-}" ]; then
        return 0
      fi
      [ -n "$host_home" ] && [ -d "$host_home/.aliyun" ]
      ;;
  esac
}

cloud_doctor_provider() {
  provider=$1
  if cloud_auth_ready "$provider"; then
    echo "ok: $provider credential source detected"
    return 0
  fi
  echo "missing: $provider credential source" >&2
  return 1
}

cloud_doctor() {
  cloud_validate
  command -v docker >/dev/null 2>&1 || {
    echo "missing: docker" >&2
    return 1
  }
  docker info >/dev/null 2>&1 || {
    echo "unavailable: Docker daemon is not running or is inaccessible" >&2
    return 1
  }
  prowler_image=${SANTET_PROWLER_IMAGE:-$PROWLER_RUNTIME_IMAGE}
  if docker image inspect "$prowler_image" >/dev/null 2>&1; then
    echo "ok: Prowler image is cached"
  else
    echo "info: Prowler image is not cached; the first cloud command will download it"
  fi

  requested_provider=${1:-all}
  failed=0
  case "$requested_provider" in
    all)
      for provider in aws azure gcp alibabacloud; do
        cloud_doctor_provider "$provider" || failed=1
      done
      ;;
    *)
      cloud_validate_provider "$requested_provider"
      cloud_doctor_provider "$requested_provider" || failed=1
      ;;
  esac
  return "$failed"
}

cloud_mount_file() {
  file_label=$1
  file_path=$2
  [ -z "$file_path" ] && return 0
  case "$file_path" in
    /*) ;;
    *) echo "$file_label must be an absolute path: $file_path" >&2; return 2 ;;
  esac
  if [ "${SANTET_DOCKER_WRAPPER:-false}" != "true" ] && [ ! -f "$file_path" ]; then
    echo "$file_label does not exist: $file_path" >&2
    return 2
  fi
}

cloud_scan_provider() {
  provider=$1
  scan_mode=$2
  cloud_validate_provider "$provider"
  cloud_auth_ready "$provider" || {
    echo "No credential source detected for $provider. Run './santet cloud-doctor $provider'." >&2
    return 2
  }

  target=${SANTET_CLOUD_TARGET:-default}
  cloud_validate_label SANTET_CLOUD_TARGET "$target"
  cloud_validate_list SANTET_CLOUD_REGIONS "${SANTET_CLOUD_REGIONS:-}"
  cloud_validate_list SANTET_CLOUD_SERVICES "${SANTET_CLOUD_SERVICES:-}"
  cloud_validate_list SANTET_CLOUD_CHECKS "${SANTET_CLOUD_CHECKS:-}"
  cloud_validate_list SANTET_CLOUD_COMPLIANCE "${SANTET_CLOUD_COMPLIANCE:-}"
  if [ -n "${SANTET_CLOUD_REGIONS:-}" ]; then
    case "$provider" in
      aws|alibabacloud) ;;
      azure)
        echo "Use SANTET_AZURE_REGION instead of SANTET_CLOUD_REGIONS for Azure." >&2
        return 2
        ;;
      gcp)
        echo "GCP assessment is scoped by organization/project, not SANTET_CLOUD_REGIONS." >&2
        return 2
        ;;
    esac
  fi

  output_dir="$REPORT_DIR/cloud/$provider/$target"
  mkdir -p "$output_dir"
  chmod 1777 "$REPORT_DIR" "$REPORT_DIR/cloud" "$REPORT_DIR/cloud/$provider" "$output_dir"

  prowler_image=${SANTET_PROWLER_IMAGE:-$PROWLER_RUNTIME_IMAGE}
  set -- docker run --rm --init \
    --security-opt=no-new-privileges --cap-drop=ALL --read-only \
    --pids-limit=512 \
    --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=512m \
    --tmpfs /home/prowler/.cache:rw,nosuid,nodev,mode=1777,size=256m \
    --label org.santet-devsecops.component=cloud-assessment \
    -v "$ROOT_DIR:/src:ro" -v "$output_dir:/output" \
    -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
    -e AWS_PROFILE -e AWS_REGION -e AWS_DEFAULT_REGION -e AWS_ROLE_ARN \
    -e AWS_WEB_IDENTITY_TOKEN_FILE -e AWS_ROLE_SESSION_NAME \
    -e AWS_CONTAINER_CREDENTIALS_RELATIVE_URI -e AWS_CONTAINER_CREDENTIALS_FULL_URI \
    -e AWS_CONTAINER_AUTHORIZATION_TOKEN -e AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE \
    -e AZURE_CLIENT_ID -e AZURE_TENANT_ID -e AZURE_CLIENT_SECRET \
    -e AZURE_FEDERATED_TOKEN_FILE -e AZURE_CLIENT_CERTIFICATE_PATH \
    -e AZURE_CLIENT_CERTIFICATE_PASSWORD -e IDENTITY_ENDPOINT -e IDENTITY_HEADER \
    -e MSI_ENDPOINT -e MSI_SECRET \
    -e GOOGLE_APPLICATION_CREDENTIALS -e GOOGLE_IMPERSONATE_SERVICE_ACCOUNT \
    -e CLOUDSDK_AUTH_ACCESS_TOKEN \
    -e ALIBABA_CLOUD_ACCESS_KEY_ID -e ALIBABA_CLOUD_ACCESS_KEY_SECRET \
    -e ALIBABA_CLOUD_SECURITY_TOKEN -e ALIBABA_CLOUD_ROLE_ARN \
    -e ALIBABA_CLOUD_OIDC_PROVIDER_ARN -e ALIBABA_CLOUD_OIDC_TOKEN_FILE \
    -e ALIBABA_CLOUD_ECS_METADATA -e ALIBABA_CLOUD_CREDENTIALS_URI

  credential_dir=${SANTET_CLOUD_CREDENTIAL_DIR:-}
  host_home=${SANTET_HOST_HOME:-${HOME:-}}
  if [ -n "$credential_dir" ]; then
    case "$credential_dir" in /*) ;; *) echo "SANTET_CLOUD_CREDENTIAL_DIR must be absolute" >&2; return 2 ;; esac
    if [ "${SANTET_DOCKER_WRAPPER:-false}" != "true" ] && [ ! -d "$credential_dir" ]; then
      echo "Credential directory does not exist: $credential_dir" >&2
      return 2
    fi
  else
    case "$provider" in
      aws) credential_dir=${host_home:+$host_home/.aws} ;;
      azure) credential_dir=${host_home:+$host_home/.azure} ;;
      gcp) credential_dir=${host_home:+$host_home/.config/gcloud} ;;
      alibabacloud) credential_dir=${host_home:+$host_home/.aliyun} ;;
    esac
    [ -d "$credential_dir" ] || credential_dir=
  fi

  if [ -n "$credential_dir" ]; then
    case "$provider" in
      aws) set -- "$@" -v "$credential_dir:/home/prowler/.aws:ro" ;;
      azure) set -- "$@" -v "$credential_dir:/home/prowler/.azure:ro" ;;
      gcp) set -- "$@" -v "$credential_dir:/home/prowler/.config/gcloud:ro" ;;
      alibabacloud) set -- "$@" -v "$credential_dir:/home/prowler/.aliyun:ro" ;;
    esac
  fi

  cloud_mount_file AWS_WEB_IDENTITY_TOKEN_FILE "${AWS_WEB_IDENTITY_TOKEN_FILE:-}"
  cloud_mount_file AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE "${AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE:-}"
  cloud_mount_file AZURE_FEDERATED_TOKEN_FILE "${AZURE_FEDERATED_TOKEN_FILE:-}"
  cloud_mount_file AZURE_CLIENT_CERTIFICATE_PATH "${AZURE_CLIENT_CERTIFICATE_PATH:-}"
  cloud_mount_file GOOGLE_APPLICATION_CREDENTIALS "${GOOGLE_APPLICATION_CREDENTIALS:-}"
  cloud_mount_file ALIBABA_CLOUD_OIDC_TOKEN_FILE "${ALIBABA_CLOUD_OIDC_TOKEN_FILE:-}"
  for credential_file in \
    "${AWS_WEB_IDENTITY_TOKEN_FILE:-}" \
    "${AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE:-}" \
    "${AZURE_FEDERATED_TOKEN_FILE:-}" \
    "${AZURE_CLIENT_CERTIFICATE_PATH:-}" \
    "${GOOGLE_APPLICATION_CREDENTIALS:-}" \
    "${ALIBABA_CLOUD_OIDC_TOKEN_FILE:-}"; do
    [ -n "$credential_file" ] && set -- "$@" -v "$credential_file:$credential_file:ro"
  done

  set -- "$@" "$prowler_image" "$provider" \
    --no-banner --no-color \
    --output-directory /output \
    --output-filename "santet-$provider-$target" \
    --output-formats csv json-ocsf html sarif

  if [ "$scan_mode" = inventory ]; then
    set -- "$@" --ignore-exit-code-3
  else
    severities=${SANTET_CLOUD_SEVERITIES:-$CLOUD_GATE_SEVERITIES}
    cloud_validate_list SANTET_CLOUD_SEVERITIES "$severities"
    set -- "$@" --severity
    for severity in $severities; do
      case "$severity" in critical|high|medium|low|informational) ;; *) echo "Invalid cloud severity: $severity" >&2; return 2 ;; esac
      set -- "$@" "$severity"
    done
  fi

  if [ -n "${SANTET_CLOUD_SERVICES:-}" ]; then
    set -- "$@" --service
    for service in $SANTET_CLOUD_SERVICES; do set -- "$@" "$service"; done
  fi
  if [ -n "${SANTET_CLOUD_CHECKS:-}" ]; then
    set -- "$@" --check
    for check in $SANTET_CLOUD_CHECKS; do set -- "$@" "$check"; done
  fi
  if [ -n "${SANTET_CLOUD_COMPLIANCE:-}" ]; then
    set -- "$@" --compliance
    for framework in $SANTET_CLOUD_COMPLIANCE; do set -- "$@" "$framework"; done
  fi

  case "$provider" in
    aws)
      if [ -n "${SANTET_CLOUD_REGIONS:-}" ]; then
        set -- "$@" --region
        for region in $SANTET_CLOUD_REGIONS; do set -- "$@" "$region"; done
      fi
      [ -n "${SANTET_AWS_PROFILE:-}" ] && set -- "$@" --profile "$SANTET_AWS_PROFILE"
      [ -n "${SANTET_AWS_ROLE_ARN:-}" ] && set -- "$@" --role "$SANTET_AWS_ROLE_ARN"
      [ -n "${SANTET_AWS_EXTERNAL_ID:-}" ] && set -- "$@" --external-id "$SANTET_AWS_EXTERNAL_ID"
      ;;
    azure)
      case "${SANTET_AZURE_AUTH:-sp}" in
        sp) set -- "$@" --sp-env-auth ;;
        cli) set -- "$@" --az-cli-auth ;;
        managed)
          [ "${SANTET_CLOUD_ALLOW_METADATA:-false}" = "true" ] || {
            echo "Azure managed identity requires SANTET_CLOUD_ALLOW_METADATA=true." >&2
            return 2
          }
          set -- "$@" --managed-identity-auth
          ;;
        *) echo "SANTET_AZURE_AUTH must be sp, cli, or managed" >&2; return 2 ;;
      esac
      [ -n "${SANTET_AZURE_SUBSCRIPTION_IDS:-}" ] && {
        cloud_validate_list SANTET_AZURE_SUBSCRIPTION_IDS "$SANTET_AZURE_SUBSCRIPTION_IDS"
        set -- "$@" --subscription-id
        for subscription_id in $SANTET_AZURE_SUBSCRIPTION_IDS; do set -- "$@" "$subscription_id"; done
      }
      [ -n "${SANTET_AZURE_REGION:-}" ] && {
        cloud_validate_token SANTET_AZURE_REGION "$SANTET_AZURE_REGION"
        set -- "$@" --azure-region "$SANTET_AZURE_REGION"
      }
      ;;
    gcp)
      [ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] && set -- "$@" --credentials-file "$GOOGLE_APPLICATION_CREDENTIALS"
      [ -n "${GOOGLE_IMPERSONATE_SERVICE_ACCOUNT:-}" ] && set -- "$@" --impersonate-service-account "$GOOGLE_IMPERSONATE_SERVICE_ACCOUNT"
      [ -n "${SANTET_GCP_ORGANIZATION_ID:-}" ] && set -- "$@" --organization-id "$SANTET_GCP_ORGANIZATION_ID"
      [ -n "${SANTET_GCP_PROJECT_IDS:-}" ] && {
        cloud_validate_list SANTET_GCP_PROJECT_IDS "$SANTET_GCP_PROJECT_IDS"
        set -- "$@" --project-id
        for project_id in $SANTET_GCP_PROJECT_IDS; do set -- "$@" "$project_id"; done
      }
      ;;
    alibabacloud)
      if [ -n "${SANTET_CLOUD_REGIONS:-}" ]; then
        set -- "$@" --region
        for region in $SANTET_CLOUD_REGIONS; do set -- "$@" "$region"; done
      fi
      [ -n "${SANTET_ALIBABA_ROLE_ARN:-}" ] && set -- "$@" --role-arn "$SANTET_ALIBABA_ROLE_ARN"
      [ -n "${SANTET_ALIBABA_OIDC_ROLE_ARN:-}" ] && set -- "$@" --oidc-role-arn "$SANTET_ALIBABA_OIDC_ROLE_ARN"
      [ -n "${SANTET_ALIBABA_ECS_RAM_ROLE:-}" ] && {
        [ "${SANTET_CLOUD_ALLOW_METADATA:-false}" = "true" ] || {
          echo "Alibaba ECS RAM role requires SANTET_CLOUD_ALLOW_METADATA=true." >&2
          return 2
        }
        set -- "$@" --ecs-ram-role "$SANTET_ALIBABA_ECS_RAM_ROLE"
      }
      ;;
  esac

  echo "Santet $scan_mode: provider=$provider target=$target evidence=$output_dir"
  "$@"
}

cloud_scan_all() {
  scan_mode=$1
  failed=0
  for provider in aws azure gcp alibabacloud; do
    cloud_scan_provider "$provider" "$scan_mode" || failed=1
  done
  return "$failed"
}

cloud_list() {
  provider=${1:-}
  list_type=${2:-checks}
  cloud_validate_provider "$provider"
  case "$list_type" in
    checks) list_flag=--list-checks ;;
    services) list_flag=--list-services ;;
    compliance) list_flag=--list-compliance ;;
    categories) list_flag=--list-categories ;;
    *) echo "List type must be checks, services, compliance, or categories" >&2; return 2 ;;
  esac
  docker run --rm --network=none --read-only \
    --security-opt=no-new-privileges --cap-drop=ALL --pids-limit=256 \
    --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=256m \
    "${SANTET_PROWLER_IMAGE:-$PROWLER_RUNTIME_IMAGE}" \
    "$provider" --no-banner --no-color "$list_flag"
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
  cloud-validate) cloud_validate ;;
  cloud-doctor) cloud_doctor "${2:-all}" ;;
  cloud-scan)
    if [ "${2:-}" = all ]; then cloud_scan_all gate; else cloud_scan_provider "${2:-}" gate; fi
    ;;
  cloud-inventory)
    if [ "${2:-}" = all ]; then cloud_scan_all inventory; else cloud_scan_provider "${2:-}" inventory; fi
    ;;
  cloud-list) cloud_list "${2:-}" "${3:-checks}" ;;
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
