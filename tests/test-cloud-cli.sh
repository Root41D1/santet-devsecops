#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/santet-cloud-test.XXXXXX")
trap 'rm -rf "$TEST_TMP"' EXIT HUP INT TERM

mkdir -p "$TEST_TMP/credentials"
export PATH="$ROOT_DIR/tests/fixtures:$PATH"
export SANTET_TEST_DOCKER_LOG="$TEST_TMP/docker-arguments"
export SANTET_CLOUD_CREDENTIAL_DIR="$TEST_TMP/credentials"

assert_argument() {
  expected=$1
  grep -Fx -- "$expected" "$SANTET_TEST_DOCKER_LOG" >/dev/null || {
    echo "missing Docker argument: $expected" >&2
    exit 1
  }
}

assert_absent() {
  forbidden=$1
  if grep -Fx -- "$forbidden" "$SANTET_TEST_DOCKER_LOG" >/dev/null; then
    echo "forbidden Docker argument: $forbidden" >&2
    exit 1
  fi
}

SANTET_CLOUD_TARGET=prod \
SANTET_CLOUD_REGIONS="ap-southeast-1 us-east-1" \
SANTET_AWS_ROLE_ARN=arn:aws:iam::123456789012:role/SantetAuditRole \
  "$ROOT_DIR/santet" cloud-scan aws
assert_argument --read-only
assert_argument aws
assert_argument --severity
assert_argument critical
assert_argument high
assert_argument --role
assert_argument arn:aws:iam::123456789012:role/SantetAuditRole
assert_argument --region
assert_absent --fixer

SANTET_CLOUD_TARGET=prod \
SANTET_AZURE_AUTH=sp \
SANTET_AZURE_SUBSCRIPTION_IDS="sub-one sub-two" \
SANTET_AZURE_REGION=southeastasia \
AZURE_CLIENT_ID=test-client \
AZURE_TENANT_ID=test-tenant \
AZURE_CLIENT_SECRET=test-only-placeholder \
  "$ROOT_DIR/santet" cloud-scan azure
assert_argument azure
assert_argument --sp-env-auth
assert_argument --subscription-id
assert_argument sub-one
assert_argument --azure-region

SANTET_CLOUD_TARGET=prod \
SANTET_GCP_ORGANIZATION_ID=123456789 \
SANTET_GCP_PROJECT_IDS="project-one project-two" \
  "$ROOT_DIR/santet" cloud-inventory gcp
assert_argument gcp
assert_argument --organization-id
assert_argument --project-id
assert_argument --ignore-exit-code-3

SANTET_CLOUD_TARGET=prod \
SANTET_CLOUD_REGIONS=ap-southeast-5 \
SANTET_ALIBABA_ROLE_ARN=acs:ram::123456789012:role/SantetAuditRole \
  "$ROOT_DIR/santet" cloud-scan alibabacloud
assert_argument alibabacloud
assert_argument --role-arn
assert_argument --region

if SANTET_CLOUD_TARGET=../escape "$ROOT_DIR/santet" cloud-scan aws >/dev/null 2>&1; then
  echo "unsafe target label was accepted" >&2
  exit 1
fi

if SANTET_AZURE_AUTH=managed "$ROOT_DIR/santet" cloud-scan azure >/dev/null 2>&1; then
  echo "metadata identity was accepted without explicit opt-in" >&2
  exit 1
fi

if SANTET_CLOUD_REGIONS=us-central1 "$ROOT_DIR/santet" cloud-scan gcp >/dev/null 2>&1; then
  echo "ambiguous GCP region scope was accepted" >&2
  exit 1
fi

if "$ROOT_DIR/santet" cloud-scan unknown >/dev/null 2>&1; then
  echo "unknown provider was accepted" >&2
  exit 1
fi

echo "ok: multi-cloud CLI safety contract"
