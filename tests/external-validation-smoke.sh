#!/usr/bin/env bash
# Network-free smoke tests for the external-validation environment contract.
# This script uses placeholders only; it must never be changed to contain a
# provider credential or a production hostname.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runner="$repo_root/tests/external-validation.sh"
workflow="$repo_root/.github/workflows/external-validation.yml"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/certmagic-validation-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

test -f "$workflow"
grep -Fq 'workflow_dispatch:' "$workflow"
grep -Fq 'environment:' "$workflow"
grep -Fq 'name: external-validation' "$workflow"
# shellcheck disable=SC2016 # Match the literal GitHub Actions expression.
grep -Fq 'ZEROSSL_API_KEY: ${{ secrets.ZEROSSL_API_KEY }}' "$workflow"
if grep -Eq '^  (push|pull_request|schedule|workflow_call):' "$workflow"; then
  echo "external validation workflow must remain manual-only" >&2
  exit 1
fi

grep -Fq -- "--contract-check MODE" <("$runner" --help)
grep -Fq -- "--print-evidence-template" <("$runner" --help)
grep -Fq -- "--loopback-challenges" <("$runner" --help)

"$runner" --print-evidence-template >"$tmp_dir/evidence.json"
grep -Fq '"schema": "certmagic.external-evidence/v1"' "$tmp_dir/evidence.json"
grep -Fq '"status": "<pass|fail|not-run>"' "$tmp_dir/evidence.json"
if grep -Eq 'ZEROSSL_API_KEY=|I_UNDERSTAND_EXTERNAL_NETWORK' "$tmp_dir/evidence.json"; then
  echo "evidence template contains a credential or confirmation value" >&2
  exit 1
fi
"$runner" --validate-evidence "$tmp_dir/evidence.json" >"$tmp_dir/evidence-valid.out"
grep -Fq 'external evidence validation passed' "$tmp_dir/evidence-valid.out"

# A copied challenge body must be rejected even when the surrounding JSON is
# otherwise schema-valid. This is intentionally generated only in a temporary
# directory and never contains a real key authorization.
sed 's/"expected_body": "not recorded"/"expected_body": "key authorization: test-only-secret"/' \
  "$tmp_dir/evidence.json" >"$tmp_dir/evidence-secret.json"
if "$runner" --validate-evidence "$tmp_dir/evidence-secret.json" \
  >"$tmp_dir/evidence-secret.out" 2>"$tmp_dir/evidence-secret.err"; then
  echo "evidence validator accepted a challenge body" >&2
  exit 1
fi
grep -Fq 'contract.expected_body must remain redacted' "$tmp_dir/evidence-secret.err"

if CERTMAGIC_PUBLIC_HTTP01_URL='https://example.net/.well-known/acme-challenge/token' \
  "$runner" --public-http-01 >"$tmp_dir/refusal.out" 2>"$tmp_dir/refusal.err"; then
  echo "external mode unexpectedly passed without confirmation" >&2
  exit 1
fi
grep -Fq 'CERTMAGIC_EXTERNAL_CONFIRM=I_UNDERSTAND_EXTERNAL_NETWORK' "$tmp_dir/refusal.err"

CERTMAGIC_PUBLIC_HTTP01_URL='https://example.net/.well-known/acme-challenge/token' \
CERTMAGIC_PUBLIC_HTTP01_EXPECTED='token.thumbprint' \
  "$runner" --contract-check public-http-01 >"$tmp_dir/http.out"
grep -Fq 'contract check passed: public-http-01' "$tmp_dir/http.out"

if CERTMAGIC_PUBLIC_HTTP01_URL='http://127.0.0.1/.well-known/acme-challenge/token' \
  CERTMAGIC_PUBLIC_HTTP01_EXPECTED='token.thumbprint' \
  "$runner" --contract-check public-http-01 >"$tmp_dir/private.out" 2>"$tmp_dir/private.err"; then
  echo "contract validator accepted a private HTTP-01 target" >&2
  exit 1
fi
grep -Fq 'public hostname/address' "$tmp_dir/private.err"

if CERTMAGIC_PUBLIC_HTTP01_URL='https://example.net/.well-known/acme-challenge/token' \
  CERTMAGIC_PUBLIC_HTTP01_EXPECTED='token.thumbprint' \
  CERTMAGIC_PUBLIC_HTTP01_TIMEOUT='0' \
  "$runner" --contract-check public-http-01 >"$tmp_dir/timeout.out" 2>"$tmp_dir/timeout.err"; then
  echo "contract validator accepted an invalid HTTP timeout" >&2
  exit 1
fi
grep -Fq 'timeout in whole seconds' "$tmp_dir/timeout.err"

CERTMAGIC_EXTERNAL_DOMAIN='certmagic-smoke.example.net' \
ZEROSSL_API_KEY='placeholder-only' \
CERTMAGIC_EXTERNAL_EMAIL='ops@example.net' \
CERTMAGIC_PUBLIC_HTTP01_URL='https://certmagic-smoke.example.net/.well-known/acme-challenge/token' \
CERTMAGIC_PUBLIC_HTTP01_EXPECTED='token.thumbprint' \
  "$runner" --contract-check zerossl-acme >"$tmp_dir/acme.out"
grep -Fq 'contract check passed: zerossl-acme' "$tmp_dir/acme.out"

CERTMAGIC_EXTERNAL_DOMAIN='certmagic-smoke.example.net' \
ZEROSSL_API_KEY='placeholder-only' \
  "$runner" --contract-check zerossl-rest >"$tmp_dir/rest.out"
grep -Fq 'contract check passed: zerossl-rest' "$tmp_dir/rest.out"

CERTMAGIC_PUBLIC_TLSALPN_HOST='certmagic-smoke.example.net' \
  "$runner" --contract-check public-tls-alpn-01 >"$tmp_dir/alpn.out"
grep -Fq 'contract check passed: public-tls-alpn-01' "$tmp_dir/alpn.out"

CERTMAGIC_DISTRIBUTED_HTTP01_URLS='https://node-a.example.net/.well-known/acme-challenge/token https://node-b.example.net/.well-known/acme-challenge/token' \
CERTMAGIC_PUBLIC_HTTP01_EXPECTED='token.thumbprint' \
  "$runner" --contract-check distributed-http-01 >"$tmp_dir/distributed.out"
grep -Fq 'contract check passed: distributed-http-01' "$tmp_dir/distributed.out"

if CERTMAGIC_DISTRIBUTED_HTTP01_URLS='https://node-a.example.net/.well-known/acme-challenge/token https://node-a.example.net/.well-known/acme-challenge/token' \
  CERTMAGIC_PUBLIC_HTTP01_EXPECTED='token.thumbprint' \
  "$runner" --contract-check distributed-http-01 >"$tmp_dir/duplicate.out" 2>"$tmp_dir/duplicate.err"; then
  echo "contract validator accepted duplicate distributed node URLs" >&2
  exit 1
fi
grep -Fq 'distinct node URLs' "$tmp_dir/duplicate.err"

echo "external validation shell smoke passed (no network or real credentials used)"
