#!/usr/bin/env bash
# A deterministic validation entry point for the boundary between local and
# external ACME validation.
#
# The default mode is deliberately offline. It never starts a network service,
# reads provider credentials, or contacts a CA. Use --pebble explicitly for
# the local Pebble/challtestsrv environment; use --help for the contract.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
  cat <<'USAGE'
Usage: tests/external-validation.sh [MODE]

Modes:
  --offline  Run the reproducible, no-network validation lane (default).
  --pebble   Run the local Pebble/challtestsrv ACME lifecycle. Set
             PEBBLE_CHALLENGE to dns-01 (default), http-01, or tls-alpn-01
             to select the challenge lane. This mode may download Go tools
             when they are not already installed.
  --loopback-challenges
             Exercise the built-in HTTP-01 and TLS-ALPN-01 listeners on
             ephemeral loopback ports; never contacts a CA or public network.
  --zerossl-rest
             Run the opt-in ZeroSSL REST smoke test. Requires an explicit
             confirmation and a disposable domain/API key.
  --zerossl-acme
             Validate the operator contract for ZeroSSL ACME/EAB and public
             challenge routing; does not start a server or contact ZeroSSL.
  --public-http-01
             Fetch an operator-supplied HTTP-01 URL and compare its body.
  --public-tls-alpn-01
             Verify that an operator-supplied endpoint negotiates acme-tls/1.
  --distributed-http-01
             Fetch the same HTTP-01 response through two or more node URLs.
  --contract-check MODE
             Validate MODE's environment contract without network access.
             MODE is one of: zerossl-rest, zerossl-acme, public-http-01,
             public-tls-alpn-01, distributed-http-01.
  --print-evidence-template
             Print the redacted, versioned operator evidence-record template.
  --validate-evidence RECORD.json
             Validate a redacted evidence record offline; reject credentials,
             challenge bodies, private addresses, and schema drift.
  --help     Show this help.

External modes never run by default. They require
CERTMAGIC_EXTERNAL_CONFIRM=I_UNDERSTAND_EXTERNAL_NETWORK. See
docs/04-external-validation.md for each environment variable contract.
USAGE
}

mode="offline"
contract_target=""
evidence_record=""
case "${1:-}" in
  ""|--offline)
    mode="offline"
    ;;
  --pebble)
    mode="pebble"
    ;;
  --loopback-challenges)
    mode="loopback-challenges"
    ;;
  --zerossl-rest)
    mode="zerossl-rest"
    ;;
  --zerossl-acme)
    mode="zerossl-acme"
    ;;
  --public-http-01)
    mode="public-http-01"
    ;;
  --public-tls-alpn-01)
    mode="public-tls-alpn-01"
    ;;
  --distributed-http-01)
    mode="distributed-http-01"
    ;;
  --contract-check)
    if [[ $# -ne 2 ]]; then
      echo "--contract-check requires exactly one MODE" >&2
      exit 2
    fi
    mode="contract-check"
    contract_target="$2"
    ;;
  --print-evidence-template)
    mode="print-evidence-template"
    ;;
  --validate-evidence)
    if [[ $# -ne 2 ]]; then
      echo "--validate-evidence requires exactly one JSON record path" >&2
      exit 2
    fi
    mode="validate-evidence"
    evidence_record="$2"
    ;;
  --help|-h)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

if [[ "$mode" == "pebble" ]]; then
  exec "$repo_root/tests/run-pebble.sh"
fi

require_external_confirmation() {
  if [[ "${CERTMAGIC_EXTERNAL_CONFIRM:-}" != "I_UNDERSTAND_EXTERNAL_NETWORK" ]]; then
    cat >&2 <<'MSG'
Refusing an external validation run without an explicit confirmation.
Set CERTMAGIC_EXTERNAL_CONFIRM=I_UNDERSTAND_EXTERNAL_NETWORK after checking
that the domain, CA account, and cleanup plan are disposable/non-production.
MSG
    exit 2
  fi
}

require_command() {
  command -v "$1" >/dev/null || {
    echo "required command is missing: $1" >&2
    exit 1
  }
}

require_env() {
  local name="$1"
  [[ -n "${!name:-}" ]] || {
    echo "required environment variable is missing: $name" >&2
    exit 2
  }
}

validate_http_url() {
  local name="$1" value="$2"
  if [[ ! "$value" =~ ^https?://[^[:space:][:cntrl:]]+$ \
    || "$value" == *'<'* || "$value" == *'>'* \
    || "$value" == *'@'* || "$value" == *'%40'* ]]; then
    echo "$name must be an absolute HTTP(S) URL without whitespace or control characters" >&2
    exit 2
  fi
}

validate_public_http_url() {
  local name="$1" value="$2"
  validate_http_url "$name" "$value"

  # The manual workflow runs on a hosted runner. Refuse obvious loopback,
  # link-local, RFC1918, CGNAT, IPv6 ULA, and operator-internal hostnames so a
  # typo cannot turn this smoke harness into an SSRF primitive. DNS resolution
  # is intentionally not performed here; public reachability remains an
  # operator responsibility and the CA is the final validator.
  local authority="${value#*://}"
  authority="${authority%%/*}"
  authority="${authority%%\?*}"
  authority="${authority%%#*}"
  if [[ -z "$authority" || "$authority" =~ [^A-Za-z0-9.:[\]-] \
    || "$authority" =~ (^|:)localhost(\.|:|$) \
    || "$authority" =~ (^|:)0\.0\.0\.0(:|$) \
    || "$authority" =~ (^|:)127\.[0-9]+\.[0-9]+\.[0-9]+(:|$) \
    || "$authority" =~ (^|:)169\.254\.[0-9]+\.[0-9]+(:|$) \
    || "$authority" =~ (^|:)10\.[0-9]+\.[0-9]+\.[0-9]+(:|$) \
    || "$authority" =~ (^|:)192\.168\.[0-9]+\.[0-9]+(:|$) \
    || "$authority" =~ (^|:)172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+(:|$) \
    || "$authority" =~ (^|:)100\.(6[4-9]|[7-9][0-9])\.[0-9]+\.[0-9]+(:|$) \
    || "$authority" =~ (^|:)\[(::1|fc[0-9a-fA-F]{2}|fd[0-9a-fA-F]{2}|fe8[0-9a-fA-F]) \
    || "$authority" =~ (^|:)[A-Za-z0-9.-]+\.(local|localhost|internal|lan)(:|$) ]]; then
    echo "$name must target a public hostname/address; private or internal authorities are not allowed" >&2
    exit 2
  fi
}

validate_challenge_url() {
  local name="$1" value="$2"
  validate_http_url "$name" "$value"
  if [[ "$value" != */.well-known/acme-challenge/* ]]; then
    echo "$name must point below /.well-known/acme-challenge/" >&2
    exit 2
  fi
}

validate_expected_body() {
  local name="$1" value="$2"
  if [[ -z "$value" || "$value" =~ [[:cntrl:]] ]]; then
    echo "$name must be non-empty and contain no control characters" >&2
    exit 2
  fi
}

validate_port() {
  local name="$1" value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < 1 || value > 65535 )); then
    echo "$name must be a TCP port between 1 and 65535" >&2
    exit 2
  fi
}

validate_timeout() {
  local name="$1" value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < 1 || value > 300 )); then
    echo "$name must be a timeout in whole seconds between 1 and 300" >&2
    exit 2
  fi
}

validate_domain() {
  local name="$1" value="$2"
  local IFS=.
  local -a labels
  read -r -a labels <<<"$value"
  if [[ "$value" != *.* || ${#value} -gt 253 || "$value" =~ [^A-Za-z0-9.-] \
    || "$value" == .* || "$value" == *. || "$value" == "*."* \
    || "$value" == *..* || "$value" == *.test || "$value" == *.invalid \
    || "$value" == *.example || ${#labels[@]} -lt 2 ]]; then
    echo "$name must be a real, non-wildcard disposable DNS name" >&2
    exit 2
  fi
  local label
  for label in "${labels[@]}"; do
    if [[ -z "$label" || ${#label} -gt 63 \
      || ! "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]]; then
      echo "$name contains an invalid DNS label" >&2
      exit 2
    fi
  done
}

external_domain() {
  require_env CERTMAGIC_EXTERNAL_DOMAIN
  validate_domain CERTMAGIC_EXTERNAL_DOMAIN "$CERTMAGIC_EXTERNAL_DOMAIN"
}

print_evidence_template() {
  # Keep this output deliberately free of environment values. Operators can
  # redirect it into an evidence record and fill it outside the repository.
  cat <<'JSON'
{
  "schema": "certmagic.external-evidence/v1",
  "run": {
    "capability": "<zerossl-rest|zerossl-acme|public-http-01|public-tls-alpn-01|distributed-http-01|dns-01|ocsp>",
    "status": "<pass|fail|not-run>",
    "started_at_utc": "<RFC3339>",
    "finished_at_utc": "<RFC3339>",
    "repository_revision": "<git commit, or redacted>",
    "runner": "<operator-controlled identifier>"
  },
  "subject": {
    "provider": "<CA/provider or local fixture>",
    "endpoint_class": "<disposable non-production>",
    "domain": "<keep outside repository logs>",
    "node_count": "<integer or null>"
  },
  "contract": {
    "confirmation": "not recorded",
    "credential_source": "environment or secret manager; value not recorded",
    "challenge_url": "<keep outside repository logs>",
    "expected_body": "not recorded"
  },
  "evidence": {
    "order_id": "<redacted or provider identifier>",
    "certificate_id": "<redacted or provider identifier>",
    "observations": ["<short, non-secret observation>"]
  },
  "cleanup": {
    "certificate_revoked": "<yes|no|not-applicable|unknown>",
    "temporary_storage_removed": "<yes|no|not-applicable|unknown>",
    "cleanup_status": "<pass|fail|not-run>",
    "notes": "<no API keys, private keys, tokens, challenge bodies, or internal addresses>"
  }
}
JSON
}

run_validate_evidence() {
  require_command python3
  python3 "$repo_root/tests/validate_external_evidence.py" "$evidence_record"
}

run_contract_check() {
  # This branch intentionally does not require confirmation and never invokes
  # curl, openssl, Cargo, or a provider. It is safe for CI and shell smoke.
  case "$contract_target" in
    zerossl-rest)
      external_domain
      require_env ZEROSSL_API_KEY
      ;;
    zerossl-acme)
      external_domain
      require_env ZEROSSL_API_KEY
      require_env CERTMAGIC_EXTERNAL_EMAIL
      require_env CERTMAGIC_PUBLIC_HTTP01_URL
      require_env CERTMAGIC_PUBLIC_HTTP01_EXPECTED
      validate_public_http_url CERTMAGIC_PUBLIC_HTTP01_URL "$CERTMAGIC_PUBLIC_HTTP01_URL"
      validate_challenge_url CERTMAGIC_PUBLIC_HTTP01_URL "$CERTMAGIC_PUBLIC_HTTP01_URL"
      validate_expected_body CERTMAGIC_PUBLIC_HTTP01_EXPECTED "$CERTMAGIC_PUBLIC_HTTP01_EXPECTED"
      ;;
    public-http-01)
      require_env CERTMAGIC_PUBLIC_HTTP01_URL
      require_env CERTMAGIC_PUBLIC_HTTP01_EXPECTED
      validate_public_http_url CERTMAGIC_PUBLIC_HTTP01_URL "$CERTMAGIC_PUBLIC_HTTP01_URL"
      validate_challenge_url CERTMAGIC_PUBLIC_HTTP01_URL "$CERTMAGIC_PUBLIC_HTTP01_URL"
      validate_expected_body CERTMAGIC_PUBLIC_HTTP01_EXPECTED "$CERTMAGIC_PUBLIC_HTTP01_EXPECTED"
      validate_timeout CERTMAGIC_PUBLIC_HTTP01_TIMEOUT "${CERTMAGIC_PUBLIC_HTTP01_TIMEOUT:-15}"
      ;;
    public-tls-alpn-01)
      require_env CERTMAGIC_PUBLIC_TLSALPN_HOST
      validate_domain CERTMAGIC_PUBLIC_TLSALPN_HOST "$CERTMAGIC_PUBLIC_TLSALPN_HOST"
      validate_port CERTMAGIC_PUBLIC_TLSALPN_PORT "${CERTMAGIC_PUBLIC_TLSALPN_PORT:-443}"
      ;;
    distributed-http-01)
      require_env CERTMAGIC_DISTRIBUTED_HTTP01_URLS
      require_env CERTMAGIC_PUBLIC_HTTP01_EXPECTED
      local -a contract_urls
      read -r -a contract_urls <<<"$CERTMAGIC_DISTRIBUTED_HTTP01_URLS"
      if (( ${#contract_urls[@]} < 2 )); then
        echo "CERTMAGIC_DISTRIBUTED_HTTP01_URLS must contain at least two URLs" >&2
        exit 2
      fi
      local contract_url
      for contract_url in "${contract_urls[@]}"; do
        validate_public_http_url CERTMAGIC_DISTRIBUTED_HTTP01_URLS "$contract_url"
        validate_challenge_url CERTMAGIC_DISTRIBUTED_HTTP01_URLS "$contract_url"
      done
      for ((i = 0; i < ${#contract_urls[@]}; i++)); do
        for ((j = 0; j < i; j++)); do
          if [[ "${contract_urls[i]}" == "${contract_urls[j]}" ]]; then
            echo "CERTMAGIC_DISTRIBUTED_HTTP01_URLS must contain distinct node URLs" >&2
            exit 2
          fi
        done
      done
      validate_timeout CERTMAGIC_PUBLIC_HTTP01_TIMEOUT "${CERTMAGIC_PUBLIC_HTTP01_TIMEOUT:-15}"
      validate_expected_body CERTMAGIC_PUBLIC_HTTP01_EXPECTED "$CERTMAGIC_PUBLIC_HTTP01_EXPECTED"
      ;;
    *)
      echo "unsupported contract-check mode: $contract_target" >&2
      exit 2
      ;;
  esac
  echo "contract check passed: $contract_target (no network or credentials used)"
}

run_public_http01() {
  require_external_confirmation
  require_command curl
  require_env CERTMAGIC_PUBLIC_HTTP01_URL
  require_env CERTMAGIC_PUBLIC_HTTP01_EXPECTED
  validate_public_http_url CERTMAGIC_PUBLIC_HTTP01_URL "$CERTMAGIC_PUBLIC_HTTP01_URL"
  validate_expected_body CERTMAGIC_PUBLIC_HTTP01_EXPECTED "$CERTMAGIC_PUBLIC_HTTP01_EXPECTED"
  validate_timeout CERTMAGIC_PUBLIC_HTTP01_TIMEOUT "${CERTMAGIC_PUBLIC_HTTP01_TIMEOUT:-15}"
  local body
  body="$(curl --fail --silent --show-error --noproxy '*' \
    --max-time "${CERTMAGIC_PUBLIC_HTTP01_TIMEOUT:-15}" \
    "$CERTMAGIC_PUBLIC_HTTP01_URL")" || {
    echo "public HTTP-01 request failed" >&2
    exit 1
  }
  if [[ "$body" != "$CERTMAGIC_PUBLIC_HTTP01_EXPECTED" ]]; then
    echo "public HTTP-01 body did not match the expected key authorization" >&2
    exit 1
  fi
  echo "public HTTP-01 smoke passed"
}

run_public_tls_alpn01() {
  require_external_confirmation
  require_command openssl
  require_env CERTMAGIC_PUBLIC_TLSALPN_HOST
  local port="${CERTMAGIC_PUBLIC_TLSALPN_PORT:-443}"
  validate_domain CERTMAGIC_PUBLIC_TLSALPN_HOST "$CERTMAGIC_PUBLIC_TLSALPN_HOST"
  validate_port CERTMAGIC_PUBLIC_TLSALPN_PORT "$port"
  local output
  output="$(mktemp "${TMPDIR:-/tmp}/certmagic-tls-alpn.XXXXXX")"
  trap 'rm -f "$output"' RETURN
  if ! openssl s_client -connect "${CERTMAGIC_PUBLIC_TLSALPN_HOST}:${port}" \
    -servername "$CERTMAGIC_PUBLIC_TLSALPN_HOST" -alpn acme-tls/1 \
    -brief < /dev/null >"$output" 2>&1; then
    echo "public TLS-ALPN-01 connection failed" >&2
    exit 1
  fi
  if ! grep -Fq 'ALPN protocol: acme-tls/1' "$output"; then
    echo "public TLS-ALPN-01 endpoint did not negotiate acme-tls/1" >&2
    exit 1
  fi
  echo "public TLS-ALPN-01 smoke passed"
}

run_distributed_http01() {
  require_external_confirmation
  require_command curl
  require_env CERTMAGIC_DISTRIBUTED_HTTP01_URLS
  require_env CERTMAGIC_PUBLIC_HTTP01_EXPECTED
  validate_expected_body CERTMAGIC_PUBLIC_HTTP01_EXPECTED "$CERTMAGIC_PUBLIC_HTTP01_EXPECTED"
  validate_timeout CERTMAGIC_PUBLIC_HTTP01_TIMEOUT "${CERTMAGIC_PUBLIC_HTTP01_TIMEOUT:-15}"
  local -a urls
  read -r -a urls <<<"$CERTMAGIC_DISTRIBUTED_HTTP01_URLS"
  if (( ${#urls[@]} < 2 )); then
    echo "CERTMAGIC_DISTRIBUTED_HTTP01_URLS must contain at least two URLs" >&2
    exit 2
  fi
  for ((i = 0; i < ${#urls[@]}; i++)); do
    for ((j = 0; j < i; j++)); do
      if [[ "${urls[i]}" == "${urls[j]}" ]]; then
        echo "CERTMAGIC_DISTRIBUTED_HTTP01_URLS must contain distinct node URLs" >&2
        exit 2
      fi
    done
  done
  local url body
  for url in "${urls[@]}"; do
    validate_public_http_url CERTMAGIC_DISTRIBUTED_HTTP01_URLS "$url"
    validate_challenge_url CERTMAGIC_DISTRIBUTED_HTTP01_URLS "$url"
    body="$(curl --fail --silent --show-error --noproxy '*' \
      --max-time "${CERTMAGIC_PUBLIC_HTTP01_TIMEOUT:-15}" "$url")" || {
      echo "distributed HTTP-01 request failed for one node" >&2
      exit 1
    }
    if [[ "$body" != "$CERTMAGIC_PUBLIC_HTTP01_EXPECTED" ]]; then
      echo "distributed HTTP-01 response differed across nodes" >&2
      exit 1
    fi
  done
  echo "distributed HTTP-01 smoke passed for ${#urls[@]} node URLs"
}

run_zerossl_rest() {
  require_external_confirmation
  external_domain
  require_env ZEROSSL_API_KEY
  require_command cargo
  # The test receives the API key through the environment and never prints it.
  # Email validation is intentionally operator-mediated by ZeroSSL; the test
  # blocks while the certificate is pending and then revokes it on success.
  cargo test --locked --features integration-tests --test external_zerossl \
    -- --nocapture
}

run_zerossl_acme_contract() {
  require_external_confirmation
  external_domain
  require_env ZEROSSL_API_KEY
  require_env CERTMAGIC_EXTERNAL_EMAIL
  require_env CERTMAGIC_PUBLIC_HTTP01_URL
  require_env CERTMAGIC_PUBLIC_HTTP01_EXPECTED
  cat <<'MSG'
ZeroSSL ACME/EAB preflight passed. Start the application that owns the public
HTTP-01 listener, then run the ACME issuance operation with:

  ZEROSSL_API_KEY=<redacted> CERTMAGIC_EXTERNAL_EMAIL=<redacted> \
  CERTMAGIC_EXTERNAL_DOMAIN=<domain> CERTMAGIC_EXTERNAL_CONFIRM=\
I_UNDERSTAND_EXTERNAL_NETWORK

The preflight does not contact ZeroSSL and does not claim issuance evidence.
MSG
}

run_loopback_challenges() {
  require_command cargo
  cargo test --locked --offline --test loopback_challenges -- --nocapture
}

case "$mode" in
  print-evidence-template) print_evidence_template; exit 0 ;;
  validate-evidence) run_validate_evidence; exit 0 ;;
  contract-check) run_contract_check; exit 0 ;;
  public-http-01) run_public_http01; exit 0 ;;
  public-tls-alpn-01) run_public_tls_alpn01; exit 0 ;;
  distributed-http-01) run_distributed_http01; exit 0 ;;
  zerossl-rest) run_zerossl_rest; exit 0 ;;
  zerossl-acme) run_zerossl_acme_contract; exit 0 ;;
  loopback-challenges) run_loopback_challenges; exit 0 ;;
esac

echo "Running certmagic offline validation (network and provider credentials disabled)"

# Cargo's offline switch is intentional here. A missing local registry/cache
# must fail instead of silently turning this lane into a network test.
# These two tests intentionally open loopback listeners and are covered by the
# explicit Pebble/server lanes. Some sandboxed runners deny listener binding;
# excluding them keeps this lane a deterministic protocol/state-machine check.
# RSA-8192 generation is covered by the provider matrix but is intentionally
# excluded here because it is a multi-minute CPU-bound test on small runners.
offline_test_args=(
  --skip handshake::acceptor_tests::acceptor_issues_on_demand_over_real_tls
  --skip solvers::http::tests::live_server_answers_challenge
  --skip crypto::tests::keygen_rsa_works_with_rsa_feature
)
cargo test --locked --offline --lib -- "${offline_test_args[@]}"
cargo test --locked --offline --test api_aliases
cargo test --locked --offline --test cert_store_separation
cargo check --locked --offline --no-default-features --features ring
cargo check --locked --offline --no-default-features --features aws-lc-rs

echo "Offline validation passed; no external CA/provider evidence was claimed."
