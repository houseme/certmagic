#!/usr/bin/env bash
# Sets up Pebble + challtestsrv and runs the ACME integration test.
# Usage: PEBBLE_CHALLENGE=dns-01|http-01|tls-alpn-01 ./tests/run-pebble.sh
# (requires Go toolchain + openssl + curl)
set -euo pipefail
cd "$(dirname "$0")/.."

command -v go >/dev/null || { echo "Go toolchain required"; exit 1; }
command -v openssl >/dev/null || { echo "openssl required"; exit 1; }
command -v curl >/dev/null || { echo "curl required"; exit 1; }

export PATH="$HOME/go/bin:$PATH"
# Skip installation when the binaries are already available.
PEBBLE_VERSION="${PEBBLE_VERSION:-v2.10.1}"
CHALLTESTSRV_VERSION="${CHALLTESTSRV_VERSION:-$PEBBLE_VERSION}"
PEBBLE_CHALLENGE="${PEBBLE_CHALLENGE:-dns-01}"
PEBBLE_HTTP_PORT="${PEBBLE_HTTP_PORT:-5002}"
PEBBLE_TLS_PORT="${PEBBLE_TLS_PORT:-5001}"
case "$PEBBLE_CHALLENGE" in
  dns-01|http-01|tls-alpn-01) ;;
  *)
    echo "PEBBLE_CHALLENGE must be dns-01, http-01, or tls-alpn-01" >&2
    exit 2
    ;;
esac
for port_name in PEBBLE_HTTP_PORT PEBBLE_TLS_PORT; do
  port_value="${!port_name}"
  if [[ ! "$port_value" =~ ^[0-9]+$ ]] || (( port_value < 1 || port_value > 65535 )); then
    echo "$port_name must be a TCP port between 1 and 65535" >&2
    exit 2
  fi
done
command -v pebble >/dev/null || \
  go install "github.com/letsencrypt/pebble/v2/cmd/pebble@${PEBBLE_VERSION}"
command -v pebble-challtestsrv >/dev/null || \
  go install "github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@${CHALLTESTSRV_VERSION}"

mkdir -p target/pebble
(
  cd target/pebble
  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 \
    -nodes -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
  cat > pebble-config.json <<JSON
{
  "pebble": {
    "listenAddress": "127.0.0.1:14000",
    "managementListenAddress": "127.0.0.1:15000",
    "certificate": "cert.pem",
    "privateKey": "key.pem",
    "httpPort": ${PEBBLE_HTTP_PORT},
    "tlsPort": ${PEBBLE_TLS_PORT},
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "domainBlocklist": ["blocked-domain.example"],
    "keyAlgorithm": "ecdsa"
  }
}
JSON
)

challtestsrv_pid=""
pebble_pid=""
cleanup() {
  if [[ -n "$pebble_pid" ]]; then
    kill "$pebble_pid" 2>/dev/null || true
    wait "$pebble_pid" 2>/dev/null || true
  fi
  if [[ -n "$challtestsrv_pid" ]]; then
    kill "$challtestsrv_pid" 2>/dev/null || true
    wait "$challtestsrv_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT
cleanup

# Bind everything to explicit loopback addresses so the VA's DNS queries
# cannot fall back to an IPv6 or system-resolver path. Disable the
# challtestsrv HTTP/TLS responders: in these lanes certmagic's own solver
# must answer the VA request on Pebble's configured validation port. Flag
# names differ between challtestsrv versions (-dns01 vs -dnsserver), so
# probe -help.
CHALL_FLAGS=()
if pebble-challtestsrv -help 2>&1 | grep -q -- '-dns01'; then
  CHALL_FLAGS=(-dns01 127.0.0.1:8053 -http01 "" -management 127.0.0.1:8055 -tlsalpn01 "" -https01 "" -defaultIPv6 "")
else
  CHALL_FLAGS=(-dnsserver 127.0.0.1:8053 -http01 "" -management 127.0.0.1:8055 -tlsalpn01 "" -https01 "" -doh "" -defaultIPv6 "")
fi
pebble-challtestsrv "${CHALL_FLAGS[@]}" &
challtestsrv_pid=$!
sleep 1
( cd target/pebble && exec env PEBBLE_VA_NOSLEEP=1 pebble -config pebble-config.json \
  -dnsserver "127.0.0.1:8053" ) &
pebble_pid=$!

wait_for_port() {
  local port="$1" name="$2"
  for _ in $(seq 1 30); do
    if [[ -n "$challtestsrv_pid" ]] && ! kill -0 "$challtestsrv_pid" 2>/dev/null; then
      echo "${name} dependency exited before readiness" >&2
      return 1
    fi
    if [[ -n "$pebble_pid" ]] && ! kill -0 "$pebble_pid" 2>/dev/null; then
      echo "${name} dependency exited before readiness" >&2
      return 1
    fi
    if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:${port}" \
      || curl -sk -o /dev/null --max-time 2 "https://127.0.0.1:${port}"; then
      echo "${name} is ready (port ${port})"
      return 0
    fi
    sleep 1
  done
  echo "${name} never became ready on port ${port}" >&2
  return 1
}
wait_for_port 8055 challtestsrv
wait_for_port 14000 pebble

PEBBLE_DIRECTORY=https://localhost:14000/dir \
CHALLTESTSRV_MANAGEMENT=http://127.0.0.1:8055 \
PEBBLE_CHALLENGE="$PEBBLE_CHALLENGE" \
PEBBLE_HTTP_PORT="$PEBBLE_HTTP_PORT" \
PEBBLE_TLS_PORT="$PEBBLE_TLS_PORT" \
TEST_DOMAIN=example.test \
cargo test --locked --features integration-tests --test integration -- --nocapture
