#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd)"

IP_CHECK_URL="${E2E_IP_CHECK_URL:-https://api.ipify.org}"
SOCKS_HOST="${E2E_SOCKS_HOST:-127.0.0.1}"
SOCKS_PORT="${E2E_SOCKS_PORT:-5040}"
SOCKS_ADDR="${SOCKS_HOST}:${SOCKS_PORT}"
AUTH_MODE="${E2E_AUTH_MODE:-authkey}"
EXIT_NODE="${E2E_EXIT_NODE:-}"
LOGIN_SERVER="${E2E_LOGIN_SERVER:-}"
EXPECTED_PROXY_IP="${E2E_EXPECTED_PROXY_IP:-}"
WAIT_TIMEOUT_SEC="${E2E_WAIT_TIMEOUT_SEC:-90}"
WAIT_INTERVAL_SEC="${E2E_WAIT_INTERVAL_SEC:-1}"
HOSTNAME="${E2E_HOSTNAME:-tailsocks-e2e-$(date +%s)}"

if [[ -z "${EXIT_NODE}" ]]; then
  echo "E2E_EXIT_NODE is required" >&2
  exit 1
fi

TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/tailsocks-e2e.XXXXXX")"
STATE_DIR="${TEMP_ROOT}/state"
LOG_FILE="${TEMP_ROOT}/tailsocks.log"
mkdir -p "${STATE_DIR}"

TAILSOCKS_PID=""
OAUTH2_HOME=""
OAUTH2_ACCESS_TOKEN=""
OAUTH2_TAG=""

cleanup() {
  local status=$?
  trap - EXIT INT TERM

  if [[ -n "${TAILSOCKS_PID}" ]] && kill -0 "${TAILSOCKS_PID}" 2>/dev/null; then
    kill "${TAILSOCKS_PID}" 2>/dev/null || true
    wait "${TAILSOCKS_PID}" 2>/dev/null || true
  fi

  rm -rf "${TEMP_ROOT}"
  exit "${status}"
}
trap cleanup EXIT INT TERM

fail() {
  local msg="$1"
  echo "ERROR: ${msg}" >&2
  if [[ -f "${LOG_FILE}" ]]; then
    echo "--- tailsocks logs ---" >&2
    tail -n 120 "${LOG_FILE}" >&2 || true
  fi
  exit 1
}

run_cmd=(
  go run .
  --exit-node "${EXIT_NODE}"
  --socks-addr "${SOCKS_ADDR}"
  --state-dir "${STATE_DIR}"
  --hostname "${HOSTNAME}"
  --ephemeral=true
)

case "${AUTH_MODE}" in
  authkey)
    AUTHKEY="${E2E_TS_AUTHKEY:-${TS_AUTHKEY:-${TS_AUTH_KEY:-}}}"
    if [[ -z "${AUTHKEY}" ]]; then
      fail "authkey mode selected but no auth key provided (set E2E_TS_AUTHKEY or TS_AUTHKEY)"
    fi
    ;;
  oauth2)
    OAUTH2_ACCESS_TOKEN="${E2E_TS_OAUTH_ACCESS_TOKEN:-}"
    OAUTH2_TAG="${E2E_TS_OAUTH_TAG:-}"

    if [[ -n "${OAUTH2_ACCESS_TOKEN}" ]]; then
      if [[ -z "${OAUTH2_TAG}" ]]; then
        fail "oauth2 mode with direct access token requires E2E_TS_OAUTH_TAG"
      fi
    else
      OAUTH2_CLIENT_ID="${E2E_TS_OAUTH_CLIENT_ID:-}"
      OAUTH2_CLIENT_SECRET="${E2E_TS_OAUTH_CLIENT_SECRET:-}"

      if [[ -z "${OAUTH2_CLIENT_ID}" || -z "${OAUTH2_CLIENT_SECRET}" || -z "${OAUTH2_TAG}" ]]; then
        fail "oauth2 mode requires either E2E_TS_OAUTH_ACCESS_TOKEN+E2E_TS_OAUTH_TAG or OAuth2 client credentials (E2E_TS_OAUTH_CLIENT_ID, E2E_TS_OAUTH_CLIENT_SECRET, E2E_TS_OAUTH_TAG)"
      fi

      OAUTH2_HOME="${TEMP_ROOT}/home"
      mkdir -p "${OAUTH2_HOME}/.config/tailsocks"
      cat > "${OAUTH2_HOME}/.config/tailsocks/oauth2.json" <<EOF
{
  "client_id": "${OAUTH2_CLIENT_ID}",
  "client_secret": "${OAUTH2_CLIENT_SECRET}",
  "tag": "${OAUTH2_TAG}"
}
EOF
    fi

    run_cmd+=(--oauth2)
    ;;
  *)
    fail "unsupported E2E_AUTH_MODE='${AUTH_MODE}' (expected 'authkey' or 'oauth2')"
    ;;
esac

if [[ -n "${LOGIN_SERVER}" ]]; then
  run_cmd+=(--login-server "${LOGIN_SERVER}")
fi

echo "Starting tailsocks with SOCKS5 on ${SOCKS_ADDR}"

(
  cd "${REPO_ROOT}"
  case "${AUTH_MODE}" in
    authkey)
      export TS_AUTHKEY="${AUTHKEY}"
      ;;
    oauth2)
      unset TS_AUTHKEY
      unset TS_AUTH_KEY
      if [[ -n "${OAUTH2_ACCESS_TOKEN}" ]]; then
        export TS_OAUTH_ACCESS_TOKEN="${OAUTH2_ACCESS_TOKEN}"
        export TS_OAUTH_TAG="${OAUTH2_TAG}"
      else
        export HOME="${OAUTH2_HOME}"
      fi
      ;;
  esac
  exec "${run_cmd[@]}"
) >"${LOG_FILE}" 2>&1 &
TAILSOCKS_PID=$!

HOST_IP="$(curl --fail --silent --show-error --max-time 20 "${IP_CHECK_URL}")"
echo "Host IP: ${HOST_IP}"

echo "Waiting for proxy to become available..."
PROXY_IP=""
deadline=$((SECONDS + WAIT_TIMEOUT_SEC))
while (( SECONDS < deadline )); do
  if ! kill -0 "${TAILSOCKS_PID}" 2>/dev/null; then
    fail "tailsocks process exited before proxy became ready"
  fi

  if PROXY_IP="$(curl --fail --silent --show-error --max-time 10 --proxy "socks5://${SOCKS_ADDR}" "${IP_CHECK_URL}" 2>/dev/null)"; then
    if [[ -n "${PROXY_IP}" ]]; then
      break
    fi
  fi

  sleep "${WAIT_INTERVAL_SEC}"
done

if [[ -z "${PROXY_IP}" ]]; then
  fail "timed out waiting for proxy at socks5://${SOCKS_ADDR}"
fi

if [[ -n "${EXPECTED_PROXY_IP}" ]]; then
  if [[ "${PROXY_IP}" != "${EXPECTED_PROXY_IP}" ]]; then
    fail "proxied IP did not match configured expected proxy IP"
  fi
  echo "Proxy IP matched expected value"
else
  echo "Proxy IP: ${PROXY_IP}"
fi

if [[ "${HOST_IP}" == "${PROXY_IP}" ]]; then
  fail "expected different IP when routing through proxy, but both were '${HOST_IP}'"
fi

echo "PASS: proxied IP is different from host IP"
