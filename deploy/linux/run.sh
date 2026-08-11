#!/usr/bin/env bash
# Start orca-mcp on a Linux host. Idempotent: refuses to double-start.
# Prefer systemd (orca-bridge.service) in production; this script is for
# manual / watchdog paths.
set -euo pipefail

ROOT="${ORCA_BRIDGE_RUNTIME_DIR:-${HOME}/bridge-vm}"
ENV_FILE="${ROOT}/env"
PID_FILE="${ROOT}/bridge.pid"
LOG_DIR="${ROOT}/logs"
LOG_FILE="${LOG_DIR}/bridge.log"
# Absolute path to server.mjs — set in env file or here.
SERVER="${ORCA_BRIDGE_SERVER:-}"
PORT="${ORCA_BRIDGE_PORT:-8787}"
NODE_BIN="${ORCA_BRIDGE_NODE_BIN:-/usr/bin/node}"

mkdir -p "${LOG_DIR}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "$(date -Is) ERROR: missing ${ENV_FILE}" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

SERVER="${ORCA_BRIDGE_SERVER:-${SERVER}}"
NODE_BIN="${ORCA_BRIDGE_NODE_BIN:-${NODE_BIN}}"
PORT="${ORCA_BRIDGE_PORT:-${PORT}}"

if [[ -z "${SERVER}" || ! -f "${SERVER}" ]]; then
  echo "$(date -Is) ERROR: set ORCA_BRIDGE_SERVER to server.mjs (got: ${SERVER:-empty})" >&2
  exit 1
fi

if [[ -z "${ORCA_BRIDGE_TOKEN:-}" ]]; then
  echo "$(date -Is) ERROR: ORCA_BRIDGE_TOKEN empty in ${ENV_FILE}" >&2
  exit 1
fi

is_bridge_pid() {
  local pid="$1"
  [[ -n "${pid}" ]] || return 1
  kill -0 "${pid}" 2>/dev/null || return 1
  local cmd
  cmd="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)"
  [[ "${cmd}" == *"${NODE_BIN}"* && "${cmd}" == *"server.mjs"* ]]
}

if [[ -f "${PID_FILE}" ]]; then
  old_pid="$(tr -d '[:space:]' < "${PID_FILE}" 2>/dev/null || true)"
  if is_bridge_pid "${old_pid}"; then
    echo "$(date -Is) already running pid=${old_pid}"
    exit 0
  fi
  rm -f "${PID_FILE}"
fi

export PATH="$(dirname "${NODE_BIN}"):/usr/bin:/bin:${PATH:-}"

{
  echo "===== $(date -Is) starting orca-mcp ====="
  echo "public_origin=${ORCA_BRIDGE_PUBLIC_ORIGIN:-}"
  echo "server=${SERVER} port=${PORT}"
} >> "${LOG_FILE}"

nohup "${NODE_BIN}" "${SERVER}" --port "${PORT}" >> "${LOG_FILE}" 2>&1 &
pid=$!
echo "${pid}" > "${PID_FILE}"
disown "${pid}" 2>/dev/null || true

for _ in 1 2 3 4 5 6 7 8 9 10; do
  if is_bridge_pid "${pid}" && ss -ltn 2>/dev/null | grep -qE "127\\.0\\.0\\.1:${PORT}\\b"; then
    echo "$(date -Is) started pid=${pid} port=${PORT}"
    exit 0
  fi
  sleep 0.3
done

if is_bridge_pid "${pid}"; then
  echo "$(date -Is) started pid=${pid} (port not yet confirmed)"
  exit 0
fi

echo "$(date -Is) ERROR: process died immediately; see ${LOG_FILE}" >&2
rm -f "${PID_FILE}"
exit 1
