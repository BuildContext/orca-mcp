#!/bin/sh
# Launch orca-mcp under launchd.
# Secrets live in ~/.orca-bridge/env (mode 600), not in the plist.
#
# Cutover-safe: if 127.0.0.1:PORT is already taken, exit 0 so KeepAlive
# does not thrash against a manual process still holding the channel.
set -eu

ROOT="${HOME}/.orca-bridge"
ENV_FILE="${ROOT}/env"
LOG_DIR="${ROOT}/logs"
PORT="${ORCA_BRIDGE_PORT:-8787}"

# Prefer values from env file. Fallbacks require absolute paths set at install.
NODE_BIN="${ORCA_BRIDGE_NODE_BIN:-}"
SERVER="${ORCA_BRIDGE_SERVER:-}"

mkdir -p "${LOG_DIR}"

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

log() {
  printf '%s %s\n' "$(ts)" "$*" >> "${LOG_DIR}/launchd.log"
}

if [ ! -f "${ENV_FILE}" ]; then
  log "ERROR: missing env file ${ENV_FILE} (mode 600 expected)"
  exit 1
fi

# shellcheck disable=SC1090
set -a
. "${ENV_FILE}"
set +a

NODE_BIN="${ORCA_BRIDGE_NODE_BIN:-${NODE_BIN}}"
SERVER="${ORCA_BRIDGE_SERVER:-${SERVER}}"

if [ -z "${ORCA_BRIDGE_TOKEN:-}" ]; then
  log "ERROR: ORCA_BRIDGE_TOKEN empty in ${ENV_FILE}"
  exit 1
fi

if [ -z "${NODE_BIN}" ] || [ ! -x "${NODE_BIN}" ]; then
  log "ERROR: node binary not executable: ${NODE_BIN:-unset}"
  exit 1
fi

if [ -z "${SERVER}" ] || [ ! -f "${SERVER}" ]; then
  log "ERROR: server.mjs missing: ${SERVER:-unset}"
  exit 1
fi

if command -v lsof >/dev/null 2>&1; then
  if lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
    holder="$(lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN 2>/dev/null | awk 'NR==2 {print $1, $2}' || true)"
    log "INFO: port ${PORT} already listening (${holder:-unknown}); standing down until cutover"
    exit 0
  fi
fi

export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:${PATH:-}"
if [ -n "${ORCA_CLI_COMMAND:-}" ]; then
  export ORCA_CLI_COMMAND
fi

log "INFO: starting ${NODE_BIN} ${SERVER} --port ${PORT}"
cd "${ROOT}"
exec "${NODE_BIN}" "${SERVER}" --port "${PORT}"
