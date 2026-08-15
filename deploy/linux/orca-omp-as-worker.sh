#!/usr/bin/env bash
# NAS-255 / NAS-258 — launch a TUI agent as the dedicated worker uid.
#
# Installed (mode 0755, root-owned) at:
#   /usr/local/lib/orca-mcp/orca-omp-as-worker.sh
#
# Usage: orca-omp-as-worker.sh [--task-id <id>] <agent-binary> [args...]
#
# NAS-258: capability is a 994:994 0600 file, not env. This wrapper:
#   1. seeds creds (and any staged cap files) via the existing sudo seed verb
#   2. waits for /run/orca-mcp/worker-caps/by-task/<taskId> so grok/omp
#      cannot start before the file exists
#   3. launches grok with --permission-mode bypassPermissions
set -euo pipefail

WORKER_USER="${ORCA_BRIDGE_WORKER_USER:-orca-worker}"
TASK_ID=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --task-id)
      TASK_ID="${2:-}"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    --*)
      echo "orca-omp-as-worker: unknown flag: $1" >&2
      exit 64
      ;;
    *)
      break
      ;;
  esac
done

REAL_AGENT="${1:-${ORCA_BRIDGE_WORKER_REAL_AGENT:-omp}}"
if [[ $# -ge 1 ]]; then
  shift
fi

if [[ -z "${REAL_AGENT}" || "${REAL_AGENT}" == */* || "${REAL_AGENT}" == *..* ]]; then
  echo "orca-omp-as-worker: refusing agent binary name: ${REAL_AGENT}" >&2
  exit 64
fi

if [[ -n "${TASK_ID}" && ! "${TASK_ID}" =~ ^[A-Za-z0-9._:-]{1,128}$ ]]; then
  echo "orca-omp-as-worker: refusing task-id: ${TASK_ID}" >&2
  exit 64
fi

# Resolve agent on PATH of the *worker* after drop; use bridge PATH only to find it now.
AGENT_PATH="$(command -v "${REAL_AGENT}" 2>/dev/null || true)"
if [[ -z "${AGENT_PATH}" || ! -x "${AGENT_PATH}" ]]; then
  echo "orca-omp-as-worker: agent not found on PATH: ${REAL_AGENT}" >&2
  exit 127
fi

# NAS-258 — seed the allowlisted provider credential (and any staged
# capability files) before dropping uid. Failure is terminal: do not launch
# omp into the interactive setup wizard.
SEED_HELPER="/usr/local/lib/orca-mcp/orca-seed-worker-creds"
if [[ ! -x "${SEED_HELPER}" ]]; then
  echo "orca-omp-as-worker: credential seed helper missing: ${SEED_HELPER}" >&2
  exit 66
fi
if ! sudo -n "${SEED_HELPER}" seed; then
  echo "orca-omp-as-worker: credential seed failed (no usable host auth.json, or helper/sudoers missing)" >&2
  exit 66
fi

# Close the "file exists before agent start" race: grok/omp does not start
# until the privileged side has materialized the by-task pointer.
# Existence is enough — the file is 994:994 0600 so this (997) process
# cannot read it, which is intended.
wait_for_cap_file() {
  [[ -n "${TASK_ID}" ]] || return 0
  local pointer="/run/orca-mcp/worker-caps/by-task/${TASK_ID}"
  local wait_sec="${ORCA_WORKER_CAP_WAIT_SEC:-90}"
  local deadline=$((SECONDS + wait_sec))
  while (( SECONDS < deadline )); do
    if [[ -e "${pointer}" ]]; then
      # pointer is 0600 994:994; 997 can only observe existence, not contents.
      echo "orca-omp-as-worker: capability pointer present for task ${TASK_ID}" >&2
      return 0
    fi
    sleep 0.1
  done
  echo "orca-omp-as-worker: capability file not ready for task ${TASK_ID} after ${wait_sec}s" >&2
  exit 67
}
wait_for_cap_file

# Drop every bridge / runtime secret from the child environment.
# Capability is delivered by file; env copies are not the delivery path.
unset ORCA_BRIDGE_TOKEN \
      ORCA_BRIDGE_CLI_ADMIN \
      ORCA_BRIDGE_CLI_HARDENING \
      ORCA_BRIDGE_SENDER_TERMINAL \
      ORCA_BRIDGE_FROM \
      ORCA_BRIDGE_SENDER_SHARED \
      ORCA_BRIDGE_HMAC_SECRET \
      ORCA_BRIDGE_WORKER_HMAC_SECRET \
      ORCA_WORKER_CAPABILITY \
      ORCA_WORKER_BRIDGE_ORIGIN \
      ORCA_WORKER_ORCH_HELPER \
      2>/dev/null || true

unset ORCA_RUNTIME_TOKEN ORCA_DAEMON_TOKEN ORCA_AUTH_TOKEN 2>/dev/null || true

export ORCA_WORKER_UID_ISOLATION=1
export ORCA_WORKER_USER="${WORKER_USER}"
if [[ -n "${TASK_ID}" ]]; then
  export ORCA_WORKER_TASK_ID="${TASK_ID}"
fi

AGENT_EXTRA=()
if [[ "${REAL_AGENT}" == "grok" ]]; then
  has_pm=0
  for a in "$@"; do
    if [[ "${a}" == "--permission-mode" || "${a}" == "--always-approve" ]]; then
      has_pm=1
    fi
  done
  if [[ "${has_pm}" -eq 0 ]]; then
    AGENT_EXTRA+=(--permission-mode bypassPermissions)
  fi
fi

# Prefer setpriv (util-linux) — no sudo tty; falls back to sudo -u.
if command -v setpriv >/dev/null 2>&1 && [[ "$(id -u)" -eq 0 ]]; then
  WORKER_UID="$(id -u "${WORKER_USER}")"
  WORKER_GID="$(id -g "${WORKER_USER}")"
  exec setpriv \
    --reuid="${WORKER_UID}" \
    --regid="${WORKER_GID}" \
    --init-groups \
    -- \
    "${AGENT_PATH}" "${AGENT_EXTRA[@]}" "$@"
fi

if command -v sudo >/dev/null 2>&1; then
  sudo -n -u "${WORKER_USER}" -- "${AGENT_PATH}" "${AGENT_EXTRA[@]}" "$@" &
  child=$!
  trap 'kill "$child" 2>/dev/null || true; wait "$child" || true' TERM INT HUP
  wait "$child"
  exit $?
fi

echo "orca-omp-as-worker: cannot drop to ${WORKER_USER} (need sudoers or root+setpriv)" >&2
exit 77
