#!/usr/bin/env bash
# NAS-255 — launch a TUI agent as the dedicated worker uid.
#
# Installed (mode 0755, root-owned) at:
#   /usr/local/lib/orca-mcp/orca-omp-as-worker.sh
#
# The bridge never setuid's itself. When ORCA_BRIDGE_WORKER_ISOLATION=1 it
# places agents via `terminal create --command <this-wrapper> <agent>` so the
# agent process is re-exec'd as ORCA_BRIDGE_WORKER_USER (default orca-worker).
#
# Hard requirements:
#   - Bridge service account may run ONLY this wrapper via sudoers
#     (see deploy/linux/orca-mcp-workers.sudoers).
#   - Worker account must NOT share a group that can read bridge secrets
#     (~/.orca-bridge*, ~/.config/orca/* tokens).
#   - Wrapper strips bridge secrets from the environment before exec.
#
# Usage: orca-omp-as-worker.sh <agent-binary> [args...]
set -euo pipefail

WORKER_USER="${ORCA_BRIDGE_WORKER_USER:-orca-worker}"
REAL_AGENT="${1:-${ORCA_BRIDGE_WORKER_REAL_AGENT:-omp}}"
if [[ $# -ge 1 ]]; then
  shift
fi

if [[ -z "${REAL_AGENT}" || "${REAL_AGENT}" == */* || "${REAL_AGENT}" == *..* ]]; then
  echo "orca-omp-as-worker: refusing agent binary name: ${REAL_AGENT}" >&2
  exit 64
fi

# Resolve agent on PATH of the *worker* after drop; use bridge PATH only to find it now.
AGENT_PATH="$(command -v "${REAL_AGENT}" 2>/dev/null || true)"
if [[ -z "${AGENT_PATH}" || ! -x "${AGENT_PATH}" ]]; then
  echo "orca-omp-as-worker: agent not found on PATH: ${REAL_AGENT}" >&2
  exit 127
fi

# Drop every bridge / runtime secret from the child environment.
# Capability (if minting is enabled) is re-exported explicitly below.
_CAP="${ORCA_WORKER_CAPABILITY:-}"
_ORIGIN="${ORCA_WORKER_BRIDGE_ORIGIN:-}"
_HELPER="${ORCA_WORKER_ORCH_HELPER:-/usr/local/lib/orca-mcp/orca-worker-orch.sh}"

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

# Also clear common leaked token names.
unset ORCA_RUNTIME_TOKEN ORCA_DAEMON_TOKEN ORCA_AUTH_TOKEN 2>/dev/null || true

if [[ -n "${_CAP}" ]]; then
  export ORCA_WORKER_CAPABILITY="${_CAP}"
fi
if [[ -n "${_ORIGIN}" ]]; then
  export ORCA_WORKER_BRIDGE_ORIGIN="${_ORIGIN}"
fi
if [[ -x "${_HELPER}" ]]; then
  export ORCA_WORKER_ORCH_HELPER="${_HELPER}"
  # Prefer the worker orch helper on PATH so `orca orchestration …` can be
  # shimmed without the daemon token (see orca-worker-orch.sh).
  export PATH="$(dirname "${_HELPER}"):${PATH}"
fi

export ORCA_WORKER_UID_ISOLATION=1
export ORCA_WORKER_USER="${WORKER_USER}"

# Prefer setpriv (util-linux) — no sudo tty; falls back to sudo -u.
if command -v setpriv >/dev/null 2>&1 && [[ "$(id -u)" -eq 0 ]]; then
  # Root path (unusual for the bridge; present for test harnesses).
  WORKER_UID="$(id -u "${WORKER_USER}")"
  WORKER_GID="$(id -g "${WORKER_USER}")"
  exec setpriv \
    --reuid="${WORKER_UID}" \
    --regid="${WORKER_GID}" \
    --init-groups \
    -- \
    "${AGENT_PATH}" "$@"
fi

if command -v setpriv >/dev/null 2>&1 && id -u "${WORKER_USER}" >/dev/null 2>&1; then
  # Non-root bridge: setpriv cannot change uid without CAP_SETUID.
  # Use sudo -n -u (sudoers.d/orca-mcp-workers).
  :
fi

if command -v sudo >/dev/null 2>&1; then
  exec sudo -n -u "${WORKER_USER}" -- "${AGENT_PATH}" "$@"
fi

echo "orca-omp-as-worker: cannot drop to ${WORKER_USER} (need sudoers or root+setpriv)" >&2
exit 77
