#!/usr/bin/env bash
# Install / refresh the Mac LaunchAgent for orca-mcp.
#
# Idempotent. Does NOT kill a live process on :8787.
# After bootstrap the agent either stands down (port busy) or runs the bridge.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

LABEL="com.orca-mcp.bridge"
RUNTIME_DIR="${HOME}/.orca-bridge"
LOG_DIR="${RUNTIME_DIR}/logs"
ENV_FILE="${RUNTIME_DIR}/env"
START_DST="${RUNTIME_DIR}/start.sh"
PLIST_SRC="${SCRIPT_DIR}/${LABEL}.plist"
PLIST_DST="${HOME}/Library/LaunchAgents/${LABEL}.plist"

# Durable checkout that outlives Orca worktrees. Default = this repo clone.
DURABLE_CHECKOUT="${ORCA_BRIDGE_DURABLE_CHECKOUT:-${REPO_ROOT}}"
DURABLE_SERVER="${DURABLE_CHECKOUT}/server.mjs"

# Resolve node: env override → common locations → PATH
resolve_node() {
  if [[ -n "${ORCA_BRIDGE_NODE_BIN:-}" && -x "${ORCA_BRIDGE_NODE_BIN}" ]]; then
    printf '%s\n' "${ORCA_BRIDGE_NODE_BIN}"
    return
  fi
  local c
  for c in \
    "$(command -v node 2>/dev/null || true)" \
    /opt/homebrew/bin/node \
    /usr/local/bin/node \
    "${HOME}/.local/share/fnm/node-versions/"*/installation/bin/node
  do
    if [[ -n "${c}" && -x "${c}" ]]; then
      printf '%s\n' "${c}"
      return
    fi
  done
  return 1
}

NODE_BIN="$(resolve_node || true)"

UID_NUM="$(id -u)"
DOMAIN="gui/${UID_NUM}"

DO_BOOTSTRAP=1
DRY_RUN=0
SYNC_SERVER=0
SEED_ENV_FROM_PID=""

usage() {
  cat <<'EOF'
Usage: deploy/macos/install-mac.sh [options]

  --dry-run              print actions, touch nothing
  --no-bootstrap         write files only; do not launchctl bootstrap
  --sync-server          copy server.mjs into ORCA_BRIDGE_DURABLE_CHECKOUT
                         (default: run from the git checkout in place)
  --seed-env-from-pid N  copy ORCA_BRIDGE_TOKEN from process N environ
  -h, --help             this help

Env:
  ORCA_BRIDGE_TOKEN            master token (or use --seed-env-from-pid)
  ORCA_BRIDGE_PUBLIC_ORIGIN    public HTTPS origin (Funnel / reverse proxy)
  ORCA_BRIDGE_DURABLE_CHECKOUT path to repo root (default: this clone)
  ORCA_BRIDGE_NODE_BIN         absolute path to node ≥18
EOF
}

run() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf 'DRY: %s\n' "$*"
    return 0
  fi
  "$@"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --no-bootstrap) DO_BOOTSTRAP=0; shift ;;
    --sync-server) SYNC_SERVER=1; shift ;;
    --seed-env-from-pid)
      SEED_ENV_FROM_PID="${2:?--seed-env-from-pid needs PID}"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

need() {
  if [[ ! -e "$1" ]]; then
    echo "install-mac: missing $1" >&2
    exit 1
  fi
}

need "${PLIST_SRC}"
need "${SCRIPT_DIR}/start.sh"
need "${REPO_ROOT}/server.mjs"

if [[ -z "${NODE_BIN}" || ! -x "${NODE_BIN}" ]]; then
  echo "install-mac: could not find node ≥18" >&2
  echo "install-mac: set ORCA_BRIDGE_NODE_BIN to an absolute node binary" >&2
  exit 1
fi

NODE_VER="$("${NODE_BIN}" -v 2>/dev/null || true)"
echo "install-mac: node ${NODE_BIN} (${NODE_VER})"
echo "install-mac: server ${DURABLE_SERVER}"

# --- runtime dir -----------------------------------------------------------
echo "install-mac: runtime dir ${RUNTIME_DIR}"
run mkdir -p "${LOG_DIR}" "${HOME}/Library/LaunchAgents"

# --- start.sh (copy, not symlink) ------------------------------------------
echo "install-mac: install start.sh → ${START_DST}"
if [[ "${DRY_RUN}" -eq 0 ]]; then
  install -m 755 "${SCRIPT_DIR}/start.sh" "${START_DST}"
else
  run install -m 755 "${SCRIPT_DIR}/start.sh" "${START_DST}"
fi

# --- optional durable server copy ------------------------------------------
if [[ "${SYNC_SERVER}" -eq 1 ]]; then
  echo "install-mac: sync server.mjs → ${DURABLE_SERVER}"
  run mkdir -p "$(dirname "${DURABLE_SERVER}")"
  if [[ "${DRY_RUN}" -eq 0 ]]; then
    if [[ -f "${DURABLE_SERVER}" ]]; then
      old_hash="$(shasum -a 256 "${DURABLE_SERVER}" | awk '{print $1}')"
      new_hash="$(shasum -a 256 "${REPO_ROOT}/server.mjs" | awk '{print $1}')"
      if [[ "${old_hash}" != "${new_hash}" ]]; then
        bak="${DURABLE_SERVER}.bak-$(date -u +%Y%m%dT%H%M%SZ)"
        cp -p "${DURABLE_SERVER}" "${bak}"
        echo "install-mac: previous durable server saved → ${bak}"
      fi
    fi
    install -m 644 "${REPO_ROOT}/server.mjs" "${DURABLE_SERVER}"
    # also copy lib/ next to server when syncing
    if [[ -d "${REPO_ROOT}/lib" ]]; then
      mkdir -p "$(dirname "${DURABLE_SERVER}")/lib"
      cp -a "${REPO_ROOT}/lib/." "$(dirname "${DURABLE_SERVER}")/lib/"
    fi
  fi
else
  # In-place: server is the checkout copy
  DURABLE_SERVER="${REPO_ROOT}/server.mjs"
  need "${DURABLE_SERVER}"
fi

# --- env file 600 ----------------------------------------------------------
seed_token_from_pid() {
  local pid="$1"
  python3 - "$pid" <<'PY'
import re, sys, subprocess
pid = sys.argv[1]
out = subprocess.check_output(["ps", "eww", "-p", pid], text=True, errors="replace")
line = out.splitlines()[-1]
m = re.search(r"\bORCA_BRIDGE_TOKEN=([^\s]+)", line)
if not m:
    sys.exit(2)
tok = m.group(1)
if len(tok) < 16:
    sys.exit(3)
sys.stdout.write(tok)
PY
}

ORCA_BIN_DEFAULT="$(command -v orca 2>/dev/null || command -v orca-ide 2>/dev/null || echo /opt/homebrew/bin/orca)"

if [[ -f "${ENV_FILE}" ]]; then
  mode="$(stat -f '%Lp' "${ENV_FILE}" 2>/dev/null || stat -c '%a' "${ENV_FILE}")"
  echo "install-mac: env exists ${ENV_FILE} mode=${mode}"
  if [[ "${mode}" != "600" && "${DRY_RUN}" -eq 0 ]]; then
    chmod 600 "${ENV_FILE}"
  fi
else
  echo "install-mac: create env ${ENV_FILE}"
  token=""
  origin="${ORCA_BRIDGE_PUBLIC_ORIGIN:-}"
  if [[ -n "${SEED_ENV_FROM_PID}" ]]; then
    if ! token="$(seed_token_from_pid "${SEED_ENV_FROM_PID}")"; then
      echo "install-mac: failed to read ORCA_BRIDGE_TOKEN from pid ${SEED_ENV_FROM_PID}" >&2
      exit 1
    fi
    echo "install-mac: seeded ORCA_BRIDGE_TOKEN from pid ${SEED_ENV_FROM_PID} (len=${#token})"
  elif [[ -n "${ORCA_BRIDGE_TOKEN:-}" ]]; then
    token="${ORCA_BRIDGE_TOKEN}"
    echo "install-mac: seeded ORCA_BRIDGE_TOKEN from installer environ (len=${#token})"
  else
    echo "install-mac: ERROR: no env file and no token source." >&2
    echo "install-mac: export ORCA_BRIDGE_TOKEN or pass --seed-env-from-pid <pid>" >&2
    exit 1
  fi
  if [[ -z "${origin}" ]]; then
    echo "install-mac: WARNING: ORCA_BRIDGE_PUBLIC_ORIGIN unset (OAuth URLs may be wrong)" >&2
  fi
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "DRY: write ${ENV_FILE} with ORCA_BRIDGE_TOKEN len=${#token}"
  else
    umask 077
    cat > "${ENV_FILE}" <<EOF
# orca-mcp Mac env. chmod 600. Not in git.
ORCA_BRIDGE_TOKEN=${token}
ORCA_BRIDGE_PUBLIC_ORIGIN=${origin}
ORCA_BRIDGE_NODE_BIN=${NODE_BIN}
ORCA_BRIDGE_SERVER=${DURABLE_SERVER}
ORCA_CLI_COMMAND=${ORCA_BIN_DEFAULT}
HINDSIGHT_URL=http://127.0.0.1:8888
EOF
    chmod 600 "${ENV_FILE}"
    echo "install-mac: wrote ${ENV_FILE} mode=600 (token len=${#token})"
  fi
fi

if [[ "${DRY_RUN}" -eq 0 && -f "${ENV_FILE}" ]]; then
  tmp="$(mktemp)"
  grep -vE '^(ORCA_BRIDGE_NODE_BIN|ORCA_BRIDGE_SERVER)=' "${ENV_FILE}" > "${tmp}" || true
  {
    cat "${tmp}"
    printf 'ORCA_BRIDGE_NODE_BIN=%s\n' "${NODE_BIN}"
    printf 'ORCA_BRIDGE_SERVER=%s\n' "${DURABLE_SERVER}"
  } > "${ENV_FILE}"
  rm -f "${tmp}"
  chmod 600 "${ENV_FILE}"
fi

# --- plist (rewrite __HOME__ placeholders) ---------------------------------
echo "install-mac: install plist → ${PLIST_DST}"
if [[ "${DRY_RUN}" -eq 0 ]]; then
  sed "s|__HOME__|${HOME}|g" "${PLIST_SRC}" > "${PLIST_DST}"
  chmod 644 "${PLIST_DST}"
  plutil -lint "${PLIST_DST}" >/dev/null
else
  run sed "s|__HOME__|${HOME}|g" "${PLIST_SRC}"
fi

# --- launchctl -------------------------------------------------------------
if [[ "${DO_BOOTSTRAP}" -eq 0 ]]; then
  echo "install-mac: skip bootstrap (--no-bootstrap)"
  echo "install-mac: done (files only)"
  exit 0
fi

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "DRY: launchctl bootout/bootstrap ${DOMAIN}/${LABEL}"
  echo "install-mac: done (dry-run)"
  exit 0
fi

if launchctl print "${DOMAIN}/${LABEL}" >/dev/null 2>&1; then
  echo "install-mac: bootout existing ${DOMAIN}/${LABEL}"
  launchctl bootout "${DOMAIN}/${LABEL}" 2>/dev/null || \
    launchctl bootout "${DOMAIN}" "${PLIST_DST}" 2>/dev/null || true
  sleep 1
fi

echo "install-mac: bootstrap ${DOMAIN} ${PLIST_DST}"
launchctl bootstrap "${DOMAIN}" "${PLIST_DST}"
launchctl enable "${DOMAIN}/${LABEL}" 2>/dev/null || true
launchctl kickstart -k "${DOMAIN}/${LABEL}" 2>/dev/null || \
  launchctl kickstart "${DOMAIN}/${LABEL}" 2>/dev/null || true

sleep 1
echo "install-mac: launchctl print ${DOMAIN}/${LABEL}"
launchctl print "${DOMAIN}/${LABEL}" || echo "install-mac: WARNING: print failed" >&2

echo "install-mac: listeners on :8787"
lsof -nP -iTCP:8787 -sTCP:LISTEN 2>/dev/null || echo "(none)"
if [[ -f "${LOG_DIR}/launchd.log" ]]; then
  echo "install-mac: recent start log"
  tail -n 20 "${LOG_DIR}/launchd.log" || true
fi

echo "install-mac: done"
echo "install-mac: if a manual node still holds :8787, agent is loaded and waiting (start.sh exit 0)."
