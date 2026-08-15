#!/usr/bin/env bash
# NAS-255 — attended installer for the dedicated worker uid.
#
# OWNER runs this in a maintenance window. It does NOT restart the live bridge
# by default; pass --restart only when you intend cutover.
#
# Safe to re-run (idempotent). Never writes ~/.orca-bridge* as root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRIDGE_USER="${ORCA_BRIDGE_SERVICE_USER:-orca}"
WORKER_USER="${ORCA_BRIDGE_WORKER_USER:-orca-worker}"
LIB_DIR="${ORCA_MCP_LIB_DIR:-/usr/local/lib/orca-mcp}"
SUDOERS_DST="/etc/sudoers.d/orca-mcp-workers"
DO_RESTART=0
DRY_RUN=0

usage() {
  cat <<EOF
Usage: sudo $0 [--restart] [--dry-run]
  --restart   systemctl restart orca-bridge.service after install
  --dry-run   print actions only
Env:
  ORCA_BRIDGE_SERVICE_USER  (default orca)
  ORCA_BRIDGE_WORKER_USER   (default orca-worker)
  ORCA_MCP_LIB_DIR          (default /usr/local/lib/orca-mcp)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --restart) DO_RESTART=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 64 ;;
  esac
done

run() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "+ $*"
  else
    echo "+ $*"
    "$@"
  fi
}

if [[ "$(id -u)" -ne 0 ]]; then
  echo "install-worker-uid: must run as root (attended)" >&2
  exit 1
fi

echo "install-worker-uid: bridge_user=${BRIDGE_USER} worker_user=${WORKER_USER}"

# 1) worker account — system user, no login shell, own primary group, no shared groups.
if id -u "${WORKER_USER}" >/dev/null 2>&1; then
  echo "install-worker-uid: user ${WORKER_USER} already exists"
else
  run useradd --system --create-home --home-dir "/home/${WORKER_USER}" \
    --shell /usr/sbin/nologin --user-group "${WORKER_USER}"
fi

WORKER_UID="$(id -u "${WORKER_USER}")"
WORKER_GID="$(id -g "${WORKER_USER}")"
BRIDGE_UID="$(id -u "${BRIDGE_USER}")"
echo "install-worker-uid: worker uid=${WORKER_UID} gid=${WORKER_GID}; bridge uid=${BRIDGE_UID}"

if [[ "${WORKER_UID}" -eq "${BRIDGE_UID}" ]]; then
  echo "install-worker-uid: ERROR worker and bridge uid are identical" >&2
  exit 2
fi

# Refuse shared supplementary groups with the bridge account.
BRIDGE_GROUPS="$(id -nG "${BRIDGE_USER}")"
WORKER_GROUPS="$(id -nG "${WORKER_USER}")"
for g in ${WORKER_GROUPS}; do
  if [[ "${g}" == "${WORKER_USER}" ]]; then
    continue
  fi
  for bg in ${BRIDGE_GROUPS}; do
    if [[ "${g}" == "${bg}" ]]; then
      echo "install-worker-uid: ERROR shared group '${g}' between ${BRIDGE_USER} and ${WORKER_USER}" >&2
      echo "  remove the worker from shared groups — shared group re-opens the secret class" >&2
      exit 3
    fi
  done
done

# 2) install wrappers, seed helper, PATH entry, tmpfiles
run install -d -m 0755 "${LIB_DIR}"
run install -m 0755 "${SCRIPT_DIR}/orca-omp-as-worker.sh" "${LIB_DIR}/orca-omp-as-worker.sh"
run install -m 0755 "${SCRIPT_DIR}/orca-worker-orch.sh" "${LIB_DIR}/orca-worker-orch.sh"
run install -m 0755 "${SCRIPT_DIR}/orca-seed-worker-creds" "${LIB_DIR}/orca-seed-worker-creds"
# Worker-facing orca on the sudo secure_path. 994 has no ~/.local/bin.
if [[ -f /usr/local/bin/orca && ! -f /usr/local/bin/orca.pre-nas258-cap ]]; then
  run cp -a /usr/local/bin/orca /usr/local/bin/orca.pre-nas258-cap
fi
run install -m 0755 "${SCRIPT_DIR}/orca-as-worker" /usr/local/bin/orca
if [[ -f "${SCRIPT_DIR}/tmpfiles-orca-mcp-worker-caps.conf" ]]; then
  run install -m 0644 "${SCRIPT_DIR}/tmpfiles-orca-mcp-worker-caps.conf" \
    /etc/tmpfiles.d/orca-mcp-worker-caps.conf
  if [[ "${DRY_RUN}" -eq 0 ]]; then
    systemd-tmpfiles --create /etc/tmpfiles.d/orca-mcp-worker-caps.conf || true
  fi
fi

# 3) sudoers
tmp="$(mktemp)"
sed \
  -e "s/^orca /${BRIDGE_USER} /g" \
  -e "s/(orca-worker)/(${WORKER_USER})/g" \
  -e "s/Defaults:orca /Defaults:${BRIDGE_USER} /g" \
  "${SCRIPT_DIR}/orca-mcp-workers.sudoers" > "${tmp}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "+ install sudoers → ${SUDOERS_DST}"
  cat "${tmp}"
  rm -f "${tmp}"
else
  install -m 0440 "${tmp}" "${SUDOERS_DST}"
  rm -f "${tmp}"
  visudo -cf "${SUDOERS_DST}"
fi

# NAS-258 uses a separate, exact-command sudoers fragment. Do not merge it
# into the worker-launch allowlist: no argument wildcards or SETENV are allowed.
SEED_SUDOERS_DST="/etc/sudoers.d/orca-mcp-seed-creds"
if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "+ install NAS-258 sudoers → ${SEED_SUDOERS_DST}"
  cat "${SCRIPT_DIR}/orca-mcp-seed-creds.sudoers"
else
  install -m 0440 "${SCRIPT_DIR}/orca-mcp-seed-creds.sudoers" "${SEED_SUDOERS_DST}"
  visudo -cf "${SEED_SUDOERS_DST}"
fi

# 4) worktree / repo access without shared group (NAS-259 variant 2).
#    Do NOT grant a recursive/default ACL on the workspaces root — that lets
#    uid 994 write every sibling tree and inherit rwx on the checkout .git
#    pointer (NAS-266). The bridge grants u:${WORKER_USER}:rwx on the specific
#    worktree at create time and strips the named ACL from .git.
echo "install-worker-uid: per-worktree ACL is applied by the bridge at worktree-create."
echo "install-worker-uid: if a tree-wide default ACL is already present, strip it as ${BRIDGE_USER}:"
echo "  setfacl -R -x u:${WORKER_USER} /home/${BRIDGE_USER}/orca/workspaces"
echo "  setfacl -R -k /home/${BRIDGE_USER}/orca/workspaces"
echo "  # then re-grant only live in-flight checkouts (see docs/runbooks/nas-255-worker-uid.md)"

# 5) env fragment for the unit (does not write secrets)
ENV_HINT="/etc/orca-mcp/worker-isolation.env"
if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "+ would write ${ENV_HINT}"
else
  install -d -m 0755 /etc/orca-mcp
  if [[ ! -f "${ENV_HINT}" ]]; then
    umask 077
    cat > "${ENV_HINT}" <<EOF
# Generated by install-worker-uid.sh (NAS-255). Source from EnvironmentFile= or merge into /etc/orca-mcp/env.
ORCA_BRIDGE_WORKER_ISOLATION=1
ORCA_BRIDGE_WORKER_USER=${WORKER_USER}
ORCA_BRIDGE_WORKER_UID=${WORKER_UID}
ORCA_BRIDGE_WORKER_LAUNCH_WRAPPER=${LIB_DIR}/orca-omp-as-worker.sh
# Generate a dedicated secret (do NOT reuse ORCA_BRIDGE_TOKEN long-term):
#   openssl rand -hex 32
# ORCA_BRIDGE_WORKER_HMAC_SECRET=
EOF
    chown root:"${BRIDGE_USER}" "${ENV_HINT}" 2>/dev/null || chown root:root "${ENV_HINT}"
    chmod 0640 "${ENV_HINT}"
  fi
fi

echo "install-worker-uid: merge ${ENV_HINT} into the bridge EnvironmentFile and set ORCA_BRIDGE_WORKER_HMAC_SECRET."
echo "install-worker-uid: do NOT restart from this script unless --restart."

if [[ "${DO_RESTART}" -eq 1 ]]; then
  run systemctl daemon-reload
  run systemctl restart orca-bridge.service
  run systemctl --no-pager --full status orca-bridge.service || true
else
  echo "install-worker-uid: skipped restart (owner cutover). When ready:"
  echo "  1) merge worker-isolation.env + HMAC secret into /etc/orca-mcp/env"
  echo "  2) systemctl daemon-reload && systemctl restart orca-bridge.service"
fi

echo "install-worker-uid: done"
