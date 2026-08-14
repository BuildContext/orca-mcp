#!/usr/bin/env bash
# NAS-255 — worker-side orchestration helper.
#
# Workers under the dedicated uid cannot read the Orca daemon/runtime token
# (0600, bridge-owned). Coordinator paths (inject / release / terminal
# read|close|send) stay on the bridge process (bridge uid) and keep working.
#
# For worker→coordinator signals (worker_done, ask, heartbeat, escalation)
# the bridge mints ORCA_WORKER_CAPABILITY into the launch environment. This
# helper is a thin stub that:
#   1. Refuses to read bridge secret paths.
#   2. Documents that full capability→runtime relay is operator-attended
#      cutover work (pair with bridge HTTP path or a future runtime grant).
#   3. Still lets operators smoke-test that the worker uid has the capability
#      env and cannot open secrets.
#
# Installed next to the launch wrapper:
#   /usr/local/lib/orca-mcp/orca-worker-orch.sh
set -euo pipefail

cmd="${1:-}"
shift || true

if [[ -z "${ORCA_WORKER_CAPABILITY:-}" ]]; then
  echo "orca-worker-orch: ORCA_WORKER_CAPABILITY missing — bridge did not mint a worker capability" >&2
  exit 78
fi

# Never open bridge secrets even if HOME points at the bridge account.
for p in \
  "${HOME}/.orca-bridge-tokens.json" \
  "${HOME}/.orca-bridge-sender-pins.json" \
  "${HOME}/.orca-bridge/audit.ndjson" \
  "${HOME}/.orca-bridge/dispatch-ownership.json" \
  "${HOME}/.config/orca/orca-runtime.json" \
  "${HOME}/.config/orca/daemon/daemon-v32.token"
do
  if [[ -e "${p}" ]] && [[ -r "${p}" ]]; then
    echo "orca-worker-orch: refusing to run — can read bridge secret ${p} (uid isolation broken)" >&2
    exit 79
  fi
done

case "${cmd}" in
  whoami)
    echo "uid=$(id -u) user=$(id -un) capability=present"
    exit 0
    ;;
  capability)
    # Print length only — never dump the token to logs by default.
    echo "ORCA_WORKER_CAPABILITY len=${#ORCA_WORKER_CAPABILITY}"
    exit 0
    ;;
  worker_done|ask|heartbeat|escalation|check)
    echo "orca-worker-orch: op=${cmd} accepted locally; runtime relay requires attended cutover (see docs/runbooks/nas-255-worker-uid.md)" >&2
    echo "capability_ok=1 op=${cmd}"
    exit 0
    ;;
  ""|-h|--help|help)
    cat <<'EOF'
orca-worker-orch.sh — worker uid orchestration helper (NAS-255)

Commands:
  whoami       print uid + capability presence
  capability   print capability length
  worker_done|ask|heartbeat|escalation|check
               accept op under capability (runtime relay is cutover work)

Env:
  ORCA_WORKER_CAPABILITY   required (minted by bridge at dispatch)
  ORCA_WORKER_BRIDGE_ORIGIN optional bridge HTTP origin
EOF
    exit 0
    ;;
  *)
    echo "orca-worker-orch: unknown command: ${cmd}" >&2
    exit 64
    ;;
esac
