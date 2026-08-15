#!/usr/bin/env bash
# NAS-255 / NAS-258 — worker-side orchestration helper.
#
# Isolated uid 994 cannot read the Orca runtime token. This helper loads the
# HMAC capability file (994:994 0600) and POSTs the CLI argv to the bridge
# at bridgeOrigin (/worker/orch). The bridge verifies the capability and
# relays `orca orchestration send|ask|check` as the bridge uid.
#
# Installed next to the launch wrapper:
#   /usr/local/lib/orca-mcp/orca-worker-orch.sh
# Also exec'd by /usr/local/bin/orca when a cap file is readable.
set -euo pipefail

find_cap_file() {
  if [[ -n "${ORCA_WORKER_CAP_FILE:-}" && -r "${ORCA_WORKER_CAP_FILE}" ]]; then
    printf '%s\n' "${ORCA_WORKER_CAP_FILE}"
    return 0
  fi
  local home="${HOME:-/home/orca-worker}"
  if [[ -r "${home}/.orca-worker/current-cap.json" ]]; then
    printf '%s\n' "${home}/.orca-worker/current-cap.json"
    return 0
  fi
  local prev="" a
  for a in "$@"; do
    if [[ "${prev}" == "--dispatch-id" && -n "${a}" && "${a}" =~ ^[A-Za-z0-9._:-]{1,128}$ ]]; then
      local f="/run/orca-mcp/worker-caps/${a}.json"
      if [[ -r "${f}" ]]; then
        printf '%s\n' "${f}"
        return 0
      fi
    fi
    if [[ "${prev}" == "--task-id" && -n "${a}" && "${a}" =~ ^[A-Za-z0-9._:-]{1,128}$ ]]; then
      local ptr="/run/orca-mcp/worker-caps/by-task/${a}"
      if [[ -r "${ptr}" ]]; then
        local did
        did="$(tr -d '[:space:]' < "${ptr}")"
        local f="/run/orca-mcp/worker-caps/${did}.json"
        if [[ -r "${f}" ]]; then
          printf '%s\n' "${f}"
          return 0
        fi
      fi
    fi
    prev="${a}"
  done
  return 1
}

# Never open *bridge* secrets. Check the bridge HOME, not $HOME — the worker
# account may have leftover userData from a previous isolated grok launch.
BRIDGE_HOME="${ORCA_BRIDGE_HOME:-/home/orca}"
for p in \
  "${BRIDGE_HOME}/.orca-bridge-tokens.json" \
  "${BRIDGE_HOME}/.orca-bridge-sender-pins.json" \
  "${BRIDGE_HOME}/.orca-bridge/audit.ndjson" \
  "${BRIDGE_HOME}/.orca-bridge/dispatch-ownership.json" \
  "${BRIDGE_HOME}/.config/orca/orca-runtime.json" \
  "${BRIDGE_HOME}/.config/orca/daemon/daemon-v32.token"
do
  if [[ -e "${p}" ]] && [[ -r "${p}" ]]; then
    echo "orca-worker-orch: refusing to run — can read bridge secret ${p} (uid isolation broken)" >&2
    exit 79
  fi
done

CAP_FILE=""
if ! CAP_FILE="$(find_cap_file "$@")"; then
  echo "orca-worker-orch: capability file missing — bridge did not mint a worker capability" >&2
  exit 78
fi

cmd="${1:-}"
if [[ "${cmd}" == "whoami" ]]; then
  echo "uid=$(id -u) user=$(id -un) capability=file:${CAP_FILE}"
  exit 0
fi
if [[ "${cmd}" == "capability" ]]; then
  python3 - "${CAP_FILE}" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
print("ORCA_WORKER_CAPABILITY len=%d file=%s dispatchId=%s" % (
    len(obj.get("capability") or ""), sys.argv[1], obj.get("dispatchId") or ""))
PY
  exit 0
fi
if [[ -z "${cmd}" || "${cmd}" == "-h" || "${cmd}" == "--help" || "${cmd}" == "help" ]]; then
  cat <<'EOF'
orca-worker-orch.sh — worker uid orchestration helper (NAS-258)

Commands:
  whoami / capability
  orchestration send|ask|check …
  worker_done|ask|heartbeat|escalation|check

Reads /run/orca-mcp/worker-caps/<dispatchId>.json (or ~/.orca-worker/current-cap.json)
and POSTs to the bridge /worker/orch endpoint. Capability is never printed.
EOF
  exit 0
fi

# Relay argv to the bridge. Python so we do not depend on jq.
export ORCA_WORKER_CAP_FILE="${CAP_FILE}"
exec python3 - "${CAP_FILE}" "$@" <<'PY'
import json, os, sys, urllib.error, urllib.request

cap_path = sys.argv[1]
argv = sys.argv[2:]
with open(cap_path, encoding="utf-8") as f:
    rec = json.load(f)
capability = rec.get("capability") or ""
origin = (rec.get("bridgeOrigin") or "http://127.0.0.1:8787").rstrip("/")
url = origin + "/worker/orch"
timeout = 620
# ask can block up to 600s; others finish quickly.
if "ask" in argv:
    timeout = 620
body = json.dumps({
    "capability": capability,
    "argv": argv,
    "capFile": cap_path,
}).encode("utf-8")
req = urllib.request.Request(
    url,
    data=body,
    method="POST",
    headers={"content-type": "application/json", "accept": "application/json"},
)
try:
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        status = resp.status
except urllib.error.HTTPError as e:
    raw = e.read()
    status = e.code
except Exception as e:
    print(f"orca-worker-orch: relay failed: {e}", file=sys.stderr)
    sys.exit(75)

text = raw.decode("utf-8", errors="replace")
try:
    payload = json.loads(text) if text else {}
except json.JSONDecodeError:
    payload = {"ok": False, "error": text}

if status >= 400 or payload.get("ok") is False:
    err = payload.get("error") or payload.get("message") or text or f"http {status}"
    print(f"orca-worker-orch: {err}", file=sys.stderr)
    sys.exit(int(payload.get("exitCode") or 1))

stdout = payload.get("stdout")
if stdout:
    sys.stdout.write(stdout if stdout.endswith("\n") else stdout + "\n")
elif "result" in payload:
    json.dump(payload["result"], sys.stdout)
    sys.stdout.write("\n")
else:
    print("ok")
sys.exit(int(payload.get("exitCode") or 0))
PY
