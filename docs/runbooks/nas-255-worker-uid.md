# NAS-255 — dedicated worker uid (bridge ↔ worker trust)

**Status:** code + unit files + installer prepared. **Live cutover is OWNER-attended** — this runbook does not restart the bridge for you.

## What “done” means (and does not)

| Done | Not done |
| --- | --- |
| ONE system user for all dispatched workers (`orca-worker` by default) | Per-dispatch uid |
| Worker cannot read/write bridge secrets (tokens, sender-pins, audit, ownership store) or the Orca runtime/daemon token | Worker-to-worker isolation |
| With argv gate disabled, catalogue attacks that need same-uid trust do not pass **as the worker** | Replacing the argv/ownership gate (it becomes second echelon) |
| Coordinator paths (dispatch inject, await, release, terminal read/close/send via bridge) stay on the bridge uid | Automatic Mac cutover |

State this plainly in tickets and reports: **per-dispatch uid / worker-to-worker isolation is NOT shipped.**

## Why

Every finding in the NAS-248 line reduces to single-uid trust: the worker *is* the bridge user, so it can open `~/.orca-bridge*` (mode 0600 but same uid) and forge coordinator identity. A separate uid closes that class at the FS/process boundary.

## Architecture

```text
  MCP coordinator
        │
        ▼
  orca-mcp (User=orca)  ──execFile(orca)──►  Orca runtime (uid orca)
        │                                         │
        │  dispatch places agent via              │ terminal PTY
        │  terminal create --command              ▼
        │  /usr/local/lib/orca-mcp/         agent process
        │    orca-omp-as-worker.sh omp      (uid orca-worker)
        │                                         │
        │  secrets 0600 bridge-owned              ├─ cannot read ~/.orca-bridge*
        │  HMAC capability minted                 ├─ cannot read runtime token
        │  into worker env (optional)             └─ worker_done via capability / bridge
```

- **Bridge process** stays `User=orca` / `Group=orca`. State stays under that HOME.
- **Agent launch** no longer uses `worktree create --agent` when isolation is on (that would spawn as orca). Flow: bare `worktree create` → `terminal create --command <wrapper> <agent>`.
- **Wrapper** (`deploy/linux/orca-omp-as-worker.sh`) strips bridge secrets from env and `sudo -n -u orca-worker` (or root `setpriv`) execs the real agent.
- **No shared unix group** between bridge and worker for secret paths. Repo/worktree access via **ACLs** on tree roots, not a shared group.
- **Runtime token** (`~/.config/orca/orca-runtime.json`, daemon token) stays 0600 bridge-owned. Workers do not get it. Coordinator inject/release/terminal ops run inside the bridge (bridge uid) and keep working. Worker→mailbox signals use a bridge-minted **HMAC capability** (`ORCA_WORKER_CAPABILITY`); full capability→runtime relay is part of attended cutover.

## Linux VM cutover (attended)

1. **Prep (no restart yet)**
   ```bash
   cd /path/to/orca-mcp   # this release / checkout
   sudo ./deploy/linux/install-worker-uid.sh
   # creates orca-worker, installs wrappers + sudoers, writes /etc/orca-mcp/worker-isolation.env
   ```
2. **HMAC secret**
   ```bash
   openssl rand -hex 32
   # add to /etc/orca-mcp/env (mode 600, owned by root:orca or root:root):
   #   ORCA_BRIDGE_WORKER_HMAC_SECRET=<hex>
   # merge other keys from /etc/orca-mcp/worker-isolation.env
   ```
3. **Repo/worktree ACLs** (example — adjust roots):
   ```bash
   setfacl -R -m u:orca-worker:rwx /home/orca/orca/workspaces
   setfacl -R -d -m u:orca-worker:rwx /home/orca/orca/workspaces
   # git objects: ensure worker can read the main repo + write worktrees
   ```
4. **Prove FS denial before enabling**
   ```bash
   sudo -u orca-worker cat /home/orca/.orca-bridge-tokens.json          # must fail
   sudo -u orca-worker cat /home/orca/.orca-bridge-sender-pins.json      # must fail
   sudo -u orca-worker cat /home/orca/.config/orca/orca-runtime.json     # must fail
   ```
5. **Enable + restart (owner window)**
   ```bash
   # /etc/orca-mcp/env contains ORCA_BRIDGE_WORKER_ISOLATION=1 and friends
   sudo systemctl daemon-reload
   sudo systemctl restart orca-bridge.service   # OWNER only
   ```
6. **Smoke**
   - `action=health` verbose → `isolation.workerUid.enabled === true`, `perDispatchUid === false`
   - Dispatch a throwaway worker; on the host: `ps -o user,pid,cmd -C omp` shows `orca-worker`
   - From that worker uid: secret cats still fail
   - Coordinator await → worker_done → release still works

Rollback: set `ORCA_BRIDGE_WORKER_ISOLATION=0` (or remove), restart bridge; agents return to same-uid launch. Leave the `orca-worker` account in place.

## Mac (backup contour) — cost, not this PR’s apply

| Item | Cost |
| --- | --- |
| Separate user | Create `orca-worker` via Directory Utility / `sysadminctl` or a dedicated managed user |
| LaunchAgent | Bridge remains a **per-user** LaunchAgent under the bridge account; there is no system-wide setuid path as clean as Linux sudoers |
| Drop mechanism | Prefer a small `launchctl asuser` / `sudo -u` wrapper analogous to Linux; GUI/TUI agents often need the bridge user’s bootstrap namespace — **expect extra bring-up** |
| Secrets | Same 0600 files under the bridge HOME; ensure worker home ≠ bridge home |
| This PR | Ships Linux unit comments + installer. **Does not touch the backup Mac.** |

## Env reference

| Variable | Meaning |
| --- | --- |
| `ORCA_BRIDGE_WORKER_ISOLATION=1` | Opt-in |
| `ORCA_BRIDGE_WORKER_USER` | Default `orca-worker` |
| `ORCA_BRIDGE_WORKER_UID` | Numeric uid (health + tests) |
| `ORCA_BRIDGE_WORKER_LAUNCH_WRAPPER` | Default `/usr/local/lib/orca-mcp/orca-omp-as-worker.sh` |
| `ORCA_BRIDGE_WORKER_HMAC_SECRET` | Capability HMAC (do not reuse master token long-term) |
| `ORCA_BRIDGE_WORKER_REAL_AGENT` | Default real binary name (`omp`) |

## Tests

```bash
npm test   # includes lib/worker-isolation.test.mjs
```

- Hermetic FS classify + attack catalogue with argv gate treated as disabled  
- PRE-FIX baseline assertion: same uid ⇒ catalogue attacks still pass  
- Optional live disposable `useradd` + `setpriv` proof under an isolated HOME (never writes live `~/.orca-bridge*`)

## Follow-up ticket (file as separate)

**Title:** Per-dispatch worker uid / worker-to-worker isolation  
**Body must state:** NAS-255 shipped one shared `orca-worker` uid only. Worker-to-worker filesystem and process isolation is **not** done; a hostile worker can still affect sibling workers’ worktrees if ACLs grant shared write.
