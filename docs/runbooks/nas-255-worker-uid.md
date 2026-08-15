# NAS-255 — dedicated worker uid (bridge ↔ worker trust)

**Status:** code + unit files + installer prepared. **Live cutover is OWNER-attended** — this runbook does not restart the bridge for you.

## What “done” means (and does not)

| Done | Not done |
| --- | --- |
| ONE system user for all dispatched workers (`orca-worker` by default) | Per-dispatch uid |
| Worker cannot read/write bridge secrets (tokens, sender-pins, audit, ownership store) or the Orca runtime/daemon token | Worker-to-worker isolation |
| With argv gate disabled, catalogue attacks that need same-uid trust do not pass **as the worker** | Replacing the argv/ownership gate (it becomes second echelon) |
| Coordinator paths (dispatch inject, await, release, terminal read/close/send via bridge) stay on the bridge uid | Automatic Mac cutover |

**Submit input with `--enter`. There is no `--submit` flag.**
A **shell** target submits on one
`orca-ide terminal send --terminal <owned> --text '…' --enter`.
A **TUI compose box** (Grok draft buffer) needs that text send plus a
following empty `--enter` (verified live 2026-08-15; the extra send is
harmless on a shell). Stuck TUI: `--interrupt` on the same command.
`orchestration dispatch --inject` types the brief only; the bridge follows
with `terminal send --enter` to submit it.

State this plainly in tickets and reports: **per-dispatch uid / worker-to-worker isolation is NOT shipped.** NAS-259 variant 2 (per-worktree ACL at create) **is** shipped; a uid pool is a separate project.

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

## Linux VM cutover (attended) — 0.3.3 full order

This is the **owner-attended** path from a live 0.3.0 host (unsigned pin /
ownership stores) onto the merged 0.3.3 tree (signed stores + optional worker
uid). Do **not** weaken runtime load: unsigned stays rejected until the
migrator runs.

**Install root must be outside `/home`.** The signer unit ships
`WorkingDirectory=/opt/orca-mcp` and `ProtectHome=true`. Pointing the unit at a
checkout under `/home/...` fails with `status=200/CHDIR`. Do not weaken
`ProtectHome` to paper over that — install under `/opt/orca-mcp`.

**After deploying 0.3.3:** remove the live NAS-257 workaround drop-in (if
present) and reload:

```bash
sudo rm -f /etc/systemd/system/orca-bridge-store-signer.service.d/10-fix-startpost.conf
sudo rmdir /etc/systemd/system/orca-bridge-store-signer.service.d 2>/dev/null || true
sudo systemctl daemon-reload
```

The shipped unit no longer has `ExecStartPost=` (it raced `Type=simple` async
`listen()`). The daemon `chmodSync(0o660)`s the socket itself.

### Order (do not reorder past the stop/migrate fence)

| Step | Action | Bridge must be stopped? |
| --- | --- | --- |
| 1 | Install + start **store-signer** unit | No |
| 2 | **Stop** old bridge (`orca-bridge.service`) | **Yes — stay stopped through step 5** |
| 3 | Migrator **dry-run** (bridge uid) | **Yes** |
| 4 | Migrator **apply** (bridge uid) | **Yes** |
| 5 | Install 0.3.3 tree / unit files | **Yes** |
| 6 | Optional: set `ORCA_BRIDGE_WORKER_ISOLATION=1` (+ worker install) | **Yes** |
| 7 | Start bridge | starting here |
| 8 | Verify health | No (running) |

`ORCA_BRIDGE_CLI_HARDENING` needs **no** explicit setting: NAS-227 made exact-form
allowlist **default-on in code** (`0`/`false`/`off` only to disable).

### Why stop before migrate (C5)

Bare unsigned 0.3.0 JSON has **no MAC**. The migrator will sign whatever bare
payload is on disk. Already-signed envelopes with a bad/foreign signature are
**refused** (not overwritten). Residual risk is a concurrent same-uid write
racing read→sign→write — so migration runs only with the **bridge stopped**.

### Commands

1. **Install and start the signer unit** (bridge may still be the old process):
   ```bash
   cd /path/to/orca-mcp   # this release / checkout
   # ensure orca-bridge-signer user + group exist; install unit from deploy/linux/
   sudo install -m 644 deploy/linux/orca-bridge-store-signer.service \
     /etc/systemd/system/orca-bridge-store-signer.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now orca-bridge-store-signer.service
   sudo systemctl status orca-bridge-store-signer.service --no-pager
   # socket should exist and be 0660, group orca-bridge-signer:
   sudo ls -l /run/orca-bridge/store-signer.sock
   ```

2. **Stop the old bridge** (required before migrate; control plane is down):
   ```bash
   sudo systemctl stop orca-bridge.service
   ```

3. **Migrator dry-run** as the **bridge uid** (reads only; must see would-sign or already-signed/missing).
   `sudo -u orca` does **not** attach supplementary group `orca-bridge-signer`,
   so `connect(2)` on the 0660 socket always returns `EACCES`. Use `setpriv`:
   ```bash
   setpriv --reuid=orca --regid=orca --groups orca-bridge-signer \
     env HOME=/home/orca \
         ORCA_BRIDGE_STORE_SIGNER_SOCKET=/run/orca-bridge/store-signer.sock \
     node /opt/orca-mcp/scripts/migrate-store-signatures.mjs --dry-run
   ```

4. **Migrator apply** (backs up each original to `*.pre-sign-<stamp>.bak`, then signs):
   ```bash
   setpriv --reuid=orca --regid=orca --groups orca-bridge-signer \
     env HOME=/home/orca \
         ORCA_BRIDGE_STORE_SIGNER_SOCKET=/run/orca-bridge/store-signer.sock \
     node /opt/orca-mcp/scripts/migrate-store-signatures.mjs
   # safe to re-run: second pass is already-signed no-op
   ```
   If the signer socket is down the CLI exits **non-zero** with a clear message
   (never silent no-op).

5. **Install 0.3.3** tree + bridge unit (still stopped):
   ```bash
   # copy/checkout 0.3.3 into /opt/orca-mcp (MUST be outside /home)
   sudo install -m 644 deploy/linux/orca-bridge.service /etc/systemd/system/orca-bridge.service
   # EnvironmentFile=/etc/orca-mcp/env must include:
   #   ORCA_BRIDGE_STORE_SIGNER_SOCKET=/run/orca-bridge/store-signer.sock
   # Bridge unit SupplementaryGroups=orca-bridge-signer (shipped in unit file).
   sudo systemctl daemon-reload
   ```

6. **Optional worker isolation (NAS-255)** — still stopped:
   ```bash
   sudo ./deploy/linux/install-worker-uid.sh
   # creates orca-worker, wrappers, sudoers, /etc/orca-mcp/worker-isolation.env
   openssl rand -hex 32
   # add to /etc/orca-mcp/env (mode 600):
   #   ORCA_BRIDGE_WORKER_ISOLATION=1
   #   ORCA_BRIDGE_WORKER_HMAC_SECRET=<hex>
   # merge other keys from /etc/orca-mcp/worker-isolation.env
   # NAS-259 variant 2 / NAS-266: do NOT grant a recursive+default ACL on
   # /home/orca/orca/workspaces. That paints every sibling tree and the
   # checkout .git pointer. The bridge grants per-worktree ACL at create
   # and strips the named ACL from .git. If a tree-wide grant is already
   # present, strip it as uid 997 (orca) — see "Pre-existing worktrees".
   setfacl -R -x u:orca-worker /home/orca/orca/workspaces
   setfacl -R -k /home/orca/orca/workspaces
   # Prove FS denial before enabling:
   sudo -u orca-worker cat /home/orca/.orca-bridge-tokens.json          # must fail
   sudo -u orca-worker cat /home/orca/.orca-bridge-sender-pins.json      # must fail
   sudo -u orca-worker cat /home/orca/.config/orca/orca-runtime.json     # must fail
   ```
   Skip this whole step if you are not enabling worker isolation on this cutover.

7. **Start bridge**:
   ```bash
   sudo systemctl start orca-bridge.service
   sudo systemctl status orca-bridge.service --no-pager
   ```

8. **Verify health** (coordinator / `action=health` verbose):
   - `versionOk` — bridge reports the installed 0.3.3 tree
   - `statusProbe.ok`
   - `senderTerminal.ok` — **proves pins survived**; if this is false after cutover,
     the migrator did not run or the wrong HOME was migrated
   - When worker isolation enabled: `isolation.workerUid.enabled === true`,
     `perDispatchUid === false`, `perWorktreeAcl === true`

### Migrator invocation (reference)

```bash
# Working invocation — join orca-bridge-signer so the 0660 socket is writable.
setpriv --reuid=orca --regid=orca --groups orca-bridge-signer \
  env HOME=/home/orca \
      ORCA_BRIDGE_STORE_SIGNER_SOCKET=/run/orca-bridge/store-signer.sock \
  node /opt/orca-mcp/scripts/migrate-store-signatures.mjs [--dry-run] [--home DIR] [--audit-dir DIR]
```

`sudo -u orca …` is **not** a working path (always `EACCES` on the signer socket).

Touches **only**:

- `$HOME/.orca-bridge-sender-pins.json`
- `$ORCA_BRIDGE_AUDIT_DIR/dispatch-ownership.json` (default `$HOME/.orca-bridge/…`)

### Rollback notes

- Store files: restore the `*.pre-sign-*.bak` next to each store, then start the
  previous bridge build (unsigned load path).
- Worker isolation alone: set `ORCA_BRIDGE_WORKER_ISOLATION=0` (or remove), restart
  bridge; leave the `orca-worker` account in place.

## Linux VM — worker-uid-only fragment (bridge already on signed stores)

Use this shorter path only when pins/ownership are **already** signed (migrator
already applied) and you are enabling NAS-255 later.

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
3. **Repo/worktree ACLs** (NAS-259 variant 2 — per-worktree, not tree-wide):
   ```bash
   # Strip any leftover recursive/default grant. New trees get ACL from the
   # bridge at worktree-create. Do not re-apply -R / -d on the workspaces root.
   setfacl -R -x u:orca-worker /home/orca/orca/workspaces
   setfacl -R -k /home/orca/orca/workspaces
   # git objects: 994 stays checkout-write-only; 997 commits (NAS-262).
   # Never ACL the shared .git (hooks → RCE as 997).
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
   - `action=health` verbose → `isolation.workerUid.enabled === true`, `perDispatchUid === false`, `perWorktreeAcl === true`
   - Dispatch a throwaway worker; on the host: `ps -o user,pid,cmd -C omp` shows `orca-worker`
   - From that worker uid: secret cats still fail
   - Coordinator await → worker_done → release still works

Rollback: set `ORCA_BRIDGE_WORKER_ISOLATION=0` (or remove), restart bridge; agents return to same-uid launch. Leave the `orca-worker` account in place.

## Pre-existing worktrees (operator, uid 997)

The bridge **does not** rewrite ACLs on trees that already exist. 994 cannot
`setfacl` on orca-owned files (`Operation not permitted`). After deploy, run
this once as **orca** (no sudo):

```bash
WORKSPACES=/home/orca/orca/workspaces
WORKER=orca-worker

setfacl -R -x "u:${WORKER}" "${WORKSPACES}"
setfacl -R -k "${WORKSPACES}"

# Re-grant ONLY live in-flight worker checkouts, then strip the .git pointer:
#   setfacl -m "u:${WORKER}:rwx" -d -m "u:${WORKER}:rwx" "$WT"
#   find "$WT" -mindepth 1 -maxdepth 1 ! -name .git \
#     -exec setfacl -R -m "u:${WORKER}:rwx" -d -m "u:${WORKER}:rwx" {} +
#   setfacl -x "u:${WORKER}" "$WT/.git"
#   chmod 0644 "$WT/.git"

getfacl -p "${WORKSPACES}"
# must NOT show default:user:orca-worker
```

Until the parent default is stripped, new files (including `.git` pointers)
keep inheriting `u:orca-worker:rwx`. The create-time strip still removes it
from **new** pointers; foreign trees stay writable until this pass.

997 git in a worker checkout must go through `assertWorktreeGitdirPointer`
(`GITDIR_POINTER_REFUSED` if `.git` is a directory, a symlink, or not
`<repo>/.git/worktrees/<name>`). Compose `git add -- <paths>` only — never
`git add -A`.

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
