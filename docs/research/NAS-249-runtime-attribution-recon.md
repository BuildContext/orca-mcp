# NAS-249 — Can the runtime attribute live dispatches after a bridge restart?

Read-only reconnaissance. No writes, no restarts, no store mutation.
Live contour: orca-ide 1.4.180, `runtimeId` `9fb4ec9b-f9f3-4cce-b97e-06be26686774`,
bridge process `orca-mcp@0.3.0` on `127.0.0.1:8787`.
NAS-248 hydrate code was read from branch `BuildContext/nas-248-ownership-invariant`
@ `65f3a8a` only; that branch was not checked out and
`~/.orca-bridge/dispatch-ownership.json` was not present on this host
(live 0.3.0 never writes it).

Subject dispatch (this recon worker):
`ctx_d873be6e19c7` / `task_be9ba2bbaf8b` / `run_024f8e980759`.
Worker handle `term_af9b4b36-5a8b-4d18-9818-d27b6a6b7faf`.
Coordinator handle named in the dispatch preamble:
`term_4f8d8fb4-1c6c-49e8-96df-057428ac0c5c`.

---

## VERDICT: PARTIALLY FEASIBLE

The runtime can reconstruct `dispatch_id → coordinator terminal handle`
after a **bridge** restart, without reading any bridge-written file.
Two independent runtime fields name that handle:
`runs.coordinator_handle` (current Run binder) and
`tasks.created_by_terminal_handle` (immutable at INSERT).
Live probes on this dispatch return both as
`term_4f8d8fb4-1c6c-49e8-96df-057428ac0c5c`.
The runtime **never** stores or returns `clientKey` / `oauth:…`.
The only existing map from that handle to the bridge's ownership
principal (`oauth:72d3b599cda9f8cc`) is
`~/.orca-bridge-sender-pins.json`, a 0600 same-uid file the
bridge already hydrates at boot. Direction (2) therefore
reconstructs `dispatch → handle` from the runtime, then
re-attaches `handle → clientKey` from a **different plantable
bridge file**. That is moving the bind oracle, not removing it.
The runtime channel itself is a unix socket + a 48-char token
in `~/.config/orca/orca-runtime.json` (0600, same uid) compared
with `===`. A same-uid worker can steal that token and speak
RPC; `orchestration.db` is the same 0600 file. Direction (2)
is not more trusted than the file against the actual threat
model. Use it only if ownership is redefined to *handle*
(and the reconnect/rematch problem below is solved without a
plantable map). Otherwise direction (1) is the one that
addresses the oracle.

---

## The attribution chain

```
dispatch_id
    │
    │  runtime-sourced (orchestration.db + CLI)
    │  dispatch-show --task <task_id>
    │     → dispatch.id, run_id, task_id, assignee_handle (WORKER)
    │
    ├─► run_id ── run-show / run-list ──► runs.coordinator_handle
    │                                      CURRENT binder (mutable via run-use)
    │                                      runtime-sourced
    │
    └─► task_id ── task-list --run ──► tasks.created_by_terminal_handle
                                       ORIGINATING creator (INSERT-only)
                                       runtime-sourced

coordinator_handle / created_by_terminal_handle
    │
    │  bridge-file-sourced
    │  ~/.orca-bridge-sender-pins.json   (and in-memory senderCaches
    │                                     hydrated from that file)
    │
    └─► clientKey   e.g. oauth:72d3b599cda9f8cc
                    THIS is what requireOwnedDispatch / requireOwnedHandle
                    key on. Not present in the runtime.
```

Half that still lives in a plantable bridge file: **the last hop**.
`clientKey → senderHandle` is written by `persistSenderPin` to
`~/.orca-bridge-sender-pins.json` (0600) and reloaded by
`loadPersistedPins()` at bridge boot — same shape as the NAS-248
ownership store, different filename.

NAS-248's `dispatch-ownership.json` (not on this live host; code
@ `65f3a8a`) would be a second bridge-file hop:
`dispatchId → clientKey` written by `persistOwnershipBindings`
and trusted by `loadPersistedOwnership`. That is the file the
ticket wants to delete. Deleting it does not delete the pin
file, and the pin file is what turns a runtime handle back
into a `clientKey`.

No runtime field identifies an OAuth client, session token, or
MCP `clientKey`. Searched every text column of a WAL-inclusive
copy of `orchestration.db`; the only `oauth:` / `clientKey` hit
was this ticket's objective string.

---

## Evidence table

| Claim | Evidence |
| --- | --- |
| Live runtime is 1.4.180 / `9fb4ec9b-…` with the listed capabilities | `orca-ide status --json` → `runtime.appVersion`, `runtime.runtimeId`, `runtime.capabilities` includes `orchestration.contract.v1`, `orchestration.federation.v1`, `orchestration.federation-control-mail.v1`, `workspace-run-context.v1`, `task-source-context.v1`, `agent-session.host-authority.v1`, `agent-session.session-boundary.v1`, `files.mutation-ownership.v1` |
| Live bridge is 0.3.0, not NAS-248 | `npm ls -g` → `orca-mcp@0.3.0`; `/proc/159345/cmdline` = `node /usr/bin/orca-mcp --port 8787`; `~/.orca-bridge/` has `audit.ndjson` only, no `dispatch-ownership.json` |
| NAS-248 hydrates `dispatchId+clientKey` from a 0600 file at boot | `BuildContext/nas-248-ownership-invariant:server.mjs` `OWNERSHIP_STORE` / `loadPersistedOwnership` / `persistOwnershipBindings` (lines 334–470 of that file). `bindOwner` refuses reassignment (`lib/audit.mjs` ~539). Corrupt/missing store fail-closed (ticket + that function's `catch` returns 0) |
| `dispatch-show` returns worker identity, not coordinator | `orca-ide orchestration dispatch-show --task task_be9ba2bbaf8b --json` → `dispatch.id=ctx_d873be6e19c7`, `run_id=run_024f8e980759`, `assignee_handle=term_af9b4b36-…` (this worker). No `from`, no `coordinator_handle`, no `clientKey`. Handler (`out/main/index.js:93569-93593`) returns `{ dispatch: ctx }` only |
| `run-show` / `run-list` return the originating-coordinator handle | `orca-ide orchestration run-show --id run_024f8e980759 --json` → `coordinator_handle=term_4f8d8fb4-1c6c-49e8-96df-057428ac0c5c`, `coordinator_pane_key=a1d01306-…:f0326be9-…`. Same row in `run-list --limit 20` |
| `task-list --run` returns immutable creator handle + dispatch id | `orca-ide orchestration task-list --run run_024f8e980759 --json` → `created_by_terminal_handle=term_4f8d8fb4-…`, `dispatch_id=ctx_d873be6e19c7`, `assignee_handle=term_af9b4b36-…` |
| Those two handle fields exist in the runtime DB, not just the CLI envelope | WAL-inclusive snapshot of `~/.config/orca/orchestration.db`: `runs.coordinator_handle`, `tasks.created_by_terminal_handle` match the probes. Schema: `CREATE TABLE runs (… coordinator_handle TEXT …)`, `CREATE TABLE tasks (… created_by_terminal_handle TEXT …)` |
| `created_by_terminal_handle` is INSERT-only | `out/main/index.js:86713` INSERT; grep of that file shows no `UPDATE … created_by_terminal_handle`. `runs.coordinator_handle` **is** rewritten by `bindRun` (`85963-85967`) on `run-use` when the caller handle/pane differs |
| `worker-show` / `worker-read` / `worker-list` do **not** see this dispatch | `worker-show --dispatch ctx_d873be6e19c7` → `dispatch_not_found`. `worker-read` → `has no agent terminal`. `worker-list` returned 17 rows; this `ctx_d873be6e19c7` is absent. Cause: this dispatch is an `orchestration.dispatch` mailbox context (`dispatch_contexts` row) with **no** `worker_dispatches` row. `workerShow` requires both (`91065-91067`) |
| `worker-list` fields are worker-side only | Sample keys: `dispatchId, taskId, runId, workerState, terminalState, agentTerminalHandle, dispatchStatus, resource`. No coordinator / from / clientKey |
| `terminal show` / `terminal list` carry no owner | Keys: `handle, ptyId, incarnationId, orphaned, worktreeId, worktreePath, branch, tabId, leafId, title, connected, writable, lastOutputAt, preview`. Coordinator title on this host is rewritten to `orca@orca-server-1: ~/src/rahunok-space` (no oauth suffix) |
| `worktree show` / `worktree current` / `worktree ps` carry no coordinator | `lineage: null`. `cliProvenance.kind=created-by-cli`, `createdWithAgent=grok`. `linkedTaskSourceContext: null` |
| `check --all` on the worker handle returns run+dispatch, not coordinator | `{ runId, dispatchId, messages: [], count: 0 }` |
| `check --all --terminal <coordinator>` from this worker is fenced | `consumer_fenced`: attested as `term_af9b4b36-…`, cannot act as `term_4f8d8fb4-…`. Identity exists, but this worker cannot read the coordinator's mailbox |
| `inbox` messages have `from_handle` = sender of that message (worker, here), not originating coordinator | Heartbeats from this worker: `from_handle=term_af9b4b36-…`, `to_handle=run:run_024f8e980759` |
| `run-current` from this worker is unbound | `{ run: null }`. `task-list` without `--run` → `run_required` |
| Runtime has no `clientKey` | sqlite scan of all tables/columns on the WAL snapshot: only hit is `runs.objective` containing the ticket text |
| Bridge maps `clientKey → handle` via a plantable file | Copy of `~/.orca-bridge-sender-pins.json` (0600): `oauth:72d3b599cda9f8cc` → `term_4f8d8fb4-1c6c-49e8-96df-057428ac0c5c` (`source=pinned`, `at=2026-08-13T04:16:34Z`). Three other keys (`master`, two other `oauth:`) pin three other handles. Loader: `/usr/lib/node_modules/orca-mcp/server.mjs:215-259` |
| Pin rediscovery without that file will not rematch this coordinator | `resolveSenderTerminal` (`server.mjs:630-785`): trust pin → revalidate pin → env → exact title → title suffix (first 10 chars of clientKey) → **create a new tab**. Live coordinator title is `orca@orca-server-1: ~/src/rahunok-space`, which equals none of those and does not contain `72d3b599cd`. Code comment at 625-628 states title rediscovery creates a sibling tab |
| `requireOwned*` keys on `clientKey`, not handle | NAS-248 `lib/state-ownership.mjs:683-728` `resolveDispatchOwnership(dispatchId, clientKey, …)` / `collectDispatchIdSets` walk `clientOwnership` + `dispatchRegistry` rows' `clientKey` |
| Worker processes survive a **bridge** restart | grok pid 232125 parent chain: `grok` → bash rcfile → `orca-ide daemon-entry.js` → `orca-ide --serve` (pid 167111). Bridge pid 159345's only child during the probe was an `orca-ide` CLI `orchestration check --wait` it spawned. Workers are not children of the bridge |
| Runtime RPC auth is a single host token on a same-uid socket | `~/.config/orca/orca-runtime.json` mode 0600, keys `runtimeId, pid, transports, authToken, startedAt`. Transport `unix` → `/home/orca/.config/orca/o-167111-9fb4.sock` mode 0600. CLI writes `authToken` on connect (`out/cli/runtime/transport.js:139-149`). Server accepts iff `request.authToken === this.authToken` (`out/main/index.js:201297-201298`). Token is `randomBytes(24).toString("hex")` (`200632`) |
| WS on `0.0.0.0:6768` is a second listener | `ss`: `orca-ide` listens `0.0.0.0:6768` and `127.0.0.1:42097`. WS path requires a **device** token (`201325-201331`), not the unix `authToken`. Port 42097 answered `HTTP/1.1 404` to `GET /` |
| Same-uid can also read the daemon token | `/home/orca/.config/orca/daemon/daemon-v32.token` mode 0600, socket `daemon-v32.sock` mode 0600 |
| Capabilities named in the ticket do not carry coordinator/OAuth identity | `task-source-context.v1` / `workspace-run-context.v1` are project/repo/path (`out/shared/task-source-context.js`). `agent-session.host-authority.v1` is TUI session claim digests keyed by `~/.config/orca/agent-session-authority.key` (0600, same uid). `files.mutation-ownership.v1` is a capability assert only (`file-mutation-ownership.js`). Federation tables (`federated_dispatches`, `remote_dispatch_attachments`) store peer environment / remote terminal, not `clientKey` |
| CLI surface enumerated from the shipped 1.4.180 handlers, not assumed | Read verbs probed: `run-list`, `run-show`, `run-current`, `task-list`, `dispatch-show`, `worker-show`, `worker-read`, `worker-list`, `check --all`, `inbox`, `gate-list`, `terminal list`, `terminal show`, `worktree list` (via current/show/ps). Mutations (`dispatch`, `worker-stop/abandon/release/retain`, `reset`, `run-create/use`, `task-create/update`, `send`, `reply`) were not invoked except the required worker heartbeats/ask-channel already in contract |

### CLI identity field cheat-sheet (this dispatch)

| Command | Identity-bearing fields actually returned |
| --- | --- |
| `dispatch-show --task` | `id, run_id, task_id, assignee_handle` (worker), pane/capability hashes. **No coordinator** |
| `run-show` / `run-list` | `coordinator_handle`, `coordinator_pane_key` |
| `task-list --run` | `created_by_terminal_handle`, `created_by_pane_key`, `created_by_process_incarnation`, `dispatch_id`, `assignee_handle` |
| `worker-show` / `worker-read` | n/a — `dispatch_not_found` for mailbox dispatches |
| `worker-list` | worker handle + run/task ids; this mailbox dispatch absent |
| `terminal show/list` | handle, pty, title, worktree. No owner |
| `worktree show/current/ps` | lineage null; no coordinator |
| `check --all` (own handle) | `runId`, `dispatchId` |
| `inbox` | `from_handle` of each message (sender of that message) |

---

## What breaks on bridge restart vs runtime restart

### Bridge process restart (the case direction (2) must cover)

**Not lost (proven without restarting):** worker PTYs and the runtime DB
are owned by `orca-ide` (pid 167111 / daemon-entry), not by
`orca-mcp` (pid 159345). `orchestration.db` is under
`~/.config/orca/`, not `~/.orca-bridge/`. Live CLI reads of
`run-show` / `task-list` / `dispatch-show` therefore remain
available to a newly started bridge.

**Lost in the live 0.3.0 bridge (in-memory only):**
`clientOwnership` and `dispatchRegistry` (`server.mjs:167-266`).
A 0.3.0 restart already forgets who owns what. NAS-248 added
`dispatch-ownership.json` specifically to refill those maps.

**Lost even if the runtime half is used to refill them:**
the `clientKey` side of each row. Runtime can refill
`dispatchId → handle`. It cannot refill `dispatchId → clientKey`
unless the new bridge process also reads
`~/.orca-bridge-sender-pins.json` (or waits for each OAuth
client to reconnect and somehow prove it is that handle).

**Reconnect without the pin file (deduced from live title +
`resolveSenderTerminal`, not from a restart):** the new bridge
creates a **new** sender tab. `run-use` with that new handle
executes `UPDATE runs SET coordinator_handle = ?` (`bindRun`).
That would *move* the runtime's current-binder field to the
new tab. `tasks.created_by_terminal_handle` would still name
the old tab. A naive "trust `runs.coordinator_handle` after
reconnect" hydrate is a claim path. A hydrate that keys on
`created_by_terminal_handle` keeps the original handle, which
the newly created pin will not match — so the reconnected
client still cannot `requireOwnedDispatch` until something
maps the new pin to the old handle.

### Runtime process restart

**Not performed** (forbidden). Deduced from code + process tree:

- `orchestration.db` is a durable sqlite file. Schema and
  current rows live there. A new runtime process that reopens
  the same userData path should see the same
  `runs` / `tasks` / `dispatch_contexts` rows. **UNPROVEN
  live.**
- Worker processes are descendants of `orca-ide`. Killing the
  runtime kills them. After a runtime restart there are
  typically **no live workers to re-attribute** — only tombstone
  rows. `workerShow` already special-cases
  `worker.runtime_epoch !== runtime.getRuntimeId()` by marking
  `start_unknown` / `stop_unknown` (`out/main/index.js:91119-91121`).
- Direction (2) does not get a free answer for the
  runtime-restart case: there is nothing live to rebuild
  ownership over. Coordinators would be releasing dead
  handles. Fail-closed is the honest posture.

---

## Trust analysis of the runtime channel

The local CLI does not talk to a privileged broker. It reads
`~/.config/orca/orca-runtime.json` (0600, uid 997 = `orca`)
and connects to the unix socket listed there (also 0600, same
uid), presenting `authToken`. The server compares that string
with the in-process token (`===`). Any process running as the
bridge's uid — every dispatched worker on this host — can:

1. read the token,
2. connect to the socket,
3. invoke any unix RPC the CLI can, including
   `orchestration.runUse` (which rewrites `coordinator_handle`)
   and the various list/show reads.

`orchestration.db` is the same 0600 file. A same-uid process
can plant `coordinator_handle` / `created_by_terminal_handle`
while the runtime is down the same way it can plant
`dispatch-ownership.json` while the bridge is down.

The WS listener on `0.0.0.0:6768` is a different gate (device
registry token, not the unix `authToken`). That does not
rescue the unix path the bridge actually uses (`orca-ide`
CLI → unix socket).

So: runtime-provided attribution is **not** more trusted than
the ownership file against the NAS-249 threat model. Both are
permission-protected same-uid state. Direction (2) changes
*where* the bind record lives (runtime sqlite vs bridge json),
not *who can write it*.

`audit.ndjson` (`~/.orca-bridge/audit.ndjson`) does record
`clientKey` per bridge action. It is another bridge-written
same-uid file. Using it to rebuild ownership is not a runtime
source and is the same oracle class.

---

## UNPROVEN (with the experiment)

| Item | Why unproven | Experiment (do not run on this live contour without an explicit go) |
| --- | --- | --- |
| `orchestration.db` rows survive a real runtime process restart | File-backed sqlite + WAL strongly suggest yes; not restarted | Restart only `orca-ide`, then `run-show --id run_024f8e980759` and `task-list --run` and compare `coordinator_handle` / `created_by_terminal_handle` |
| Worker PTYs die with the runtime | Parent is `orca-ide`; not killed | Same restart; `terminal show --terminal term_af9b4b36-…` should fail or `orphaned=true` |
| Stolen unix `authToken` can actually invoke RPC | Code path is `===`; not exercised (would be an impersonation test) | From a same-uid helper, connect to `o-167111-9fb4.sock` and send `status.get` with the token from `orca-runtime.json`. Stop at `status.get` |
| `run-use` from a newly created sender rebinds `coordinator_handle` | `bindRun` UPDATE is in the binary; not live-tested | On a disposable run: `run-use --id <run> --from <other-live-handle>` and re-`run-show`. Do not do this to `run_024f8e980759` |
| Title rematch after deleting the pin file | Live title + code say it will create a sibling; not deleted | Isolated bridge process with `HOME` pointing at a copy of the pin-less state, call `resolveSenderTerminal`, compare handle to `term_4f8d8fb4-…` |
| `worker-start` supervised workers expose a coordinator field the mailbox path lacks | This host's 17 `worker_dispatches` were not this ticket's dispatch; `worker-list` keys have no coordinator | `worker-show` on one of those 17 ids (read-only) and inspect keys. Still will not yield `clientKey` |
| WS `:6768` can be used to read orchestration state without a device token | Handler rejects missing device token | `curl`/raw WS without a token; expect `unauthorized` |
| Hydrate-from-runtime after a real NAS-248 bridge restart | Live bridge is 0.3.0; NAS-248 not installed; restart forbidden | Install NAS-248 in a throwaway process, dispatch, restart *that* process only, ask it to rebuild from `run-list`+`task-list` with the pin file removed vs present |

---

## If PARTIAL: what direction (1) minimally requires

Direction (2) can feed `dispatch → handle` from the runtime.
It cannot produce an unforgeable `dispatch → clientKey`, and
the handle itself is forgeable by the same uid via the unix
RPC or the sqlite file.

To keep `clientKey` as the ownership principal and survive
bridge restart without a plantable bind oracle, direction (1)
has to put the bind record (and, if pins remain the
handle↔client map, the pin record) behind a secret or uid
that **workers cannot read or write**:

- HMAC/sign `dispatch-ownership.json` (and, if still used,
  `~/.orca-bridge-sender-pins.json`) with a key that is not
  in any 0600-orca file (`~/.orca-bridge/*`,
  `~/.config/orca/*`, `/tmp/orca-state-*`). A key sitting
  next to the store is the same oracle.
- Or run the store / signer as a different uid (privileged
  helper, systemd `DynamicUser`, root-owned 0400 key + 0200
  helper socket).
- Reject any hydrate row whose MAC fails; missing store
  stays fail-closed (already true on NAS-248).
- Do not re-introduce a claim path (`await` must not
  `bindOwner`; `run-use` from a new pin must not be treated
  as proof of the old `clientKey`).

Signing with a same-uid-readable key, or moving the JSON
into `orchestration.db` without a second uid, is direction
(2) under another name.

---

## Non-goals (not investigated)

P0 #3, P0 #5, hardening-off gap, F3, F5, implementation,
tests, Linear updates, recommendation between remaining
NAS-248 follow-ups.
