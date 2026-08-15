<!-- BEGIN GENERATED: coordinator-discipline -->
# Coordinator discipline (served by `orca{action:"guide"}`)

Long-form rules that **should not** live in the MCP client system prompt.
Bridge ≥ 0.2.9 returns the same structure via `action=guide`.

> **Generated** from `lib/coordinator-doctrine.mjs`. Edit the doctrine module, then run `npm run docs:build`.

## Supervised flow

```text
dispatch → await(≤45s)×N [honor liveness] → worker_done → release(dispatchId, terminalHandle) → read-only
```

Optional diagnostics (compact default: version, versionOk, statusProbe.ok, defaultRepo, next). Pass verbose:true for full statusProbe/actionAnnotations. Not required before each wave — dispatch/await/release self-diagnose runtime/version failures.

| await `summary.status` | Action |
|------------------------|--------|
| empty / timeout (active|idle) | Call `await` again — **normal** early; watch `liveness` + `emptyWindowsConsecutive` |
| empty + liveness=stalled | `check --peek` → optional ping → `release` + report owner (**stop-condition**) |
| question | `cli` → `orchestration reply --id … --body … --json`, then `await` + `ack` |
| escalation | `cli` → `orchestration reply` (bridge dual-routes onto `dispatch:<id>`), then `await` + `ack`; prefer `orchestration ask` for back-and-forth |
| worker_done | `release` with `dispatchId` + worker `terminalHandle`; outcome = body + filesModified |

next.action is a **hint**. Prefer summary.status when they disagree. On empty windows also honor liveness (stalled → diagnose, not blind re-await).

### Liveness stop-condition

- Escalate when `liveness=stalled` (default: ≥ **8** empty ~45s windows, or ~**8 min** without activity).
- Hard ceiling ~**15 min** without progress → release with diagnostics and report to owner.
- Protocol: `check`/`cli` peek → optional worker ping (`terminal send --enter`; `--interrupt` if stuck) → release + owner report. Do **not** infinite-loop `await` on empty.

## Waves

- One wave = one run_id (omit runId on first dispatch; pass same runId on later workers).
- Parallel: N dispatch then one await loop — bridge serializes dispatch/await per OAuth client (0.2.11+); safe to issue N in parallel.
- Each OAuth client gets a durable sender pin-by-handle (0.2.12+) — shell may rewrite tab title; bridge must not recreate mid-wave.
- Two coordinators on one bridge no longer fence each other when they use separate OAuth tokens.
- Keep-list (worktree path/id + dispatch_id + terminal_handle) is yours; do not copy foreign inventory into it.
- await may report foreign_messages — never release those; next.action never targets foreign dispatch_id.

## Brief template (`spec`)

The bridge **appends** a `worker_done` contract itself. Still spell out in the brief:

1. Goal + Definition of Done + explicit non-goals (no merge/main/eas without owner order).
2. Repo/worktree context; linked issue id if any.
3. worker_done contract is auto-appended by the bridge — you may still restate it.
4. Cleanup tasks: only touch keep-list objects; never foreign terminals in default-worktree.
5. UI tasks: devices/dev.mjs acquire → exec → release in finally; stable --owner; no positional UDID.

## Anti-patterns (“wait until ready”)

| Don't | Why |
| --- | --- |
| `worktree create --agent --prompt` | blocked on action=cli; no completion signal |
| `terminal wait --for tui-idle/exit as completion` | idle ≠ done; omp rarely exits |
| `single await waitMs > 45000 when client wrapper ~60s` | prefer 45000 and re-call; hard max 240000 |
| `success from terminal preview text` | only `worker_done` + outcome |
| `release on timeout / empty while active|idle` | only after `worker_done` (or stalled diagnose) |
| `health before every wave as a ritual` | use on demand; runtime errors self-diagnose |
| `infinite await on empty when liveness=stalled` | diagnose / ping / release+report |

`terminal read --limit N` is for liveness/debug, not a substitute for `await`.

## Raw `cli` — exact-form contract

- CONTRACT (NAS-254): `action=cli` admits only an **exact command form** — exact command path (never a prefix hit) + only the flags listed for that path + the value grammar below. Short options fail closed. Hardening is ON by default (NAS-227). Globals on every form: `--help --json --pairing-code --environment`.
- Value grammar: `orchestration check` refuses `--peek` together with `--all` (exactly one read mode). `worktree create --agent --prompt` is always-on `forbidden_handoff` (use `action=dispatch`). Ownership of `--terminal` / `--dispatch` / `--worktree` / `--task` / `--run` / `--id` selectors is independent of the hatch — foreign targets deny either way.
- OK-tier (default surface, no admin unlock): `status`; `worktree list` (`--repo --limit`); `worktree show` (`--worktree`); `terminal list` (`--worktree --limit --include-visual-layouts`); `terminal read` (`--terminal --cursor --limit`); `terminal close` (`--terminal --tab`); `skills get` (alias `skills show`; positional `topic` / `--topic --full`); `orchestration check` (`--terminal --run --ack --unread --peek --all --types --format --wait --timeout-ms --retry-request`; peek⊕all mutex); `orchestration reply` (`--id --body --run --from --retry-request`); `orchestration worker-show` (`--dispatch`); `orchestration worker-read` (`--dispatch --source --cursor --limit`); `orchestration dispatch-show` (`--task --preamble --from`).
- ADMIN-tier (admin toolset / `ORCA_BRIDGE_CLI_ADMIN=1`): `terminal send` (`--terminal --text --enter --interrupt`; shell: one `--text … --enter`; TUI compose box: that plus a following empty `--enter`; `--interrupt` if stuck; no `--submit`); `terminal create` (`--worktree --command --title --focus`); `worktree create` (`--repo --project --host --project-host-setup --name --agent --prompt --base-branch --issue --linear-issue --comment --setup --parent-worktree --no-parent --run-hooks --activate`); `worktree rm` (aliases `remove`/`delete`; `--worktree --force --run-hooks`); `orchestration send` (`--to --run --from --subject --body --type --priority --thread-id --payload --task-id --dispatch-id --dispatch-capability --retry-request --outcome --files-modified --report-path --phase`); `orchestration task-create` (`--spec --task-title --display-name --deps --parent --run --from --retry-request`); `orchestration worker-start` (`--task --on --worktree --name --repo --base-branch --display-name --comment --setup --agent --model --effort --terminal --retry-of --timeout-ms --run --from --retry-request`); `orchestration dispatch` (`--task --to --from --run --inject --dry-run --return-preamble --retry-request`); `orchestration run-create` (`--objective --from --retry-request`); `orchestration run-use` (`--id --from --takeover-legacy --retry-request`). Anything else denies and does not spawn.

Not allowed:

- worktree create --agent --prompt as main work path (enforced reject)
- prefer action=await over raw orchestration check except debug / stalled diagnose

## Devices

- One UI slot; only one worker should hold devices at a time.
- iOS Simulator = Mac only; Android usually VM
- devices/dev.mjs acquire → exec → release; DEVICES_OWNER / --owner stable

## Release (inject path)

After inject-path worker_done, dispatch is already settled; worker-release often returns dispatch_not_found. release still closes the tab when terminalHandle is passed — that is success.

Pass the **worker** `terminal_handle` from the `dispatch` response, never the
coordinator sender from `health`.

## Post-done read-only

After `worker_done` the coordinator may inspect: git status/diff/log, grep, files.
Patches / commits / package installs / fixes → **new dispatch** (flow step 4).
Close any raw terminals you opened immediately after reading.
<!-- END GENERATED: coordinator-discipline -->
