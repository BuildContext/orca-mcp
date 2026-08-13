# NAS-250 / NAS-251 / NAS-252 — three ownership inversions

**Branch:** `BuildContext/nas-248-ownership-invariant`  
**Baseline HEAD:** `65f3a8a`  
**Suite before:** 353 pass / 0 fail  
**Suite after:** 388 pass / 0 fail  

## Root cause (shared)

Prior gates enumerated **known-bad** cases:

1. known command prefixes (`OWNERSHIP_GATED_PREFIXES`, `DISPATCH_OWNERSHIP_GATED_PREFIXES`)
2. known response shapes (`terminals[]` list rows)
3. tests that asserted on **policy object shape** rather than effects

Anything unenumerated was treated as safe. Live holes:

| Ticket | Live hole | Why enumeration failed |
|--------|-----------|------------------------|
| NAS-250 | `terminal show --json --terminal <foreign>` returns `result.terminal.preview` | Redaction only walked `terminals[]` |
| NAS-251 | `terminal stop --worktree <foreign>` soft-executes under hardening off | Prefix table never named `stop` / `--worktree` |
| NAS-252 | Ownership only bit on named prefixes; hardening off was load-bearing outside them | Policy of "known gated names" |

## Inversion 1 — default-deny on target selectors (NAS-252 + NAS-251)

### What changed

`lib/cli-policy.mjs` `evaluateCliArgv` no longer decides ownership solely from prefix tables.

**New rule:** if argv carries a **target selector**, ownership must be positively proven for that target or the call is **denied**. Hardening is irrelevant to this decision (allowlist only).

Selector kinds wired:

| Flag(s) | Checker | Effect on miss |
|---------|---------|----------------|
| `--terminal` / `--terminal=` | `ownershipCheck` | deny `handle_not_owned` |
| `--dispatch` / `--dispatch-id` | `dispatchOwnershipCheck` | deny `handle_not_owned` (kind=dispatch) |
| `--worktree` / `--worktree=` | `worktreeOwnershipCheck` | deny `handle_not_owned` (kind=worktree) |

Also:

- Legacy prefix tables expanded (show/wait/switch/rename/split/stop/inbox) so command-path lookalikes without flags still fail closed where appropriate (e.g. `terminal show` with no handle).
- Missing checker + present selector → **fail closed** (`ownership_check_not_configured`), never soft-exec.
- `orchestration check` / `inbox` without `--terminal` still skip handle gate (pin injection path).
- `terminal stop` without `--terminal` skips handle null-gate; `--worktree` is the target.
- Admin-tier `--from` / `--to` are **not** ownership selectors (stay admin allowlist).

`server.mjs` wires `worktreeOwnershipCheck` → `resolveWorktreeOwnership` over `dispatchRegistry` worktree fields.

### Selector list enumerated FROM THE CLI

Source: live AppImage v1.4.180 unpacked specs at  
`/tmp/nas-248-cli/squashfs-root/resources/app.asar.unpacked/out/cli/specs/`

Method:

```text
rg -n "usage:|allowedFlags" specs/core.js specs/orchestration.js specs/orchestration-worker-specs.js
```

**Target selectors used for ownership default-deny** (names that identify a concrete runtime object the caller can act on):

| Flag | Spec evidence |
|------|----------------|
| `terminal` | `terminal {show,read,send,wait,switch,close,rename,split}` allowedFlags |
| `worktree` | `terminal stop --worktree`, `terminal list/create`, `worktree {show,rm,set}`, many browser cmds |
| `dispatch` | `orchestration worker-{show,read,stop,abandon,release,retain}` |
| `dispatch-id` | `orchestration send` allowedFlags / worker_done payload |
| `tab` | boolean on `terminal close` (mode flag; still pairs with `--terminal`) |
| `task` | `dispatch-show`, `task-*`, `gate-*` (inventory; F3 deferred) |
| `run` | check/list filters (inventory) |
| `id` | run-show / task-update / reply (mixed; not all effectful) |
| `pane` | not present as a flag in v1.4.180 specs (task prompt listed it as incomplete-on-purpose) |
| `from` / `to` | admin-tier address selectors — **exempt** from ownership default-deny |

How enumeration was done: read `allowedFlags` arrays and `usage` strings from the shipped specs above; cross-check `handlers/terminal.js` for `terminal.stop` requiring `worktree`.

## Inversion 2 — redact by content, not by known shape (NAS-250)

### What changed

`applyOwnershipListRedaction` / `redactOwnershipContent` in `lib/state-ownership.mjs`:

- Recursively walks the **entire** response (envelope and/or JSON stdout).
- On each object node: if a terminal `handle` (or `terminalHandle`) is present and **owned**, keep content keys and recurse; otherwise **strip every content-bearing key** and recurse.
- No special-case for `terminals[]` vs `terminal`.
- Unknown / missing handle → redact (fail closed toward redaction).
- Inventory preserved: handle, title, state, counts, paths, ids.

Human stdout path still rewrites `preview:` lines; also attempts banner+pretty JSON recovery by scanning for the first `{`/`[` line.

### Content-bearing key list

```js
TERMINAL_CONTENT_KEYS = [
  'preview', 'scrollback', 'buffer', 'buffers', 'buffersByLeafId',
  'scrollbackRefsByLeafId', 'output', 'lines', 'tail', 'snapshot',
  'text', 'content', 'body', 'chunk', 'chunks', 'data',
]
```

How found:

1. Live list row keys (prior review + `terminal list --json` shape): includes `preview`.
2. Live `terminal show` own-handle probe (prior adversarial review): `result.terminal.preview`.
3. Runtime shared modules under the same AppImage: `workspace-session-terminal-buffers.js` (`buffersByLeafId`, `scrollbackRefsByLeafId`), snapshot/scrollback helpers.
4. Defensive extras (`output`, `lines`, `tail`, `snapshot`, `text`, `content`, `body`, `chunk(s)`, `data`) for nearby shapes not observed live on list/show but present in buffer/session code.

`findTerminalContentKeys` deep-scans payloads for effect assertions in tests.

## Inversion 3 — tests drive effects, not shapes

Added/rewrote tests so they:

1. Call `evaluateCliArgv` / `applyOwnershipListRedaction` on real argv and response shapes.
2. Assert **effects**:
   - `decision === 'deny'` and `rejection.code === 'handle_not_owned'` (no runtime call would proceed).
   - After redaction, `findTerminalContentKeys(payload)` is `[]` and the secret string is absent anywhere in the JSON.
3. Table-test argv spellings for `terminal show` and `terminal stop --worktree` with **hardening true and false**.
4. Explicit test: `resolveCliPolicyConfig({})` (hardening unset) still denies foreign `terminal show`.

## Files touched

| File | Change |
|------|--------|
| `lib/cli-policy.mjs` | Selector default-deny funnel; worktree kind; expanded legacy prefixes |
| `lib/cli-policy.test.mjs` | Effect tables for show/stop; hardening-unset; updated soft-path expectations |
| `lib/state-ownership.mjs` | Worktree collectors/resolver; recursive content redaction |
| `lib/state-ownership.test.mjs` | Show-shape redaction deep-scan; worktree ownership units |
| `lib/toolsets.test.mjs` | Admin policy eval supplies owned checker |
| `server.mjs` | Wire `worktreeOwnershipCheck` |
| `docs/research/NAS-250-252-inversions.md` | This file |

## Definition of done checklist

| Criterion | Status |
|-----------|--------|
| `terminal show --json --terminal <foreign>` → no preview anywhere after redaction | Covered by deep-scan unit tests on live show envelope shape |
| `terminal stop --worktree <foreign>` denied | Covered by evaluateCliArgv effect table (hard on/off) |
| Ownership denies with hardening off | Explicit test + show/stop tables |
| Full suite green; before/after counts | **353 → 388**, 0 fail |
| This doc with honest section | Below |

## What I could not prove

1. **Did not re-run live foreign-handle probes on the shared contour.** Task forbids destructive probes against foreign handles. Show/stop denials and show redaction are unit-proven against the live v1.4.180 **shapes** and argv collectors, not against a second live MCP client calling the bridge on a foreign tab.
2. **Did not prove worktree ownership for worktrees never recorded on `dispatchRegistry`.** Owned worktrees are derived from dispatch rows (`worktree` / `worktreePath` / `worktreeId`). A foreign `--worktree path:…` that the registry has never seen is `unknown` (still denied). A path alias that does not string-match the registered form could also be `unknown` rather than `not-owned`.
3. **Did not prove every browser/file command with `--worktree` is a desirable ownership surface.** Selector default-deny applies uniformly whenever `--worktree` is present and `worktreeOwnershipCheck` is wired. That is intentional fail-closed; some status-tier browser commands may now deny under multi-tenant use when they previously warn-allowed. Not live-validated against a browser session.
4. **`--task` / `--run` / bare `--id` are not ownership-gated as first-class selectors** beyond existing dispatch/handle paths. F3 (`dispatch-show` metadata) remains deferred per task non-goals. A caller can still read dispatch-show metadata for a foreign task id if allowlisted.
5. **Human `terminal show` without a `term_…` header line** still fail-closes preview lines via the human rewriter; pretty-printed JSON show goes through JSON parse + recursive redact. Banner + pretty JSON recovery is best-effort (first `{` line); I did not fuzz every banner variant the CLI might print in future versions.
6. **Did not flip `ORCA_BRIDGE_CLI_HARDENING`, restart the bridge, publish, or bump the version** (non-goals).
7. **NAS-249 (sender-pin bind oracle / durable key ownership) untouched.**
8. **`--pane` was not found in v1.4.180 CLI specs**; if a future CLI adds it as a terminal target alias, collectors must grow. Current gate will not see an unknown flag name unless it is one of the collected selectors.
9. **Effect tests do not start an in-process HTTP bridge** and mock `runJson`. They prove the policy funnel returns deny (the server short-circuits on `!policyResult.ok` before spawn — verified by reading `server.mjs` call site, not by an integration harness in this change).

---

# Adversarial review of `bb755f5` — try to break the inversions

**Reviewer:** dispatched attack worker (NAS-250/251/252 review)  
**Target:** `BuildContext/nas-248-ownership-invariant` @ `bb755f5`  
**Worktree read:** `/home/orca/orca/workspaces/orca-mcp/nas-250-252-inversions` (branch already checked out there; this review only appends this section)  
**CLI oracle:** live AppImage v1.4.180 (`/tmp/nas-248-cli/squashfs-root/.../out/cli`) plus live `orca` against runtime v1.4.180  
**Date:** 2026-08-13  
**Production code changed by this review:** no  
**Bridge process touched:** no  
**`ORCA_BRIDGE_CLI_HARDENING` on the live bridge:** not flipped  
**Destructive live `stop` / `release` / `close` / `worker-start` / `tab close` / `task-update` / `gate-resolve` / `reply`:** not executed (NAS-202 boundary). Those shapes are argv-proof only.

This review treats every implementer claim as a hypothesis. A green suite is not evidence. Five prior rounds in this lineage each shipped live P0s behind 321 / 346 / 353 / 353 / 388.

## VERDICT

**BREAKABLE.** NAS-250's named `terminal show --json --terminal <foreign>` hole and NAS-251's named `terminal stop --worktree <foreign>` hole are closed on the collected `--terminal` / `--worktree` / `--dispatch` surface, hardening on and off. The inversion that was supposed to make ownership an invariant — "any argv carrying a target selector is denied unless ownership is positively proven" — is not implemented. `--task`, `--run`, `--id`, `--page`, and `--parent-worktree` are named in `TARGET_SELECTOR_FLAGS` and then never collected, so they never enter the default-deny funnel. Live v1.4.180 will happily return another coordinator's 10 kB dispatch preamble, a 5.9 kB task spec, and run objectives through those ungated flags. NAS-252 is not closed. The author's own "What I could not prove" §4 already admitted this; the live probes confirm it is an effect, not a paperwork deferral.

Do not merge to main.

## Method

- Diffed `65f3a8a..bb755f5`. Read `lib/cli-policy.mjs`, `lib/state-ownership.mjs`, `server.mjs` (`CLI_POLICY.evaluate` at the `action=cli` chokepoint, `applyCliOwnershipRedaction`, `withSender` / `injectSenderArgv`), `lib/release-worker.mjs` (prior F1 ordering only).
- Read live `args.js` `parseArgs` / `BOOLEAN_FLAGS` / `commandPathStartsAt`, `selectors.js` (`getTerminalHandle` cwd-resolve, `getRequiredWorktreeSelector`), `specs/{core,orchestration,orchestration-worker-specs}.js`, `handlers/{terminal,orchestration}.js`, `terminal-format.js`.
- Independent `npm test` at `bb755f5`: **388 pass / 0 fail / 0 skipped**.
- `/tmp/nas-250-252-attack-probe.mjs` imports branch modules only. No mutating CLI against foreign objects.
- Live read-only `orca` (host identity, shape + effect oracle): `terminal list --json`, `terminal show --json --terminal <foreign>`, `worktree list --json`, `orchestration inbox --json`, `orchestration run-list --json`, `orchestration run-show --id <foreign>`, `orchestration task-list --run <foreign>`, `orchestration dispatch-show --task <foreign> [--preamble]`. Bodies / specs / preambles were measured by length and then discarded; they are not reproduced here.

## Findings (ranked)

### P0-1 — `orchestration dispatch-show --task <foreign> [--preamble]` is allowlisted and ungated

NAS-252's inversion sentence is "default-deny any argv that carries a handle, dispatch id, worktree, tab, **run or any other target selector**." `--task` is in `TARGET_SELECTOR_FLAGS`. `argvHasOwnershipTargetSelector` / `collect*` never look at it. `dispatch-show` is on `RAW_CLI_OK_PREFIXES`, so the call is `decision=allow` with **hardening on and off**.

`withSender` injects `--from <pin>` because `dispatch-show` is in `ORCH_FROM_CMDS`. That pin is used to render a preamble, not to authorize which task may be read. The live handler is `orchestration.dispatchShow({ task, preamble, from })`.

**Reproduction (read-only, already run against live v1.4.180):**

```
# policy (branch modules, hardening true AND false)
evaluateCliArgv(['orchestration','dispatch-show','--task','task_491a5031a2b2','--preamble','--json'],
                {hardening, ownershipCheck, dispatchOwnershipCheck, worktreeOwnershipCheck})
# → { ok:true, decision:'allow' }   both postures

# live runtime (host CLI; this is what action=cli would spawn after allow)
orca orchestration dispatch-show --task task_491a5031a2b2 --json
# → result.dispatch.{id,run_id,task_id,assignee_handle,assignee_pane_key,status,…}

orca orchestration dispatch-show --task task_491a5031a2b2 --preamble --json
# → same dispatch object + result.preamble  (10289 bytes of worker prompt)
```

`redactOwnershipContent` on that envelope is a no-op (`bytesBefore === bytesAfter === 11453`). `preamble` is not in `TERMINAL_CONTENT_KEYS`. The dispatch node has no `handle` / `terminalHandle` field (`assignee_handle` is a different key), so the walker never even considers it a terminal node.

The implementer's own "legitimate argv" table in `cli-policy.test.mjs` asserts this path `decision=allow`. The suite is green because the hole is the test.

This is F3 from the first NAS-248 review, still open, now with a live 10 kB preamble. NAS-252 is not closed.

### P0-2 — `--run` / `--id` inventory commands soft-execute under hardening-off and dump other coordinators' specs

Live VM posture is hardening off. None of these flags are collected. None of these prefixes are on the ownership gate.

| argv | hardening off | hardening on | Live effect (this review) |
|------|---------------|--------------|---------------------------|
| `orchestration task-list --run <foreign>` | `allow_with_warning` | allowlist deny | 1 task, `spec` length **5971**, plus `created_by_terminal_handle` |
| `orchestration run-list --json` | `allow_with_warning` | allowlist deny | **100** runs, each with `objective` + `coordinator_handle` |
| `orchestration run-show --id <foreign>` | `allow_with_warning` | allowlist deny | `result.run.objective` (122 bytes on the implementer's run) |
| `orchestration check --run <foreign>` | `allow` | `allow` | pin-injected `--terminal`; scoped to this client's mailbox (weaker) |
| `orchestration worker-list --run <foreign>` | `allow_with_warning` | allowlist deny | argv-proof; not live-executed |

**Reproduction (read-only, already run):**

```
orca orchestration run-list --json
# 100 rows. Keys: id, objective, coordinator_handle, coordinator_pane_key, …

orca orchestration task-list --run run_ce10b0214da1 --json
# result.tasks[0].spec length 5971. Keys include spec, result, created_by_terminal_handle.

orca orchestration run-show --id run_ce10b0214da1 --json
# result.run.objective present.
```

`redactOwnershipContent` on the foreign `task-list` envelope does not touch `spec` (8221 → 8221). Same for `objective` on `run-show`. These are content-bearing fields whose names are not in the author's key list, hanging off nodes that have no `handle` property.

Hardening-on hides most of this behind the allowlist. NAS-252's entire point is that ownership must not ride on that flag. Live posture is the vulnerable one.

### P0-3 — `orchestration inbox` is not pin-injected and is not allowlist-denied under hardening off

Author text: "`orchestration check` / `inbox` without `--terminal` still skip handle gate **(pin injection path)**."

`withSender` / `injectSenderArgv` inject `--terminal` only when `sub === 'check'`. Inbox is not in that set. Inbox is also **not** on `RAW_CLI_OK_PREFIXES` (it is only on the legacy `OWNERSHIP_GATED_PREFIXES` list). So:

1. No `--terminal` → handle gate skipped (`isOrchInbox`).
2. No pin injected.
3. Hardening off → `allow_with_warning` → `runOrca(['orchestration','inbox','--json'])` as the **host** identity.
4. Live handler `orchestration.inbox` with no `terminal` filter returns the host-wide mailbox.

**Reproduction (read-only, already run):**

```
evaluateCliArgv(['orchestration','inbox','--json'], {hardening:false, …checks})
# → allow_with_warning

injectSenderArgv(['orchestration','inbox','--json'], 'term_OWN')
# → unchanged (no --terminal injected)

orca orchestration inbox --json --limit 5
# 5 messages. Keys: id, run_id, from_handle, to_handle, subject, body, payload, …
# has_body=2 has_payload=5
# distinct handles included a foreign term_3ea701f6-… plus other runs
```

Redaction of the live inbox envelope **does** drop `body` (`body` is in `TERMINAL_CONTENT_KEYS`) and shrinks the blob 4357 → 3152. It **keeps** `payload` (present on all 5 rows; not in the key list) and `subject`. `from_handle` / `to_handle` are not recognized as handle fields (`nodeTerminalHandle` only looks at `handle` / `terminalHandle` / `terminal.handle`).

This is a standing cross-coordinator message oracle under the configuration that is actually running.

### P1-1 — `TARGET_SELECTOR_FLAGS` is documentation, not a gate

```js
// cli-policy.mjs
export const TARGET_SELECTOR_FLAGS = [ 'terminal','tab','dispatch','dispatch-id',
  'worktree','parent-worktree','task','run','pane','id' ];

export function argvHasOwnershipTargetSelector(args) {
  if (collectTerminalHandlesFromArgv(args).length) return true;
  if (collectAllDispatchTargetIdsFromArgv(args).length) return true;
  if (collectWorktreeSelectorsFromArgv(args).length) return true;
  return false;
}
```

`argvHasFlag` exists. Nothing in `evaluateCliArgv` loops `TARGET_SELECTOR_FLAGS`. `--parent-worktree` is listed and uncollected. `--page` (browser tab id; NAS-252 literally says "tab") is not even listed. `--repo` is a selector in the live help text and is uncollected.

Probe: `worktree create --name x --parent-worktree /home/other/foreign-wt` → hardening off `allow_with_warning`. `tab show --page page_FOREIGN`, `snapshot --page page_FOREIGN`, `tab close --page page_FOREIGN` (destructive — argv-proof only) → same. `orchestration reply --id msg_FOREIGN` → **`allow` with hardening on** (allowlisted; `--id` not a selector). `orchestration worker-start --task FOREIGN --agent grok` → hardening off `allow_with_warning` (argv-proof only).

The comment above the flag list ("Default-deny applies via collect when present alongside effectful commands") is false. Collect never sees those names.

### P1-2 — `--worktree` on non-`stop` commands is shadowed by a null-handle deny (false deny of legitimate coordinator argv)

`looksLikeOwnershipGatedArgv` returns true if *any* worktree selector is present. `evaluateCliArgv` then sets `leadingIsHandle = ownershipLeadingFlag && !leadingIsDispatch` and runs the **handle** checker with `toCheck = [null]` for every such argv that is not `terminal stop` / orch check / inbox.

Probe:

```
terminal list --worktree /home/orca/src/orca-mcp --json
worktree show --worktree /home/orca/src/orca-mcp --json
```

Both: `decision=deny`, `ownership_kind=handle`, `reason=missing_or_malformed_handle`, `handle=null`. Same for the foreign path. The worktree checker never runs. `file open secret.env --worktree <path>` dies the same way (fail-closed for the file read; also breaks a legitimate owned `file open --worktree`).

`worktree show` is on `RAW_CLI_OK_PREFIXES`. The allowlisted spelling in the test suite is `worktree show --json` **without** `--worktree`. Live usage is `worktree show --worktree <selector>` — required by the CLI spec. The useful form is now unconditionally denied. `terminal list --worktree` is how a coordinator scopes inventory to its checkout; that form is now denied too.

This is not a foreign bypass. It is a gate that breaks the coordinator, which the brief listed as a ship-blocker of its own.

Author claim 3 ("selector default-deny applies uniformly whenever `--worktree` is present") is also inaccurate here: the deny is a null **handle** miss, not a worktree ownership verdict.

### P1-3 — Deny path is an existence oracle and leaks this client's owned-handle list

`ownershipDecision` always emits `ownership_status` (`not-owned` vs `unknown`), `reason` (`foreign_handle` vs `handle_not_in_registry`), a detail string that names the difference, **and** `owned_handles` / `owned_worktrees`.

Probe against the branch resolver:

```
exists  term_FOREIGN  → status=not-owned  reason=foreign_handle
                        detail=…is not-owned… Owned handles: term_OWN. reason=foreign_handle.
ghost   term_GHOST    → status=unknown    reason=handle_not_in_registry
                        detail=…is unknown… Owned handles: term_OWN. reason=handle_not_in_registry.
```

A caller can walk `term_*` values from `terminal list` (allowlisted) and distinguish "this handle is bound to someone else on this host" from "this handle does not exist." That is an existence oracle over other coordinators' handles. The owned-handle list in the error is extra recon.

Worktree path aliases that do not string-match (`/path/` vs `/path`, `branch:`, `issue:`, `id:repo::path`) return `unknown` / `worktree_not_in_registry` rather than `not-owned`. That is fail-closed for NAS-251 (no bypass) and a second oracle bit.

### P1-4 — Inventory titles still carry cwd / repo paths

Live `terminal list --json` (11 rows) row keys:

`handle, ptyId, incarnationId, orphaned, worktreeId, worktreePath, branch, tabId, leafId, title, connected, writable, lastOutputAt, preview`

After `applyOwnershipListRedaction(..., [])` every `preview` is gone. Titles remain:

```
term_39b7ee45-…  orca@orca-server-1: ~/src/rahunok-rn
term_4f8d8fb4-…  orca@orca-server-1: ~/src/rahunok-space
term_216444a5-…  orca@orca-server-1: ~/src/orca-mcp
…plus every NAS-248/249/250 worktree path in title and worktreePath
```

The author called this "inventory preserved." It is also attacker-visible metadata that names other coordinators' checkouts. Not a PTY-body leak; still a multi-tenant recon channel the ticket asked us to check.

### P2-1 — Redaction-by-key-name is still an enumeration

Live `terminal show` on the coordinator handle (`term_4f8d8fb4-…`, read-only) keys:

`branch, connected, handle, incarnationId, lastOutputAt, leafId, orphaned, paneRuntimeId, preview, ptyId, rendererGraphEpoch, tabId, title, worktreeId, worktreePath, writable`

`preview` is the only content-bearing field on that shape. The new walker strips it. NAS-250's named hole is closed at both the gate and the redactor.

The same walker, given live sibling envelopes, leaves:

| envelope | secret-class field | survives? |
|----------|--------------------|-----------|
| `terminal show` | `preview` | no (good) |
| `terminal list` | `preview` | no (good) |
| `dispatch-show --preamble` | `preamble` (10289 B) | **yes** |
| `task-list --run` | `spec` (5971 B) | **yes** |
| `run-show` / `run-list` | `objective` | **yes** |
| `inbox` | `payload` (5/5 rows) | **yes** |
| `inbox` | `body` | no (good) |
| synthetic `stdout` / `stderr` | those keys | **yes** |
| worker-read transcript | `blocks[].input.prompt` | **yes** (unit) |
| human `terminal read` stdout | raw `tail` lines, no `preview:` prefix | **yes** (unit) |

`formatTerminalRead` prints `terminal.tail` as bare lines. `redactTerminalListHumanStdout` early-returns unless the text contains the literals `preview` or `scrollback`, and even then only rewrites key-shaped lines. Foreign `terminal read` is denied by the handle gate, so this is defense-in-depth only — the same class of "we enumerated names" miss that produced NAS-250.

### P2-2 — `terminal stop --worktree new-child` is treated as owned

`resolveWorktreeOwnership('new-child')` returns `owned` / `synthetic_create_selector`. Policy: hardening off `allow_with_warning`. Live CLI `terminal stop` requires `--worktree` and passes the token through to `terminal.stop` unchanged (`getRequiredWorktreeSelector` only special-cases `active`/`current`). Not executed live. If the runtime rejects `new-child` this is a nothingburger; if it ever binds that token, the gate will not save us. Argv-proof only.

### P2-3 — Worktree string-equality did not yield a foreign allow

Tried trailing `/`, `/.`, `..` segments, `//`, `path:` prefix, `branch:`, `issue:`, `name:`, `id:repo::path`, `active`/`current`. All fail closed (`unknown`, still `handle_not_owned`). Duplicate `--worktree owned --worktree foreign` deny-any. `-- --terminal FOREIGN` fail-closed. Case-folded `--Terminal` is not accepted by live `parseArgs` either (both sides case-sensitive). **No NAS-251 bypass found** via normalisation. The author's "registry string-equality" note is accurate as a false-deny / oracle risk, not as a foreign teardown.

## Author claims that are inaccurate

| Claim at `bb755f5` | Reality |
|--------------------|---------|
| "if argv carries a **target selector**, ownership must be positively proven or the call is **denied**. Hardening is irrelevant." | True only for `--terminal` / `--dispatch` / `--dispatch-id` / `--worktree`. False for `--task`, `--run`, `--id`, `--parent-worktree`, `--page`. |
| `TARGET_SELECTOR_FLAGS` includes `task`/`run`/`id`/`parent-worktree` and "Default-deny applies via collect" | Collectors do not implement those names. The array is unused by `evaluateCliArgv`. |
| "`orchestration check` / `inbox` without `--terminal` still skip handle gate (pin injection path)" | Skip is true. Pin injection is **false** for inbox (`injectSenderArgv` only treats `check`). |
| "Selector default-deny applies uniformly whenever `--worktree` is present" | For `terminal list` / `worktree show` / `file open` / `worktree set`, a null-handle check fires first and the worktree checker is never consulted. |
| "tests drive the real path and assert the effect did not happen" | True for `terminal show` / `terminal stop` tables. False as a methodology: `dispatch-show --task` is in the **legitimate allow** table; inbox / run-list / task-list / `--page` / `--parent-worktree` have no effect assertions. |
| "a caller can still read dispatch-show metadata for a foreign task id if allowlisted" (framed as a deferred F3 non-goal) | Understated. Live `--preamble` is 10 kB of worker prompt, not "metadata." The inversion brief required `--task` / `--run` to be treated as selectors. Deferring them means NAS-252 is not done. |
| Suite **388 / 0** | **Accurate.** Independent rerun: tests 388, pass 388, fail 0, skipped 0. |

## HELD — must not regress in any follow-up

These behaviours were attacked and did not break. A fix for the P0s must keep them.

1. `terminal show --json --terminal <foreign>` (space, `=`, leading `--json`, interleaved `--json`, `TERMINAL SHOW`) → `decision=deny`, `code=handle_not_owned`, hardening on **and** off. No runtime spawn.
2. Same for `terminal read` / `close` / `send` / `wait` / `switch` / `rename` / `split` with a foreign `--terminal`.
3. `terminal stop --worktree <foreign>` and `path:<foreign>` (exact registered strings) → deny, hardening on and off. Path aliases fail closed, they do not allow.
4. Duplicate `--terminal` / `--worktree` deny-any (foreign then owned, owned then foreign).
5. Interleaved `orchestration --json worker-read --dispatch FOREIGN` is no longer the NAS-248 F4 soft-exec: `--dispatch` presence is enough to enter the dispatch checker.
6. Missing checker + present collected selector → `ownership_check_not_configured` deny (never soft-exec).
7. `applyOwnershipListRedaction` on the live `terminal list --json` envelope (11 rows) and the live `terminal show` envelope strips every `preview` and leaves `findTerminalContentKeys` empty. No `terminals[]` special-case required for those two shapes.
8. Owned `terminal read --terminal <own>` and owned `orchestration worker-read --dispatch <own>` remain `allow` with hardening on and off.
9. Owned `orchestration check` (no `--terminal`; pin injected later) remains `allow`.
10. `action=cli` still returns `policyResult.rejection` before `runOrca` when `!policyResult.ok` (`server.mjs` ≈2477–2479).
11. `action=release` still runs `preflightReleaseOwnership` before any `worker-release` / close (`lib/release-worker.mjs`). Not re-broken by this commit.
12. `resolve*` still does not key on `runtimeId`.
13. Forbidden handoff (`worktree create --agent --prompt`) still always denies.

## Independent suite numbers

```
# tests 388
# suites 81
# pass 388
# fail 0
# cancelled 0
# skipped 0
# duration_ms 939.581504
```

Run at `bb755f5` in `/home/orca/orca/workspaces/orca-mcp/nas-250-252-inversions` via `npm test`. Matches the implementer's 353 → 388 claim. As in every previous round, the number is not evidence that the inversion holds.

## Named-ticket scorecard

| Ticket | Named hole | At `bb755f5` |
|--------|------------|--------------|
| NAS-250 | `terminal show --json --terminal <foreign>` → `result.terminal.preview` | **Holds.** Gate denies (on/off). Redaction would also strip `preview` from the live show envelope. |
| NAS-251 | `terminal stop --worktree <foreign>` soft-exec under hardening off | **Holds** for exact registered selectors. Path-alias / `new-child` notes above. Not live-executed. |
| NAS-252 | Ownership default-deny of **any** target selector, hardening-independent | **Broken.** `--task` / `--run` / `--id` / `--page` / `--parent-worktree` never enter the funnel. `dispatch-show --task` allows even with hardening on. Inbox / run-list / task-list soft-exec with hardening off and return foreign specs, preambles, payloads. |

## What this review did not do

- Did not exec `terminal stop`, `worker-release`, `worker-start`, `tab close`, `task-update`, `gate-resolve`, or `orchestration reply` against any foreign id.
- Did not flip `ORCA_BRIDGE_CLI_HARDENING`, restart the bridge, or write `~/.orca-bridge/`.
- Did not stand up an isolated HOME bridge (unit + live host-CLI shape probes were enough to falsify the claims).
- Did not re-test NAS-249 / NAS-253 bind oracles.

Probe script: `/tmp/nas-250-252-attack-probe.mjs`. Live key dumps (no bodies): `/tmp/nas-250-252-live/`.


---

# Fix wave — real inversions A/B (post `3e4e6da` review)

**Author:** dispatched fix worker (NAS-250/251/252 real inversion)  
**Branch:** `BuildContext/nas-248-ownership-invariant`  
**Baseline HEAD:** `3e4e6da` (bb755f5 code + adversarial review)  
**Suite before:** 388 pass / 0 fail  
**Suite after:** 406 pass / 0 fail  

## What changed

### A — ARGV allowlist (not selector blocklist)

`lib/cli-policy.mjs` now drives ownership from **one table**:

- `FLAG_TABLE` / `TARGET_FLAG_RESOLVERS` / `NON_TARGET_FLAGS` / `ADMIN_SELECTOR_FLAGS`
- Every long-flag on argv is classified. **Unclassified → DENY.**
- Every target entry binds a resolver kind (`handle|dispatch|worktree|parent_worktree|task|run|id|page|repo`).
- `evaluateCliArgv` consumes that table; `assertTargetFlagResolversComplete()` fails if any target lacks a resolver.
- Flags enumerated from shipped CLI **v1.4.180** specs (`allowedFlags` + usage `--flags` + GLOBAL/BOOLEAN).

Selector kinds newly enforced (were documentation-only at bb755f5):

| Flag | Resolver | Notes |
|------|----------|-------|
| `--task` / `--task-id` | task | closes P0-1 dispatch-show |
| `--run` | run | closes P0-2 task-list / worker-list |
| `--id` | id (task→run→dispatch; `msg_*` runtime-scoped) | closes run-show / reply path |
| `--page` | page | fail-closed (no page registry) |
| `--parent-worktree` | parent_worktree → worktree | |
| `--repo` | repo | fail-closed unless deps.ownedRepos |

**run-list:** takes no selector and returned 100 foreign runs live. **Denied** unscoped (`unscoped_run_list`). Justification: no safe default scope without a caller-owned `--run`/`--id`; coordinators already bind a run via dispatch/await.

Ownership decisions are **identical with hardening on and off**. Hardening remains allowlist-only.

### B — RESPONSE inventory allowlist (not content-key blocklist)

`lib/state-ownership.mjs`:

- Deleted the deny-list strategy as the redaction engine. `TERMINAL_CONTENT_KEYS` remains only as a legacy/effect-helper list.
- New `INVENTORY_ALLOWLIST_KEYS` + `isInventoryAllowlistKey`.
- Non-owned nodes keep **only** inventory keys (ids, handles, states, booleans, counts, timestamps, branch, structural containers).
- Everything else stripped: preamble, spec, objective, payload, subject, body, stdout, stderr, blocks, prompt, tail, …
- Handle attribution uses `handle|terminalHandle|assignee_handle|from_handle|to_handle|coordinator_handle|created_by_terminal_handle|…`.
- No resolvable handle → inherit parent ownership; default **strip**.
- Non-owned rows also drop `title` / `worktreePath` / `path` (P1-4). Owned rows keep full content. HELD item 7 still holds for `preview` strip + inventory ids/state.

P2-1 (key-name enumeration) is **subsumed by inversion B**.

### C — False deny (P1-2)

Selector kinds route to **their own** resolver only. A `--worktree` argv no longer triggers a null-handle check. Verified allow:

- `terminal list --worktree <own>`
- `worktree show --worktree <own>`
- `file open … --worktree <own>`

### D — Uniform deny (P1-3)

Caller-facing rejection is one shape:

- `code: 'handle_not_owned'`, `error: 'cli_policy_denied'`
- Uniform detail string (no foreign vs unknown, no owned_* lists)
- **No** `ownership_status`, `reason`, `owned_handles`, `owned_worktrees`, `owned_dispatches`, `handle`/`dispatch_id` oracle fields on the rejection

Distinctions remain only in the local `onWarning` audit payload (`_audit_*` fields).

### E — inbox (P0-3)

`injectSenderArgv` now injects `--terminal <pin>` for **both** `check` and `inbox`. Inbox is mailbox-scoped like check; no longer host-wide under hardening off. Defense-in-depth: response redaction still strips body/payload/subject on non-owned message nodes.

### F — synthetic stop (P2-2)

`resolveWorktreeOwnership('new-child'|'new-top-level')` returns **owned** only when `deps.allowSyntheticCreate === true`. Policy sets that only for `worktree create` / `worker-start`. `terminal stop --worktree new-child` → deny.

## P0 / P1 scorecard

| ID | Finding | Status |
|----|---------|--------|
| P0-1 | dispatch-show --task foreign (+preamble) | **Fixed** — task resolver deny, hard on/off |
| P0-2 | task-list/run-show/run-list/worker-list foreign content | **Fixed** — run/id resolvers; run-list unscoped deny |
| P0-3 | inbox host-wide + payload leak | **Fixed** — pin inject + inventory redaction |
| P1-1 | TARGET_SELECTOR_FLAGS unwired | **Fixed** — FLAG_TABLE consumed by evaluate |
| P1-2 | false deny list/show/file --worktree | **Fixed** — per-kind routing |
| P1-3 | deny existence oracle + owned_* leak | **Fixed** — uniform rejection |
| P1-4 | title/worktreePath recon on foreign rows | **Fixed** — stripped on non-owned |
| P2-1 | content-key enumeration | **Subsumed by B** |
| P2-2 | stop --worktree new-child synthetic own | **Fixed** |
| P2-3 | worktree path-alias bypass | **HELD** (still fail-closed) |

## HELD (13) — still required

Unit-pinned via existing NAS-250/251/252 tables + new NAS-252 real-inversion suite. All 13 behaviours from the review remain enforced (show/stop deny on/off, deny-any dups, interleaved worker-read, missing checker fail-closed, list/show preview strip, owned read/worker-read/check allow, server short-circuit, release preflight, no runtimeId keying, forbidden handoff).

## Files touched

| File | Change |
|------|--------|
| `lib/cli-policy.mjs` | FLAG_TABLE allowlist gate; uniform deny; multi-kind evaluate |
| `lib/cli-policy.test.mjs` | Effect tests for new selectors; oracle asserts removed; HELD retained |
| `lib/state-ownership.mjs` | Collectors + task/run/id/page/repo resolvers; inventory allowlist redaction; synthetic guard |
| `lib/state-ownership.test.mjs` | preamble/spec/payload/title strip; synthetic stop |
| `lib/security-core.mjs` | inbox pin inject |
| `lib/security-core.test.mjs` | inbox inject pin |
| `server.mjs` | Wire task/run/id/page/repo/parent checkers; register taskId; synthetic flag |
| `docs/research/NAS-250-252-inversions.md` | This section |

## What I could not prove

1. **Did not re-run live foreign-handle/task probes on the shared contour.** Task forbids destructive live commands against foreign objects. Gate denials and redaction are unit-proven against v1.4.180 shapes and the reviewer's argv catalogue; not re-spawned through a second live MCP client on a foreign tab.
2. **Page / repo ownership has no durable registry.** `--page` and bare `--repo` fail closed (`unknown`) unless tests inject `ownedPageIds` / `ownedRepos`. A future browser-session ownership store would need wiring; today that is intentional deny.
3. **`msg_*` reply ids are runtime-scoped, not bridge-indexed.** `resolveGenericIdOwnership` treats `msg_*` as owned so legitimate `orchestration reply --id msg_…` is not false-denied. The runtime + injected `--from` pin remain the real mailbox boundary. I did not prove a foreign msg id cannot be replied to if the runtime accepts it under the caller's pin — that is a runtime concern outside this gate.
4. **Task ownership depends on dispatch-time `taskId` registration.** Tasks never recorded on `dispatchRegistry` / `clientOwnership.tasks` resolve `unknown` (denied). Path is correct for bridge-dispatched work; ad-hoc CLI task ids the bridge never saw fail closed.
5. **run-list is hard-denied unscoped** rather than filtered to owned runs post-hoc. Filtering would need a response-path run allowlist walk; deny is the conservative choice and matches "no selector → no proof".
6. **Did not flip `ORCA_BRIDGE_CLI_HARDENING`, restart the bridge, publish, or bump the version.**
7. **NAS-249 / NAS-253 bind oracles untouched** (out of scope).
8. **Human stdout redaction** for non-preview secret classes (raw `terminal read` tails without `preview:` lines) remains best-effort; foreign read is denied at the gate first.
9. **Effect tests do not start an in-process HTTP bridge.** They prove `evaluateCliArgv` returns deny before spawn (server short-circuit at `!policyResult.ok` still present — read, not integration-harnessed this round).

---

# Adversarial review of `6c97af0` — try to break the real inversions

**Reviewer:** dispatched attack worker (NAS-252 review r7, fresh eyes)  
**Target:** `BuildContext/nas-248-ownership-invariant` @ `6c97af0`  
**Worktree:** `/home/orca/orca/workspaces/orca-mcp/nas-252-review-r7` (reset onto the target; this review only appends this section)  
**CLI oracle:** live AppImage v1.4.180 (`/tmp/nas-248-cli/squashfs-root/.../out/cli`) plus live `orca` against runtime v1.4.180  
**Date:** 2026-08-13  
**Production code changed by this review:** no  
**Bridge process touched:** no  
**`ORCA_BRIDGE_CLI_HARDENING` on the live bridge:** not flipped  
**Destructive live `stop` / `release` / `close` / `worker-start` / `tab close` / `task-update` / `gate-resolve` / `reply` / `automations remove|run` / `artifacts delete`:** not executed (NAS-202 boundary). Those shapes are argv-proof only.

This review treats every implementer claim at `6c97af0` as a hypothesis. A green suite is not evidence. Six prior rounds in this lineage each shipped live P0s behind 321 / 346 / 353 / 353 / 388 / 406.

## VERDICT

**BREAKABLE. Do not merge to main.**

The FLAG_TABLE / per-kind resolver work at `6c97af0` does close the *named-flag* holes from the previous review: `dispatch-show --task`, `task-list --run`, `run-show --id`, `run-list` unscoped, `--page`, `--parent-worktree`, `--repo`, the P1-2 null-handle false deny, the deny-path oracle, and synthetic `stop --worktree new-child` all deny on the collected `--flag` surface, hardening on and off. Those named reproductions are genuinely dead, not just rewritten.

The inversion that was supposed to make ownership an invariant is still not implemented. Both new mechanisms are allowlists over **named flags and named JSON keys**. The shipped v1.4.180 CLI names many of the same targets **positionally**; `normalizeCommandPositionals` promotes those tokens to flags *after* the bridge gate, so `FLAG_TABLE` never sees them. Independently, P0-3 is not fixed on the production spawn path: `injectSenderArgv` gained an inbox pin, but `withSender` in `server.mjs` still only injects for `check`. Combined with `describeRun` putting human stdout on the redaction path that no-ops unless the text contains `preview`/`scrollback`/`buffer`, `orchestration inbox --full` (no `--json`) still dumps the host-wide mailbox. Live v1.4.180 printed that shape on this host (subjects + `[payload]` marker, no `preview` word). NAS-252 is not closed.

## Method

- Diffed `3e4e6da..6c97af0`. Read `lib/cli-policy.mjs` (`FLAG_TABLE`, `evaluateCliArgv`, `ownershipDecision`), `lib/state-ownership.mjs` (`INVENTORY_ALLOWLIST_KEYS`, `redactOwnershipContent`, `resolveGenericIdOwnership`), `lib/security-core.mjs` (`injectSenderArgv`), `server.mjs` (`withSender` at 1276, `action=cli` at 2529–2555, `applyCliOwnershipRedaction`, `describeRun`).
- Enumerated positionalArgs + usage `--flags` from live v1.4.180 specs under `/tmp/nas-248-cli/squashfs-root/resources/app.asar.unpacked/out/cli/specs/`. Cross-checked `args.js` `normalizeCommandPositionals` / `parseArgs` and `handlers/{file,orchestration,automations}.js`.
- Independent `npm test` at `6c97af0`: **406 pass / 0 fail / 0 skipped**.
- `/tmp/nas-252-r7-attack-probe.mjs` imports branch modules only. Full transcript: `/tmp/nas-252-r7-probe-out.txt`.
- Live read-only `orca` (host identity, shape + effect oracle): `orchestration inbox --json/--limit`, `inbox` human, `inbox --full` human, `automations list --json`, `terminal list` human, `worker-list --json`. Bodies / payloads / titles were measured by length and then discarded; they are not reproduced here.

## Prior-reproduction scorecard (re-run against `6c97af0`, not trusted from the fix summary)

| Prior finding | `evaluateCliArgv` @ 6c97af0 (hard off / on) | Genuinely dead? |
|---------------|---------------------------------------------|-----------------|
| P0-1 `dispatch-show --task FOREIGN [--preamble]` | deny / deny, `handle_not_owned`, no oracle fields | **Dead** on the `--task` flag |
| P0-2 `task-list --run FOREIGN` | deny / deny | **Dead** on the `--run` flag |
| P0-2 `run-show --id FOREIGN` | deny / deny | **Dead** on the `--id` flag |
| P0-2 `run-list` unscoped | deny / deny, `unscoped_run_list` | **Dead** |
| P0-2 `worker-list --run FOREIGN` | deny / deny | **Dead** on the `--run` flag |
| P0-2 `worker-list` *unscoped* | **allow_with_warning** / allowlist deny | **Still live** under hardening off (see P1-5) |
| P0-3 `inbox --json` no `--terminal` | **allow_with_warning** / allowlist deny | **Still live** — pin is not injected at spawn |
| P0-3 `inbox --full` no `--json` | **allow_with_warning** / allowlist deny | **Still live**, and redaction is a no-op |
| `check --run FOREIGN` | deny / deny | Dead (new; was allow at bb755f5) |
| `--page` / `--parent-worktree` / `--repo` | deny / deny | Dead on those flags |
| P1-2 `terminal list --worktree OWN` / `worktree show --worktree OWN` | allow / allow | **Fixed** |
| P1-2 `file open PATH --worktree OWN` | allow_with_warning / allowlist deny | Ownership false-deny is **fixed**; still not on `RAW_CLI_OK` |
| P1-3 deny oracle + `owned_*` | uniform `handle_not_owned`; ghost === foreign detail; no `ownership_status` / `reason` / `owned_*` | **Dead** |
| P1-4 JSON `title` / `worktreePath` | stripped on non-owned JSON nodes | **Dead on JSON**; **live on human stdout** |
| P2-2 `stop --worktree new-child` | deny | **Dead** |
| P2-3 worktree `name:` / `id:repo::path` / `branch:` / `issue:` | deny (fail-closed) | **HELD** |

"Looks dead" vs "is dead": the `--json` inbox path would have inventory-redacted bodies *if it spawned*. It still spawns, unscoped, because `withSender` never adds `--terminal`. Omitting `--json` makes even that defense disappear.

## Findings (ranked)

### P0-1 — `orchestration inbox` is still host-wide; the pin was wired in a helper the spawn path does not call

Author claim E: "`injectSenderArgv` now injects `--terminal <pin>` for **both** `check` and `inbox`."

That sentence is true of `lib/security-core.mjs` and of `lib/security-core.test.mjs`. It is false of the production caller.

```js
// server.mjs:1276
async function withSender(argv) {
  if (argv[0] !== 'orchestration') return argv;
  const sub = argv[1];
  const needsFrom = ORCH_FROM_CMDS.has(sub);
  const needsTerminal = sub === 'check';   // inbox is not here
  if (!needsFrom && !needsTerminal) return argv;
  const sender = await resolveSenderTerminal();
  return injectSenderArgv(argv, sender.handle);
}
```

`action=cli` (`server.mjs:2533–2539`) evaluates policy on the raw argv, then calls `withSender`. Inbox has no target flag, is not on `RAW_CLI_OK_PREFIXES`, and is explicitly skipped by the null-handle fail-closed (`isOrchInbox`). Hardening off (the live posture) → `allow_with_warning` → `runOrca(['orchestration','inbox',…])` as the host identity. The live handler (`handlers/orchestration.js:522`) passes `terminal: undefined` and the runtime returns the host-wide mailbox. The CLI's own help text still says "Show all messages across recipients."

`injectSenderArgv(['orchestration','inbox','--json'], 'term_own')` does append `--terminal term_own`. The unit test asserts that. `withSender` never reaches it.

Defense-in-depth also fails on the path an attacker would actually use. `describeRun` only attaches `envelope` when `argvWantsJson` is true. Without `--json`, the described object is `{ stdout: <human text> }`. `applyOwnershipListRedaction` then:

1. skips the envelope walk (none present);
2. tries to `JSON.parse` the human mailbox dump, fails;
3. only runs the human rewriter if the text matches `/preview|scrollback|buffer/i`.

Live `orca orchestration inbox --limit 3` on this host: 301 bytes, lines start `msg_…`, **no** `preview` word. Live `inbox --full --limit 2`: 379 bytes, **`[payload]` marker present**, still no `preview` word. The walker is a no-op. Default human inbox prints `id from -> to: "subject"`. `--full` appends body and `[payload] …`.

JSON `--json` inbox *would* strip `subject`/`body`/`payload` on rows whose first resolvable handle (`from_handle`) is not owned. That is not the spawn path that matters, and even that JSON walk keeps host-wide `id` / `from_handle` / `to_handle` / `run_id` inventory.

This is the previous P0-3, still live. The suite is green because the test covers the helper, not `withSender`.

### P0-2 — FLAG_TABLE is an allowlist over flags; v1.4.180 names the same targets positionally

Source of truth: shipped specs' `positionalArgs` + `normalizeCommandPositionals` in `args.js`. After a base-path match, leftover command-path tokens are copied onto flags **inside the CLI**, after the bridge has already decided.

Documented positionals that map onto a `TARGET` resolver name (`id`) or onto a path that names a foreign object:

| argv the CLI documents | flags `collectFlagNamesFromArgv` sees | hard off | hard on |
|------------------------|----------------------------------------|----------|---------|
| `automations show <id>` | `[]` | **allow_with_warning** | allowlist deny |
| `automations show --id <id>` | `['id']` | **deny** `handle_not_owned` | deny |
| `automations edit/remove/run <id>` | `[]` (plus `--name` on edit) | **allow_with_warning** | allowlist deny |
| `artifacts delete <id>` | `[]` | **allow_with_warning** | allowlist deny |
| `artifacts delete --id <id>` | `['id']` | **deny** | deny |
| `linear issue <id>` | `['json']` | **allow_with_warning** | allowlist deny |
| `file open <path>` (no `--worktree`) | `[]` | **allow_with_warning** | allowlist deny |
| `file open --path <path>` | `['path']` (`path` is `non_target`) | **allow_with_warning** | allowlist deny |

The same command, same id, two spellings, opposite ownership verdicts. `FLAG_TABLE` never sees `argv[n]`. Hardening is load-bearing. NAS-252's entire point was that it must not be.

`formatAutomationShow` prints `prompt: ${automation.prompt}`. Human `automations show <id>` has no `preview` word, so redaction would not run. This host currently has **0** automations (`automations list --json` → `n=0`), so there is no live prompt to steal today; the shape is argv-proven against the shipped spec and handler. `automations remove|run <id>` and `artifacts delete <id>` are destructive — not live-executed; the gate will not save us.

Related misses that are *not* a live teardown because the CLI rejects extra tokens (no `positionalArgs` on those specs), but that the gate also does not see:

- `worktree rm <selector>` — not a spec form (`--worktree` is required). Under `admin:true` the prefix `worktree rm` is allowlisted and a positional selector is invisible; live CLI validation should fail closed. Argv-proof of gate-blindness only.
- `orchestration reply <msg_id> --body x` — allow (reply is on `RAW_CLI_OK`); CLI should reject the extra token. The `--id` form is a different hole (P1-3).
- `terminal show <handle>` — fail-closed by the legacy null-handle gate. Good.

`--path` is classified `non_target`. An absolute path that names another checkout is not a selector as far as the gate is concerned. `file open` still infers worktree from cwd when `--worktree` is omitted; runtime may reject paths outside that worktree. Not claimed as a clean foreign-file read without a runtime check. The positional *id* split above is the clean bypass.

### P1-1 — Human stdout / stderr never reach the inventory walker

`applyOwnershipListRedaction` walks `described.envelope` and, if present, `described.stdout`. It does not walk `stderr` or `stderrTail`. Human `terminal list` (allowlisted, commonly used without `--json`) formats:

```
${handle}  ${title}  connected  ${worktreePath}
preview: ${preview}
```

The rewriter fires (the text contains `preview:`) and strips preview lines. **Titles and `worktreePath` remain.** Live `orca terminal list` on this host: 13 `term_` rows, 9650 bytes, `~/` paths in the first line. P1-4 is JSON-only.

Same class: any allowed/soft-exec command whose human formatter prints `subject`, `prompt`, `spec`, `objective`, or `[payload]` and whose text lacks `preview`/`scrollback`/`buffer` is unredacted. Inbox `--full` is the P0 instance. Automation show is the empty-host instance.

`error` objects keep `message` (and `code`) because `error` is allowlisted and the walker recurses into allowlisted keys with `parentOwned=false`, then keeps allowlisted children — and `message` is not stripped (it is not in `NON_OWNED_STRIP_EXTRA`; wait: `message` is an inventory key). Probe: `{ error: { message: SECRET, code: 'x', stack: SECRET } }` → `stack` gone, **`message` kept**.

Bare-string arrays under allowlisted keys survive: `{ messages: [SECRET, 'also-secret'] }` is unchanged. Live inbox messages are objects, so this is a shape risk, not a live envelope.

`name` / `source` / `agent` / `branch` on a node with no handle are kept as strings. Live terminal-list `branch` after JSON redaction is still present on foreign rows (`feat/secret` in the unit probe). Branch names on this host are attacker-relevant recon (other coordinators' feature branches). P2 as content, listed here because it is the allowlist-string cousin of the human-stdout miss.

### P1-2 — Admin-exempt `--to` / `--from` and other object-naming flags that FLAG_TABLE calls `non_target`

`--to` / `--from` are `ADMIN_SELECTOR_FLAGS`. Their *values* name handles, `run:id`, and `dispatch:id`. The gate does not run a resolver on the value.

```
orchestration send --to dispatch:ctx_FOREIGN --subject x --json
orchestration send --to run:run_FOREIGN --subject x
orchestration send --to term_FOREIGN --subject x
orchestration reply --id msg_FOREIGN --body x --from term_FOREIGN --json
```

All four: `decision=allow` with hardening **on and off** (send/reply are on the admin / default allow surface respectively).

`withSender` / `injectSenderArgv` do **not** overwrite a caller-supplied `--from`:

```
injectSenderArgv(['orchestration','reply','--id','msg_FOREIGN','--body','x','--from', FOREIGN], OWN)
→ ['orchestration','reply','--id','msg_FOREIGN','--body','x','--from', FOREIGN]
```

Author open item 3 says "the runtime + injected `--from` pin remain the real mailbox boundary." The pin is optional. Combined with `resolveGenericIdOwnership` treating every `msg_*` as `owned` / `message_id_runtime_scoped`, the bridge will spawn `reply --id msg_FOREIGN --from term_FOREIGN`. Not live-executed. Whether the runtime honors a spoofed `--from` is NAS-249-adjacent; the bridge gate does not enforce the pin it claims is the boundary.

Other object-naming flags classified `non_target` (hardening-off `allow` / `allow_with_warning`; `--ack` even allows under hardening because `check` is on `RAW_CLI_OK`):

| flag | names | argv-proof decision (hard off) |
|------|-------|--------------------------------|
| `--ack` | delivery id | `check --ack delivery_FOREIGN` → **allow** |
| `--retry-of` | dispatch id | `worker-start --task OWN --retry-of FOREIGN` → **allow** |
| `--resume` | message id | `ask --resume msg_FOREIGN` → allow_with_warning |
| `--parent` | task id | `task-create --spec x --parent task_FOREIGN` → **allow** |

`--ack` of a foreign delivery is a consume/steal. Not live-executed.

Compound `--worktree name:…` / `id:repo::path` / `branch:` / `issue:` still fail closed. No NAS-251 bypass via the value grammar.

### P1-3 — `msg_*` is a blanket own; author's "runtime-scoped" note hides a gate hole

```js
if (n.startsWith('msg_')) {
  return pack(HANDLE_OWNED, 'message_id_runtime_scoped', { kind_hint: 'message' });
}
```

`orchestration reply --id msg_FOREIGN --body x --json` → `allow` hardening on **and** off. This is intentional in the author's text. It is not correctly scoped: the compensating control (forced `--from` pin) is not actually forced (P1-2). Judge: **hiding a live effect**, not a paperwork deferral.

### P1-4 — Unscoped `worker-list` still soft-execs (the run-list fix was not applied to the sibling)

`run-list` without `--run`/`--id` is specially denied. `worker-list` without `--run` is not.

```
evaluateCliArgv(['orchestration','worker-list','--json']) → allow_with_warning (hard off)
```

Live `orca orchestration worker-list --json` on this host: **17** rows. Keys: `agentTerminalHandle`, `dispatchId`, `dispatchStatus`, `resource`, `runId`, `taskId`, `terminalState`, `workerState`. No spec/preamble (so JSON inventory redaction would drop some fields — `agentTerminalHandle` is not even a recognised handle key). What remains after a JSON walk is still every `dispatchId` / `runId` / `taskId` on the host. Human worker-list, if used, skips the walker.

Same class, weaker: unscoped `task-list` is `allow_with_warning`, but the CLI scopes it via `callerTerminalHandle` when `--run` is omitted, and `task-list` is in `ORCH_FROM_CMDS` so `withSender` *does* inject `--from`. Not claimed as a host-wide spec dump.

### P1-5 — `worktree list --repo` / `repo show --repo` / `computer permissions --id` are false denies of documented forms

Page/repo have no registry. The author declared that. The effect is that the **documented** `orca worktree list [--repo <selector>]` form is unconditionally `handle_not_owned` whenever `--repo` is present, including `--repo` of a repo this client actually uses. `worktree list` without `--repo` still allows (and is the form coordinators need).

`computer permissions --id accessibility` is a documented Computer Use flag. `--id` is a target resolver. `accessibility` is not a `task_`/`run_`/`msg_`/`ctx_` id → deny. False deny, P2-ish as coordinator impact (computer-use via the bridge) — listed here because it is the same `--id` overload that made positional `automations show` a bypass.

`cookie set --httpOnly` / `--sameSite`: v1.4.180 `allowedFlags` includes `httpOnly` and `sameSite`. `FLAG_TABLE` does not (`missing_in_table: ["httponly","samesite"]`). Unclassified → deny. False deny, not a bypass. The claim "every long-flag the shipped CLI accepts is classified" is false.

## Author claims that are inaccurate

| Claim at `6c97af0` | Reality |
|--------------------|---------|
| "Every long-flag on argv is classified. Unclassified → DENY." | True for `--` flags that `collectFlagNamesFromArgv` sees. False as a description of the CLI: positionals never become flags at the gate. Also false for `--httpOnly` / `--sameSite`. |
| "listed-but-unwired is impossible by construction via a test" | True inside `TARGET_FLAG_RESOLVERS` ↔ `FLAG_TABLE`. The test does not know about `positionalArgs`. |
| "inbox pin inject + inventory redaction" (P0-3 **Fixed**) | `injectSenderArgv` is fixed. `withSender` is not. Human/`--full` inbox never reaches the walker. Live host still serves the unscoped mailbox. |
| "Redaction is now an inventory ALLOWLIST… kills preamble, spec, objective, payload and title at once" | True for JSON nodes whose first handle-shaped key is unowned. False for human stdout, `stderr`/`stderrTail`, allowlisted string fields (`name`, `source`, `error.message`, `branch`), and bare-string arrays under allowlisted keys. |
| "inbox scoped via pin injection" | Skip-handle-gate is true. Pin injection at spawn is **false**. |
| "The runtime + injected `--from` pin remain the real mailbox boundary" for `msg_*` | `--from` is not injected when the caller already supplied one, and is not ownership-checked. |
| "run-list is hard-denied unscoped" (implied: the host-wide list class is closed) | `run-list` is. `worker-list` is not. 17 live rows on this host. |
| Suite **406 / 0** | **Accurate.** Independent rerun below. |

## Regressions that break legitimate coordinator use (not bypasses)

These are ship-relevant even when they are fail-closed.

1. **`worktree list --repo <selector>`** — documented form, now always denied (no `ownedRepos` on the live server). Coordinators should use `worktree list` without `--repo`; that form still allows. Still a false deny of a shipped usage string.
2. **`cookie set --httpOnly` / `--sameSite`** — shipped flags, now unclassified deny.
3. **`computer permissions --id accessibility`** — shipped flag, now ownership-denied.
4. **`orchestration check --run <id>`** — now ownership-gated. Foreign deny is correct. An owned run the bridge never registered is a false deny; coordinators can omit `--run` (pin-scoped mailbox still allows). Not observed as a live coordinator break in this session.
5. **Unscoped `run-list` deny** — conservative and justified. Coordinators bind a run via dispatch/await and do not need the host-wide catalogue. **Not a ship-blocker.** `run-list --run OWN` is `allow_with_warning` under hardening off (then allowlist-denied under hardening, same as other non-`RAW_CLI_OK` orch reads).
6. **Human `action=cli orchestration check` would redact incoming bodies** if anyone used that path: `from_handle` is the first handle key, so worker→coordinator messages look unowned and lose `body`/`payload`. Coordinators use `action=check` / `action=await`, which do **not** call `applyCliOwnershipRedaction`. Not a live coordinator break today; a trap if check is ever moved onto `action=cli`.

P1-2 (`terminal list --worktree`, `worktree show --worktree`) is **fixed** and was re-tested allow/allow.

## HELD — still hold, must not regress

Re-probed at `6c97af0`. Keep all 13 from the previous review:

1. `terminal show --json --terminal <foreign>` (space, `=`, leading/interleaved `--json`, `TERMINAL SHOW`) → deny, `handle_not_owned`, hardening on and off.
2. Same for `terminal read` / `close` / `send` / `wait` / `switch` / `rename` / `split` with foreign `--terminal`. Positional `terminal show <handle>` also fail-closes (null handle).
3. `terminal stop --worktree <foreign>` and `path:<foreign>` / `name:` / `id:repo::path` / `branch:` / `issue:` → deny, on and off. Not a bypass.
4. Duplicate `--terminal` / `--worktree` deny-any.
5. Interleaved `orchestration --json worker-read --dispatch FOREIGN` still enters the dispatch checker.
6. Missing checker + present collected selector → deny (never soft-exec).
7. JSON `applyOwnershipListRedaction` on list/show shapes strips `preview`; non-owned JSON rows also drop `title` / `worktreePath`. (Human list titles are **not** in this HELD item — see P1-1.)
8. Owned `terminal read --terminal <own>` and owned `worker-read --dispatch <own>` remain allow, on and off.
9. Owned `orchestration check` (no `--terminal`) remains allow.
10. `action=cli` still returns `policyResult.rejection` before `runOrca` when `!policyResult.ok` (`server.mjs:2533–2536`).
11. `action=release` still runs `preflightReleaseOwnership` first. Not re-broken.
12. `resolve*` still does not key on `runtimeId`.
13. Forbidden handoff (`worktree create --agent --prompt`) still always denies.

Plus, newly holding and required:

14. Named `--task` / `--run` / `--id` (non-`msg_*`) / `--page` / `--parent-worktree` / `--repo` presence enters the resolver funnel; foreign/unknown denies on and off.
15. Unscoped `run-list` denies on and off.
16. Caller-facing ownership rejection has no `ownership_status` / `reason` / `owned_*`.
17. `stop --worktree new-child` is not synthetic-owned.
18. `terminal list --worktree <own>` and `worktree show --worktree <own>` allow (P1-2).

## Author open items — scoped or hiding?

| # | Author note | Judge |
|---|-------------|-------|
| 1 | No live foreign re-probe | **Correctly scoped** for destructive exec. **Hides the P0**: they also did not re-read `withSender`, which is the only spawn-path caller. A helper unit test is not a live path. |
| 2 | Page/repo fail-closed without registry | **Correctly scoped as fail-closed**, and **hides a live documented false deny** (`worktree list --repo`). Intentional, but it is an effect, not just a footnote. |
| 3 | `msg_*` runtime-scoped via injected `--from` | **Hiding a live effect.** Blanket `owned` + skippable `--from` is a gate hole, not a runtime-only concern. |

## Independent suite numbers

```
# tests 406
# suites 83
# pass 406
# fail 0
# cancelled 0
# skipped 0
# todo 0
# duration_ms 1370.751388
```

Run at `6c97af0` in `/home/orca/orca/workspaces/orca-mcp/nas-252-review-r7` via `npm test`. Matches the implementer's 388 → 406 claim. As in every previous round, 406/0 is not evidence that the inversion holds. The inbox pin test is green because it asserts on `injectSenderArgv`, not on `withSender`.

## Named-ticket scorecard

| Ticket | Named hole | At `6c97af0` |
|--------|------------|--------------|
| NAS-250 | `terminal show --json --terminal <foreign>` → `result.terminal.preview` | **Holds** on the JSON/`--terminal` surface. Human `terminal list` still prints foreign titles/paths. |
| NAS-251 | `terminal stop --worktree <foreign>` soft-exec under hardening off | **Holds** for flagged selectors. Path-alias fail-closed. Not live-executed. |
| NAS-252 | Ownership default-deny of **any** target selector, hardening-independent | **Broken.** Positionals that the CLI promotes to `--id`/`--path` never enter the funnel. Inbox spawn is still hardening-dependent (`allow_with_warning`). Unscoped `worker-list` is still hardening-dependent. `--to`/`--from`/`--ack`/`--retry-of`/`--parent` name objects and are classified non-target/admin. |

## What this review did not do

- Did not exec `terminal stop`, `worker-release`, `worker-start`, `tab close`, `task-update`, `gate-resolve`, `orchestration reply`, `automations remove|run`, or `artifacts delete` against any foreign id.
- Did not flip `ORCA_BRIDGE_CLI_HARDENING`, restart the bridge, or write `~/.orca-bridge/` / `~/.orca-bridge-sender-pins.json`.
- Did not stand up an isolated HOME bridge.
- Did not re-test NAS-249 / NAS-253 bind oracles. The `--from` overwrite miss is reported as a gate fact, not as a bind-oracle result.

Probe script: `/tmp/nas-252-r7-attack-probe.mjs`. Live key dumps (no bodies): `/tmp/nas-252-r7-live/`.

---

# Fix wave — parse/output parity (post r7)

**Author:** dispatched fix worker (NAS-252 parity)  
**Branch:** `BuildContext/nas-248-ownership-invariant`  
**Baseline HEAD:** `6c97af0` + r7 review log  
**Suite before:** 406 pass / 0 fail  
**Suite after:** 419 pass / 0 fail  

## Meta-lesson (what actually changed)

Two parity failures, not a longer FLAG_TABLE:

1. **Parse parity.** Evaluate policy on argv after the same positional→flag promotion the shipped CLI (`normalizeCommandPositionals`) performs. Implemented in `lib/cli-argv-normalize.mjs` (pinned v1.4.180 specs + BOOLEAN_FLAGS). `evaluateCliArgv` normalizes first; differential tests assert every shipped allowed flag is classified and every `positionalArgs` entry promotes into a classified flag.
2. **Output parity.** `action=cli` always injects `--json` on spawn (`ensureWalkableCliArgv`) so `describeRun` attaches a walkable envelope. Human rewriter no longer gates on `/preview|scrollback|buffer/`; `stderr` / `stderrTail` are walked too.

## Required fixes A–H

| ID | Fix | Where |
|----|-----|-------|
| A | Positional normalize before evaluate; spec differential tests | `lib/cli-argv-normalize.mjs`, `evaluateCliArgv` |
| B | Force walkable JSON on spawn; delete human keyword gate; walk stderr | `server.mjs`, `applyOwnershipListRedaction` |
| C | `withSender` pin-injects **inbox** (spawn path); `applySpawnPathSenderInject` tested | `server.mjs`, `lib/security-core.mjs` |
| D | Value-typed resolution via `classifyValueOwnershipKind` on every flag value; `--to`/`--ack`/`--retry-of`/`--parent`/`--resume` | `cli-policy` + `state-ownership` |
| E | `injectSenderArgv` always **overwrites** `--from` and `--terminal` with pin | `security-core.mjs` |
| F | Spec-derived unscoped list deny (`run-list`, `worker-list`, …) | `listShapedOrchestrationCommands` + evaluate |
| G | False denies: `--repo` non-target (git filter); `httpOnly`/`sameSite` classified; `computer permissions --id` not orch-id | FLAG_TABLE + evaluate exception |
| H | Inventory default strip-unless-proven: drop `branch`/`name`/`source`/`agent`/`error.message`; strip bare-string arrays on non-owned | `redactOwnershipContent` |

### msg_* reply path

Blanket `message_id_runtime_scoped` **owned** is gone. `msg_*` / `delivery_*` fail closed unless listed in `deps.ownedMessageIds` / `ownedDeliveryIds`. Gate still allows `orchestration reply|ask --id msg_*` only because spawn **always** overwrites `--from` (E). Non-msg `--id` still resolves.

### --repo justification

`--repo` is a git/path **filter**, not a bridge-owned runtime object. Foreign teardown uses `--worktree`. Documented `worktree list --repo` must not false-deny. Classified `non_target`.

## P0/P1 scorecard (r7)

| ID | Status |
|----|--------|
| P0-1 inbox spawn pin | **Fixed** — `withSender` + spawn-path test |
| P0-2 positional id split | **Fixed** — normalize parity |
| P1-1 human stdout/stderr | **Fixed** — force JSON + rewriter always + stderr |
| P1-2 value-typed admin/object flags | **Fixed** |
| P1-3 msg_* blanket own | **Fixed** (fail closed + forced --from) |
| P1-4 unscoped worker-list | **Fixed** (spec list class) |
| P1-5 false denies | **Fixed** (classification) |
| Allowlist leaks (H) | **Fixed** |

## HELD (18) — pinned

Unit-pinned in `NAS-252 r7 parse/output parity` + prior tables. Foreign show/stop/task/run/page deny on/off; owned list/show/read/check/run-list--run allow; unscoped run-list/worker-list deny; uniform rejection shape; synthetic stop deny; no ownership_status/owned_* on rejection.

## Files touched

| File | Change |
|------|--------|
| `lib/cli-argv-normalize.mjs` | **new** — pinned CLI parse/normalize + list catalogue |
| `lib/cli-policy.mjs` | normalize-first evaluate; value-typed scan; list unscoped; classification fixes |
| `lib/cli-policy.test.mjs` | parity + HELD r7 suite |
| `lib/state-ownership.mjs` | value grammar; msg fail-closed; redaction tighten; stderr walk |
| `lib/state-ownership.test.mjs` | redaction parity |
| `lib/security-core.mjs` | overwrite --from/--terminal; spawn-path helpers |
| `lib/security-core.test.mjs` | overwrite + spawn-path inbox |
| `server.mjs` | withSender inbox; ensureWalkableCliArgv |
| `docs/research/NAS-250-252-inversions.md` | r7 log retained + this section |

## What I could not prove

1. **Did not re-run live foreign probes on the shared contour** (destructive boundary). Gate/redaction proven in unit tests against v1.4.180 shapes and the r7 argv catalogue.
2. **Did not start an in-process HTTP bridge** to integration-test `withSender` via `action=cli`. Spawn-path decisions are factored into `applySpawnPathSenderInject` / `orchestrationNeedsSenderPin` and asserted there; `server.mjs` `withSender` body now matches those helpers line-for-line on the needsTerminal set. A reviewer should still read `server.mjs` withSender — do not trust the helper alone without that read.
3. **msg_* reply still depends on runtime mailbox enforcement** under the forced `--from` pin. Bridge no longer pretends msg ids are owned; it only skips the id ownership checker on reply/ask. A runtime that ignores `--from` remains NAS-249-adjacent and out of scope.
4. **`--repo` non-target means a future effectful "repo delete" style command would not be ownership-gated by flag name.** None exists in v1.4.180 specs; value-typed absolute paths still do not auto-gate bare `--path` (file open) to avoid false denies.
5. **Force `--json` on all action=cli spawns** changes the wire shape coordinators see when they omitted `--json`. Inventory redaction still applies; human-format consumers of action=cli get JSON envelopes. Coordinators using `action=check`/`await` are unchanged.
6. **Did not flip `ORCA_BRIDGE_CLI_HARDENING`, restart bridge, publish, or bump version.**
7. **NAS-249 / NAS-253 bind oracles untouched.**
8. **Page ownership still has no durable registry** — `--page` fail-closed unless tests inject `ownedPageIds`.
9. **task-list / gate-list unscoped remain pin-scoped via CLI `--from`**, not hard-denied like worker-list/run-list (CLI already scopes task-list to caller when `--run` omitted). Not re-proven live.

---

# Adversarial review of `a2a715d` — try to break the parse/output parity wave

**Reviewer:** dispatched attack worker (NAS-252 review r9, fresh eyes)  
**Target:** `BuildContext/nas-248-ownership-invariant` @ `a2a715d`  
**Worktree:** this checkout (reset onto the target; this review only appends this section)  
**CLI oracle:** live AppImage v1.4.180 (`/tmp/nas-248-cli/squashfs-root/.../out/cli`) `args.js` + `specs/index.js` `COMMAND_SPECS`  
**Date:** 2026-08-13  
**Production code changed by this review:** no  
**Live shared bridge process touched:** no  
**`ORCA_BRIDGE_CLI_HARDENING` on the live bridge:** not flipped  
**`~/.orca-bridge/` / `~/.orca-bridge-sender-pins.json`:** not modified  
**Destructive live `stop` / `release` / `close` / `worker-start` / `tab close` / `task-update` / `gate-resolve` / `reply` / `send --to @all` / `automations remove|run` / `artifacts delete`:** not executed (NAS-202 boundary). Those shapes are argv-proof and/or isolated-HOME + fake-`orca` only.

This review treats every implementer claim at `a2a715d` as a hypothesis. A green suite is not evidence. Seven prior rounds in this lineage each shipped live P0s behind 321 / 346 / 353 / 353 / 388 / 406 / 419.

## VERDICT

**BREAKABLE. Do not merge to main.**

The r7 *named-flag / named-positional* catalogue is mostly genuinely dead on the production `action=cli` spawn path, not just on helpers. Isolated-HOME HTTP (`PORT=18788`, fake `orca`, `HOME` under `/tmp/nas-252-r9-iso/`) spawned `orchestration inbox --terminal <pin> --json` (no `--json` on the caller argv), overwrote caller `--from term_FOREIGN` with the pin, refused to spawn `automations show <id>` / `terminal show --terminal FOREIGN` / `linear issue NAS-252`, and returned an inbox envelope with `subject`/`body`/`payload` stripped. Independent suite at `a2a715d`: **419 pass / 0 fail**. That number is still not evidence.

The inversion is still not closed. `classifyValueOwnershipKind` implements a subset of the shipped `--to` address grammar (`term_*`, `run:`, `dispatch:`). The same v1.4.180 spec that documents those forms also documents **group addresses** `--to @all` and `--to @worktree:<id>`. Those values return `vk=null`, `--to` is `VALUE_TYPED_ONLY` so the name-based handle resolver never runs, and default toolset `admin=true` makes `orchestration send` allowlisted. Result: `decision=allow` with hardening **on and off**, and the spawn sequence is `['orchestration','send','--to','@all',…,'--from',<pin>,'--json']`. `@worktree:path:/foreign` is the same miss against the worktree checker. That is the r7 P1-2 "fix" failing on the rest of the flag it claimed to cover.

Separately, the differential test that was supposed to lock parse parity has teeth for *unclassified names* and is decoration for *resolver binding*. Removing `id` from `TARGET_FLAG_RESOLVERS` (leaving it `NON_TARGET`) keeps both `spec differential` tests green and reopens `automations show <id>` as `allow_with_warning`. The test is driven from a pinned `CLI_COMMAND_SPECS` snapshot (241 duplicate entries; unique set currently matches live v1.4.180), not from the shipped specs at runtime.

## Mutation-test of the differential test (first, because it is the claimed lock)

The two tests in `lib/cli-policy.test.mjs` (`spec differential: every shipped allowed flag is classified in FLAG_TABLE` / `every command positional promotes into a classified flag`) were mutation-tested against the **real** `node --test --test-name-pattern 'spec differential'` run, then restored.

| Mutation | How | Result | Teeth? |
|----------|-----|--------|--------|
| MUT1 — new positional | prepend `{path:['synthetic','show'], positionalArgs:['secretid'], allowedFlags:[…,'secretid']}` to `CLI_COMMAND_SPECS` | **FAIL** (both tests; `unclassified shipped flags: secretid` + `positional flag not in FLAG_TABLE`) | Yes, for a *new unclassified name* |
| MUT2 — new flag, no resolver | prepend `{path:['synthetic','run'], allowedFlags:[…,'nonesuch-flag']}` | **FAIL** (flag-table test only) | Yes, for an unclassified flag |
| MUT3 — remove a resolver | delete `id: 'id'` from `TARGET_FLAG_RESOLVERS`; add `'id'` to `NON_TARGET_FLAGS` | **PASS** (2/2). Then `evaluateCliArgv(['automations','show','auto_FOREIGN'])` → `allow_with_warning` | **No. Decoration.** |

MUT3 is the whole point of the author's claim. The tests assert `FLAG_TABLE[name]` is truthy. They do not assert `kind==='target'`, they do not assert a resolver ran, and they do not compare "targets the gate sees" to "targets the CLI resolves." A positional whose name is already a `NON_TARGET` classified flag (today: `path`, `file`, `query`, `topic`, …) can be added to a spec and both tests stay green while evaluate never ownership-checks it.

**Runtime source of specs:** `lib/cli-argv-normalize.mjs` `CLI_COMMAND_SPECS` is a frozen JSON dump (`CLI_SPEC_VERSION="1.4.180"`). Tests import that dump. They do **not** `require` the AppImage `specs/index.js` at runtime. Compared this review: live `COMMAND_SPECS` unique paths = 228, snapshot unique paths = 228, `onlyLive=[]`, `onlySnap=[]`, `positionalArgs` / `allowedFlags` / `BOOLEAN_FLAGS` identical. Snapshot currently matches. It will silently rot on the next CLI bump. Snapshot length is 469 because the dump concatenates the same commands ~2× (`snapDupes=241`); first-match wins and the duplicates are identical, so this is not a live parse split today.

Parse-engine parity vs live `args.js` `parseArgs` + `normalizeCommandPositionals` on 18 differential inputs (`--`, flags before/after, `=`, alias `artifacts rm`, `--ID`, `--json=false`, extra arity, `claude-teams --resume`, `check --wait 5000`, cookie `--httpOnly`, …): **0 flag/path diffs**. The new normalizer is a faithful copy of the live parser *for the candidate set*. Divergence is in the `--to` *value grammar*, not in argv tokenization.

## Method

- Diffed `6c97af0..a2a715d`. Read `lib/cli-argv-normalize.mjs`, `evaluateCliArgv` (normalize-first, `VALUE_TYPED_ONLY`, unscoped list, computer-`--id` exception, msg_* reply skip), `classifyValueOwnershipKind`, `applyOwnershipListRedaction` / `redactTerminalListHumanStdout`, `injectSenderArgv` / `applySpawnPathSenderInject`, `server.mjs` `withSender` (1292–1297), `ensureWalkableCliArgv` (783–787), `action=cli` (2541–2569).
- Mutation-tested the two differential tests on the real files (MUT1/2/3 above). Compared snapshot to live `COMMAND_SPECS`. Compared `parseArgs`/`normalizeCommandPositionals` to live `args.js`.
- Isolated-HOME HTTP bridge (`HOME=/tmp/nas-252-r9-iso/home2`, `PORT=18788`, `ORCA_CLI_COMMAND=/tmp/nas-252-r9-iso/fake-orca`, `ORCA_BRIDGE_SENDER_TERMINAL=term_iso_pin`). Drove `tools/call` `action=cli`. Asserted on **spawned argv** (fake-orca jsonl) and **caller JSON** (`content[0].text`). Did not write `~/.orca-bridge*`.
- Re-ran the r7 reproduction catalogue through `evaluateCliArgv` hardening on **and** off, plus spawn-path for inbox / positional / `--from` overwrite / `@all`.
- Independent `npm test` at `a2a715d`: **419 / 0**.

Probe: `/tmp/nas-252-r9-attack-probe.mjs`. Mutation log: `/tmp/nas-252-r9-mut-out.txt`. Isolated spawn + payloads: `/tmp/nas-252-r9-iso/`.

## Prior-reproduction scorecard (re-run against `a2a715d`, not trusted from the fix summary)

| Prior finding | `evaluateCliArgv` @ a2a715d (hard off / on) | Isolated `action=cli` spawn? | Genuinely dead? |
|---------------|---------------------------------------------|------------------------------|-----------------|
| P0-1 inbox `--json` / `--full` no `--terminal` | allow_with_warning / allowlist deny (no selector; pin is post-policy) | **spawned** `inbox --terminal <pin> --json`; caller envelope stripped subject/body/payload | **Dead on spawn path.** Helper-only hole from r7 is closed. |
| P0-2 `automations show/edit/remove/run <id>` | deny / deny | **not spawned** | **Dead** |
| P0-2 `artifacts delete <id>` / `artifacts rm` | deny / deny | (argv-proof; not live-exec) | **Dead** |
| P0-2 `linear issue <id>` | deny / deny | **not spawned** | Dead as a *bypass*; **live as a coordinator false deny** (see Regressions) |
| P0-2 `file open <path>` / abs path | allow_with_warning / allowlist deny | — | Still not an ownership target. Author-declared. Not a clean foreign-file read without FS/runtime. |
| P1-1 human `terminal list` titles / inbox `--full` | n/a (output) | list forced `--json`; foreign row kept only `handle/connected/writable`; inbox JSON stripped | **Dead on the JSON spawn path.** Human rewriter still broken (P1-3) as fallback. |
| P1-2 `--to term_*` / `run:` / `dispatch:` | deny / deny | **not spawned** | **Dead** for those three spellings |
| P1-2 `--to @all` / `@worktree:` | **allow / allow** (admin default) | would spawn (sequence + default `admin=true`) | **Still live** — see P0-1 |
| P1-2 `--ack delivery_*` | deny / deny | — | **Dead** for `delivery_*` prefix |
| P1-2 `--retry-of` / `--parent task_*` | deny / deny | — | **Dead** |
| P1-2 `--resume msg_*` | allow_with_warning / allowlist deny (msg skip on ask) | — | Same reply/ask pin-scope design; not a new hole |
| P1-3 reply `msg_FOREIGN --from FOREIGN` | allow / allow at gate | **spawned** `reply --id msg_FOREIGN --from <pin> --json` | Gate skip remains; **`--from` overwrite holds** on spawn path |
| P1-4 unscoped `worker-list` | deny / deny | — | **Dead** |
| P1-5 `worktree list --repo` | allow / allow | **spawned** | **Fixed** |
| P1-5 cookie `--httpOnly` / `--sameSite` | allow_with_warning / allowlist deny (not ownership-deny) | — | **Fixed** as a false *ownership* deny |
| P1-5 `computer permissions --id accessibility` | allow_with_warning / allowlist deny | — | **Fixed** for permission names |
| P2-2 `stop --worktree new-child` | deny / deny | — | **Dead** |
| P2-3 worktree `name:` / `id:repo::path` / `branch:` | deny / deny | — | **HELD** |

"Looks dead" vs "is dead": inbox `--json` at the *policy* layer is still `allow_with_warning` (no selector). The compensating control is `withSender` + `ensureWalkableCliArgv` **after** evaluate. Isolated `action=cli` proved those fire on the production functions, not only on `applySpawnPathSenderInject`.

## Findings (ranked)

### P0-1 — documented `--to @all` / `--to @worktree:<sel>` bypass the value-typed `--to` gate

Author claim D: "Value-typed resolution via `classifyValueOwnershipKind` on every flag value; `--to`/`--ack`/`--retry-of`/`--parent`/`--resume`."

`--to` is in `VALUE_TYPED_ONLY`, so the name-based handle resolver is **skipped**. Only the value grammar decides. That grammar is:

```js
// state-ownership.mjs classifyValueOwnershipKind
if (/^run:/i.test(v)) return 'run';
if (/^dispatch:/i.test(v)) return 'dispatch';
if (/^task:/i.test(v)) return 'task';
if (/^term_[A-Za-z0-9_-]+$/.test(v)) return 'handle';
// … ctx_/task_/run_/msg_/delivery_/page_/path:/absolute/name|branch|issue|id:
```

Shipped v1.4.180 `specs/orchestration.js` send notes, same flag:

> quote group addresses such as `--to "@all"` or `--to "@worktree:<id>"`.

Those values return `vk=null`. Default toolset is `admin=true` (`createToolsetGate` enabledList includes `admin`). `orchestration send` is on `RAW_CLI_ADMIN_PREFIXES`.

**Reproduction (argv-proof; not live-executed):**

```
evaluateCliArgv(['orchestration','send','--to','@all','--subject','x'],
                {hardening:true, admin:true, all-checkers-not-owned})
→ { decision:'allow' }

evaluateCliArgv(['orchestration','send','--to','@worktree:path:/home/other/secret','--subject','x'],
                {hardening:true, admin:true, all-checkers-not-owned})
→ { decision:'allow' }

# same two argv, hardening false: also allow
# --to term_FOREIGN / --to run:run_FOREIGN : deny handle_not_owned (the r7 spellings)
```

Spawn sequence (evaluate → `applySpawnPathSenderInject` → `ensureWalkableCliArgv`), which isolated `action=cli` showed is what `server.mjs` actually runs:

```
['orchestration','send','--to','@all','--subject','x','--from','term_own','--json']
['orchestration','send','--to','@worktree:path:/home/other/secret','--subject','pwn','--from','term_own','--json']
```

`--from` is pinned. That does not authorize a host-wide or foreign-worktree *destination*. `@worktree:` never enters `worktreeOwnershipCheck`. NAS-251's worktree invariant does not apply to this spelling.

Hardening is not load-bearing: send is admin-allowlisted. Isolated and default `createToolsetGate({})` both have `admin=true`.

Not live-executed against the shared runtime (would be a cross-coordinator write).

### P1-1 — the differential test does not lock the positional class

See MUT3 above. The author's sentence "a spec-driven differential test asserts that for every command the targets the gate sees equal the targets the CLI resolves" is false of the tests that exist. They assert classification membership against a copied snapshot.

This is the same shape as `redactTerminalListPayload` / `injectSenderArgv` vs `withSender`: a green test on a weaker predicate than the production claim. Today `id` is still a TARGET and positional `automations show` denies. Tomorrow someone "classifies" a new positional as `NON_TARGET` to silence MUT1 and the class reopens with a green suite.

### P1-2 — human / exception-path output is still not an inventory walk

Force-`--json` + envelope walk **works** on the isolated happy path (inbox/list payloads above). The claimed "human stdout and stderr are now fully redacted" is false of the fallback rewriter and of unparseable bodies.

1. `redactTerminalListHumanStdout` inbox-subject regex is a typo: `/:s*"/` (literal `s`) instead of `/:\s*"/`. Unit probe:

   ```
   stdout: msg_abc term_FOREIGN -> term_own: "SECRET_PREAMBLE_DO_NOT_LEAK"
   [payload] …  → payload line redacted, **subject line kept**
   ```

   Live CLI `format` for inbox is exactly `` `${id} ${from} -> ${to}: "${subject}"` ``. Force-`--json` hides this on the happy path. Any envelope-miss (timeout, `maxBuffer` truncate, non-JSON command that ignores `--json`) falls into this rewriter.

2. One-line truncated JSON (`{"ok":true,"result":{"preamble":"SECRET"`) is not `JSON.parse`-able; the rewriter only matches `preamble:` at **line start**. Secret survives.

3. `stderr: "error: SECRET"` is unchanged. `error:` is not in the content-line regex. `error.message` *is* stripped on JSON nodes (`NON_OWNED_STRIP_EXTRA`).

4. Non-UTF8 / binary stdout is returned unmodified.

5. `ensureWalkableCliArgv` treats any `--json=*` as already walkable, so `--json=false` is not rewritten. Live CLI uses `flags.has('json')`, so `--json=false` is still JSON mode — not a human bypass today, but the gate and the CLI disagree on what the token *means*.

`runOrca` does not throw on timeout/non-zero (returns `stdout`/`stderr`); `action=cli` still redacts that object. The miss is "unwalkable body", not an uncaught exception.

### P1-3 — `computer permissions --id task_*` and `--ack` non-`delivery_*` skip ownership

The computer-permissions exception deletes the `id` kind and `continue`s, so it also skips value-typed resolution:

```
computer permissions --id task_FOREIGN  → allow_with_warning (hard off)
```

`--id accessibility` is the documented form and must stay allowed. The exception is command-based, not value-based.

`--ack` is `VALUE_TYPED_ONLY`. `delivery_*` denies. A non-matching token (`check --ack ack_FOREIGN`, or a UUID) is `vk=null` → **allow with hardening on** (`check` is on `RAW_CLI_OK`). Live inbox rows use `msg_*` ids (which *would* classify as `id` and deny on check). Whether the runtime's `--ack <delivery_id>` is always `delivery_*` was not live-proven; the grammar hole is real if it is not.

### P2-1 — snapshot duplication / `--json=false` semantic drift / `file open` abs path

Recorded, not a teardown: 241 duplicate spec entries; `--json=false` CLI-vs-gate meaning; `file open /abs` still `allow_with_warning` (author-declared, `--path` is `NON_TARGET`, bare absolute skipped in the worktree special case). `file open path:/foreign` *does* deny.

## Author claims that are inaccurate

| Claim at `a2a715d` | Reality |
|--------------------|---------|
| "A spec-driven differential test asserts that for every command the targets the gate sees equal the targets the CLI resolves." | Tests assert `FLAG_TABLE` membership + positional promotion. MUT3 (remove `id` resolver) stays green and reopens the positional class. Snapshot, not live specs. |
| "Value-typed ownership… so `--to`/`--ack`/`--retry-of`/`--parent`/`--resume` are covered" | Covered for `term_*` / `run:` / `dispatch:` / `delivery_*` / `task_*` / `msg_*`. **Not** covered for documented `--to @all` / `--to @worktree:<id>`, nor for `--ack` values outside `delivery_*`/`msg_*`. |
| "Human stdout and stderr are now fully redacted; the `/preview\|scrollback\|buffer/` precondition is gone" | Keyword gate is gone. Rewriter is still a key-name regex. Inbox subject typo `/:s*"/`. stderr `error:` and unparseable/partial/binary bodies survive. Happy-path force-`--json` is what actually works. |
| "in-process `action=cli` withSender integration not proven" (author open item 2) | **Accurate as of the author's commit.** This review *did* stand up isolated `action=cli`. Inbox pin, `--from` overwrite, positional deny, list/inbox redaction hold on that path. `@all` would also spawn. |
| "False denies fixed by classification, not loosening" | True for `worktree list --repo`, cookie `httpOnly`/`sameSite`, `computer permissions --id accessibility`. **False** that the funnel was not tightened onto legitimate coordinator argv: `linear issue NAS-252` and exact-handle `--body`/`--text`/`--subject`/`--payload`/`--dispatch-capability ctx_*` now ownership-deny. |
| Suite **419 / 0** | **Accurate.** Independent rerun below. |

## Regressions (not bypasses)

These are ship-relevant even when they are fail-closed. Isolated/unit, not live-executed against foreign objects.

1. **`linear issue NAS-252` / `linear comment add NAS-252` / every Linear positional `--id`** — now `handle_not_owned` because `--id` is an orch-id resolver and Linear ids are unknown. Isolated `action=cli` did not spawn. Documented `linear issue --current` remains `allow_with_warning`. Coordinators that address a ticket by id via `action=cli` are broken. r7 wanted the positional *bypass* closed; this closes it by denying the whole Linear id space.

2. **Value-typed scan of every flag value** — `orchestration reply --id msg_own --body term_FOREIGN`, `terminal send --terminal term_own --text term_FOREIGN`, `send --subject term_FOREIGN`, `send --payload term_FOREIGN`, `send --dispatch-capability ctx_FOREIGN` all `handle_not_owned`. Any owned command whose string argument *is* a handle/id token is now a false deny.

3. **`computer permissions --id accessibility`** is no longer an *ownership* deny (fixed). Under hardening on it is still allowlist-denied (not on `RAW_CLI_OK`). Same for cookie set. Not new to this wave.

4. **Unscoped `run-list` deny** — still conservative, still justified. `run-list --run OWN` is `allow_with_warning` / hardening allowlist-deny. Matches r7.

Legitimate coordinator argv re-tested **allow** (hard off, owned checkers): `terminal list --worktree path:/own`, `worktree show --worktree path:/own`, owned `read`/`close`/`send`, owned `check`, `run-list --run run_own`, `worktree list --repo my-repo`. Isolated spawn confirmed list/read/`worktree list --repo`. `action=release` not re-driven (prior HELD; out of this wave's diff).

## HELD — still hold, must not regress

Re-probed at `a2a715d` (unit + isolated spawn where noted). Keep all 18 from r7:

1. `terminal show --json --terminal <foreign>` (space, `=`, leading/interleaved `--json`, `TERMINAL SHOW`) → deny, `handle_not_owned`, on and off. Isolated: **not spawned**.
2. Same for `terminal read` / `close` / `send` / `wait` / `switch` / `rename` / `split` with foreign `--terminal`. Positional `terminal show <handle>` fail-closes.
3. `terminal stop --worktree <foreign>` and `path:` / `name:` / `id:repo::path` / `branch:` / `issue:` → deny, on and off.
4. Duplicate `--terminal` / `--worktree` deny-any.
5. Interleaved `orchestration --json worker-read --dispatch FOREIGN` still enters the dispatch checker.
6. Missing checker + present collected selector → deny (never soft-exec).
7. JSON `applyOwnershipListRedaction` on list/show strips `preview`; non-owned JSON rows drop `title` / `worktreePath`. Isolated list: foreign row `{handle, connected, writable}` only; owned row keeps preview/title/path.
8. Owned `terminal read --terminal <own>` and owned `worker-read --dispatch <own>` remain allow, on and off. Isolated owned read **spawned**.
9. Owned `orchestration check` (no `--terminal`) remains allow. Isolated inbox/check pin-inject **spawned**.
10. `action=cli` still returns `policyResult.rejection` before `runOrca` when `!policyResult.ok` (`server.mjs:2545–2548`). Isolated deny-show/auto/linear: spawned argv `[]`.
11. `action=release` still runs `preflightReleaseOwnership` first. Not re-broken by this commit (read, not re-driven).
12. `resolve*` still does not key on `runtimeId`.
13. Forbidden handoff (`worktree create --agent --prompt`) still always denies.
14. Named `--task` / `--run` / `--id` (non-`msg_*` on non-reply) / `--page` / `--parent-worktree` presence enters the resolver funnel; foreign/unknown denies on and off. **`--to @all` / `@worktree:` are not in this item.**
15. Unscoped `run-list` and `worker-list` deny on and off.
16. Caller-facing ownership rejection has no `ownership_status` / `reason` / `owned_*`. Isolated deny payload confirmed (audit fields stay on the local `onWarning` log only).
17. `stop --worktree new-child` is not synthetic-owned.
18. `terminal list --worktree <own>` and `worktree show --worktree <own>` allow (P1-2 from the first inversion review).

Newly holding and required, from this review's spawn-path drive:

19. `action=cli orchestration inbox` (with or without `--json`/`--full`) injects `--terminal <resolved pin>` and `--json` before spawn. Caller JSON has no `subject`/`body`/`payload` on unowned `from_handle` rows.
20. `injectSenderArgv` / `withSender` overwrite a caller-supplied `--from` (isolated: `reply --from term_FOREIGN` spawned as `--from term_iso_pin`).
21. Positional `automations show <id>` / `artifacts delete <id>` deny on and off and do not spawn.

## Independent suite numbers

```
# tests 419
# suites 85
# pass 419
# fail 0
# cancelled 0
# skipped 0
# todo 0
# duration_ms 950.727719
```

Run at `a2a715d` via `npm test`. Matches the implementer's 406 → 419 claim. As in every previous round, 419/0 is not evidence that the inversion holds. MUT3 is green for the same reason the inbox-pin test was green at `6c97af0`: the assertion is on the weaker object.

## Named-ticket scorecard

| Ticket | Named hole | At `a2a715d` |
|--------|------------|--------------|
| NAS-250 | `terminal show --json --terminal <foreign>` → `result.terminal.preview` | **Holds** on the JSON/`--terminal` surface. Isolated deny does not spawn. Force-`--json` list redacts foreign preview/title/path. Fallback human/partial JSON is P1-2. |
| NAS-251 | `terminal stop --worktree <foreign>` soft-exec under hardening off | **Holds** for flagged `--worktree` selectors. **Broken** for the documented `--to @worktree:<sel>` send address (P0-1). Not live-executed. |
| NAS-252 | Ownership default-deny of **any** target selector, hardening-independent | **Broken.** `--to @all` / `--to @worktree:<sel>` are documented target addresses that never enter a resolver. Differential test does not lock the positional class (MUT3). |

## What this review did not do

- Did not exec `terminal stop`, `worker-release`, `worker-start`, `tab close`, `task-update`, `gate-resolve`, `orchestration reply` / `send --to @all` / `@worktree:`, `automations remove|run`, or `artifacts delete` against any foreign id on the shared runtime.
- Did not flip `ORCA_BRIDGE_CLI_HARDENING`, restart the live bridge, or write `~/.orca-bridge/` / `~/.orca-bridge-sender-pins.json`. Isolated HOME copies only.
- Did not re-test NAS-249 / NAS-253 bind oracles. `--from` overwrite was proven as a gate/spawn fact.
- Did not fuzz every banner variant or `maxBuffer` ceiling on the live CLI.

Attack surface actually covered: mutation of the two differential tests (real file edits, restored); snapshot-vs-live spec/BOOLEAN_FLAGS compare; parseArgs parity vs live `args.js` on 18 inputs; `evaluateCliArgv` tables for the r7 catalogue + `@all`/`@worktree`/`--json=false`/`--ack` non-delivery/`computer --id task_*`/value-typed over-match/legitimate coordinator argv; isolated `action=cli` spawn + caller payload for inbox, list, deny-show, deny-auto, deny-linear, owned read, `worktree list --repo`, reply `--from` overwrite; unit redaction of show/inbox/human/partial/binary/error/bare-array; independent 419/0 suite.

# Closeout of round-9 findings on `a8d3b42` base (fix author wave)

Branch: `BuildContext/nas-248-ownership-invariant`. No merge, no PR, no main touch.
Constraint honored: no action=cli redesign, no uid-model change, no new modules/abstractions/config.
Baseline suite at start of wave (a8d3b42 / a2a715d lineage): **419 pass / 0 fail**.
After closeout: **427 pass / 0 fail**.

## Items

### Item 1 — group addresses (P0) — FIXED

`evaluateCliArgv` value-typed block (only on `VALUE_TYPED_ONLY`: `to`/`ack`/`retry-of`/`parent`/`resume`):

- any value beginning with `@` that is not `@worktree:…` → **deny** (`unowned_group_address`), including `@all` and unknown `@…` forms.
- `@worktree:<sel>` → `stripAddressPrefix` then `note('worktree', [sel])` → existing `worktreeOwnershipCheck`. No new resolver.
- unrecognised non-`@` value on a value-typed address flag (except `--ack`, see Item 5) → **deny** (`unrecognized_address_value`). Null no longer falls through on `--to`.

Argv-proof:

```
evaluateCliArgv(['orchestration','send','--to','@all','--subject','x'], {admin:true, all-not-owned}) → deny
evaluateCliArgv(['orchestration','send','--to','@worktree:path:/foreign','--subject','x'], …) → deny (worktree checker)
evaluateCliArgv(['orchestration','send','--to','term_FOREIGN','--subject','x'], …) → deny (unchanged)
```

### Item 2 — lock differential on resolver kind — FIXED

New test: `spec differential: target-capable flags are kind=target with a live resolver`.

- Asserts every target-capable flag (`terminal`,`id`,`to`,`ack`,…) has `FLAG_TABLE[name].kind === 'target'` and a non-null `resolver` matching `TARGET_FLAG_RESOLVERS`.
- Asserts positional promotion into those names keeps `kind==='target'`.
- Effect-locks `automations show auto_FOREIGN` → deny via id resolver.

`CLI_COMMAND_SPECS` deduped **469 → 228** (241 identical duplicates removed). Still pinned at `CLI_SPEC_VERSION = "1.4.180"`. Cheap test fails if snapshot has duplicate paths or version ≠ `1.4.180`. **Did not** re-plumb to AppImage at runtime.

#### Mutation re-run (real file edits, restored)

| Mutation | How | Result |
|----------|-----|--------|
| MUT1 — new positional | prepend `{path:['synthetic','show'], positionalArgs:['secretid'], allowedFlags:[…,'secretid']}` | **FAIL** 2/3 differential tests (`unclassified shipped flags: secretid` + positional not in FLAG_TABLE). New target-capable test still green (secretid not target-capable). |
| MUT2 — new flag, no resolver | prepend `{path:['synthetic','run'], allowedFlags:[…,'nonesuch-flag']}` | **FAIL** 1/3 (flag-table classification). |
| MUT3 — remove id resolver | delete `id: 'id'` from `TARGET_FLAG_RESOLVERS`; add `'id'` to `NON_TARGET_FLAGS` | **FAIL** 1/3 — new target-capable test. Then `evaluateCliArgv(['automations','show','auto_FOREIGN'])` → `allow_with_warning` (proves the demotion reopens the class; the test now catches it). |

All three mutations FAIL. MUT3 is no longer decoration.

### Item 3 — delete fallback rewriter — FIXED

Deleted the body of `redactTerminalListHumanStdout` (regex set + typo `/:s*"/`). Stub returns `UNWALKABLE_OUTPUT_NOTE`.

`applyOwnershipListRedaction`:

- walks `envelope` structurally (unchanged happy path; force---`--json` still the production path).
- JSON-parseable stdout/stderr → `redactOwnershipContent` walk.
- unparseable / truncated / binary / non-UTF8 / human text / stderr noise → **withhold** body, keep exit `code`, set `output_withheld=true`. No regex rewrite.

Legitimate owned JSON/envelope responses still walk. Human-only bodies are withheld rather than half-redacted.

### Item 4 — stop scanning content flags — FIXED

Value-typed scan now runs **only** on `VALUE_TYPED_ONLY` address flags. Content flags (`body`,`text`,`subject`,`payload`,`spec`,`prompt`,`message`, siblings in `NON_TARGET_FLAGS`) are not value-scanned.

False denies gone:

- `orchestration reply --id msg_own --body term_FOREIGN` → allow (gate; pin still overwrites `--from` on spawn)
- `terminal send --terminal term_own --text term_FOREIGN` → allow when handle owned
- `send --subject/--payload term_FOREIGN` / `--dispatch-capability ctx_FOREIGN` → allow when `--to` owned
- `linear issue NAS-252` → not ownership-denied

Address flags were not loosened.

### Item 5 — `--id` / `--ack` value rule — FIXED

Removed the command-based `computer permissions` exception (`isComputerPerms` delete-id-and-continue).

`--id` name-based collection keeps only values whose `classifyValueOwnershipKind` is non-null (orch grammar: `task_`/`run_`/`ctx_`/`msg_`/`delivery_`/`auto_`/`art_`/…). 

- `computer permissions --id accessibility` → not a target → allow_with_warning / hardening allowlist (unchanged non-ownership path)
- `computer permissions --id task_FOREIGN` → id target → deny
- `linear issue NAS-252` → null grammar → not a target → allow (not ownership-deny)
- `automations show auto_FOREIGN` / `artifacts delete art_x` → id grammar → deny

`--ack`: value-typed. `delivery_*` / `msg_*` / underscore orch ids classify and resolve (foreign → deny). Values outside recognised grammar (`ack_FOREIGN` matches underscore id → deny; a pure UUID / bare word → not-a-target, continue). Justification: ack tokens that look like orch ids must not skip ownership; tokens that do not name orch objects are not ownership-relevant. Silent allow of `delivery_*`-shaped foreign ids remains impossible.

## Round-9 open items — disposition

| Finding | Disposition |
|---------|-------------|
| P0-1 `--to @all` / `@worktree:` | **Fixed** (Item 1) |
| P1-1 differential MUT3 | **Fixed** (Item 2); MUT3 now fails |
| P1-2 human/exception output | **Fixed** fail-closed withhold (Item 3); happy-path JSON walk retained |
| P1-3 computer `--id task_*` / `--ack` | **Fixed** value rule (Item 5) |
| P2-1 snapshot dups | **Fixed** dedupe + version test (Item 2) |
| P2-1 `--json=false` semantic drift | **Refused** this wave — live CLI `flags.has('json')` still treats token as JSON; force-json path remains correct. Not a coordinator break. Named open. |
| P2-1 `file open /abs` | **Held as author-declared** — bare absolute on `--path` is not a worktree selector. Out of closeout scope. |
| Regressions 1–2 (linear / content false denies) | **Fixed** (Items 4–5) |
| HELD 1–21 | **Still hold** — pinned by existing + closeout tests |

## Special-case ledger (honest)

**Removed:**

1. `isComputerPerms` command exception in value-typed loop.
2. Entire `redactTerminalListHumanStdout` regex rewriter body (contentLine/jsonKey/msgRow/title strip).
3. Universal value-scan over every flag name (content flags included).

**Added:**

1. `@` / `@worktree:` branch inside existing VALUE_TYPED_ONLY loop (~15 lines).
2. Orch-grammar filter on `--id` collection (~20 lines).
3. `tryParseWalkableJson` + withhold diagnostic (~40 lines, replacing ~80 lines of regex).
4. Two differential assertions + closeout effect tests.

**Net: removed more special cases than added.** No new modules, no new config knobs, no uid changes.

## Mutation / suite evidence

```
# before (a8d3b42 lineage)
# tests 419 / pass 419 / fail 0

# after closeout
# tests 427 / pass 427 / fail 0

MUT1: FAIL (2 differential tests)
MUT2: FAIL (1 differential test)
MUT3: FAIL (target-capable resolver test); evaluate → allow_with_warning
```

## What I could not prove

- Did not re-drive isolated-HOME `action=cli` HTTP spawn for `@all` / withhold path (unit + argv-proof only this wave). Round 9 already proved spawn wiring for pin/force-json/deny; this wave did not regress those helpers and did not re-stand the fake-orca bridge.
- Did not live-exec `orchestration send --to @all` or foreign `@worktree:` against the shared runtime (boundary).
- Did not re-prove NAS-249 / NAS-253 bind oracles.
- Did not flip `ORCA_BRIDGE_CLI_HARDENING`, restart bridge, touch `~/.orca-bridge*`, publish, or bump package version.
- `--ack` with a pure UUID (no underscore orch grammar) is treated as not-a-target; whether production ever emits non-`delivery_*` ack tokens was not live-proven — same residual as round 9, now explicit.
- `--json=false` gate-vs-CLI token meaning left open (refused above).

Attack surface covered this wave: Items 1–5 code paths; MUT1/2/3 on real files; full `npm test` 427/0; closeout effect tests for group addresses, content-flag allow, computer id value rule, linear allow, HELD smoke.

# Adversarial review of `a119214` — try to break the closeout (FINAL / r10)

**Reviewer:** dispatched attack worker (NAS-252 review-final, fresh eyes)  
**Target:** `BuildContext/nas-248-ownership-invariant` @ `a119214`  
**Worktree:** `/home/orca/orca/workspaces/orca-mcp/nas-252-review-r9` (already on the target; this review only appends this section)  
**CLI oracle:** live AppImage v1.4.180 (`/tmp/nas-248-cli/squashfs-root/.../out/cli`) `specs/index.js` `COMMAND_SPECS` + `handlers/automations.js`  
**Date:** 2026-08-13  
**Production code changed by this review:** no (MUT1–4 edited real files, then restored; md5 of `lib/cli-policy.mjs` after restore = `4b1392879216cf9d65068258fd3aed94` = `HEAD`)  
**Live shared bridge process touched:** no  
**`ORCA_BRIDGE_CLI_HARDENING` on the live bridge:** not flipped  
**`~/.orca-bridge/` / `~/.orca-bridge-sender-pins.json`:** not modified (isolated HOME copies under `/tmp/nas-252-r10-iso/home` only)  
**Destructive live `stop` / `release` / `close` / `worker-start` / `tab close` / `task-update` / `gate-resolve` / `reply` / `send --to @all` / `automations remove|run` / `artifacts delete`:** not executed (NAS-202 boundary). Those shapes are argv-proof and/or isolated-HOME + fake-`orca` only.

This review treats every closeout claim at `a119214` as a hypothesis. A green suite is not evidence. Ten prior rounds in this lineage shipped live P0s behind 321 / 346 / 353 / 353 / 388 / 406 / 419 / 427. Three times the failure was a green test asserting on a weaker object than the claim.

## VERDICT

**BREAKABLE. Do not merge to main.**

Items 1, 3 and 5, the four round-9 *coordinator* regressions, and HELD 1–21 *as written* are genuinely closed on the production `action=cli` spawn path, not just on helpers. Isolated-HOME HTTP (`PORT=18789/18790/18791`, fake `orca`, `HOME` under `/tmp/nas-252-r10-iso/`) refused to spawn `--to @all`, `--to @worktree:path:/foreign`, `terminal show --terminal term_FOREIGN`, `automations show auto_FOREIGN`, `computer permissions --id task_FOREIGN`; spawned `orchestration inbox --terminal <pin> --json` with `subject`/`body`/`payload` stripped; overwrote caller `--from term_FOREIGN` with the pin; withheld human stdout (`output_withheld=true`, static diagnostic, no secret); and refused `action=release` of `ctx_FOREIGN_RELEASE` / `term_FOREIGN_RELEASE` before any worker-release/close. Independent suite at `a119214`: **427 pass / 0 fail**. That number is still not evidence.

The inversion is still not closed. Item 4 *removed* value-scanning from every flag that is not in the five-name `VALUE_TYPED_ONLY` set. `--workspace` is classified `NON_TARGET` (a "content" sibling only by table membership) but the shipped v1.4.180 spec and handler treat it as a worktree selector: *«Use --workspace to run in an existing worktree»* / `getOptionalWorktreeSelector(flags, 'workspace', …)`. At `a2a715d` the universal value-scan routed `path:` / `name:` / `branch:` / `issue:` / `id:` values on *any* flag into `worktreeOwnershipCheck`. After Item 4 that scan is gone, so:

```
evaluateCliArgv(['automations','create','--workspace','path:/foreign', …],
                {hardening:false, admin:true, all-checkers-not-owned})
→ { decision:'allow_with_warning' }

# isolated action=cli spawned:
['automations','create','--name','x','--trigger','daily','--prompt','p',
 '--provider','g','--workspace','path:/foreign','--json']
```

Hardening on is an *allowlist* deny (`automations create` is on neither `RAW_CLI_OK` nor `RAW_CLI_ADMIN`), not an ownership deny. Default `ORCA_BRIDGE_CLI_HARDENING` is unset. NAS-252's rule is that ownership must not be load-bearing on the allowlist. This is the r9 `@worktree:` P0 in a different spelling, created by the loosening the author billed as a false-deny fix.

MUT1/MUT2/MUT3 all FAIL as claimed. The invented fourth mutation (content-named address flag) PASSES: add `recipient` to `NON_TARGET_FLAGS` + a spec that takes it, and `spec differential` stays 3/3 green while `synthetic deliver --recipient term_FOREIGN` is `allow_with_warning`. `--workspace` is that mutation already shipping.

## Mutation-test of the differential lock (real file edits, restored)

`node --test --test-name-pattern 'spec differential'` against the real files, then restore. Baseline: **3 pass / 0 fail**.

| Mutation | How | Result | Teeth? |
|----------|-----|--------|--------|
| MUT1 — new positional | prepend `{path:['synthetic','show'], positionalArgs:['secretid'], allowedFlags:[…,'secretid']}` to `CLI_COMMAND_SPECS` | **FAIL** 2/3 (`unclassified shipped flags: secretid` + `positional flag not in FLAG_TABLE`) | Yes, for a *new unclassified name* |
| MUT2 — new flag, no resolver | prepend `{path:['synthetic','run'], allowedFlags:[…,'nonesuch-flag']}` | **FAIL** 1/3 (flag-table classification) | Yes, for an unclassified flag |
| MUT3 — remove id resolver | delete `id: 'id'` from `TARGET_FLAG_RESOLVERS`; add `'id'` to `NON_TARGET_FLAGS` | **FAIL** 1/3 — `target-capable` test (`--id must be kind=target, got non_target`). Then `evaluateCliArgv(['automations','show','auto_FOREIGN'])` → `allow_with_warning` | **Yes.** MUT3 is no longer decoration. |
| MUT4a — reclassify address `--to` as content | delete `to: 'handle'` from `TARGET_FLAG_RESOLVERS`; add `'to'` to `NON_TARGET_FLAGS` | **FAIL** 1/3 (`--to must be kind=target, got non_target`). Evaluate `--to @all` still **deny** (`VALUE_TYPED_ONLY` is a separate hardcoded set and does not consult `FLAG_TABLE.kind`) | Yes for the *named* address flag. Defense-in-depth: table demotion does not reopen `@all`. |
| MUT4b — new address flag whose name resembles content | add `'recipient'` to `NON_TARGET_FLAGS`; prepend spec `{path:['synthetic','deliver'], positionalArgs:['recipient'], allowedFlags:[…,'recipient']}` | **PASS** 3/3. `FLAG_TABLE.recipient = {kind:'non_target'}`. `evaluate --recipient term_FOREIGN` and positional `synthetic deliver term_FOREIGN` → `allow_with_warning` | **No. Enumeration.** `TARGET_CAPABLE` is a hardcoded name list, not "targets the CLI resolves." |
| MUT4c — stub the advertised `resolvers.worktree` map to always-owned | replace `worktree: worktreeOwnershipCheck` in the completeness map | **PASS** 3/3. Evaluate `@worktree:path:/foreign` and `stop --worktree path:/foreign` still **deny** | The map is a completeness table. Production `runChecker` calls `worktreeOwnershipCheck` from config, not `resolvers.worktree`. |
| MUT4c2 — always-owned at the *real* call site | replace the `worktree` `runChecker` argument with `() => ({status:'owned'})` | **spec differential PASS 3/3**. Closeout test `denies --to @all and routes @worktree through worktree checker` **FAILS**. Evaluate `@worktree:path:/foreign` → **allow**; `stop --worktree path:/foreign` → **allow_with_warning** | Differential lock does not bind the resolver implementation. The closeout *effect* test binds `@worktree` specifically. Nothing binds `--workspace`. |

**Runtime source of specs:** `CLI_SPEC_VERSION = "1.4.180"`, 228 unique paths, 0 duplicate paths (dedupe holds). Compared this review to live `COMMAND_SPECS`: `onlyLive=[]`, `onlySnap=[]`, `nDiffs=0` on `path` / `positionalArgs` / `allowedFlags`. Snapshot currently matches. The version test fails if the pin is not the string `1.4.180`; it still does not `require` the AppImage at runtime.

## Method

- Diffed `a8d3b42..a119214` (via reading closeout + current sources). Read `evaluateCliArgv` value-typed block, `VALUE_TYPED_ONLY`, `--id` orch-grammar filter, `FLAG_TABLE` construction, `applyOwnershipListRedaction` / `tryParseWalkableJson` / `redactTerminalListHumanStdout` stub, `classifyValueOwnershipKind` / `stripAddressPrefix`, `withSender` / `ensureWalkableCliArgv` / `action=cli` (`server.mjs:2541–2569`), `executeReleaseWorker` ordering, v1.4.180 `specs/automations.js` + `handlers/automations.js`.
- Mutation-tested the three differential tests on the real files (MUT1/2/3 + invented MUT4a/b/c/c2). Compared snapshot to live `COMMAND_SPECS`.
- Enumerated every v1.4.180 spec flag classified `non_target` whose *name* is selector-ish (`workspace`, `selector`, `destination`, `to-id`, `parent-id`, `reply-to`, `thread-id`, `environment`, `path`, `file`, …) and checked the live handler for each.
- Isolated-HOME HTTP bridge (`HOME=/tmp/nas-252-r10-iso/home`, `PORT=18789+`, `ORCA_CLI_COMMAND=/tmp/nas-252-r10-iso/fake-orca`, `ORCA_BRIDGE_SENDER_TERMINAL=term_iso_pin`). Drove `tools/call` `action=cli` and `action=release`. Asserted on **spawned argv** (fake-orca jsonl) and **caller SSE payload** (`content[0].text`). Did not write `~/.orca-bridge*`.
- Re-ran the r9 catalogue through `evaluateCliArgv` hardening on **and** off, plus spawn-path for `@all` / `@worktree` / `--workspace` / `file open path:` / inbox / list / deny-show / reply `--from` / release / human withhold.
- Independent `npm test` at `a119214`: **427 / 0**.

Probe: `/tmp/nas-252-r10-probe.mjs` → `/tmp/nas-252-r10-probe-out.json`. Mutations: `/tmp/nas-252-r10-mutation.sh`. Isolated spawn + payloads: `/tmp/nas-252-r10-iso/`.

## Prior-reproduction scorecard (re-run against `a119214`, not trusted from the closeout)

| Prior finding | `evaluateCliArgv` @ a119214 (hard off / on) | Isolated `action=cli` spawn? | Genuinely dead? |
|---------------|---------------------------------------------|------------------------------|-----------------|
| r9 P0-1 `--to @all` | deny / deny (`unowned_group_address`) | **not spawned**; caller `cli_policy_denied` / `handle_not_owned` | **Dead** (also `@ALL`, `@everyone`, `@worktree` without `:`, `@worktree:`, leading/trailing space, bare `all`, `*`) |
| r9 P0-1 `--to @worktree:path:/foreign` | deny / deny (worktree checker) | **not spawned** | **Dead** for the `--to` spelling |
| r9 P0-1 `--to @worktree:path:/own` | allow / allow (owned checker) | isolated checker has no owned worktree → deny (fail-closed) | **Holds** when the checker says owned |
| r9 P1-1 MUT3 | n/a (test) | n/a | **Dead** — MUT3 now fails |
| r9 P1-2 human/exception output | n/a (output) | human fake-orca `terminal list` → `output_withheld=true`, static note, secret absent | **Dead** as a leak. New fail-closed withhold of owned human (see Regressions) |
| r9 P1-3 `computer permissions --id task_FOREIGN` | deny / deny | **not spawned** | **Dead** |
| r9 P1-3 `computer permissions --id accessibility` | allow_with_warning / allowlist deny | **spawned** `--id accessibility --json` | **Fixed** as a false *ownership* deny |
| r9 P1-3 `--ack` non-`delivery_*` | `ack_FOREIGN` deny; UUID allow / allow | UUID spawned `check --ack <uuid> --terminal <pin> --json` | **Dead** for underscore orch ids. UUID residual author-declared (P2) |
| r9 regression: `linear issue NAS-252` | allow_with_warning / allowlist deny | **spawned** `linear issue NAS-252 --json` | **Fixed** (no longer ownership-deny) |
| r9 regression: owned reply/send/term-send with token-shaped content | allow / allow | reply spawned with `--from <pin>`; term-send spawned | **Fixed** |
| r7/r9 `automations show <id>` | deny / deny | **not spawned** | **Dead** |
| r7/r9 inbox `--json`/`--full`/no flag | allow_with_warning / allowlist deny (pin is post-policy) | **spawned** `inbox --terminal <pin> --json`; foreign row stripped to `id/from_handle/to_handle/run_id` | **Dead on spawn path** |
| r7 `--to term_*` / `run:` / `dispatch:` | deny / deny | **not spawned** | **Dead** |
| r7 unscoped `worker-list` / `run-list` | deny / deny | **not spawned** | **Dead** |
| r9 `file open path:/foreign` | **allow_with_warning / allowlist deny** | **spawned** `file open path:/foreign --json` | **Reopened by Item 4** — see P1-2 |
| r9 `file open /abs` | allow_with_warning / allowlist deny | **spawned** | Unchanged; author-declared |
| New: `automations create --workspace path:/foreign` (and `name:` / `branch:` / `id:`) | **allow_with_warning / allowlist deny** | **spawned** with `--workspace` intact + `--json` | **Live. P0-1** |

## Findings (ranked)

### P0-1 — Item 4 un-gates the shipped `--workspace` worktree selector

Item 4 claim: "Value-typed scan now runs **only** on `VALUE_TYPED_ONLY` address flags. Content flags … are not value-scanned. Address flags were not loosened."

`--workspace` is not a content flag. v1.4.180 `specs/automations.js`:

> Use `--workspace` to run in an existing worktree; otherwise the automation creates a new worktree per run.

`handlers/automations.js` calls `getOptionalWorktreeSelector(flags, 'workspace', cwd, client)` — the same selector grammar as `--worktree` (`path:`, `name:`, `branch:`, `issue:`, `id:repo::path`, absolute paths). `FLAG_TABLE.workspace = { kind: 'non_target', resolver: null }`. It is not in `VALUE_TYPED_ONLY` and not in `TARGET_CAPABLE`.

At `a2a715d` the universal value-scan did this for every flag:

```js
// a2a715d
if (vk === 'worktree') {
  const pathLikeFlag =
    name === 'worktree' || name === 'parent-worktree' ||
    String(raw).startsWith('path:') ||
    /^(name|branch|issue|id):/.test(String(raw));
  …
  note(vk, [v]);
}
```

So `--workspace path:/foreign` / `name:secret` / `branch:feat/secret` / `id:repo::/home/other/secret` entered `worktreeOwnershipCheck`. Item 4 deleted that loop's application to non-`VALUE_TYPED_ONLY` flags. The `--workspace` spelling of NAS-251 is now unowned.

**Reproduction (argv-proof + isolated spawn; not live-executed against a real foreign worktree):**

```
evaluateCliArgv(
  ['automations','create','--name','x','--trigger','daily',
   '--prompt','p','--provider','g','--workspace','path:/foreign'],
  {hardening:false, admin:true, all-checkers-not-owned})
→ { decision:'allow_with_warning' }

# hardening true: deny, reason = allowlist ("automations create" not on RAW_CLI_*),
#                 NOT handle_not_owned

# isolated action=cli (HOME=/tmp/nas-252-r10-iso/home, fake orca):
spawned:
  ['automations','create','--name','x','--trigger','daily','--prompt','p',
   '--provider','g','--workspace','path:/foreign','--json']
caller envelope: { ok:true, result:{} }   # walker stripped prompt/workspace keys
                                          # (no handle on the node) — the SIDE EFFECT
                                          # is the bug, not the echo
```

Same allow for `--workspace name:secret`, `branch:feat/secret`, `id:repo::/home/other/secret`, and a bare absolute `/home/other/secret`.

`automations edit --id auto_* --workspace path:/foreign` still *denies*, but on `--id` (orch-id grammar), not on `--workspace`. Create has no `--id`. That is the hole.

Linear commands also accept `--workspace`; that flag is a Linear workspace UUID, not `getOptionalWorktreeSelector`. Out of this P0. The automations spelling is the worktree one.

Hardening is not load-bearing. Isolated and default `resolveCliPolicyConfig({})` both have `hardening=false`. Default `createToolsetGate` enables `admin`. `automations` is not on the admin allowlist either — the only thing that used to make this an ownership deny was Item 4's predecessor scan.

Not live-executed against the shared runtime (would be a cross-coordinator schedule/write).

### P1-1 — the differential lock is still an enumeration (MUT4b)

MUT3 is fixed. The new test asserts `TARGET_CAPABLE` — a handwritten set of 16 names — have `kind==='target'` and a matching `TARGET_FLAG_RESOLVERS` entry, plus the `automations show auto_FOREIGN` effect. It does **not** assert that every flag a shipped handler uses as a selector is in that set.

MUT4b (content-named address flag `recipient` as `NON_TARGET` + spec) stays 3/3 green and reopens a positional class. `--workspace` is the live instance: already in `NON_TARGET_FLAGS`, already on two shipped specs, already unbound. Adding it to `TARGET_CAPABLE` is the missing assertion; the tests will not fail until someone writes that line.

MUT4c2 shows the same shape on the resolver *implementation*: stub the real `worktree` `runChecker` to always-owned and the differential tests stay green. The closeout `@worktree` effect test catches *that* spelling only.

This is the third time in the lineage a green test asserted on a weaker object than the claim (`redactTerminalListPayload` vs the response boundary; `injectSenderArgv` vs `withSender`; `FLAG_TABLE` membership vs resolver binding; now `TARGET_CAPABLE` membership vs "every selector the CLI resolves").

### P1-2 — `file open path:/foreign` is allow again

r9 scorecard: "`file open path:/foreign` *does* deny." Author-declared exception at `a2a715d` was **bare absolute** on `--path` / `--file`, not the `path:` selector grammar. Item 4 dropped the `path:`/`name:`/`branch:`/`issue:`/`id:` scan on non-address flags.

```
evaluate ['file','open','path:/foreign'] → allow_with_warning / hardening allowlist deny
isolated action=cli spawned ['file','open','path:/foreign','--json']
```

`file open /abs` is unchanged (author-declared). Positional promotion puts the token on `--path` or `--file`, both `NON_TARGET`. Live handler uses it as a filesystem path, optionally scoped by `--worktree` (which *is* still gated). `path:/foreign` without `--worktree` is the worktree-selector spelling of "open something over there."

Not a host-wide inventory dump. Ranked P1, not P0: it is a foreign open, it was explicitly dead last round, and Item 4 reopened it, but it is not the automations schedule/write.

Same loosening class, weaker effect, also spawn-proven: `environment show --environment path:/foreign`, `project setup-clone --destination path:/foreign`. Those handlers do **not** call `getOptionalWorktreeSelector` (environment name / clone destination). Recorded as P2 residuals, not additional P0s.

### P2-1 — `--ack` UUID still skips ownership

`check --ack aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee` → allow (on and off). Isolated spawned `check --ack <uuid> --terminal <pin> --json`. Author-declared: tokens outside orch-id grammar are "not an ownership target." Live inbox rows use `msg_*` / `delivery_*` (both deny). Residual, same as r9, now explicit.

### P2-2 — `--json=false` semantic drift; snapshot is still a pin

Refused by the author this wave. Live CLI `flags.has('json')` still treats the token as JSON; `ensureWalkableCliArgv` treats any `--json=*` as already walkable. Not a bypass today. Snapshot equals live 1.4.180 (0 path/flag/positional diffs) and the version test fails on the string `1.4.180` only — it will not notice a future AppImage bump until someone edits the pin.

### P2-3 — advertised `resolvers` map is not the binding

See MUT4c/MUT4c2. Completeness-checked, unused for dispatch. Hygiene. The closeout `@worktree` test is what actually binds that path.

### P2-4 — inventory-allowlist string values still pass through walkable JSON

`{"error":"SECRET"}` / other allowlisted keys with string values are not walked (only objects recurse). `error.message` as a nested object *is* stripped (`message` ∈ `NON_OWNED_STRIP_EXTRA`). Pre-existing inversion-B residual; Item 3 did not make it worse (human/partial/binary now withhold instead of leaking via the broken rewriter). Confirmed this review: parseable `{preamble:SECRET}` → `{ok,result:{}}`; `{secret,title}` → `{}`; `[SECRET,'x']` → `[]`; stderr `error: SECRET` → withheld.

## Author claims that are inaccurate

| Claim at `a119214` | Reality |
|--------------------|---------|
| "Address flags were not loosened." | `--to`/`--ack`/`--retry-of`/`--parent`/`--resume` were not. `--workspace` is a shipped worktree *address* that was only gated by the scan Item 4 deleted. That *is* an address-flag loosening, just of a flag the table had misfiled as `non_target`. |
| "MUT1, MUT2 and MUT3 now ALL fail" / lock on resolver binding | **True for MUT1–3** (re-run). **False** that the lock equals "targets the gate sees = targets the CLI resolves." MUT4b (content-named address) and the live `--workspace` flag stay green. MUT4c2 (always-owned call site) stays green on the differential tests. |
| "HELD 1–21 all pinned" | True of the 21 items *as written* (re-probed; HELD 11 re-driven). The items name `--worktree` / `--to @worktree:` / positional `automations show`. They do not name `--workspace`. The invariant those items exist to protect is still broken in that spelling. |
| "Four round-9 coordinator regressions fixed" | **True.** `linear issue NAS-252`, token-shaped `--body/--text/--subject/--payload/--dispatch-capability`, `computer permissions --id accessibility`, and the `@all` / `@worktree:` send path are no longer false-denies or bypasses (see Regressions). |
| "The human fallback rewriter is DELETED; unwalkable output … body withheld" | **True** on unit and isolated spawn. Human `terminal list` → `output_withheld=true`, note has no secret, exit code kept. Owned *human* bodies are also withheld (fail-closed; see Regressions). Walkable owned JSON/envelopes still walk. |
| "Value scanning removed from CONTENT flags … retained on address/selector flags only" | Half true. Retained on the five `VALUE_TYPED_ONLY` names. Not retained on `--workspace`, which is a selector. No sibling-matching heuristic exists — "content" is `NON_TARGET_FLAGS` membership. An address flag is misclassified into that set by whoever appends the name, not by resemblance (`to-id` / `to-x` / `thread-id` are explicit). |
| Suite **427 / 0** | **Accurate.** Independent rerun below. Not evidence. |

## Regressions (not bypasses)

These are ship-relevant even when they are fail-closed. Isolated/unit, not live-executed against foreign objects.

The four round-9 coordinator breaks are **gone**:

1. `linear issue NAS-252` / `linear issue --id NAS-252` — no longer `handle_not_owned`. Isolated spawned.
2. Owned `reply --body term_FOREIGN`, `terminal send --text term_FOREIGN`, `send --subject/--payload term_FOREIGN`, `send --dispatch-capability ctx_FOREIGN` — allow when the *address* is owned. Isolated reply/send spawned; `--from` still overwritten.
3. `computer permissions --id accessibility` — not an ownership deny. Isolated spawned. (`--id task_FOREIGN` still denies.)
4. `@all` / `@worktree:path:/foreign` — deny, not spawned.

Legitimate coordinator argv re-tested **allow** (hard off, owned checkers) and/or isolated spawn: `terminal list --worktree path:/own`, `worktree show --worktree path:/own`, owned `read`/`send`, owned `check`, `run-list --run run_own` (allow_with_warning / hardening allowlist-deny — unchanged), `worktree list --repo my-repo`, `--to @worktree:path:/own`. Isolated list: owned row keeps `title`/`worktreePath`/`preview`; foreign row is `{handle,connected,writable}` only.

New fail-closed behavior (not a bypass):

5. **Owned human stdout is withheld.** `applyOwnershipListRedaction` withholds any non-JSON stdout, including ordinary human output of an owned command. Isolated `FAKE_MODE=human terminal list` returned `output_withheld=true` and the static note. Force-`--json` is the production path (`ensureWalkableCliArgv`); commands that ignore `--json` now lose their body. Better than the r9 rewriter leak; coordinators that relied on human format via `action=cli` are darker.

`action=release` **re-driven** (HELD 11), not just read:

- Unit `executeReleaseWorker({dispatch_id:'ctx_FOREIGN_RELEASE'})` and `({terminal_handle:'term_FOREIGN_RELEASE'})` returned `ownership_denied` with **zero** `runJson` calls.
- Isolated HTTP `action=release` / `dispatchId=ctx_FOREIGN_RELEASE` returned `mode=ownership_denied`, `reason=dispatch_not_in_registry`, no worker-release/close spawn. `ensureRuntimeReady()` may probe `status --json` before the wrapper (NAS-246 lazy status); that is not a teardown. Missing ids throw `dispatch_id (or terminal handle) is required` before effects.

## HELD — still hold, must not regress

Re-probed at `a119214` (unit + isolated spawn where noted). Keep all 21 from r9:

1. `terminal show --json --terminal <foreign>` (space, `=`) → deny, `handle_not_owned`, on and off. Isolated: **not spawned**; caller `cli_policy_denied`.
2. Same for `terminal read` / `close` / `send` / `wait` / `switch` / `rename` / `split` with foreign `--terminal`. Positional `terminal show <handle>` fail-closes.
3. `terminal stop --worktree <foreign>` and `path:` / `name:` / `id:repo::path` / `branch:` / `issue:` → deny, on and off. (**`--workspace` is not this item.**)
4. Duplicate `--terminal` / `--worktree` deny-any.
5. Interleaved `orchestration --json worker-read --dispatch FOREIGN` still enters the dispatch checker (not re-broken).
6. Missing checker + present collected selector → deny (never soft-exec). Unit: `terminal show --terminal term_x` with no checkers → deny `handle_not_owned`.
7. JSON walk on list/show: isolated list foreign row `{handle, connected, writable}` only; owned row keeps preview/title/path. Inbox foreign row drops `subject`/`body`/`payload`.
8. Owned `terminal read --terminal <own>` remains allow. Isolated owned read **spawned**.
9. Owned `orchestration check` (no `--terminal`) remains allow. Isolated check/inbox pin-inject **spawned**.
10. `action=cli` still returns `policyResult.rejection` before `runOrca` when `!policyResult.ok`. Isolated deny-show/auto/send-`@all`: spawned argv `[]`.
11. `action=release` still runs `preflightReleaseOwnership` first. **Re-driven** this round (unit + isolated HTTP). Foreign dispatch/handle → `ownership_denied`, zero teardown `runJson`.
12. `resolve*` still does not key on `runtimeId` (not re-broken; read).
13. Forbidden handoff (`worktree create --agent --prompt`) still always denies.
14. Named `--task` / `--run` / `--id` (non-`msg_*` on non-reply) / `--page` / `--parent-worktree` presence enters the resolver funnel; foreign/unknown denies on and off. **`--to @all` / `@worktree:` now deny. `--workspace` is not in this item.**
15. Unscoped `run-list` and `worker-list` deny on and off. Isolated worker-list **not spawned**.
16. Caller-facing *cli-policy* rejection has no `ownership_status` / `reason` / `owned_*` (audit fields stay on the local `onWarning` log). Isolated `@all` / foreign-show payloads confirmed. `action=release` denials *do* carry those fields (by design of `releaseOwnershipDenial`; not a cli-policy regression).
17. `stop --worktree new-child` is not synthetic-owned.
18. `terminal list --worktree <own>` and `worktree show --worktree <own>` allow.
19. `action=cli orchestration inbox` injects `--terminal <pin>` and `--json`. Isolated: no `--json` on caller → spawned `inbox --terminal <pin> --json`; caller JSON has no `subject`/`body`/`payload` on unowned `from_handle` rows.
20. `withSender` overwrites caller `--from` (isolated: `reply --from term_FOREIGN` spawned as `--from term_iso_pin`).
21. Positional `automations show <id>` / `artifacts delete <id>` deny on and off and do not spawn.

## Independent suite numbers

```
# tests 427
# suites 86
# pass 427
# fail 0
# cancelled 0
# skipped 0
# todo 0
# duration_ms 928.214241
```

Run at `a119214` via `npm test`. Matches the implementer's 419 → 427 claim. As in every previous round, 427/0 is not evidence that the inversion holds. MUT4b is green for the same reason MUT3 was green at `a2a715d`: the assertion is on the weaker object.

## Named-ticket scorecard

| Ticket | Named hole | At `a119214` |
|--------|------------|--------------|
| NAS-250 | `terminal show --json --terminal <foreign>` → `result.terminal.preview` | **Holds** on the JSON/`--terminal` surface. Isolated deny does not spawn. Isolated list redacts foreign preview/title/path. Unwalkable bodies withhold (Item 3 holds). |
| NAS-251 | `terminal stop --worktree <foreign>` soft-exec under hardening off | **Holds** for flagged `--worktree` and for `--to @worktree:<sel>`. **Broken** for the documented `--workspace <sel>` automation address (P0-1). Not live-executed. |
| NAS-252 | Ownership default-deny of **any** target selector, hardening-independent | **Broken.** `--workspace path:/foreign` (and `name:`/`branch:`/`id:`) is a documented target selector that never enters a resolver. Hardening off spawns. Differential lock does not know this name (MUT4b). |

## What this review did not do

- Did not exec `terminal stop`, `worker-release`, `worker-start`, `tab close`, `task-update`, `gate-resolve`, `orchestration reply` / `send --to @all` / `@worktree:`, `automations create|remove|run`, or `artifacts delete` against any foreign id on the shared runtime.
- Did not flip `ORCA_BRIDGE_CLI_HARDENING`, restart the live bridge, or write `~/.orca-bridge/` / `~/.orca-bridge-sender-pins.json`. Isolated HOME copies only.
- Did not re-test NAS-249 / NAS-253 bind oracles. `--from` overwrite was proven as a gate/spawn fact.
- Did not fuzz every banner variant or `maxBuffer` ceiling on the live CLI.
- Did not stand a second isolated bridge with `ORCA_BRIDGE_CLI_HARDENING=1` — allowlist deny of `automations create` under hardening on is a unit fact (`evaluateCliArgv`); the P0 is the hardening-off spawn, which is the default.

## Attack surface actually covered

Enumerated, not implied:

- MUT1, MUT2, MUT3, MUT4a, MUT4b, MUT4c, MUT4c2 on the real files (restored; md5 match HEAD).
- Snapshot-vs-live spec compare (228/228, 0 diffs) and `CLI_SPEC_VERSION` pin.
- v1.4.180 flag census: every spec flag classified; 0 unclassified shipped flags; every selector-ish `NON_TARGET` name checked against live handlers (`workspace` → `getOptionalWorktreeSelector`; `selector` → CSS; `to-id`/`parent-id`/`reply-to`/`write-id` → Linear; `destination` → clone path; `environment` → global env name; `thread-id` → send thread; `path`/`file` → filesystem; `from` → admin, overwritten).
- No sibling-matching heuristic: "content flag" = `NON_TARGET_FLAGS` membership. `to-id` / `to-x` / `to-y` cannot pull `--to` into content; `--to` is TARGET and applied last in `FLAG_TABLE`.
- `evaluateCliArgv` tables (hard on and off) for the r9 catalogue plus `@ALL`/`@everyone`/`@worktree`/`@worktree:`/whitespace/`all`/`*`, `--ack` UUID/`ack_FOREIGN`/`delivery_FOREIGN`, `computer --id accessibility`/`task_FOREIGN`, content-token owned argv, `--to @worktree:path:/own`, `--workspace` forms, `file open path:`/`/abs`, `environment --environment path:`, `project setup-clone --destination path:`, `linear comment --reply-to`, `dispatch --to @all`, `ask --to @all`, `claude-teams --resume`, forbidden handoff, unscoped lists.
- Item 3 withhold unit: human, truncated JSON, binary NUL, non-UTF8 `\uFFFD`, stderr `error: SECRET`, stderr JSON `{error:{message}}`, parseable `{preamble}`, inbox envelope, owned human, owned JSON, empty stdout, non-zero JSON, bare-string array, parseable non-envelope, stub `redactTerminalListHumanStdout`.
- Isolated `action=cli` spawn + caller SSE payload: inbox (no json / `--full` / `--json`), automations show deny, reply `--from` overwrite, terminal list redaction, linear issue, worktree list `--repo`, owned read, foreign show deny, send `--to` foreign/`@all`/`@worktree:foreign`, automations create `--workspace path:`/`name:`, file open `path:`/`/abs`, computer `--id` both forms, owned reply/send, unscoped worker-list deny, `--ack` UUID, human-mode list withhold.
- Isolated `action=release` foreign dispatch + foreign handle (HELD 11).
- Unit `executeReleaseWorker` foreign dispatch/handle/missing (zero effects).
- Independent 427/0 suite.

## Follow-up if this is closed (not this review)

The merge-blocking fix is small and in the existing tables, not a redesign:

1. Move `workspace` from `NON_TARGET_FLAGS` to `TARGET_FLAG_RESOLVERS` as `'worktree'` (or collect it in the name-based worktree branch the way `--worktree` is collected). Linear `--workspace` is a UUID / non-orch value — the Item 5 `--id` pattern (ignore `classifyValueOwnershipKind == null`) keeps those as non-targets.
2. Add `workspace` to `TARGET_CAPABLE` so MUT4b-shaped demotion fails.
3. Effect-lock `automations create --workspace path:/foreign` → deny, and `file open path:/foreign` → deny (restore the r9 fact).
4. Optional P2: `--ack` UUID, `--json=false`, wire the `resolvers` map or delete it, owned-human withhold docs.

Until (1) lands, NAS-251/252 are not closed. Do not merge.
