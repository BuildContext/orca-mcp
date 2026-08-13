# NAS-248 adversarial review — try to break the ownership invariant

**Reviewer:** dispatched attack worker (read-only against live foreign objects)  
**Branch:** `BuildContext/nas-248-ownership-invariant` @ `69b1c9f`  
**Worktree read:** `/home/orca/orca/workspaces/orca-mcp/nas-248-attack-review` (detached at the target commit; sibling worktree already holds the branch name)  
**CLI oracle:** live AppImage v1.4.180 `parseArgs` / `BOOLEAN_FLAGS` / command specs (`/tmp/nas-248-cli/squashfs-root/.../out/cli`)  
**Date:** 2026-08-13  
**Production code changed by this review:** no  
**Bridge process touched:** no  
**Destructive live `release`/`close`/`worker-release`/`worker-stop`:** not executed (NAS-202 boundary)

NAS-247's first review said ready-to-merge because the code matched its description. The bypass was a path the description never mentioned. This review assumes NAS-248's "cannot bypass" claim is false and tries to make a handle-accepting effect run without the new resolvers.

## Verdict

**Breakable.** The new resolvers are real, and the paths the implementer named *and tested* do fail closed. Ownership is still not a system invariant. Two client-facing effects reach foreign content or foreign teardown without a successful `requireOwnedHandle` / `requireOwnedDispatch` judgement.

1. **`action=release` still closes a foreign settled worker.** `requireOwnedHandle` sits on the `terminal close --tab` fallback. The function calls `orchestration worker-release --dispatch <id>` first and returns success if that call succeeds. `requireOwnedDispatch` exists in `lib/state-ownership.mjs` and is never imported by `server.mjs`. Hardening does not apply: this is not `action=cli`.
2. **`terminal list` preview redaction is a positional response filter, not a chokepoint.** Live CLI v1.4.180 still ships `preview` on every row (14 terminals observed; keys only, no bodies logged). `applyCliOwnershipRedaction` runs only when `args[0]==='terminal'` and `args[1]==='list'` *and* `describeRun` built an `envelope`. `terminal list` (no `--json`), `terminal list --json=true`, `--json terminal list`, and `terminal --json list` all return foreign `preview` text.

Independent suite on this commit: **321 pass / 0 fail / 0 skipped** (matches the implementer's count). Unknown-ownership fail-closes in the resolvers and in `requireOwnedHandle`. Legitimate same-process coordinator release of an owned handle still works. After a bridge process restart, wiped `workerHandles` fail closed on the close fallback — and the worker-release side door still runs first.

## Method

- Diffed `95d12b1..69b1c9f` (5 files; production: `lib/cli-policy.mjs`, `lib/state-ownership.mjs`, `server.mjs`).
- Read live `args.js`, `flags.js`, `specs/{core,orchestration,orchestration-worker-specs}.js`, `terminal-format.js`, `workspace-format.js`, `handlers/terminal.js`.
- Ran `npm test` on `69b1c9f`: **tests 321, pass 321, fail 0**.
- Ran `/tmp/nas-248-attack-probe.mjs` (imports branch modules + inlined `parseArgs` semantics from the live CLI). Probe never exec'd mutating CLI against real terminals.
- Read-only live `orca terminal list --json` / `orca worktree list --json` / `orca worktree show --json` to confirm **field names only**.

Legend used below:

| Column | Meaning |
|--------|---------|
| Bridge | `evaluateCliArgv(..., {hardening, admin:true, ownershipCheck, dispatchOwnershipCheck})` or the named `server.mjs` path |
| CLI | live `parseArgs` + spec `allowedFlags`; `flags.has('json')` turns on JSON even for `--json=true` |
| Agree? | whether both would allow the *same successful foreign read/close/release* |

---

## Lead findings (ranked)

### F1 — P0 — `action=release` worker-release runs before the ownership gate

`releaseWorker` in `server.mjs` (≈1911–2088) now has the advertised `requireOwnedHandle` block (≈2016–2057) immediately before `terminal close --tab`. That block is not the first effect.

Given a `dispatchId`, the function:

1. Optionally looks the handle up via internal `dispatch-show` / `worker-show` (`runJson`, no policy).
2. **Unconditionally** `runJson(['orchestration','worker-release','--dispatch', dispatchId, '--json'])`.
3. If that call is `ok`, **returns `{ ok: true, mode: 'worker-release' }`**. `requireOwnedHandle` never runs.

`requireOwnedDispatch` is exported, unit-tested, and commented as "release-by-id". `server.mjs` does not call it.

The live CLI spec for `worker-release` is "Release the terminal of one settled supervised worker" and "closes only the exact coordinator-owned agent terminal of that worker." The bridge invokes that CLI as the **host Orca identity**, not as the MCP `clientKey`. Every dispatch this process created is "coordinator-owned" from the runtime's point of view. MCP-client isolation is supposed to be the bridge's job. This path does not do that job.

Reproduction (hardening on or off; do **not** run this against a live foreign dispatch):

```
orca{ action: "release", dispatchId: "<foreign settled ctx_…>" }
```

Control-flow probe (`/tmp/nas-248-attack-probe.mjs` F1): `worker-release-success`, `gated: false`.

Same-effect via `action=cli` (default / hardening **off** only):

```
orca{ action: "cli", args: ["orchestration","worker-release","--dispatch","<foreign>","--json"] }
```

Policy: `allow_with_warning` / `cli_policy_would_deny`. Hardening on: allowlist deny. The `action=release` side door does not need the allowlist.

Close fallback after worker-release *fails* **is** gated. Probe F1b: foreign handle → `ownership-denied`. That is why a description-matching review of lines 2018–2055 would miss this.

### F2 — P0 — `terminal list` preview leak: redaction is `args[0]`/`args[1]` + envelope only

`applyCliOwnershipRedaction` (server.mjs ≈563–595) is not exported and has **zero tests**. It:

- returns immediately unless `args.length >= 2`
- lowercases `args[0]` / `args[1]` and requires exact `terminal`+`list` or `worktree`+`list`
- redacts only `described.envelope`, never `described.stdout`
- `describeRun` builds `envelope` only when `a.args.includes('--json')` (exact token `--json`, not `--json=true`)

Live CLI v1.4.180 `terminal list --json` row keys (keys-only probe, 14 rows):

`handle, ptyId, incarnationId, orphaned, worktreeId, worktreePath, branch, tabId, leafId, title, connected, writable, lastOutputAt, preview`

Human formatter (`terminal-format.js`) prints `preview: ${terminal.preview}` for every row.

| argv | CLI output | Bridge wantJson | Redaction fires? | Foreign preview |
|------|------------|-----------------|------------------|-----------------|
| `terminal list --json` | JSON envelope | yes | yes | **omitted** (happy path) |
| `terminal list` | human text | no | looks at missing envelope | **LEAK via stdout** |
| `terminal list --json=true` | JSON (`flags.has('json')`) | **no** (`includes('--json')` is false) | envelope missing | **LEAK via stdout** |
| `terminal list --json=` | JSON | no | envelope missing | **LEAK via stdout** |
| `--json terminal list` | JSON (`parseArgs` skips leading flags in the path) | yes | `t0='--json'` → skip | **LEAK via envelope** |
| `terminal --json list` | JSON | yes | `t1='--json'` → skip | **LEAK via envelope** |
| `TERMINAL LIST --json` | JSON | yes | lowercased match | redacted |

`--read-only` / status tier still allows `terminal list`. This is the same standing capability NAS-248 was split out to kill (NAS-218 / NAS-170 class), minus the one argv spelling the implementer unit-tested the helper against.

`redactTerminalListPayload` itself is fine on `{terminals:[...]}` / `{result:{terminals}}` / bare arrays. The leak is the **call site**, not the helper.

### F3 — P1 — `requireOwnedDispatch` is dead code on the release path; dispatch-id teardown is ungated

Comment in `state-ownership.mjs`: "Dispatch-id ownership (NAS-248) — worker-read / worker-show / **release-by-id**."

Wired:

- `action=cli orchestration worker-read|worker-show` → `dispatchOwnershipCheck` → `resolveDispatchOwnership`

Not wired:

- `action=release` + `dispatchId`
- `action=cli orchestration worker-release|worker-stop|worker-abandon|worker-retain`
- `action=cli orchestration dispatch-show` (allowlisted, prefix-only)

`dispatch-show --task <id>` is on `RAW_CLI_OK_PREFIXES`, not on either ownership prefix list. Probe: hardening **allow**. It does not return PTY preview (spec is task/dispatch metadata + optional preamble). It does return assignee handles. That is how `releaseWorker` itself learns a handle when the caller omitted one.

### F4 — P1 — interleaved globals skip the new ownership funnel (soft-executes; hardening still allowlist-denies)

`looksLikeOwnershipGatedArgv` still requires **adjacent** `orchestration`+`check|worker-read|worker-show`. Live `parseArgs` skips `--flags` while matching a command path (`commandPathStartsAt`).

| argv | looksGated | tokens | Hardening | Soft (default) | CLI |
|------|------------|--------|-----------|----------------|-----|
| `orchestration check --terminal FOREIGN` | true | `orchestration check` | `handle_not_owned` | warn + run | would run FOREIGN |
| `orchestration --json check --terminal FOREIGN` | **false** | `orchestration` | allowlist deny | **`cli_policy_would_deny` + run, no ownership** | would run FOREIGN |
| `--json orchestration check --terminal FOREIGN` | true (leading-flag path) | `[]` | `handle_not_owned` | warn ownership | would run |
| `orchestration --json worker-read --dispatch FOREIGN` | **false** | `orchestration` | allowlist deny | run, no ownership | would run |

Not a NAS-227 hardening bypass today. It is the same tokenizer disagreement NAS-247 F4 warned about, now on the prefixes NAS-248 just added. Default posture is still hardening **off**.

### F5 — P2 — MCP resources fail open when `clientKey` is missing

`readMcpResource`:

- transcript: denies only if `clientKey && meta?.clientKey && meta.clientKey !== clientKey`
- dispatch row: same
- `registry.list({clientKey})` keeps rows with **empty** `clientKey`

Probe:

- `appendTranscript('disp_orphan', {body:'secret body'})` with no upsert → `orca-bridge://transcripts/disp_orphan` returns the body to `clientKey=alice`. Listed in `resources/list`.
- `upsert('disp_nobind', {status:'seen'})` (no clientKey) → `orca-bridge://dispatches/disp_nobind` is readable.

These are mailbox excerpts the await path already ran through `redactValue`, not raw PTY preview. Still a client-isolation miss, and `listMcpResources` advertises orphan transcript URIs to every client.

Audit log records redacted **args**, not list payloads. Not a preview door.

### F6 — P2 — test suite never drives the effect

New tests (34 of the +34, 287→321) assert:

- `evaluateCliArgv` deny/allow/warn on hand-built argv
- `requireOwnedHandle` / `requireOwnedDispatch` / `redactTerminalListPayload` as pure helpers
- prefix tables contain the new names

They do **not**:

- call `releaseWorker`
- assert worker-release is not invoked for a foreign `dispatchId`
- call `applyCliOwnershipRedaction`
- run `describeRun` + redaction on human / `--json=true` / leading-flag argv
- start an in-process bridge and issue `action=release` / `action=cli`

This is how the NAS-247 duplicate-flag bypass survived the first review: the suite agreed with the policy object.

### What held (negative results — useful)

| Attempt | Result |
|---------|--------|
| `action=cli terminal read\|close\|send --terminal FOREIGN` (hardening on) | deny `handle_not_owned` |
| `action=cli orchestration check --terminal FOREIGN` (canonical spelling, hardening on) | deny `handle_not_owned` |
| `action=cli orchestration worker-read\|show --dispatch FOREIGN` (`=` and space forms) | deny, `ownership_kind=dispatch` |
| deny-any own-then-foreign `--terminal` / `--dispatch` | deny |
| missing `--dispatch` on worker-read | unknown fail-closed |
| `--id` / `--dispatch-id` instead of `--dispatch` | collector sees nothing → unknown deny; CLI spec does not allow those flags |
| `--TERMINAL` / `--Dispatch` case variants | not collected; check-without-`--terminal` skips (pin-inject path) but CLI rejects unknown flag |
| `requireOwnedHandle(FOREIGN)` / `null` / missing registry | `ok: false` |
| `ownershipCheck` throws | policy deny, `ownership_check_threw` |
| `runtimeId` passed as deps noise | verdict unchanged; no `runtimeId` parameter |
| bridge-restart: wiped `clientOwnership` + registry, pin remains | worker handle **unknown fail-closed**; pin still owned |
| own handle after worker-release miss | `requireOwnedHandle` allows → close fallback (legitimate path still works) |
| `action=check` (not cli) | argv is constructed by the bridge; caller cannot inject `--terminal` |
| live worktree list / worktree show JSON (v1.4.180) | **no `preview` key** — F2 worktree half is dead code against this runtime |
| `worker-stop` / `inbox --terminal` under hardening | allowlist deny |

---

## Attack log (parser / argv)

Handles in the probe: `OWN=term_own_aaaaaaaa` (alice worker), `FOREIGN=term_foreign_bbbbbbbb` (bob), `SENDER=term_sender_cccccccc` (alice pin), `DISP_OWN` / `DISP_FOREIGN`. Hardening on unless noted.

### 1. Flag-value syntax (handle + dispatch)

| argv | Bridge (hardening) | CLI | Agree? |
|------|--------------------|-----|--------|
| `orchestration check --terminal FOREIGN --json` | deny foreign | would run FOREIGN | yes (gate holds) |
| `orchestration check --terminal=FOREIGN` | deny foreign | would run | yes |
| `orchestration check --json` (no handle) | **allow** (pin-inject skip) | inject / resolveActive | intended |
| `orchestration worker-read --dispatch FOREIGN` | deny foreign dispatch | would run | yes |
| `orchestration worker-read --dispatch=FOREIGN` | deny | would run | yes |
| `orchestration worker-read --dispatch OWN --dispatch FOREIGN` | deny-any | last-wins FOREIGN | fail-closed |
| `orchestration check --terminal OWN --terminal FOREIGN` | deny-any | last-wins FOREIGN | fail-closed |
| `orchestration worker-read --id FOREIGN` | no `--dispatch` → unknown deny | unknown flag | both fail |
| `orchestration worker-read --dispatch-id FOREIGN` | unknown deny | unknown flag | both fail |
| `orchestration check --TERMINAL FOREIGN` | not collected; orch-check skip → **allow** | unknown flag | CLI fails; bridge would run check on injected pin (not FOREIGN) |
| `orchestration worker-read --Dispatch FOREIGN` | unknown deny | unknown flag | both fail |

Collectors match live `parseArgs` for `--terminal` / `--dispatch` space and `=` forms, including empty/`=` → null and flag-shaped values. No second extractor. The NAS-247 duplicate-flag class did not reopen.

### 2. Leading / interleaved globals (the class that breaks redaction + soft ownership)

Live `parseArgs` does not implement POSIX `--`. Global `--json` may appear before or between command tokens; `commandPathStartsAt` skips flags.

| argv | looksGated | Hardening | Soft | CLI would run? |
|------|------------|-----------|------|----------------|
| `--json orchestration check --terminal FOREIGN` | true | ownership deny | ownership warn | yes |
| `orchestration --json check --terminal FOREIGN` | false | allowlist deny | **run, no ownership** | yes |
| `--json orchestration worker-read --dispatch FOREIGN` | true | ownership deny | ownership warn | yes |
| `orchestration --json worker-read --dispatch FOREIGN` | false | allowlist deny | **run, no ownership** | yes |
| `terminal --json read --terminal FOREIGN` | false | allowlist deny | run, no ownership | yes |
| `--json terminal list` | n/a (not gated) | allow + **no redact** | same | yes, JSON previews |

### 3. Case, whitespace, unicode

Same as NAS-247. No prefix matching, no case-fold on flag names. `normalizeTerminalHandle` / `normalizeDispatchId` trim and reject embedded whitespace. Padded FOREIGN still denys after trim. ZWSP / lookalikes ≠ registered handle → unknown deny. Not foreign-reachable.

### 4. Aliases and other handle-bearing commands

From live specs, every `--terminal` / `--dispatch` consumer:

```
orchestration check --terminal          ← gated (NAS-248)
orchestration inbox --terminal          ← not allowlisted
orchestration worker-start --terminal   ← admin
orchestration worker-{show,read,release,stop,abandon,retain} --dispatch
                                        ← show/read gated; the rest not
orchestration dispatch-show --task      ← allowlisted, not gated
orchestration send --to / --dispatch-id ← admin
terminal {read,close,send} --terminal   ← gated (NAS-247)
terminal {show,wait,switch,rename,split} --terminal  ← not allowlisted
terminal list                           ← allowlisted; preview redaction is F2
terminal stop --worktree                ← not allowlisted; stops every terminal in a worktree
worktree {list,show}                    ← allowlisted; v1.4.180 JSON has no preview
worktree ps                             ← not allowlisted; formatter still has preview
```

No `--pane`, `--term`, `--dispatch-id` alias on worker-read. `worker-read` allowedFlags are exactly `dispatch, source, cursor, limit`.

### 5. Soft mode (hardening off) — default ship posture

Default is still `ORCA_BRIDGE_CLI_HARDENING !== '1'`. Every ownership miss on `action=cli` is `allow_with_warning`. That includes the prefixes NAS-248 just "gated." Soft mode is the documented migration knob for the **allowlist**, and the implementer reused it for ownership. That is incompatible with the ticket sentence "ownership becomes an invariant every handle-accepting path passes through."

`requireOwnedHandle` itself has no soft mode. Only the close fallback uses it.

---

## Fail-closed / back-compat

| Check | Result |
|-------|--------|
| Unknown / missing / malformed handle | `HANDLE_UNKNOWN` → `requireOwnedHandle.ok === false` |
| Missing registry | `missing_registry` → fail-closed |
| `ownershipCheck` throws | policy deny |
| Ghost handle after bridge restart | unknown fail-closed (tested) |
| Pin after bridge restart | still owned (tested); coordinator set still refuses close of that handle |
| `runtimeId` | not a resolver key; noise deps do not change the verdict |
| Legitimate same-process release of owned worker handle | allowed on the close fallback (probe F1c) |
| Legitimate release after **runtime** restart (same bridge process, `runtimeId` flipped) | still allowed — maps are keyed on `clientKey` |
| Legitimate inject-path release after **bridge process** restart | **false deny** on the close fallback (documented as intentional). Worker-release side door still fires if the dispatch is still settled in the runtime. |

Both a false allow (F1) and a false deny (post-bridge-restart close) exist. The ticket's back-compat note was about `runtimeId` changing mid-session, not about wiping `clientOwnership`. That narrower claim holds.

---

## Implementer-claim scorecard

| Claim | Accurate? |
|-------|-----------|
| Single chokepoint `resolveTerminalHandleOwnership` + `resolveDispatchOwnership` | **No.** `action=release` worker-release, list stdout, MCP resources, and non-allowlisted cli teardown do not require a successful owned verdict. |
| `requireOwnedHandle` on `action=release` before close | **Half.** True for the close fallback. False as a description of the function. |
| `orchestration check --terminal` gated | **Yes**, for adjacent-token argv under hardening. |
| `worker-read` / `worker-show` gated | **Yes**, same caveat. |
| `terminal list` omits `preview` on non-owned rows, inventory kept | **Only** for `args[0..1]==['terminal','list']` plus a parsed envelope. |
| `worktree list` strips all previews | Helper exists. Live v1.4.180 list/show JSON **has no preview**. Human `worktree ps` still formats preview and is not redacted (not allowlisted). |
| Zero `runtimeId` dependency | **Yes.** |
| Tests 321 / 0 fail | **Yes** (this review, same commit). |
| Unknown fails closed | **Yes** in the resolvers / `requireOwnedHandle`. **No** for worker-release and MCP rows with empty `clientKey`. |

---

## Brief verification

| Check | Result |
|-------|--------|
| `npm test` (this review, `69b1c9f`) | **321 pass / 0 fail / 0 skipped** |
| `ORCA_BRIDGE_CLI_HARDENING` default | still off (`=== '1'` to enable) — byte-identical default to `origin/main` |
| `RAW_CLI_OK_PREFIXES` / `RAW_CLI_ADMIN_PREFIXES` | unchanged vs NAS-247 (dispatch-show still allowlisted, worker-release still absent) |
| `lib/toolsets.mjs` / default-all | 0-byte diff vs the parent commit |
| Scope | only the five files in the commit. No toolset/allowlist/default edits. |

---

## What I would not call a break

- Deny-any rejecting foreign-then-owned. Conservative, intentional.
- Orch-check with no `--terminal` skipping ownership (pin injected after policy).
- `--TERMINAL` allowing the check (CLI rejects the flag; pin is used, not FOREIGN).
- `redactTerminalListPayload` leaving hypothetical `tail`/`scrollback` keys — live list rows do not have those keys.
- Soft-mode execution, **if** one still accepts NAS-247's migration story. I do not accept it as satisfying NAS-248's invariant claim, but it is not a new parser hole.
- `worktree show` dumping every key — no `preview` on this runtime.

---

## Recommendation (not implemented — review is read-only)

1. **Treat F1 as blocking.** Call `requireOwnedDispatch(dispatchId)` *before* `worker-release`, and do not return success on a foreign/unknown id. Internal `runJson` is fine only after that check. This is the NAS-202 actor-shaped path.
2. **Treat F2 as blocking** if NAS-248's purpose is the scrollback class (NAS-218/170). Redact after `describeRun` by **command identity** (`commandTokens` / `parseArgs` path), not `args[0]`/`args[1]`. Redact `stdout` when there is no envelope. Treat `--json=*` as JSON. Add tests that drive `applyCliOwnershipRedaction` through those four leak argv.
3. Wire `requireOwnedDispatch` or delete the comment that says it gates release-by-id.
4. Fail closed on MCP reads when `meta.clientKey` is missing; do not list orphan transcripts to every client.
5. If `commandTokens` is ever taught to skip globals, F4 becomes a hardening bypass. Fix adjacency first.
6. Do not merge under the belief that "ownership is now an invariant." It is a check on some cli prefixes and on one of two release effects.

Probe JSON: `/tmp/nas-248-attack-probe.json`  
Probe script: `/tmp/nas-248-attack-probe.mjs`

---

## Fix pass (bypass repair) — 2026-08-13

**Worker:** NAS-248 bypass-fix dispatch on `BuildContext/nas-248-ownership-invariant`  
**Base:** `ee61c23` (adversarial review)  
**Production touch:** `server.mjs`, `lib/cli-policy.mjs`, `lib/state-ownership.mjs`, new `lib/release-worker.mjs`  
**Suite:** **346 pass / 0 fail / 0 skipped** (was 321; +25 effect-driving / shape / interleaved-flag regressions)

### P0 #1 — `action=release` gate-before-effect

**Restructure:** extracted `lib/release-worker.mjs` with `preflightReleaseOwnership` → `executeReleaseWorker`. Ordering is now hard:

1. `requireOwnedDispatch(dispatchId)` via `resolveDispatchOwnership` (when id present)
2. `requireOwnedHandle(handleHint)` via `resolveTerminalHandleOwnership` (when handle present)
3. **Only then** optional lookup / `worker-release` / close
4. Close path re-checks handle via `preflightCloseHandle` before `terminal close`

`server.mjs` `releaseWorker` is a thin wrapper: runtime-ready + live deps → `executeReleaseWorker`. No `runJson` of any kind (including "harmless" lookup) runs ahead of the gate. `requireOwnedDispatch` is wired; no third argv extractor.

Regression: `lib/release-worker.test.mjs` drives the real effect path with a mocked `runJson` recorder — foreign `dispatchId` yields `ownership_denied` and **zero** effect calls. Owned close-fallback after `dispatch_not_found` still works (back-compat held).

### P0 #2 — shape-based list redaction

**Restructure:** `applyOwnershipListRedaction(described, ownedHandles)` in `state-ownership.mjs` keys on **response shape**:

- envelope / envelope.result / bare payload with `terminals[]` → `redactTerminalListPayload`
- worktree preview rows → `redactWorktreeListPayload`
- JSON stdout when envelope missing (`--json=true` / `--json=` paths)
- human stdout `preview:` lines → `redactTerminalListHumanStdout` (owned keep, foreign → `<redacted>`)

`applyCliOwnershipRedaction` in `server.mjs` no longer inspects `args[0]`/`args[1]`. `argvWantsJson` treats `--json`, `--json=true`, `--json=` as JSON so envelopes parse when present; redaction still works without envelope via stdout shape.

Table-tested argv spellings: plain list, `--json`, `--json=true`, `--json=`, `--json terminal list`, `terminal --json list`, case variants.

### P1 — ownership independent of hardening

**Findings that relied on the hardening flag for ownership (now fixed):**

1. `ownershipDecision` soft-returned `allow_with_warning` when `!hardening` — **removed**. Ownership always denies; `onWarning` still fires for observability under soft allowlist posture.
2. Interleaved globals (`orchestration --json check`) made `looksLikeOwnershipGatedArgv` false (adjacent-token only) so ownership was skipped and soft mode executed — **fixed** by flag-skipping scanner (leading *and* interleaved).
3. Soft-exec path for `worker-release|stop|abandon|retain` under hardening off — **gated** by expanding `DISPATCH_OWNERSHIP_GATED_PREFIXES` and the same always-deny ownershipDecision. Allowlist still denies these under hardening on (unchanged); ownership now stops them with hardening off too.

Hardening remains the **allowlist** migration knob only. Default is still off (`ORCA_BRIDGE_CLI_HARDENING !== '1'`). NAS-227 not touched.

### What still holds (no regression)

- Canonical check / worker-read / worker-show deny-any
- Unknown `--id` / `--dispatch-id` fail closed (collector sees nothing)
- Close-fallback still calls ownership before close
- No `runtimeId` keying
- Unknown ownership fail-closed in resolvers
- Coordinator releasing own handle in-process still works (owned worker-release + close-fallback tests)

### Disagreement with the review

**None on the P0/P1 breaks** — F1/F2/F4 were accurate against `69b1c9f`/`ee61c23` code. Minor notes:

- F3's `dispatch-show` assignee-handle metadata leak is real but out of scope for this pass (not P0; no PTY preview). Left as follow-up.
- F5 MCP orphan `clientKey` fail-open is real P2; not in this ticket's DoD.
- Soft-mode allowlist warnings remain for *non-ownership* misses (`cli_policy_would_deny`) — intentional NAS-247 migration story; only ownership was inverted to invariant.

### Files

| File | Change |
|------|--------|
| `lib/release-worker.mjs` | new — gate-first release orchestration |
| `lib/release-worker.test.mjs` | new — effect-ordering regressions |
| `lib/state-ownership.mjs` | `applyOwnershipListRedaction`, human stdout redaction |
| `lib/state-ownership.test.mjs` | shape/argv table tests |
| `lib/cli-policy.mjs` | always-deny ownership; interleaved flag scan; teardown prefixes |
| `lib/cli-policy.test.mjs` | soft→deny expectations; interleaved P1 table |
| `server.mjs` | thin release wrapper; shape redaction; `argvWantsJson` |
| this doc | append-only findings |

---

## Second adversarial review — 2026-08-13 (verification of the bypass-fix)

**Reviewer:** dispatched attack worker, fresh (did not write `69b1c9f` or `367ebb6`)  
**Target:** `BuildContext/nas-248-ownership-invariant` @ `367ebb6`  
**Worktree:** `/home/orca/orca/workspaces/orca-mcp/nas-248-attack-review-2` (detached at the target commit; sibling worktree already holds the branch name)  
**CLI oracle:** live AppImage v1.4.180 `parseArgs` / `BOOLEAN_FLAGS` / `printResult` / `formatTerminalShow` (`/tmp/nas-248-cli/squashfs-root/.../out/cli`)  
**Independent suite:** **346 pass / 0 fail / 0 skipped** (`npm test` on this commit)  
**Production code changed by this review:** no  
**Bridge process touched:** no  
**Destructive live `release` / `close` / `worker-release` / `worker-stop` / `terminal stop` / `worktree rm`:** not executed (NAS-202 boundary)  
**Read-only live probes:** `terminal list --json` (keys only), `terminal show --json` of *this worker's own* handle (keys only), `worktree list --json` (keys only)

Treat the fix-author claims as hypotheses. Deliverable is attack shapes and results, not "the description matches the code."

Probe JSON: `/tmp/nas-248-r2-probe.json`  
Probe script: `/tmp/nas-248-r2-probe.mjs`

### Verdict

**Still breakable.** The two named P0 reproductions from the first review are genuinely dead. Ownership is still not a system invariant. Two new P0s are live on this commit under the actual ship posture (`ORCA_BRIDGE_CLI_HARDENING` unset / off):

1. **`action=cli terminal show --json --terminal <foreign>` returns foreign `preview`.** Policy is `allow_with_warning` with hardening off (`looksLikeOwnershipGatedArgv` is false — only `read|close|send` are handle-gated). `applyOwnershipListRedaction` keys on `terminals[]`, so `result.terminal.preview` is not a recognized shape. Live v1.4.180 `printResult` pretty-prints `{ result: { terminal: { preview, … } } }`; own-handle probe: `preview` present, 300 chars, `result.terminals` absent. This is the NAS-218/170 class the ticket was split out to kill, via the command the first review listed as "not allowlisted" and the fix never gated.
2. **`action=await` with an empty `clientOwnership.dispatches` set fail-opens the mailbox, then `dispatchRegistry.upsert(..., { clientKey: attacker })` overwrites the victim row. `requireOwnedDispatch` then returns `owned`.** In-process: bob's `disp_bob` becomes alice-owned; a subsequent `action=release` would pass the new preflight and call `worker-release`. This is the NAS-202 actor-shaped path, one hop past the gate the fix just wired. The deferred F5 ("orphan read") was the read side of the same `clientKey` model; the write-up was not assessed.

A green suite at 346/0 does not cover either shape.

---

### Priority 1 — original P0 reproductions

#### P0 #1 (`action=release` worker-release before the gate) — **DEAD**

`server.mjs` `releaseWorker` is a thin wrapper: `ensureRuntimeReady` then `executeReleaseWorker`. No `runJson` in the wrapper. `preflightReleaseOwnership` runs before lookup / `worker-release` / close.

In-process (`executeReleaseWorker` + recording `runJson`):

| Shape | Result |
|-------|--------|
| `{ dispatch_id: FOREIGN }` | `ownership_denied`, **0** `runJson` calls |
| `{ terminal_handle: FOREIGN }` | `ownership_denied`, **0** calls |
| owned dispatch + foreign handle | preflight `ok:false kind=handle` |
| whitespace-only dispatch, no handle | treated as missing, denied |
| missing both ids | denied |
| unknown after wiped maps | denied, 0 calls |
| owned dispatch | `mode=worker-release`, one `worker-release --dispatch OWN` call |

No production caller of `executeReleaseWorker` except `releaseWorker`. No leftover `terminal close` in `server.mjs` that skips the preflight. Error/fallback after a failed worker-release re-runs `preflightCloseHandle` before close. The gate does not throw-and-continue; it returns a denial envelope.

`requireOwnedDispatch` is wired. The first review's "exported and never imported by `server.mjs`" claim is no longer true.

Not executed against any live foreign dispatch.

#### P0 #2 (`terminal list` preview leak via argv spelling) — **DEAD for list; sibling command is not**

Live v1.4.180 still ships `preview` on every list row (16/16 nonempty; keys only logged). `printResult` is `JSON.stringify(response, null, 2)` — pretty-printed, starts with `{`, no banner on this runtime. `worktree list --json` still has **no** `preview` key.

`applyOwnershipListRedaction` does not inspect argv. Combined with `argvWantsJson` (`--json` / `--json=*`) and `describeRun` parsing the whole pretty blob as the envelope, every list spelling the live `parseArgs` actually honours is redacted:

| argv | CLI `flags.has('json')` | Bridge `argvWantsJson` | Foreign preview after redaction |
|------|-------------------------|------------------------|----------------------------------|
| `terminal list` | no | no | **omitted** (human `preview:` → `<redacted>`) |
| `terminal list --json` | yes | yes | **omitted** |
| `terminal list --json=true` | yes (`json="true"`) | yes | **omitted** |
| `terminal list --json=` | yes (`json=""`) | yes | **omitted** |
| `terminal list --json=false` | yes (`json="false"`; boolean flag is presence) | yes | **omitted** |
| `terminal list --json=0` | yes | yes | **omitted** |
| `--json terminal list` | yes | yes | **omitted** |
| `terminal --json list` | yes | yes | **omitted** |
| `terminal list --json --json` | yes | yes | **omitted** |
| `terminal list --json --include-visual-layouts` | yes | yes | **omitted** |
| `terminal list --limit 20 --json` | yes | yes | **omitted** |
| `terminal list --worktree path:/x --json` | yes | yes | **omitted** |
| `terminal list --json true` | yes (boolean does not consume `true`) | yes | **omitted** |
| `TERMINAL LIST --json` | yes | yes | **omitted** (CLI `commandPath` is case-sensitive and would reject; redaction still holds) |
| `terminal list --JSON` | **no** | **no** | n/a — live CLI unknown flag |
| `-j terminal list` | **no** | **no** | n/a — no short flag in `parseArgs` |

`parseArgs` has no `--` terminator, no `-j`, no case-fold on flag names. `BOOLEAN_FLAGS` includes `json`. No sixth *list* spelling. The first review's five leak spellings are closed.

The sixth shape is not a list spelling. It is `terminal show`. See N1 below.

Latent (not live on this CLI, no banner): banner + pretty JSON makes `findEnvelopeBody` miss (`whole` does not start with `{`) and `JSON.parse(trimmed stdout)` fail; human redaction looks for lines starting `preview:` and `term_…` headers, so `"preview": "SECRET"` survives. Compact-JSON-after-banner is parsed (line starting `{`). Recorded as P1 latent, not a live P0.

---

### Priority 2 — attack the new abstraction

| Attack | Result |
|--------|--------|
| Call `executeReleaseWorker` without going through `preflightReleaseOwnership` | Not possible. The function itself is the only production path and calls preflight first. |
| `server.mjs` close / worker-release leftover | None. Wrapper is as claimed. |
| Effect after gate threw / returned undefined | Gate returns `{ok:false}`; wrapper returns `releaseOwnershipDenial`. No catch that proceeds. |
| Injected `ownershipDeps` forging ownership | Works in-process (the lib is a deps wrapper). Not a client-facing bypass — production deps are the live maps. Note only. |
| `applyOwnershipListRedaction` on `result.terminal` (show) | **Miss.** See N1. |
| `scrollback` key instead of `preview` on a list row | **Miss.** Matcher looks for the key to decide "this is a list" but `redactTerminal` only `delete`s `preview`. Live list rows do not have `scrollback`. P1 latent. |
| `envelope.error.preview` | Not stripped. Not a live list shape. |
| `envelope.result.result.terminals` | Actually stripped — `redactTerminalListPayload` walks one `result.terminals`. |
| stderr / stderrTail | Never inspected. Live list preview is stdout. |
| Streamed / chunked | `runOrca` is `execFile`; client sees the finished `describeRun`. No mid-flight leak. |
| MCP `orca-bridge://transcripts/*` and `dispatches/*` | Still fail-open on missing `clientKey`. See F5 / N2. Audit log records redacted **args**, not list payloads. Not a preview door. |
| `action=check` | Argv still constructed internally; caller cannot inject `--terminal`. Holds. |

The extraction into `lib/release-worker.mjs` is not itself a bypass. The new surface that is a bypass is **shape-based redaction that only knows about list rows**, plus **policy that only knows about a prefix table**.

---

### Priority 3 — `ORCA_BRIDGE_CLI_HARDENING` OFF (live VM posture)

`ORCA_BRIDGE_CLI_HARDENING` is unset here. Default is still `!== '1'`.

On the prefixes the fix named, the claim holds. Hardening off, ownership still denies:

| argv | decision (hardening off) |
|------|--------------------------|
| `orchestration check --terminal FOREIGN` | `deny` / `handle_not_owned` |
| `orchestration --json check --terminal FOREIGN` | `deny` / `handle_not_owned` |
| `orchestration worker-read\|show --dispatch FOREIGN` | `deny` |
| `orchestration worker-release\|stop\|abandon\|retain --dispatch FOREIGN` | `deny` |
| `orchestration --json=true worker-release --dispatch FOREIGN` | `deny` |
| `terminal read\|close --terminal FOREIGN` | `deny` |

On every other handle- or worktree-accepting command the live CLI honours, ownership is **not consulted**. Soft-exec (`allow_with_warning`) is the whole control. That is the allowlist, not an ownership invariant.

| argv | looksGated | hardening OFF | hardening ON |
|------|------------|---------------|--------------|
| `terminal show --terminal FOREIGN --json` | **false** | **`allow_with_warning` → CLI would return preview** | allowlist deny |
| `terminal --json show --terminal FOREIGN` | false | same | deny |
| `--json terminal show --terminal FOREIGN` | false | same | deny |
| `terminal stop --worktree <foreign>` | false | **`allow_with_warning` → would stop every terminal in that worktree** | deny |
| `worktree rm --worktree <foreign>` | false | **`allow_with_warning`** (NAS-202 checkout removal) | deny (admin) |
| `orchestration inbox --terminal FOREIGN` | false | allow_with_warning | deny |
| `terminal wait\|switch\|rename\|split --terminal FOREIGN` | false | allow_with_warning | deny |
| `worktree ps --json` | false | allow_with_warning; shape redaction would strip worktree previews if present | deny |
| `orchestration dispatch-show --task FOREIGN` | false | **`allow`** (allowlisted) | **`allow`** |
| `orchestration worker-list` | false | allow_with_warning | deny |

`terminal stop` and `worktree rm` were **not executed**. The proof is the guard not seeing a command the live CLI would honour. That is the same class of proof the first review used for F1.

If anything still relies on the allowlist for an ownership guarantee, the ticket's premise is unmet. It does.

---

### Lead findings (this round)

### N1 — P0 — `terminal show --json` is the list-redaction sibling the fix never named

Live formatter (`terminal-format.js` `formatTerminalShow`):

```
preview: ${terminal.preview || '<empty>'}
```

Live JSON (own handle, keys only): `result.terminal.preview` exists; `result.terminals` does not.

`looksLikeOwnershipGatedArgv` / `OWNERSHIP_GATED_PREFIXES` cover `terminal read|close|send` only. `terminal show` is the command whose summary is literally "Show terminal metadata and preview."

`applyOwnershipListRedaction`:

- `looksLikeTerminalListPayload` requires a `terminals[]` array (or a bare array of handle/preview rows)
- `result.terminal` is a single object → not redacted
- Human `terminal show` accidentally fail-closes (no `term_…` header line, so `preview:` is rewritten to `<redacted>`)
- JSON does not

Reproduction (hardening off — the live default). Do **not** point this at a foreign handle if you would log the body; the policy + shape proof is sufficient:

```
orca{ action: "cli", args: ["terminal", "show", "--terminal", "<foreign>", "--json"] }
```

Policy: `allow_with_warning`. CLI: honours. Redaction: no-op. Same `--json=true` / leading / interleaved `--json` forms as P0 #2, all still leaks, because the miss is the payload shape, not the flag spelling.

This is why a description-matching review of `applyOwnershipListRedaction` plus the seven list argv rows would pass.

### N2 — P0 — empty owned-set + await upsert forges `clientKey` and then passes the new release gate

`partitionMailbox` (documented):

```
if (owned.size === 0) return { own: list, foreign: [], filtered: false };
```

`awaitDispatch` then, for every message in `own`:

```
dispatchRegistry.upsert(did, { status, runId, clientKey: ck, ... })
```

`upsert` is `{ ...prev, ...patch }`. A row that belonged to bob becomes `clientKey: alice`.

`collectDispatchIdSets` / `requireOwnedDispatch`: `rowKey && rowKey === ck` → **owned**.

In-process (no live run, no foreign teardown):

```
owned = empty Set
messages = [{ type: 'worker_done', dispatchId: 'disp_bob', ... }]
partitionMailbox → own=1, foreign=0
upsert(disp_bob, { clientKey: 'alice' })
requireOwnedDispatch('disp_bob', 'alice') → ok: true, status: 'owned'
```

Reachability:

- **Bridge restart / first await:** `clientOwnership` is in-memory. Empty `dispatches` is the documented restart posture. The *release* path fail-closes on unknown; the *await* path fail-opens and then writes ownership.
- **`action=await runId=<any existing run>`:** `run-use` is invoked via internal `runJson` (no policy). A client that knows or guesses a run id binds their sender, reads that mailbox, and if their `dispatches` set is empty, steals every `dispatchId` in it. I did **not** run this against a live foreign run — `run-use` would fence the owner's consumer.
- **Suppression of `next.action=release` is gated on `owned.size > 0`.** Empty set → the coordinator is *told* to release the stolen id. The new preflight then allows it.

This is not the MCP orphan-read the author deferred. It is a write-up of `clientKey`, which is the only key the new invariant uses. Every gate above is decorative after one empty-set await.

### N3 — P0 (argv proof, not executed) — `terminal stop --worktree` still soft-executes

The fix extended `DISPATCH_OWNERSHIP_GATED_PREFIXES` so `worker-stop` cannot soft-exec. `terminal stop --worktree` stops **every** terminal in a worktree and is not on any ownership list. Hardening off: `allow_with_warning`. That is the session-kill half of NAS-202, still allowlist-only.

`worktree rm` is the checkout-removal half. Same posture. Ranked just below N3 because it is not handle-keyed; it is still an ownership-shaped teardown that the allowlist is the only brake on.

### F3 (deferred) — P1 — `dispatch-show` still ungated, hardening on or off

Allowlisted. `looksLikeOwnershipGatedArgv` is false. Returns assignee handle + dispatch / task / status. No PTY preview on the spec. The author called this out-of-scope / not P0. **As a preview leak, that deferral is correct.** As reconnaissance for N2 (run id / dispatch id / assignee handle), it is the oracle. Still P1, not P0, on its own.

### F5 (deferred) — P2 as stated; P0 next to it was missed

Confirmed still live, unchanged:

- `registry.list({ clientKey })` keeps `!d.clientKey` rows
- `readMcpResource` denies only if `clientKey && row.clientKey && row.clientKey !== clientKey`
- `listMcpResources` advertises orphan transcript URIs to every client
- Bound-to-bob rows are denied to alice (that half holds)
- Empty `clientKey` does **not** make `requireOwnedDispatch` treat the row as owned (`rowKey && rowKey === ck` fails closed)

So the deferred F5 *read* is still P2 (redacted mailbox excerpts + metadata, not PTY preview) and was not wrongly deferred **as written**. What was wrongly treated as "the clientKey story" is N2. An orphan/missing key is not forgeable into a release. An overwritten key is.

`deriveClientKey` itself is not attacker-settable from tool args. `sessionClientKey` reuse, `master`/`anonymous`/`default` sharing, and stdio=`master` are single-tenant by design, not a multi-tenant forge.

---

### Priority 5 — opposite failure / tests

| Check | Result |
|-------|--------|
| Legitimate owned `action=release` (in-process) | Works. `worker-release` after preflight. |
| Close-fallback after `dispatch_not_found` | Works. Second `preflightCloseHandle` then `terminal close`. |
| `runtimeId` flipped, same `clientKey` maps | Verdict unchanged. Not a resolver key. Ticket back-compat note holds. |
| Unknown / missing / malformed | Fail-closed on release and on gated cli prefixes. |
| Bridge-restart wipe of `clientOwnership` | Release fail-closes. **Await fail-opens (N2).** Asymmetric, and the dangerous half is await. |
| Own `orchestration check` without `--terminal` | Still skip (pin inject). Own `--terminal` allows. |
| Own `worker-read` | Allows. |

**Tests.** 321 → 346 is +25 as claimed. They are better than the NAS-247 suite:

- `lib/release-worker.test.mjs` (8 cases) drives `executeReleaseWorker` with a recording `runJson`. Foreign dispatch/handle → zero effects. This is a real effect test. It would have caught P0 #1.
- `applyOwnershipListRedaction` table feeds a **pre-built list envelope** for each argv and never calls `describeRun`. Argv is unused. That would not have caught N1 (`result.terminal`) or the banner+pretty landmine.
- Soft→deny / interleaved tables cover the named prefixes only. No `terminal show`, no `terminal stop`, no `dispatch-show`, no await upsert.

A green 346 is consistent with both new P0s.

---

### Attack log (this round)

Handles: `OWN=term_own_aaaaaaaa`, `FOREIGN=term_foreign_bbbbbbbb`, `OWN_D=disp_own`, `FOREIGN_D=disp_foreign`. Hardening off unless noted. No live mutating CLI.

#### Release

Already tabulated under P0 #1. All foreign / unknown / missing shapes denied with zero effects. Owned succeeds.

#### List argv vs live `parseArgs`

Already tabulated under P0 #2. Agreement between `flags.has('json')` and `argvWantsJson` for every form `BOOLEAN_FLAGS` actually accepts. Disagreement on `--JSON` / `-j` is both-fail (CLI does not honour them).

#### Show / stop / other siblings

See Priority 3 table. N1 is the live read P0. N3 is the argv-proof destructive P0.

#### MCP / clientKey

| Shape | Result |
|-------|--------|
| `appendTranscript('disp_orphan')` no upsert | listed to alice; body readable |
| `upsert('disp_nobind', {status:'seen'})` | listed + readable |
| `upsert('disp_bob', {clientKey:'bob'})` then alice read | denied |
| empty owned-set + upsert overwrite (N2) | **alice owns bob's id** |

---

### Implementer-claim scorecard (this commit)

| Claim | Accurate? |
|-------|-----------|
| `preflightReleaseOwnership` before any `runJson` (lookup / worker-release / close) | **Yes.** Reproduced. |
| `server.mjs` is a thin deps wrapper over `lib/release-worker.mjs` | **Yes.** |
| Redaction keys on response shape (envelope / JSON-stdout / human `preview:` lines) | **Only for list-shaped payloads.** `result.terminal.preview` (the live `terminal show` JSON) is untouched. Human show is accidentally redacted. |
| `argvWantsJson` covers `--json=*` | **Yes.** Matches live `BOOLEAN_FLAGS` presence semantics, including `--json=false`. |
| Ownership denies independently of `ORCA_BRIDGE_CLI_HARDENING` | **Only on the prefix tables they extended.** `terminal show`, `terminal stop`, `worktree rm`, `inbox`, `wait/switch/rename/split` still soft-exec. |
| `looksLikeOwnershipGatedArgv` skips interleaved flags | **Yes**, for those prefixes. `orchestration --json check` denies. |
| `DISPATCH_OWNERSHIP_GATED_PREFIXES` includes release/stop/abandon/retain | **Yes.** Soft-exec of those four is closed. |
| Hardening remains allowlist-only | **Yes** — and that is why N1/N3 exist. |
| F3 / F5 correctly deferred as non-P0 | **F3 yes (as preview). F5-as-read yes (P2). The clientKey write-up (N2) is P0 and was not in the deferral.** |
| Tests 346 / 0 fail | **Yes** (this review). |
| Legitimate coordinator release still works | **Yes** in-process, including `runtimeId` noise. |
| Unknown fails closed | **Yes** on release / gated cli. **No** on await mailbox + upsert. |

---

### What I would not call a break

- Closing the original five `terminal list` spellings. They are closed.
- Wiring `requireOwnedDispatch` on `action=release`. That P0 is dead.
- Deny-any on own-then-foreign. Conservative.
- Over-redacting human `terminal show` / human `worktree ps` (no `term_…` header). Fail-closed, not a leak.
- `worktree list` "redaction" against a runtime with no preview key.
- Soft-mode allowlist warnings on *non-handle* commands, **if** one still accepts NAS-247's migration story. I do not accept it as satisfying NAS-248 once `terminal show` and `terminal stop` are in the handle/teardown set.
- Deps injection in unit tests.

---

### Recommendation (not implemented — review is read-only)

1. **Treat N1 as blocking.** Gate `terminal show` the same way as `terminal read` (prefix + `looksLikeOwnershipGatedArgv`). Extend `applyOwnershipListRedaction` to `result.terminal` / any object with `handle`+`preview`/`scrollback`, not just `terminals[]`. Add a test that feeds a live `printResult` show envelope through `describeRun` + redaction, not a hand-built list.
2. **Treat N2 as blocking.** `partitionMailbox` must fail closed on an empty owned set (or await must refuse to run until this client has a registered dispatch). `upsert` must not overwrite a different `clientKey`. After restart, unknown must not become "alice owns everything she can see." Add an effect test: empty owned + foreign `worker_done` → zero upserts of `clientKey: alice` and `requireOwnedDispatch` still false.
3. **Treat N3 as blocking for the NAS-202 claim.** `terminal stop --worktree` (and, if the invariant is real, `worktree rm`) cannot remain allowlist-only under hardening off.
4. Keep F3 as a follow-up unless N2 stays open — then `dispatch-show` is the ID oracle and should be gated.
5. Do not merge under "the two P0s are fixed, 346 green." They are fixed. The invariant is not.

Independent suite: **346 pass / 0 fail / 0 skipped**.

## Fix pass (P0 #4 claim-path / N2) — 2026-08-13

**Implementer:** dispatched fix worker on `BuildContext/nas-248-ownership-invariant` (HEAD was second-review `00ebeb2`).  
**Scope:** only N2 / P0 #4 (empty owned-set + await upsert forges `clientKey`).  
**Out of scope (untouched, still live as of this commit):** N1 / P0 #3 (`terminal show --json` preview via shape redaction miss); N3 / P0 #5 (`terminal stop --worktree` soft-exec); hardening-OFF outside named prefixes; F3 `dispatch-show` metadata; F5 MCP orphan-read.

### Confirmation

P0 #4 was real on `367ebb6`/`00ebeb2`:

1. `partitionMailbox` fail-opened when `owned.size === 0` (`own = list`).
2. `awaitDispatch` then `dispatchRegistry.upsert(did, { clientKey: caller, ... })` overwrote bob→alice.
3. `requireOwnedDispatch` honestly reported owned; `action=release` would pass preflight.

### Ownership-store write sites (audit)

| Site | Provenance after this fix |
|------|---------------------------|
| `bindOwnedDispatch` → `dispatchRegistry.bindOwner` + `registerOwnedDispatch` + `persistOwnershipBindings` | **Legitimate.** Only from `dispatchWorker` after a successful dispatch. Authoritative bind. |
| `loadPersistedOwnership` → `bindOwner` + `registerOwnedDispatch` | **Legitimate hydrate.** Boot restore from `~/.orca-bridge/dispatch-ownership.json`. Same owner only (`bindOwner` refuses mismatch). Not caller-supplied identity. |
| `dispatchRegistry.upsert` (await status/liveness/transcript; release status) | **Non-claiming.** Strips `clientKey`; preserves prior owner; refuses terminalHandle overwrite when set. Await only updates rows already owned by caller. |
| `registerOwnedDispatch` from await/check | **Removed.** Reads must not mutate ownership sets. |
| `markRunBound` on await/check after successful `run-use` | **Not a dispatch ownership claim.** Tracks pin↔run bind for ack-safe skip of re-`run-use` only (`boundRunId`/`boundSender`). Not keyed into `requireOwnedDispatch` / release. No `clientKey` write on a dispatch id. |
| `ownershipFor` lazy map create | Empty reg shell only; no dispatch ids until bind. |
| Sender pin persist (`~/.orca-bridge-sender-pins.json`) | Unrelated to dispatch clientKey; pre-existing. |

No other writers of dispatch `clientKey` remain. `runtimeId` is not used.

### Defects closed

1. **Fail closed on empty ownership.** `partitionMailbox`: empty owned set → `{ own: [], foreign: list, filtered: true }` (empty mailbox stays unfiltered empty).
2. **Ownership not claimable.** `createDispatchRegistry().upsert` ignores `clientKey` and preserves prior owner; new `bindOwner` is the only bind API and refuses reassignment. Await never calls `bindOwner` / never passes claimable identity into upsert for foreign or unbound ids.

### Restart / durability tension

**Resolved by durable bindings, not by re-claim on read.**

- New store: `ORCA_BRIDGE_AUDIT_DIR` (default `~/.orca-bridge`) + `dispatch-ownership.json`.
- Written only from `bindOwnedDispatch` (dispatch-time).
- Loaded at boot into registry + `clientOwnership` via `bindOwner` / `registerOwnedDispatch`.
- Not keyed on `runtimeId` (changes across restarts; resolvers stay clean of it).
- If the file is missing/unreadable after restart: **fail closed** on release/await ownership (same as wiped maps). That is the correct security posture; durability restores the legitimate coordinator path when the store is intact.
- Coordinators that legitimately dispatched **can still release after restart** when the ownership file hydrates (covered by effect test). Pin file remains separate and still loads.

### Tests

- Baseline was **346 pass / 0 fail**.
- This pass: **353 pass / 0 fail / 0 skipped** (`npm test`).
- Real-path regressions (not policy-shape unit stubs):
  - empty owned + foreign `worker_done` → partition foreign; claim upsert does not change `clientKey`; `requireOwnedDispatch` not owned; `executeReleaseWorker` zero effects.
  - durable hydrate snapshot → owner still releases via `worker-release`; status upsert keeps `clientKey`.
  - empty store → release fail-closed.
  - `bindOwner` refuse reassignment; `upsert` never sets `clientKey`; `listOwnershipBindings` only bound rows.
  - `partitionMailbox` empty-set fail-closed unit updated.

### Sibling claim paths checked

- MCP F5 orphan-read still fail-opens on **missing** `clientKey` for resource visibility — out of scope; does **not** grant `requireOwnedDispatch` (empty key is not owned). Left untouched.
- `action=check` no longer registers runs into ownership.
- Release `upsertDispatch` no longer passes `clientKey`.
- No evidence of another read path that can forge `clientKey` after this change. If a future path calls `bindOwner` with caller identity outside dispatch/hydrate, that would re-open the class — grep for `bindOwner` / `clientKey:` in upsert patches in review.

### Files

- `lib/orch-isolation.mjs` — fail-closed `partitionMailbox`
- `lib/audit.mjs` — non-claim `upsert`, `bindOwner`, `listOwnershipBindings`
- `server.mjs` — `bindOwnedDispatch`, durable load/persist, await non-claim updates, remove await/check `registerOwnedDispatch`
- `lib/release-worker.mjs` — status-only upsert (no `clientKey`)
- `lib/*.test.mjs` — regressions above
- this document (append only)

Independent suite after fix: **353 pass / 0 fail / 0 skipped**.
