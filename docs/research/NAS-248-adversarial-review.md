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
