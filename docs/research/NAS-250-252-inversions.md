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

