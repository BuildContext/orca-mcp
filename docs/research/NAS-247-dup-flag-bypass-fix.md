# NAS-247 — duplicate `--terminal` ownership-gate bypass fix

**Branch:** `BuildContext/nas-247-ownership-gate`  
**Date:** 2026-08-12  
**Production code changed:** yes (authorized option (a))  
**Defaults changed:** no

## Test numbers

| | count |
|--|--|
| baseline (48eb399 / 21602e2) | 285 pass / 0 fail |
| after fix | **287 pass / 0 fail** (+2) |

```
npm test → tests 287, pass 287, fail 0, skipped 0
```

Net +2: known-bypass documentation tests replaced by green deny-any coverage, plus all-owned dup allow and three-occurrence / mixed-form cases; leading-flag test expanded rather than dropped.

## Defaults (untouched)

Confirmed by grep after the change:

```
lib/cli-policy.mjs:
  hardening: e.ORCA_BRIDGE_CLI_HARDENING === '1'   # still requires exact "1"
  admin:     e.ORCA_BRIDGE_CLI_ADMIN === '1'

lib/toolsets.mjs / server.mjs:
  ORCA_BRIDGE_TOOLSETS default remains all tiers (default-all)
  --read-only / env / CLI_ADMIN union precedence unchanged
```

No edits to toolset tiers, allowlist prefix lists, or `resolveCliPolicyConfig` defaults. Bridge process not restarted.

## Shared extraction helper

**Lives in** `lib/state-ownership.mjs` as:

- `collectTerminalHandlesFromArgv(argv) → Array<string|null>`  
  Walks argv left-to-right; every `--terminal <v>` / `--terminal=<v>` occurrence is recorded. Spaced form with missing or flag-shaped value records `null` and continues. Empty `=` form (`--terminal=`) records `null`; spaced `--terminal ''` keeps raw `''` so the two shapes stay distinguishable in one helper.

- `getTerminalHandle(argv)` now returns **CLI last-wins** (last collected value, then `normalizeTerminalHandle`). Multi-value ownership must not use this alone.

**Re-exported / wrapped in** `lib/cli-policy.mjs`:

- `export { collectTerminalHandlesFromArgv }` from state-ownership
- `extractTerminalHandleFromArgv(args)` — thin last-of-`collectTerminalHandlesFromArgv` wrapper (empty `=` → null); **no second argv loop**
- `looksLikeOwnershipGatedArgv(args)` — detects `terminal read|close|send` after optional leading flag tokens **without** changing `commandTokens` / allowlist matching

Import edge: `cli-policy.mjs` → `state-ownership.mjs` only (no cycle; `toolsets.mjs` still imports cli-policy).

## How multi-value argv is judged

When `ownershipCheck` is present and the argv is ownership-gated (token path **or** leading-flag lookalike):

1. Collect **every** `--terminal` value via `collectTerminalHandlesFromArgv`.
2. If none, treat as a single `null` handle (fail-closed unknown) — same as before.
3. Call `ownershipCheck` once per collected value (ctx also gets `handles` and `effective_handle`).
4. **Deny if any** value is not `owned` (not-owned or unknown). Soft mode → `allow_with_warning` with `code: 'handle_not_owned'`; hardening → `deny` with the same code. No new error codes.
5. Error/warning **payload `handle`** = CLI-effective value = **last** occurrence (`extractTerminalHandleFromArgv`), so the message names the terminal the CLI would have touched.
6. All-owned duplicates (including mixed `=` / spaced forms) still **allow**.

This closes:

- owned-then-foreign (previous bypass: first-owned allowed while CLI ran foreign)
- foreign-then-owned (deny-any, not last-wins alone)
- three occurrences / mixed forms

## Leading-flag case (scope-limited)

**Did not** change `commandTokens` or allowlist matching. Leading globals still yield `tokens = []` → prefix not allowed.

**Did** add `looksLikeOwnershipGatedArgv` so ownership still runs when argv is shaped like `[--json, terminal, read, --terminal, …]`.

Outcomes:

| argv | hardening | result |
|------|-----------|--------|
| `--json terminal read --terminal <foreign>` | on | `deny` + `handle_not_owned` (ownership consulted) |
| same | off | `allow_with_warning` + `handle_not_owned` |
| `--json terminal read --terminal <owned>` | on | still **allowlist** deny `(empty)` — surface **not** widened |
| same | off | still `cli_policy_would_deny` |

Judgement call: when ownership misses on a leading-flag shape, `rejected_subcommand` / `matched_prefix` are labeled `terminal read|close|send` for operator clarity. That label does **not** unlock the allowlist; owned+leading-flags still cannot pass the prefix gate.

`--` before/among subcommand remains fail-closed via allowlist only (ownership still skipped) — out of scope; not a hardening bypass.

## Files touched

- `lib/state-ownership.mjs` — shared collector + last-wins `getTerminalHandle`
- `lib/cli-policy.mjs` — import collector; last-wins extract; deny-any ownership loop; leading-flag ownership path
- `lib/cli-policy.test.mjs` — green dup-flag / leading-flag assertions
- `lib/state-ownership.test.mjs` — collector + last-wins + deny-any resolve coverage
- `docs/research/NAS-247-dup-flag-bypass-fix.md` — this report

## Judgement calls (explicit)

1. **Deny-any + payload last** — as specified; when first is foreign and last is owned, payload `handle` is still the owned last value while decision is deny/`handle_not_owned`. Slightly odd prose in `detail`, but matches the required effective-handle reporting rule.
2. **Leading flags: ownership diagnostics only** — did not teach `commandTokens` to skip global flags, because that would let currently-rejected argv reach the allowlist. Acceptable limited fix per task constraint.
3. **`getTerminalHandle` flipped first→last** — aligns helper with CLI effective value; multi-check callers must use the collector. Single shared implementation avoids the prior two-copy drift.
4. No further bypasses found beyond the two scoped here; none escalated as new holes.

## Verification

```
npm test
# tests 287, pass 287, fail 0
```

Defaults grep (post-change) still shows hardening opt-in `=== '1'` and toolsets default-all.
