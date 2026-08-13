# NAS-247 review nits — argv edges + no-handle note

**Branch:** `BuildContext/nas-247-ownership-gate`  
**Commit:** `48eb399`  
**Date:** 2026-08-12  
**Production code changed:** no  
**Defaults changed:** no

## Test numbers

| | count |
|--|--|
| baseline | 267 pass / 0 fail |
| after nits | **285 pass / 0 fail** (+18) |

```
npm test → tests 285, pass 285, fail 0, skipped 0
```

## Defaults (untouched)

```
lib/cli-policy.mjs:
  hardening: e.ORCA_BRIDGE_CLI_HARDENING === '1'   # still requires exact "1"
  admin:     e.ORCA_BRIDGE_CLI_ADMIN === '1'

lib/toolsets.mjs / server.mjs:
  ORCA_BRIDGE_TOOLSETS default remains all tiers (default-all)
  --read-only / env / CLI_ADMIN union precedence unchanged
```

`git diff` against parent touches only:
- `lib/cli-policy.test.mjs`
- `lib/state-ownership.test.mjs`
- `docs/research/NAS-247-handle-ownership-gate.md`

## Edge cases added

### `lib/cli-policy.test.mjs` — `evaluateCliArgv: ownership argv-shape edges`

Each case asserts full decision shape: `decision`, `matched_prefix`, `admin_required`, ownership consultation (or not), and `allow` / `allow_with_warning` / `deny` (+ `handle_not_owned` fields when ownership ran).

| Case | Proved |
|------|--------|
| Mixed/upper case (`Terminal READ`) | Tokens lowercased; ownership still gates; foreign → deny / warn |
| Extra tokens after prefix (`terminal read extra …`) | Prefix still matches; ownership still runs |
| Leading flags (`--json terminal read …`) | `commandTokens` → `[]`; ownership **not** consulted; hardening deny is allowlist/`(empty)`, not `handle_not_owned` |
| `--` before/among subcommand | Ownership skipped; fail-closed via allowlist |
| Positional handle | CLI rejects (`Unknown command`); extractors ignore bare token; missing `--terminal` → unknown deny |
| No `--terminal` | Fail-closed unknown (deny under hardening / warn when off) — NAS-227 back-compat |
| Empty / whitespace / wrong-prefix / `--terminal=` | Fail-closed unknown |
| Foreign client handle | `not-owned` deny on close |
| Dup `--terminal` extract | **First** occurrence wins in bridge extractors (space and `=` forms) |
| **KNOWN MISMATCH** first=owned, last=foreign | Gate **allows** (sees owned first). CLI last-wins → runtime would use foreign. **Bypass.** |
| **KNOWN MISMATCH** inverted first=foreign, last=owned | Gate **denies** even though CLI would use owned |
| close/send same shapes | Same rules; send still needs admin unlock to reach ownership |

### `lib/state-ownership.test.mjs`

| Case | Proved |
|------|--------|
| Dup `--terminal` | `getTerminalHandle` returns first |
| Positional | ignored → null |
| Empty/whitespace flag values | normalize → null |
| Wrong-prefix unregistered | `HANDLE_UNKNOWN` / `handle_not_in_registry` |
| Other client’s valid handle | `HANDLE_NOT_OWNED` / `foreign_handle` |
| Dup-flag first through resolver | first-own → owned; first-foreign → not-owned |

## Behaviour vs reviewer assumptions

**Not all boring.** One genuine bypass:

1. **Duplicate `--terminal` first-vs-last mismatch (bypass)**  
   - Bridge: `extractTerminalHandleFromArgv` / `getTerminalHandle` → **first**  
   - Orca CLI `parseArgs` `setFlagValue` → **last** for non-repeatable flags (`app.asar.unpacked/out/cli/args.js`)  
   - Live path: `ownershipCheck(ctx.handle)` uses extracted first value  
   - Result: `--terminal term_own --terminal term_foreign` under hardening → **allow**, while CLI acts on `term_foreign`  
   - Escalated to coordinator (`msg` subject: `Blocked: NAS-247 duplicate --terminal bypass`). **Not patched** (task rule: stop and escalate).  
   - Tests document current unsafe allow so the finding cannot regress silently into “assumed safe.”

2. **Leading flags before subcommand**  
   - Not a hardening bypass (still deny via empty allowlist), but ownership is skipped and the error is not `handle_not_owned`. Soft mode only gets `cli_policy_would_deny`.

3. **Everything else** matches the assumed model: case-insensitive tokens, extra suffix tokens OK, `--` cuts tokens, positional rejected, missing/malformed/foreign → fail-closed, no-handle fail-closed once NAS-227 enables hardening.

## Nit 2 — documentation

Added paragraph under Safe/back-compat in `docs/research/NAS-247-handle-ownership-gate.md`:

> `terminal read` without `--terminal` becomes fail-closed under NAS-227 hardening; acceptance must exercise no-handle on VM `orca-server-1` and Mac reserve.

## Left for owner

- Authorize a production fix for dup `--terminal` (recommended: collect all values; deny unless every distinct handle is owned, or align on last-wins to match CLI — deny-any-miss is safer).
- Optionally tighten leading-flag tokenisation so ownership still sees `terminal read` when globals precede the subcommand (CLI already skips leading flags when resolving command path).
