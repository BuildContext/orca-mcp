# NAS-247 — Handle-ownership gate

**Branch:** `BuildContext/nas-247-ownership-gate`  
**Date:** 2026-08-12  
**Status:** Implemented + tests green (267/267). Not merged. Hardening default unchanged (NAS-227).

## Summary

The cli allowlist matched subcommand prefixes only. `terminal read` / `close` / `send` could target any handle string. Ownership is now resolved from existing bridge structures and evaluated in the same `evaluateCliArgv` funnel as the prefix allowlist.

## Files / functions changed

| File | Change |
|------|--------|
| `lib/state-ownership.mjs` | Added `HANDLE_OWNED` / `HANDLE_NOT_OWNED` / `HANDLE_UNKNOWN`, `normalizeTerminalHandle`, `getTerminalHandle`, `collectTerminalHandleSets`, `listOwnedTerminalHandles`, `resolveTerminalHandleOwnership` |
| `lib/cli-policy.mjs` | Added `OWNERSHIP_GATED_PREFIXES`, `extractTerminalHandleFromArgv`, `isOwnershipGatedArgv`, `ownershipDecision`; threaded optional `ownershipCheck` through `createCliPolicy` / `evaluateCliArgv` |
| `server.mjs` | Import resolver; pass `ownershipCheck` closure into `createCliPolicy` using `currentClientKey()` + live `dispatchRegistry` / `clientOwnership` / `senderCaches` / `coordinatorHandles` |
| `lib/state-ownership.test.mjs` | Resolver unit tests: owned, not-owned, unknown, missing registry, malformed handle |
| `lib/cli-policy.test.mjs` | Funnel tests: deny under hardening, `allow_with_warning` when off, read/close/send, positive owned path |

## How ownership is resolved

**Source of truth (no parallel store):**

1. **`senderCaches`** — per-`clientKey` pinned sender handle (durable pin file loaded at boot).
2. **`clientOwnership`** — in-memory map populated by `registerOwnedDispatch` / `markRunBound`: `workerHandles`, `boundSender`.
3. **`dispatchRegistry`** (`createDispatchRegistry` in `lib/audit.mjs`) — rows with `terminalHandle` + `clientKey` from dispatch/await.
4. **`coordinatorHandles`** — known bridge sender tabs (known-set only; ownership still requires client match via pin).

`resolveTerminalHandleOwnership(handle, clientKey, deps)` returns:

- `owned` — handle in caller's owned set (pin and/or worker).
- `not-owned` — handle known under another client / known set but not ours.
- `unknown` — malformed/missing handle, missing registry sources, or handle never seen (**fail-closed** at policy layer).

Return fields: `status`/`verdict`, `handle`, `clientKey`, `owned_handles`/`ownedHandles`, `reason`.

## Policy funnel behaviour

Gated prefixes: `terminal read`, `terminal close`, `terminal send`.

| Hardening | Ownership miss |
|-----------|----------------|
| off (default) | `decision: allow_with_warning`, warning `code: 'handle_not_owned'` via existing `onWarning` |
| on | `decision: deny`, rejection below |

Prefix allowlist still applies: under hardening, admin-only `terminal send` without admin unlock keeps the existing allowlist denial (more specific unlock guidance). Ownership runs when the prefix is otherwise allowed, or when hardening is off.

Sender pin of the calling client remains usable (owned via `senderCaches`).

## `handle_not_owned` error shape

Matches existing envelope style (`ok` / `error` / `detail` / `next` + surface fields):

```json
{
  "ok": false,
  "error": "cli_policy_denied",
  "code": "handle_not_owned",
  "rejected_subcommand": "terminal read",
  "rejected_argv": ["terminal", "read", "--terminal", "term_foreign", "--limit", "20"],
  "handle": "term_foreign",
  "owned_handles": ["term_own", "term_worker"],
  "ownership_status": "not-owned",
  "reason": "foreign_handle",
  "allowed_surface": ["orchestration reply", "..."],
  "admin_surface": ["terminal send", "..."],
  "admin_required": false,
  "detail": "Blocked: terminal handle \"term_foreign\" is not-owned for this client. Owned handles: term_own, term_worker. reason=foreign_handle. Use a handle from dispatch (worker) or this client's pinned sender.",
  "next": {
    "action": "guide",
    "detail": "Pass a terminal handle this client owns (worker handle from dispatch, or the pinned sender)."
  }
}
```

Permissive warning uses the same `code: 'handle_not_owned'` (not `cli_policy_would_deny`) so operators can filter ownership migration noise separately.

## Tests

```
npm test → 267 pass, 0 fail, 0 skipped
assertTierMappingInvariants → []
```

No tier rows changed; ownership is orthogonal to toolset tiers.

## Back-compat call sites (do not fix silently)

Once **NAS-227** turns hardening on by default, any `action=cli` that targets a handle the caller did not dispatch / is not pinned to will fail.

### In-repo docs / doctrine that will need operator awareness

| Location | Note |
|----------|------|
| `COORDINATOR.md` ~L64 | Documents `terminal read --limit N` for liveness/debug — **OK if handle is own worker**; fails if used on foreign handles. |
| `lib/coordinator-doctrine.mjs` ~L193 | Already says `terminal read/close (own handles)` — correct; enforcement now matches prose under hardening. |
| `lib/coordinator-doctrine.mjs` ~L43 | Stall path: “optional worker ping via cli/terminal send” — must use **owned** worker handle. |
| `README.md` capability tables | Lists `terminal list/read` on status tier and `terminal close` on dispatch — still true for prefixes; ownership is an extra gate on the handle argument. |
| `docs/threat-model.md` T6 | Still accurate that default toolsets enable admin `terminal send`; after NAS-227, **foreign** handles are denied even with admin. Consider updating T6 “Not mitigated” when NAS-227 lands. |
| `docs/design.md` inject-recovery / terminal close | Internal bridge paths use `runJson` / `runOrca` **directly**, not `action=cli` — **not** subject to this gate (correct: server is the owner of those handles). |

### Patterns that will break under NAS-227

1. Coordinator scripts that `terminal list` then `terminal read`/`close` arbitrary handles belonging to other OAuth clients.
2. Cross-client debug: master token client reading a worker tab started by another OAuth client (the live recon case that motivated this ticket).
3. Closing a “ghost” tab by handle without it ever having been registered via this client’s dispatch (unknown → fail-closed). Workarounds: admin ops outside the bridge, or a future explicit break-glass path (out of scope).
4. Any external contour (VM orca-server-1 / Mac reserve per NAS-241) that copies foreign `terminal_handle` values into keep-lists and later closes them — already warned against in COORDINATOR multi-coord section; will become hard errors under hardening.

### Safe under the new rule

- `release` with worker `terminalHandle` from **this** client’s dispatch response (uses internal close path, not cli policy).
- `cli terminal read/close/send` against this client’s pinned sender or `registerOwnedDispatch` worker handles.
- `terminal list` (no handle) — not ownership-gated.

## Non-goals confirmed

- Did **not** change `ORCA_BRIDGE_CLI_HARDENING` default.
- Did **not** redesign toolset tiers.
- Did **not** touch audit beyond existing rejection return path (callTool returns `policyResult.rejection` as today).
- No unrelated refactors.

## Scope gaps

None in ticket scope. Design was unambiguous: ownership lives in existing `clientOwnership` + `dispatchRegistry` + sender pins; `client_key` reaches the funnel via `currentClientKey()` inside the `ownershipCheck` closure.

## Verification

```bash
npm test
# tests 267, pass 267, fail 0
```
