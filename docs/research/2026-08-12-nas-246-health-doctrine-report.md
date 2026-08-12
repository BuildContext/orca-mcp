# NAS-246 report — drop health-before-every-request doctrine

**Date:** 2026-08-12  
**Branch:** `noah596/nas-246-orca-mcp-ubrat-doktrinu-health-pered-kazhdim-zaprosom-self`  
**Base:** `origin/main` @ `56b1d9f` (already contained PR #3 NAS-246/240 merge)  
**Tip:** `8b45078 fix(NAS-246): tighten compact health, TTL, dead-runtime codes`

## Context

`origin/main` already shipped most of NAS-246 via PR #3 (`d76fc50`): doctrine no longer requires health before every wave; `dispatch`/`await`/`release` call `ensureRuntimeReady()`; health accepts `verbose:true`; pure helpers live in `lib/runtime-guard.mjs`.

This branch closes DoD gaps that remained after that merge:
1. default compact health was still ~807B (DoD: < ~500B)
2. probe TTL was 30s (spec: ~5–10s)
3. mid-flight dead-runtime failures still returned free-text `run-create failed` / `check failed` without a stable code + health hint

NAS-240 await-liveness (already on main) was left untouched beyond preserving it through the rebase with NAS-239 stale-delivery handling.

## Per-file changes (this tip)

| File | Change |
| --- | --- |
| `lib/runtime-guard.mjs` | TTL `10_000`; `HEALTH_DIAGNOSTICS_HINT`; slimmer `compactHealthPayload` (version/versionOk/statusProbe.ok/defaultRepo/next); `isDeadRuntimeSignal` + `deadRuntimeFailure`; recovery strings always mention health |
| `lib/runtime-guard.test.mjs` | compact <500B assertion; dead-runtime code tests; recovery must match `/action=health/` |
| `server.mjs` | import new helpers; `maybeDeadRuntime` on dispatch run-create + await check-fail; health schema text; keep NAS-239 stale_delivery path |
| `lib/coordinator-doctrine.mjs` | health blurb lists compact fields accurately |
| `COORDINATOR.md` | regenerated via `npm run docs:build` |

## Doctrine (already true on main; still true)

- `buildToolDescription` no longer says `SUPERVISED WORKERS ONLY: (1) health — require…`
- Flow starts at `dispatch`; health is "optional compact diagnostics… not required before each wave"
- `initialize.instructions` no longer says "Session start: action=health"

## Version gate

**Where:** `ensureRuntimeReady()` → `assertRuntimeReady({ version: VERSION, minVersion: MIN_BRIDGE_VERSION })` at the start of `dispatchWorker`, `awaitDispatch`, and `releaseWorker`.

**Code:** `bridge_version_too_old` (machine-readable via `error.code`).

**Why await/release also gate:** version is a pure in-process compare (no I/O). Keeping the same entry gate means a coordinator that skips dispatch (re-attaches to an old runId) still cannot proceed on an undersized bridge. Status probe uses the shared 10s TTL cache so repeated await windows do not stampede `orca status`.

**Verified by unit test:** `assertRuntimeReady` throws `bridge_version_too_old` when `0.1.0 < 0.2.0` (`lib/runtime-guard.test.mjs`).

## Compact health size (measured)

Fixture with fat verbose fields (actionAnnotations, 5k stdout, coordinator, isolation…):

| Shape | Bytes (UTF-8 `JSON.stringify`) |
| --- | ---: |
| Pre-NAS fat / verbose-like full dump | **6240** |
| Main compact (after PR #3, before this tip) | **807** |
| This branch default compact | **293** |

Default fields: `ok`, `version`, `versionOk`, `statusProbe.ok`, `defaultRepo`, `next` (detail truncated ≤120 chars), `verbose:false`.

Full dump: `verbose:true`.

## Dead-runtime error codes

| Situation | `error.code` / signal |
| --- | --- |
| Bridge package version < min | `bridge_version_too_old` |
| Lazy status probe / CLI down at gate | `runtime_unavailable` |
| Mid-flight dispatch/await spawn ENOENT / timeout / CLI missing | `runtime_unavailable` (+ `stage`) |
| Ordinary orchestration fail (envelope present) | unchanged stage/error strings |
| consumer fence / stale ack | `consumer_fenced` / `stale_delivery` (not runtime) |

Recovery text includes:  
`Call action=health (optionally verbose:true) for diagnostics, then retry the same action.`

## Backwards compatibility

Callers that parsed the **old fat default health** must either:
1. pass `verbose:true`, or
2. stop reading nested `bridge.*`, `senderTerminal`, `toolsets`, `actionAnnotations`, `coordinator`, `isolation`, `audit`, `resources`, full `statusProbe`.

New compact top-level: `version`, `versionOk` (not only under `bridge`).  
`statusProbe` is now `{ ok }` only in compact mode.

Lazy gate on dispatch/await/release is new behavior vs pre-PR#3 (those used to proceed and fail later with stage strings). Codes are additive structured fields; old free-text `error` strings remain on non-runtime paths.

## Verification

```
npm test          # 222 pass / 0 fail
npm run docs:check
npm run lint      # 17 files ok
```

## Open risks

- Compact health no longer returns `senderTerminal` by default — coordinators that used health solely to discover the sender pin must use `verbose:true` or rely on dispatch auto-injection (0.2.10+).
- `isDeadRuntimeSignal` is intentionally conservative (spawnError / timedOut / ENOENT-ish text). A non-envelope business error with exit≠0 is **not** rewritten to `runtime_unavailable`.
- TTL 10s means a runtime that dies mid-wave may still pass the gate for up to 10s on cached success; the mid-flight path covers the next CLI call.
- NAS-240 liveness remains on main; this ticket did not redesign await stop-conditions.

## Decision: await/release version gate

**Yes, keep the gate on await and release** — justification above. Status probe is shared-cache, not a pre-wave ritual; version check is free.
