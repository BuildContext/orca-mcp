# 0.3.5 — `--enter` is real; `--submit` never existed

Worker: `task_927240b0eaec` / `ctx_d9db25b243bf`. Checkout `nas260-enter-035-s7`.

## (a) Where `enter` is classified

Confirmed **before** deleting the carve-out. `--enter` needs no policy hook:

| Location | Evidence |
| --- | --- |
| `lib/cli-policy.mjs` `NON_TARGET_FLAGS` | `'enter'` in the census list (~L1046); feeds `FLAG_TABLE` |
| `lib/cli-policy.mjs` `FLAG_TABLE.enter` | `{ kind: 'non_target', resolver: null }` |
| `lib/cli-argv-normalize.mjs` `BOOLEAN_FLAGS` | Set includes `"enter"` and `"interrupt"` (not `"submit"`) |
| `CLI_COMMAND_SPECS` / derived `terminal send` form | `allowedFlags`: `help`, `json`, `pairing-code`, `environment`, `terminal`, `text`, **`enter`**, **`interrupt`** |

`FLAG_TABLE.submit` is `undefined`. `--submit` is unclassified everywhere.

## (b) What was removed / restored

Removed entirely from `lib/cli-policy.mjs` (not left as an empty map):

- `POLICY_SCOPED_BOOLEAN_FLAGS = { 'terminal send': ['submit'] }`
- `policyScopedBooleanFlagsFor()`

Restored pre-0.3.3 shape:

1. **`matchExactCliForm`** — `notPermitted = flagNames.filter((f) => !form.allowedFlags.has(f))` (no `extraAllowed` union)
2. **`evaluateCliArgv` A0** — `const unclassified = collectUnclassifiedFlagsFromArgv(args)` (no scoped-label filter)

Policy surface was not widened.

## (c) Tests

Deleted the 0.3.3 suite that asserted `--submit` is classified on `terminal send`.

Added in `lib/cli-policy.test.mjs` (`NAS-260 / 0.3.5`):

- (a) `terminal send --terminal <h> --text x --enter` allow
- (b) `--submit` on `terminal send` fail-closed unclassified
- (c) `--enter` on `status` / `orchestration send` fail-closed (`flag_not_permitted`)
- plus: classification pin + foreign handle + `--enter` still `handle_not_owned`

Added in `lib/security-core.test.mjs`:

- `buildTerminalSendArgv` emits `--enter`, never `--submit`
- `buildDispatchInjectArgv` cannot express Enter
- `server.mjs` inject path uses `buildTerminalSendArgv` + `dispatch-inject-enter`, no `'--submit'` argv token
- idle-recovery + isolated preamble emit **two** sends (`--text <payload> --enter` then empty `--enter`) because a Grok TUI draft buffer does not submit on the first Enter (live 2026-08-15)

## (d) Docs and `server.mjs` strings

Corrected (prescriptive, not historical logs):

- `README.md` — new “Terminal send — submit with `--enter`” (outside generated markers)
- `COORDINATOR.md` — regenerated from doctrine (stall ping + raw `cli` + `--interrupt`)
- `lib/coordinator-doctrine.mjs` — guide payload `await_statuses.empty_stalled` + `raw_cli_ok` (future coordinators read this via `action=guide`)
- `lib/runtime-guard.mjs` — await `next.detail` stalled protocol
- `docs/runbooks/nas-255-worker-uid.md` — `--enter` / `--interrupt` note
- `docs/design.md` — inject recovery is text `--enter` plus empty `--enter` for TUI compose
- `docs/research/NAS-257-260-033-handoff.md` — **correction note at TOP only**; body left as the 0.3.3 record
- `server.mjs` — dispatch `next.detail`; inject recovery / isolated preamble / post-`--inject` submit
- `WORKER_CONTRACT_BLOCK` did **not** teach the two-call workaround (unchanged)

## (e) Gates

| Gate | Result |
| --- | --- |
| `npm test` | **548 / 548 pass**, 0 fail (baseline 545; +3 net) |
| `npm run lint` | **34 / 34** ok |
| `npm run docs:check` | **ok** |

NAS-254 / live `args.js` diff stayed green (no re-extract).

## (f) Files changed

- `lib/cli-policy.mjs`
- `lib/cli-policy.test.mjs`
- `lib/security-core.mjs`
- `lib/security-core.test.mjs`
- `lib/coordinator-doctrine.mjs`
- `lib/runtime-guard.mjs`
- `server.mjs`
- `README.md`
- `COORDINATOR.md`
- `docs/design.md`
- `docs/runbooks/nas-255-worker-uid.md`
- `docs/research/NAS-257-260-033-handoff.md`
- `docs/research/NAS-260-035-enter-report.md` *(this file)*
- `CHANGELOG.md`
- `package.json`
- `package-lock.json`
- `server.json`

## TASK 5 — inject submit

`orchestration dispatch --inject` has **no Enter flag** (`allowedFlags` are help/json/pairing-code/environment/task/to/from/run/inject/dry-run/return-preamble/retry-request). The runtime types the brief; it cannot express Enter.

**`injected:true` is not something this bridge can honestly force.** `injected` remains `dr.injected === true` from the runtime envelope.

What *is* achievable: after a successful `--inject`, the bridge now sends one `terminal send --enter` (`dispatch-inject-enter`) so the already-typed compose is submitted. Isolated preamble and idle recovery type new text, so they emit **two** sends: `--text <payload> --enter` then empty `--enter`. A shell target submits on the first; a Grok TUI draft buffer needs the second (verified live 2026-08-15). The extra send is harmless when redundant. There is no `--submit`.

Coordinator commits as uid 997. Do not push/tag from this worker.
