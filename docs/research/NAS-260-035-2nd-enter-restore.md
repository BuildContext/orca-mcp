# 0.3.5 — restore second empty `--enter` for TUI text sends

Worker: `task_7229548f87dd` / `ctx_04168d0a09f7`. Checkout `nas260-restore-2nd-enter`.

The previous 0.3.5 worker's uncommitted tree lived in sibling worktree
`nas260-enter-035-s7`. This checkout started at the same commit (`1f13a1a`)
without those files. The 0.3.5 `--submit` carve-out removal +
`buildTerminalSendArgv` + `dispatch-inject-enter` work was copied here,
then **only** the TUI two-send deletion was reversed.

## Call sites restored

Both go through `buildTerminalSendArgv` (not raw argv arrays):

1. **Idle-recovery** (`ensureInjectLanded` in `server.mjs`):
   - `buildTerminalSendArgv({ handle, text: recovery, enter: true })`
   - then `buildTerminalSendArgv({ handle, text: '', enter: true })`
2. **Dispatch-preamble** (isolated path after `dispatchPreamble`):
   - `buildTerminalSendArgv({ handle, text: dispatchPreamble, enter: true })`
   - then `buildTerminalSendArgv({ handle, text: '', enter: true })`

Comment at both sites: a **shell** target submits on the first `--enter`;
a **Grok TUI draft buffer** needs the second (verified live 2026-08-15);
the extra send is harmless when redundant. There is no `--submit`.

## `enterOk`

Idle-recovery probe field is again `enterOk: envOk(enterRes)` — the
**second** send's envelope, not `envOk(sendRes)`. Preamble step now also
records `enterOk: envOk(preEnter)` for the empty follow-up.

## `dispatch-inject-enter` survives

Still present after runtime `--inject`:

```js
steps.push({ step: 'dispatch-inject-enter', ok: envOk(injectEnter) });
```

That path is empty `--enter` only (`buildTerminalSendArgv({ handle, enter: true })`).
`--inject` types without submitting; this Enter is required. Not removed.

## Not touched

- No `--submit` argv token in `server.mjs`.
- `POLICY_SCOPED_BOOLEAN_FLAGS` / `--submit` carve-out stays deleted
  (`lib/cli-policy.mjs`).

## Docs corrected (two-case rule)

Blanket "one `--enter` submits every target / never a second CR" claims
were rewritten to:

> Shell target takes one `--enter`. A TUI compose box needs the text send
> plus a following empty `--enter`.

| File | What changed |
| --- | --- |
| `CHANGELOG.md` 0.3.5 Fixed | inject-enter kept; recovery/preamble are two-send, not "workaround gone" |
| `README.md` "Terminal send — submit with `--enter`" | target-dependent bullets + live 2026-08-15 note |
| `docs/design.md` Inject recovery | same two-case rule; idle path is text + empty `--enter` |
| `docs/runbooks/nas-255-worker-uid.md` | same |
| `lib/coordinator-doctrine.mjs` `empty_stalled` + `raw_cli_ok` | same (feeds generated docs) |
| `COORDINATOR.md` | regenerated from doctrine |
| `docs/research/NAS-257-260-033-handoff.md` | top 0.3.5 correction now includes the two-case rule |
| `docs/research/NAS-260-035-enter-report.md` | TASK 5 / test list no longer claim the two-call path is gone |
| `lib/security-core.mjs` `buildTerminalSendArgv` jsdoc | documents the two-send rule |

## Test added

`lib/security-core.test.mjs`:

- `TUI text sends emit text+enter then empty+enter (live 2026-08-15 Grok draft buffer)`
  — source-scan: both call sites emit the two-send sequence, `enterOk`
  reads `enterRes`, `dispatch-inject-enter` remains, no `--submit` token.
- `buildTerminalSendArgv({ text: '' })` argv pin added to the existing
  helper test.

Replaced the previous worker's test that asserted *absence* of the
empty-`--text` second send (that assertion is what would have locked the
regression in).

## Gates

| Gate | Result |
| --- | --- |
| `npm test` | **548 / 548** pass, 0 fail |
| `npm run lint` | **34 / 34** ok |
| `npm run docs:check` | **ok** |

Coordinator commits as uid 997. Do not push/tag from this worker.
