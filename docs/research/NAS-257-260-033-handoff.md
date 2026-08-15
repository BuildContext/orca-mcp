# NAS-257 / NAS-260 — 0.3.3 worker handoff

> **CORRECTION (session 7 / 0.3.5):** The `--submit` premise was **disproven**.
> `submit` appears zero times in Orca's CLI parser; there is no `--submit`
> flag on any command. The real submit affordance is **`--enter`**
> ("Append Enter after sending text") on `terminal send`, plus `--interrupt`.
> `--enter` was already classified (`FLAG_TABLE` / `NON_TARGET_FLAGS`,
> `BOOLEAN_FLAGS`, and the `terminal send` exact-form `allowedFlags`) and
> needed no carve-out. The 0.3.3 `POLICY_SCOPED_BOOLEAN_FLAGS` hook that
> whitelisted a phantom `--submit` was **reverted in 0.3.5**. Submit is
> **target-dependent**: a shell takes one `--enter`; a TUI compose box
> needs the text send plus a following empty `--enter`. Do not treat
> the rest of this file as current doctrine — it records what was believed
> when 0.3.3 shipped.



Uncommitted in worktree `nas257-260-033-s6c`. Do not commit from uid 994 (NAS-262).

## Daemon chmod confirmation (NAS-257, required before the unit edit)

`scripts/store-signer-daemon.mjs` lines 62–70:

```js
server.on('listening', () => {
  try {
    // Defense in depth if systemd socket activation is not used:
    // owner = this uid, group leave default, mode 0660 so only same-group peers connect.
    fs.chmodSync(socketPath, 0o660);
  } catch {
    // systemd-managed sockets may not allow chmod; unit file sets SocketMode=.
  }
  console.error(`store-signer: listening on ${socketPath}`);
});
```

The daemon itself sets `0660` after `listen()`. `ExecStartPost` was therefore redundant and, under `Type=simple`, raced the async socket create (ENOENT → restart loop). Hardening was not weakened (`ProtectHome=true`, `NoNewPrivileges=true`, `ProtectSystem=strict` still present).

## Where `--submit` was classified (NAS-260) and why the surface did not expand

Classified only in `lib/cli-policy.mjs`:

- `POLICY_SCOPED_BOOLEAN_FLAGS = { 'terminal send': ['submit'] }`
- `matchExactCliForm` extra-allows that name on the `terminal send` form
- `evaluateCliArgv` A0 treats it as classified **only** when the matched form is `terminal send`

Not added to:

- `FLAG_TABLE` / `NON_TARGET_FLAGS` (so `status --submit` and `orchestration send --submit` stay unclassified → deny)
- `lib/cli-argv-normalize.mjs` (pinned v1.4.180 snapshot / BOOLEAN_FLAGS / `CLI_COMMAND_SPECS` untouched)
- `deriveCliCommandForms` (derived `allowedFlags` still equal the spec)

Ownership preflight still runs first: foreign `--terminal` + `--submit` → `cli_policy_denied` / `handle_not_owned`. Unknown flags remain fail-closed. Denial is loud (structured reject); there is no strip-and-type path.

## Test suite

| | tests | pass | fail |
| --- | ---: | ---: | ---: |
| Coordinator-stated baseline | 434 | 434 | 0 |
| Actual BEFORE this change | 520 | 519 | 1 |
| AFTER this change | 527 | 526 | 1 |

The single red test is **pre-existing and environmental**: `diff against live args.js: GLOBAL_FLAGS + BOOLEAN_FLAGS parity` (`lib/cli-policy.test.mjs`) requires `/tmp/nas-248-cli/.../args.js` or `/tmp/orca-asar/extracted/out/cli/args.js`, which are not present on this worker. Not introduced by this change; `lib/cli-argv-normalize.mjs` was not modified. New NAS-257 (2) and NAS-260 (5) tests pass. Lint and `docs:check` are green.

## git status --short

```
 M README.md
 M deploy/linux/orca-bridge-store-signer.service
 M docs/research/NAS-249-253-ownership-signer-report.md
 M docs/runbooks/nas-255-worker-uid.md
 M lib/cli-policy.mjs
 M lib/cli-policy.test.mjs
 M lib/store-signer.test.mjs
 M package-lock.json
 M package.json
 M scripts/migrate-store-signatures.mjs
 M server.json
?? CHANGELOG.md
?? docs/research/NAS-257-260-033-handoff.md
```

## Absolute paths changed

- `/home/orca/orca/workspaces/orca-mcp/nas257-260-033-s6c/CHANGELOG.md`
- `/home/orca/orca/workspaces/orca-mcp/nas257-260-033-s6c/README.md`
- `/home/orca/orca/workspaces/orca-mcp/nas257-260-033-s6c/deploy/linux/orca-bridge-store-signer.service`
- `/home/orca/orca/workspaces/orca-mcp/nas257-260-033-s6c/docs/research/NAS-249-253-ownership-signer-report.md`
- `/home/orca/orca/workspaces/orca-mcp/nas257-260-033-s6c/docs/research/NAS-257-260-033-handoff.md`
- `/home/orca/orca/workspaces/orca-mcp/nas257-260-033-s6c/docs/runbooks/nas-255-worker-uid.md`
- `/home/orca/orca/workspaces/orca-mcp/nas257-260-033-s6c/lib/cli-policy.mjs`
- `/home/orca/orca/workspaces/orca-mcp/nas257-260-033-s6c/lib/cli-policy.test.mjs`
- `/home/orca/orca/workspaces/orca-mcp/nas257-260-033-s6c/lib/store-signer.test.mjs`
- `/home/orca/orca/workspaces/orca-mcp/nas257-260-033-s6c/package-lock.json`
- `/home/orca/orca/workspaces/orca-mcp/nas257-260-033-s6c/package.json`
- `/home/orca/orca/workspaces/orca-mcp/nas257-260-033-s6c/scripts/migrate-store-signatures.mjs`
- `/home/orca/orca/workspaces/orca-mcp/nas257-260-033-s6c/server.json`

(`server.json` / lockfile versions were aligned with `package.json` 0.3.3 because preflight requires it.)

## Proposed commit message

```
release: orca-mcp 0.3.3 (NAS-257, NAS-260)

Remove racing ExecStartPost from the store-signer unit; the daemon already
chmodSync(0660) after listen(). Classify --submit as a policy-scoped boolean
on owned terminal send only; unknown flags stay fail-closed.

After deploy: delete
/etc/systemd/system/orca-bridge-store-signer.service.d/10-fix-startpost.conf
and daemon-reload. Install root must stay outside /home (ProtectHome=true).
Migrator: setpriv --reuid=orca --regid=orca --groups orca-bridge-signer
(sudo -u orca always EACCES on the 0660 socket).
```

## Left for the coordinator

- Commit under uid 997; do not push/tag/publish from this worker.
- After live deploy of 0.3.3, remove `10-fix-startpost.conf`.
- Do not touch `/opt/orca-mcp`, live units, sudoers, or `ORCA_BRIDGE_WORKER_ISOLATION`.
