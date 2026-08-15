# Changelog

## 0.3.6 — 2026-08-15

### Added

- **Per-worktree ACL (NAS-259 variant 2).** Isolated `worktree create` now
  grants `u:orca-worker:rwx` (named + default) on that checkout only.
  The parent `workspaces/` directory is never granted. The installer no
  longer prints a recursive+default ACL on all workspaces; it prints the
  one-shot strip (`setfacl -R -x` + `setfacl -k`) and the per-tree recipe.
  `perDispatchUid` stays `false`. Worker-to-worker isolation is
  ACL-narrowed, not uid-split.

- **Gitdir pointer guard (NAS-266).** `assertSafeGitdir` requires
  checkout `.git` to be a regular file whose contents are exactly
  `gitdir: <abs-expected>`. Directories, symlinks, extra lines,
  `includeIf`, and relative gitdirs are rejected. Harden strips the
  worker named ACL from `.git`, `chmod 0444`s the pointer, and
  `chmod 1775` (sticky) the checkout so uid 994 cannot unlink a
  bridge-owned pointer.

- **997 commit helper (NAS-262).** `commitNamedPaths` asserts the gitdir,
  `git add --` named paths only, returns `git diff --cached`, then
  commits as the bridge uid. Empty lists, `.git`, checkout escapes, and
  `git add -A` / `.` / `*` are refused. Hostile file *content* that 997
  then commits is an accepted residual.

- **Agent TUI gate + template `worker_done` reject (NAS-267).** Isolated
  dispatch snapshots after `tui-idle` and fails `stage: agent-tui` when
  the pane is a shell or the wrapper seed log. `summarizeMessages` sets
  `status: fake_worker_done` (never `next.action=release`) when the
  contract template is still in the message. `/worker/orch` rejects with
  `template_worker_done`. The recovery prompt example is commented so a
  shell cannot execute it. omp launch now passes `--auto-approve`.

- **Signed envelope v2 freshness (NAS-268).** Envelopes are
  `{ v:2, alg, n, ts, payload, sig }`. The MAC covers
  `{ n, ts, payload }`. The signer holds a monotonic `n` per store id
  (`store-seq.json`, 0600). `n < last` is `stale`. Runtime verify
  fail-closes on v1 and on missing `n`/`ts`. The migrator re-signs a
  valid v1 envelope as v2 with the bridge stopped; boot does not
  auto-migrate.

### Fixed

- **Release close without `--tab` (NAS-261).** The bridge `release`
  fallback is `terminal close --terminal <handle> --json`.
  `tab_not_found` and `workspace_session_unavailable` are treated as
  already gone (`ok: true`, `already_gone: true`); credential purge
  still runs. Coordinators may still pass `--tab` on `action=cli`.

## 0.3.5 — 2026-08-15

### Fixed

- **`--submit` never existed.** Orca's CLI has no `--submit` flag on any
  command (`grep -c submit` on shipped `args.js` is 0). Passing it is
  `invalid_argument` from the CLI. The real `terminal send` submit
  affordance is **`--enter`** ("Append Enter after sending text");
  `--interrupt` breaks a stuck TUI. `--enter` was already classified
  (`FLAG_TABLE` / `NON_TARGET_FLAGS`, `BOOLEAN_FLAGS`, and the
  `terminal send` exact-form allowlist) and needs no policy carve-out.
- Remove the 0.3.3 `POLICY_SCOPED_BOOLEAN_FLAGS` hook that whitelisted a
  phantom `--submit` on `terminal send`. Unknown flags stay fail-closed.
- Bridge dispatch no longer types-without-submit. Runtime
  `orchestration dispatch --inject` cannot express Enter; after it types
  the brief the bridge sends `terminal send --enter` (`dispatch-inject-enter`).
  Submit is target-dependent: a **shell** target submits on the first
  `--enter`; a **Grok TUI compose box** needs the text send plus a
  following empty `--enter` (verified live 2026-08-15 — a single
  `--text … --enter` left the brief in the draft buffer). Inject
  recovery and isolated preamble therefore emit that two-send sequence.
  The extra empty `--enter` is harmless on a shell that already submitted.
  `injected:true` is still whatever the runtime envelope reports — do
  not force it. There is no `--submit`.

## 0.3.4 — 2026-08-15

### Added

- **NAS-258:** mint a per-dispatch worker capability as a file, not env.
  Isolated dispatch returns `worker_capability_minted: true` and
  `worker_capability_file: /run/orca-mcp/worker-caps/<dispatchId>.json`.
  The privileged seed helper materializes that file as uid 994 / mode 0600.
  `action=release` writes a per-dispatch purge marker and reports
  `credential_purge.cap.ok`. The HMAC-gated `POST /worker/orch` relay lets
  uid 994 send `worker_done` / ask / check / heartbeat / escalation without
  the bridge bearer token. Capability bytes are never echoed to coordinators.


### Fixed

- **NAS-257:** `deploy/linux/orca-bridge-store-signer.service` no longer uses
  `ExecStartPost=chmod/chgrp`. With `Type=simple` those lines ran before the
  daemon's async `listen()` created the unix socket, so `chmod` got ENOENT,
  systemd killed `node`, and the unit restart-looped on a clean host. The
  daemon already `chmodSync(0o660)`s the socket after `listen()`
  (`scripts/store-signer-daemon.mjs`). Hardening (`ProtectHome=true`,
  `NoNewPrivileges`, `ProtectSystem=strict`, …) is unchanged.
  **After deploy:** delete the live workaround drop-in
  `/etc/systemd/system/orca-bridge-store-signer.service.d/10-fix-startpost.conf`
  and run `systemctl daemon-reload`.
  Install root must be outside `/home` (`WorkingDirectory=/opt/orca-mcp`);
  `ProtectHome=true` makes a `/home/...` working directory fail with
  `status=200/CHDIR`.
  The store-signature migrator must join the signer group:
  `setpriv --reuid=orca --regid=orca --groups orca-bridge-signer`.
  `sudo -u orca` does not attach `orca-bridge-signer` and always gets
  `EACCES` on the 0660 socket.

- **NAS-260:** classify `--submit` as a policy-scoped boolean on
  `terminal send` for caller-owned handles only. The ownership preflight is
  not weakened (a foreign handle is still denied, same as a send without
  `--submit`). Unclassified flags stay fail-closed — there is no global
  `FLAG_TABLE` grant for `--submit` or any other unknown flag. Denial is a
  loud `cli_policy_denied`; the bridge does not silently type-without-submit.
  `lib/cli-argv-normalize.mjs` (pinned v1.4.180 snapshot) is unchanged.
