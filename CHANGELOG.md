# Changelog

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
