# NAS-258 / 0.3.6 closeout note

This file does not rewrite the 0.3.4 reconcile (`NAS-258-0.3.4-reconcile.md`).
It records what 0.3.6 closed after that live path already worked.

## What 0.3.4 already delivered

Credential delivery under isolation is **fixed**: privileged seed of
`~/.grok/auth.json` into the worker HOME, cap file as 994:994 0600,
`/usr/local/bin/orca`, grok `--permission-mode bypassPermissions`.

Session 4 (2026-08-14) live acceptance **passed** on dispatch
`ctx_bf7d199bbb2c` with isolation ON, grok, no wizard.

This closeout did **not** run a new live cycle on `orca-server-1`.

## Residuals shipped in 0.3.6

| Ticket | Close |
| --- | --- |
| NAS-259 | Per-worktree ACL (variant 2). `perDispatchUid` stays false. |
| NAS-261 | Bridge `release` closes without `--tab`; `tab_not_found` = already gone. |
| NAS-262 | 994 writes the checkout; 997 commits named paths after a gitdir assert. |
| NAS-266 | Gitdir pointer must stay a regular file; sticky + ACL so 994 cannot replace `.git`. |
| NAS-267 | Isolated dispatch fails closed on a shell TUI; template `worker_done` is rejected. |
| NAS-268 | Envelope v2 with signer-held monotonic `n`. v1 rejected at runtime. |
| NAS-255 | Lineage parent: shared uid `orca-worker` is the DoD; attacks (b)/(c) proven 2026-08-15. |
| NAS-258 | Description rewritten; remaining job was waiting on the residuals above. |

## Honest residuals that stay open as facts, not tickets

- Per-dispatch uid is **not** shipped.
- Hostile file *content* that 997 commits is accepted.
- A 997 principal who also compromises the **signer uid** can reset `n`.
- omp extra launch flag is `--auto-approve` (from omp 17.3.2 help). The TUI gate is the closer if omp still fails to start.
