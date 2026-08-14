# NAS-255 — dedicated worker uid (implementation note)

**Branch:** `BuildContext/NAS-255-worker-uid`  
**Baseline HEAD (pre-fix):** `5ab2488`  
**Suite before:** 441 pass / 0 fail  
**Suite after:** 475 pass / 0 fail  

## Scope cut (explicit)

ONE dedicated uid for all dispatched workers (`orca-worker`).  
**Per-dispatch uid / worker-to-worker isolation is NOT done.** File a follow-up ticket; do not read this closeout as shipping per-dispatch uid.

## Primary criterion

With the argv gate treated as **disabled**, `evaluateAttackCatalogueAsWorker` over `docs/research/NAS-250-252-inversions.md` attack classes returns **zero passes** when:

- `workerUid !== bridgeUid`
- bridge secrets are owner-only 0600/0700 under the bridge account

PRE-FIX (same uid) still shows those attacks **pass** — the new tests fail on the pre-fix sha (module missing / same-uid baseline).

## Surfaces

| Path | Role |
| --- | --- |
| `lib/worker-isolation.mjs` | Config, FS classify, launch plan, HMAC capability, attack catalogue |
| `lib/worker-isolation.test.mjs` | Hermetic + optional live disposable uid |
| `server.mjs` | Opt-in placement via wrapper command; health.isolation.workerUid; capability mint |
| `deploy/linux/orca-omp-as-worker.sh` | setuid/sudo agent launch |
| `deploy/linux/orca-worker-orch.sh` | worker orch helper (capability present; runtime relay = cutover) |
| `deploy/linux/orca-mcp-workers.sudoers` | tight sudoers |
| `deploy/linux/install-worker-uid.sh` | attended installer (no restart by default) |
| `docs/runbooks/nas-255-worker-uid.md` | operator instruction |

## Live contour

Installer and tests use isolated HOME / disposable users only. Live bridge was **not** restarted; live `~/.orca-bridge*` not written.

## Follow-up (file separately)

**Title:** Per-dispatch worker uid / worker-to-worker isolation  
**Body:** NAS-255 closed bridge↔worker trust with one shared `orca-worker` account. Sibling workers can still interfere if ACLs grant shared write on worktree roots. Per-dispatch uid is a separate, weaker-consequence task.
