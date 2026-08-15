# NAS-262 / NAS-259 recon (session 6)

Decision package for:

- **NAS-262** — commit model under isolated worker uid 994 (`orca-worker`)
- **NAS-259** — worker-to-worker isolation surface (shared uid + shared workspaces ACL)

**This file is reconnaissance and writing only.** No sudoers, systemd, flags, commits, pushes, merges, or Mac changes were made.

| Field | Value |
| --- | --- |
| Host | `orca-server-1` |
| Date (UTC) | 2026-08-15 00:21–00:27 |
| Observer | `uid=994(orca-worker) gid=994(orca-worker) groups=994(orca-worker)` |
| Bridge | `orca-mcp@0.3.2`, runtime 1.4.182, isolation **ON**, `perDispatchUid=false` |
| Bridge uid | 997 (`orca`) |
| This worktree | `/home/orca/orca/workspaces/orca-mcp/nas262-259-recon-s6` |
| Git pointer | `gitdir: /home/orca/src/orca-mcp/.git/worktrees/nas262-259-recon-s6` |
| Branch | `BuildContext/nas262-259-recon-s6` @ `3843348` (`release: bump orca-mcp to 0.3.2`) |
| Verdict (NAS-262) | **Adopt “994 checkout-write-only, 997 commits.”** Do not grant 994 any `.git` write. |
| Verdict (NAS-259) | **Variant 2 next** (per-worktree ACL). Variant 1 is the real close of the class but is a separate project. Do not keep variant 3. |

Coordinator: commit this file as uid 997 from the worktree directory named above. Absolute path:

`/home/orca/orca/workspaces/orca-mcp/nas262-259-recon-s6/docs/research/NAS-262-259-RECON-S6.md`

---

## Sources actually read (not paraphrased as evidence)

Task asked for two papers by ref. Those refs are **not** in the orca-mcp object store. They **are** in `rahunok-space`.

| Asked | How obtained | Result |
| --- | --- | --- |
| `nas258-acceptance-s4:docs/research/NAS-258-GIT-COMMIT-UNDER-994.md` @ `7a6110f` | `git show` in orca-mcp → invalid object. In rahunok-space: commit object readable; tree `2593d0b2…` lives in mode-`0700` fanout `objects/25` → `unable to read tree`. File recovered from trash worktree (see below). | Read in full |
| `nas258-flipper-s4:docs/research/NAS-258-KEEP-FOLLOWUP.md` @ `b722184` | Same 0700-fanout problem on `git show`. Blob `debdf7e2…` walked from readable tree `24d93ae0` and decompressed. | Read in full (5808 bytes) |
| Linear `NAS-262`, `NAS-259`, `NAS-258` | MCP `linear__get_issue` | Read |
| Code | worktree `lib/`, `server.mjs`, `deploy/linux/*`; live `/usr/local/lib/orca-mcp/*`, `/opt/orca-mcp/{server.mjs,lib/*}` | Read |

Trash copy of the git-commit paper (content matches `7a6110f` subject “persist NAS-258 git-commit-under-994 diagnosis”; KEEP-FOLLOWUP is the same diagnosis text under a flipper title):

`/home/orca/orca/workspaces/rahunok-space/.orca-worktree-trash/wt-1786749968418-205ddf27/docs/research/NAS-258-GIT-COMMIT-UNDER-994.md`

Both papers **recommend** the 997-commits model and **forbid** `usermod -aG orca orca-worker` and recursive ACL on `.git` (hooks → RCE). This session **re-measured** instead of restating them.

---

## 1. Measurements (commands + output)

All commands run as uid 994 unless noted. Probe files were removed. The worktree `.git` pointer was overwritten as a proof and **restored** to the original `gitdir:` line.

### 1.1 Identity and git frontend

```text
$ id
uid=994(orca-worker) gid=994(orca-worker) groups=994(orca-worker)

$ getent passwd orca orca-worker
orca:x:997:997::/home/orca:/usr/sbin/nologin
orca-worker:x:994:994::/home/orca-worker:/usr/sbin/nologin

$ getent group orca
orca:x:997:

$ umask
0002

$ git --version
git version 2.34.1
```

`orca-worker` is **not** in group `orca`. `install-worker-uid.sh` refuses shared supplementary groups (exit 3) for this reason.

### 1.2 Worktree pointer and `core.sharedRepository`

```text
$ cat /home/orca/orca/workspaces/orca-mcp/nas262-259-recon-s6/.git
gitdir: /home/orca/src/orca-mcp/.git/worktrees/nas262-259-recon-s6

$ grep -i shared /home/orca/src/orca-mcp/.git/config
# (no match)

$ git -c safe.directory=* config --get core.sharedRepository
# exit 1, empty — unset

$ grep -i shared /home/orca/src/rahunok-space/.git/config
# (no match)
```

`core.sharedRepository` is **unset** on both shared repos. New objects created by 997 will not automatically stay group-writable / 994-readable.

orca-mcp `.git/config` `[core]` is only `repositoryformatversion`, `filemode`, `bare`, `logallrefupdates`.

### 1.3 ACL / mode on the checkout and workspaces root

```text
$ getfacl -p /home/orca/orca/workspaces
# owner: orca / group: orca
user::rwx
user:orca-worker:rwx
group::r-x
mask::rwx
other::r-x
default:user::rwx
default:user:orca-worker:rwx
default:group::r-x
default:mask::rwx
default:other::r-x
```

Identical named + **default** ACL is present on:

- `/home/orca/orca/workspaces`
- `/home/orca/orca/workspaces/orca-mcp`
- `/home/orca/orca/workspaces/orca-mcp/nas262-259-recon-s6`
- `/home/orca/orca/workspaces/rahunok-space` and its live worktrees
- `/home/orca/orca/workspaces/rahunok-design`
- `/home/orca/orca/workspaces/rahunok-rn`
- both `.orca-worktree-trash` directories

`/home/orca` and `/home/orca/orca` have **no** named `orca-worker` ACL (owner rwx, group/other r-x).

Checkout files inherit the named user ACL. Example, tracked `README.md` (uid 997):

```text
user::rw-
user:orca-worker:rwx#effective:rw-
group::r-x#effective:r--
mask::rw-
other::r--
```

`test -w` is **yes** on this worktree’s `README.md` and `server.mjs`, and on sibling `rahunok-space/membank-s5/README.md`.

A 994-created file under `docs/research/` was:

```text
-rw-rw-r--+ 1 orca-worker orca-worker
user::rw-
user:orca-worker:rwx#effective:rw-
group::r-x#effective:r--
mask::rw-
other::r--
```

So 997 can **read** 994-created files via `other::r--` (default ACL `default:other::r-x` + umask `0002`). That is what makes a 997 `git add` of worker output possible without any `.git` ACL.

### 1.4 Shared `.git` — orca-mcp (this worktree’s repo)

```text
$ ls -ld /home/orca/src/orca-mcp/.git
drwxr-xr-x 9 orca orca  ...   # 0755, no named ACL

$ getfacl -p /home/orca/src/orca-mcp/.git
user::rwx
group::r-x
other::r-x
```

No named ACL anywhere under `.git/` that we inspected (`objects`, `hooks`, `refs`, `worktrees`, this worktree gitdir, `index`, `config`).

| Path | mode / owner | 994 read | 994 write |
| --- | --- | --- | --- |
| `/home/orca/src/orca-mcp/.git` | `0755 orca:orca` | yes | **no** |
| `.../.git/objects` | `0755 orca:orca` | yes | **no** |
| `.../.git/objects/??` | 233 dirs, all `0755 orca:orca` | yes | **no** |
| loose objects | 548 × `0644 root:root`, 54 × `0444 orca:orca` | yes | **no** |
| `.../.git/hooks` | `0755`, samples `0755` | yes (and +x) | **no** |
| `.../.git/refs` | `0755` | yes | **no** |
| `.../.git/index` (main) | `0644 orca:orca` | yes | **no** |
| `.../.git/config` | `0644 orca:orca` | yes | **no** |
| `.../.git/worktrees` | `0755` | yes | **no** |
| `.../.git/worktrees/nas262-259-recon-s6` | `0755` | yes | **no** |
| `.../worktrees/.../index` | `0644` | yes | **no** |
| `.../worktrees/.../HEAD`, `logs/HEAD` | `0644` / dir `0755` | yes | **no** |
| checkout `/home/orca/orca/workspaces/.../nas262-259-recon-s6` | `0775+` + named ACL | yes | **yes** |
| checkout `.git` **file** (gitdir pointer) | `0664+` + named ACL | yes | **yes** |

Object-fanout histogram for orca-mcp: **zero** `0700` dirs. This differs from rahunok-space (below). 994 can *read* this object store but cannot create `index.lock`, loose objects, refs, or logs.

Direct write probes (all failed with `Permission denied`):

```text
$ touch /home/orca/src/orca-mcp/.git/worktrees/nas262-259-recon-s6/index.lock
touch: cannot touch '.../index.lock': Permission denied

$ touch /home/orca/src/orca-mcp/.git/objects/tmp_nas262_probe
touch: cannot touch '.../objects/tmp_nas262_probe': Permission denied

$ mkdir /home/orca/src/orca-mcp/.git/objects/zz
mkdir: cannot create directory '.../objects/zz': Permission denied

$ touch /home/orca/src/orca-mcp/.git/refs/heads/nas262-probe
touch: cannot touch '.../refs/heads/nas262-probe': Permission denied

$ echo test >> .../worktrees/nas262-259-recon-s6/HEAD
Permission denied

$ echo test >> .../worktrees/nas262-259-recon-s6/logs/HEAD
Permission denied

$ echo test >> .../packed-refs
Permission denied

$ echo '#!/bin/sh' > .../hooks/pre-commit
Permission denied
```

994 **can execute** existing hook samples (`other +x`); 994 **cannot install** a real hook. That is exactly the RCE boundary recursive ACL would destroy.

### 1.5 Shared `.git` — rahunok-space (prior NAS-258 diagnosis, re-measured)

```text
$ getfacl -p /home/orca/src/rahunok-space/.git
# 0775 orca:orca, no named ACL
user::rwx
group::rwx
other::r-x
```

Object-fanout histogram (Python `stat` as 994):

```text
dir mode hist {'0o755': 234, '0o700': 16, '0o775': 2}
unreadable fanouts (no other-read): 16
sample: 02 03 05 25 34 3c 58 5b 63 66 6d 70 86 91 ab b1   (all uid 997)
```

```text
$ test -r /home/orca/src/rahunok-space/.git/objects/03; echo $?
# r=no w=no x=no
```

`git show 7a6110f` / `git show b722184` fail with `unable to read tree 2593d0b2…` / `03ed24f5…` — both prefixes are in the `0700` set. This **reproduces** the paper’s `bad tree object HEAD` class: even if `index.lock` were granted, 994 still cannot read the full object graph on rahunok-space.

Live worktree gitdirs `membank-s5` and `postnarrow-smoke` are `0755 orca:orca`, no named ACL — same `index.lock` EACCES shape.

### 1.6 `git add` / `git commit` under 994 — exact errors

Without any workaround:

```text
$ git add -n docs/research/NAS-255-worker-uid.md
fatal: detected dubious ownership in repository at '/home/orca/orca/workspaces/orca-mcp/nas262-259-recon-s6'
To add an exception for this directory, call:

git config --global --add safe.directory /home/orca/orca/workspaces/orca-mcp/nas262-259-recon-s6
# exit 128

$ git commit -m "probe: should fail under 994" --allow-empty
fatal: detected dubious ownership in repository at '/home/orca/orca/workspaces/orca-mcp/nas262-259-recon-s6'
To add an exception for this directory, call:

git config --global --add safe.directory /home/orca/orca/workspaces/orca-mcp/nas262-259-recon-s6
# exit 128
```

`safe.directory` was **not** written to any gitconfig. Passing it only as `-c` (per-process) unmasks the real blocker:

```text
$ git -c safe.directory=* add docs/research/.nas262-probe-write.txt
fatal: Unable to create '/home/orca/src/orca-mcp/.git/worktrees/nas262-259-recon-s6/index.lock': Permission denied
# exit 128

$ git -c safe.directory=* commit --allow-empty -m "probe: should fail under 994"
fatal: Unable to create '/home/orca/src/orca-mcp/.git/worktrees/nas262-259-recon-s6/index.lock': Permission denied
# exit 128
```

That is the same string the NAS-258 paper recorded on rahunok-space, with this worktree’s gitdir substituted.

Checkout write **does** work:

```text
$ echo probe > docs/research/.nas262-probe-write.txt
# exit 0; file 0664+ uid 994
$ git -c safe.directory=* status -sb
## BuildContext/nas262-259-recon-s6
?? docs/research/.nas262-probe-write.txt
```

(Probe file removed after the measurement.)

### 1.7 What works vs what does not (994)

| Action | Result |
| --- | --- |
| Write new files in this worktree | works (named + default ACL) |
| Overwrite 997-owned tracked files in this worktree | works (`W_OK` on `README.md` / `server.mjs`) |
| Write sibling worktrees (`membank-s5`, `postnarrow-smoke`, `rahunok-design`, `rahunok-rn`, both trash dirs) | **works** — see §4 |
| Read bridge/runtime secrets | fails (`Permission denied` on tokens, pins, `orca-runtime.json`, `/etc/orca-mcp/env`, hmac key) |
| `git status` / `add` / `commit` (plain) | fails: **dubious ownership** |
| `git add` / `commit` with `safe.directory=*` | fails: **`index.lock` Permission denied** |
| Create objects / refs / logs / hooks | fails: Permission denied |
| Read orca-mcp objects | works (all fanouts `0755`) |
| Read rahunok-space `0700` fanouts | fails |
| Execute existing hook samples | works (not useful; they are samples) |
| Write `.git` gitdir **pointer** in the checkout | **works** — see §3 |
| `git config --global safe.directory` | not done (would write 994’s HOME; out of scope) |
| Commit as 994 after hypothetical ACL | not tested; would require changing `.git` ACL (forbidden) |

### 1.8 `.git` pointer overwrite (new finding)

The checkout `.git` is a **file**, not a directory, and it carries the workspaces named ACL:

```text
-rw-rw-r--+ 1 orca orca  .../.git
user:orca-worker:rwx#effective:rw-
```

Empirical (restored immediately):

```text
$ printf 'gitdir: /tmp/evil-gitdir-nas262\n' > .git
# OVERWRITE_OK
$ cat .git
gitdir: /tmp/evil-gitdir-nas262
# restored to:
gitdir: /home/orca/src/orca-mcp/.git/worktrees/nas262-259-recon-s6
```

Directory `W_OK` is also true, so 994 can `unlink` the pointer and `mkdir .git` (a full fake gitdir with hooks) inside the checkout. **This is the main residual of “checkout-write-only.”** See §3.

---

## 2. Recipe — 994 checkout-write-only, 997 commits

This is the model to adopt for NAS-262. It matches the NAS-258 papers, Linear NAS-262, and the measurements above.

### 2.1 Contract

- **994** may write the worktree checkout (and, today, every other worktree — NAS-259).
- **994** must not `git add` / `git commit` / `git push`.
- **997** (coordinator / bridge account) performs `git add` + `git commit` in the **same worktree directory** the worker used.
- **No** ACL on any `.git` (common dir, objects, refs, worktree gitdir, hooks).
- **No** `usermod -aG orca orca-worker`.
- **No** `core.sharedRepository` change required.

### 2.2 Coordinator steps (this dispatch, and the general pattern)

1. Worker finishes, reports **absolute paths** of new/changed files. Does not commit.
2. Coordinator, as uid **997**, `cd`s into the **linked worktree**, not the main checkout:

   ```bash
   cd /home/orca/orca/workspaces/orca-mcp/nas262-259-recon-s6
   ```

   General form: `cd /home/orca/orca/workspaces/<repo>/<worktree-name>`.

3. **Before any git command**, verify the gitdir pointer was not swapped (§1.8):

   ```bash
   cat .git
   # must be exactly:
   # gitdir: /home/orca/src/<repo>/.git/worktrees/<worktree-name>
   ```

   If it is anything else, **stop**. Do not `git add`. Treat as a hostile checkout.

4. Optional hardening (997 can do this as file owner; not applied this session):

   ```bash
   # strip the named ACL from the pointer only — checkout files stay writable
   setfacl -x u:orca-worker .git
   chmod 0644 .git
   ```

5. Inspect, then add **named paths** (prefer the worker’s list over `git add -A`):

   ```bash
   git status -sb
   git add -- docs/research/NAS-262-259-RECON-S6.md
   git diff --cached --stat
   git commit -m "docs: NAS-262/259 recon (994 checkout-write-only, 997 commits)"
   ```

6. Do **not** run worker-suggested hook scripts, `git` aliases, or `core.fsmonitor` / `core.pager` values from the worktree. 997’s gitconfig + the shared `.git/config` (0644, 994 cannot write) are the only trusted git config.

### 2.3 Why 997 commits from the worktree directory

A linked worktree has its own `index` / `HEAD` / logs under `.git/worktrees/<name>`. `cd /home/orca/src/orca-mcp` uses the **main** index (`HEAD` on whatever the main checkout is, currently not this branch). Committing from the main tree would:

- miss the worker’s checkout, or
- require `git worktree list` + a separate add that still has to run with `GIT_DIR`/`GIT_WORK_TREE` pointing at this worktree — i.e. the same thing as just `cd`ing there.

997 owns the worktree gitdir (`0755 orca:orca`), so `index.lock`, object creation, ref update, and reflog all succeed without any ACL change.

### 2.4 Why no ACL on `.git` is required

997 already has `W_OK` on every git-metadata path that `git commit` needs. 994 only needs to produce file bytes in the checkout. 997 reads those bytes (`other::r--` on 994-created files; named ACL on 997-owned files) and writes blobs as 997.

Granting 994 `.git` write is therefore not a convenience — it is a **trust-boundary change**.

### 2.5 Why 994 must not join group `orca`

1. **Isolation installer forbids it.** `deploy/linux/install-worker-uid.sh` lines 73–87 abort if the worker shares any supplementary group with the bridge user: *“shared group re-opens the secret class.”*
2. **rahunok-space `.git` is `0775 orca:orca`.** Group write on that tree includes `hooks/`, `objects/`, `refs/`. Group membership = recursive write by another name.
3. **Group-readable secrets exist.** `/etc/orca-mcp/worker-isolation.env` is `0640 root:orca`. 994 cannot read it today (`Permission denied`). Adding 994 to `orca` would.
4. **orca-mcp `.git` is `0755`**, so the group would not even fix `index.lock` there — operators would “fix” that with a broader chmod/ACL, which is the next bullet.

### 2.6 Why recursive ACL on `.git` is forbidden (hooks / RCE)

```text
sudo setfacl -R -m u:orca-worker:rwx /home/orca/src/<repo>/.git
```

would give 994 write on `hooks/`. Next 997 `git commit` / `git status` (with `core.hooksPath` default) executes `pre-commit` / `post-checkout` / `fsmonitor` as **997**. That is RCE on the bridge account: signer-adjacent files, `sudo -n` (997 still has a broad `/etc/sudoers.d/orca` on this box per NAS-258 apply log), worktree ACLs, seed helper, the lot.

Empirically, 994 **already** cannot create `hooks/pre-commit` (`Permission denied`). Keep it that way.

The NAS-258 “narrow ACL” recipe (this worktree gitdir + objects + one branch ref) is **strictly worse than 997-commits** and still lets 994 inject objects into the shared store and race other worktrees. Do not implement it.

---

## 3. Residual risks of the 997-commit model

These remain after the recipe is adopted. None require granting 994 `.git` write.

1. **Gitdir-pointer / fake-`.git` RCE (P0 residual).** 994 can overwrite the checkout `.git` file or replace it with a directory of hooks. 997 `git` in that cwd then runs attacker config/hooks. Mitigate with the pointer check + `setfacl -x` on the pointer (§2.2 steps 3–4). Not applied here (recon only).
2. **Blind commit of hostile content.** 994 can change any checkout file 997 then commits (backdoors, `deploy/linux/*`, `COORDINATOR.md`). 997 must read the diff. Named-path `git add` beats `git add -A`.
3. **Neighbor worktree write (NAS-259).** Same uid + recursive default ACL → 994 writes every tree under `/home/orca/orca/workspaces` (§4). The commit model does not create this; it also does not fix it.
4. **`safe.directory`.** 994 git is unusable without it; that is fine. 997 does not need `safe.directory=*` because 997 owns the worktree. Do not add 994’s HOME gitconfig as a “fix.”
5. **Unreadable 994 files.** If a worker creates mode `0600` without `other` read (explicit `chmod`, or a future default-ACL change), 997 `git add` will fail. Today’s default ACL + umask `0002` yields `other::r--`. If that happens, 997 (directory owner) can `chmod`/`setfacl` the file; do not grant 994 extra rights.
6. **root-owned objects in orca-mcp.** 548 loose objects are `0644 root:root`. Harmless for new 997 commits (new objects go into `0755` fanouts owned by 997). Repack/gc as 997 may warn; **requires attended root** to chown back if it ever blocks. Not investigated further.
7. **rahunok-space `0700` fanouts.** 997 can read them; 994 cannot. Irrelevant to 997-commits. Do not “fix” with ACL for 994.
8. **NAS-261 / release.** Coordinator still cannot always close a 994 pty (`tab_not_found`). Orphan workers are a lifecycle problem, not a commit-model problem.
9. **Shared worker HOME.** `/home/orca-worker/.grok/auth.json` and `~/.orca-worker/current-cap.json` are shared across dispatches (NAS-258 seed). A hostile 994 sibling can clobber creds/caps. Commit model does not address this (NAS-259 variant 1 does).
10. **Coordinator mistake: committing from the main src checkout** silently lands on the wrong index. Always `cd` to the worktree path the worker reported.

---

## 4. NAS-259 — worker-to-worker surface

Health already advertises the gap (`lib/worker-isolation.mjs` `workerIsolationHealth`):

```javascript
perDispatchUid: false,
note: 'NAS-255: one dedicated worker uid closes bridge↔worker trust. Per-dispatch uid / worker-to-worker isolation is NOT shipped.'
```

### 4(a) How workspace ACLs are granted — recursive + default, once, not per-dispatch

**There is no runtime `setfacl`.** Bridge code never touches ACLs on worktree create, dispatch, or release.

Exact strings:

| Location | What it does |
| --- | --- |
| `deploy/linux/install-worker-uid.sh` **114–115** (worktree + `/opt/orca-mcp` copy) | **echo only** — “example, not auto-applied”: `setfacl -R -m u:${WORKER_USER}:rwx /home/${BRIDGE_USER}/orca/workspaces` and the matching `-d` (default) line |
| `docs/runbooks/nas-255-worker-uid.md` **132–133** and **193–194** | Operator cutover steps: the same two `setfacl -R` / `setfacl -R -d` commands |
| `lib/`, `server.mjs`, `/opt/orca-mcp/server.mjs`, `/opt/orca-mcp/lib/*` | **no** `setfacl` / `getfacl` |
| `/usr/local/lib/orca-mcp/orca-omp-as-worker.sh` | uid drop + NAS-258 seed/cap wait; no ACL |
| `/usr/local/lib/orca-mcp/orca-seed-worker-creds` | `chown 994:994` of `auth.json` and cap files under `/run/orca-mcp` and `~/.orca-worker`; no workspaces ACL |

Worktree **preparation** (not ACL) is:

1. `lib/worker-isolation.mjs` `planIsolatedAgentPlacement` (lines 439–505) — `worktree create` **without** `--agent`, then `terminal create --command <wrapper>`.
2. `server.mjs` `dispatchWorker` ~1660–1768 (worktree copy) / live `/opt/orca-mcp/server.mjs` after that — same plan, then `mintAndInstallWorkerCap` (stage JSON + `sudo seed`).
3. Wrapper `/usr/local/lib/orca-mcp/orca-omp-as-worker.sh` — `sudo seed`, wait on `/run/orca-mcp/worker-caps/by-task/<taskId>`, `sudo -n -u orca-worker` (or `setpriv` if already root).

Because the operator applied **default** ACL on the workspaces **root**, every new worktree inherits `u:orca-worker:rwx` automatically. That is why this session’s worktree was writable without any per-dispatch step.

**Empirical proof it is global, not per-dispatch:** as 994, `echo probe > $tree/.nas259-acl-probe-$$` succeeded and was deleted on:

- `/home/orca/orca/workspaces/rahunok-space/membank-s5` (foreign live worktree)
- `/home/orca/orca/workspaces/rahunok-space/postnarrow-smoke`
- `/home/orca/orca/workspaces/rahunok-design`
- `/home/orca/orca/workspaces/rahunok-rn`
- `/home/orca/orca/workspaces/orca-mcp/.orca-worktree-trash`
- `/home/orca/orca/workspaces/rahunok-space/.orca-worktree-trash`

So a hostile or buggy worker can edit a neighbor’s code, plant artifacts, or rewrite trash.

### 4(b) Variant 2 — per-worktree ACL (what to change, what breaks)

**Intent:** keep one uid 994, but stop the cheapest neighbor-write.

**Must change**

1. **One-time strip** of named + default ACL on the workspaces **root** and every existing child. If the default on the parent stays, the next `worktree create` re-grants rwx to 994 on the new tree with no code change. 997 (owner) can `setfacl` without root.
2. **After** isolated `worktree create` returns `worktreePath` (`server.mjs` ~1729 / live equivalent), apply:

   ```bash
   setfacl -m u:orca-worker:rwx -d -m u:orca-worker:rwx "$worktreePath"
   ```

   Default on the **tree** (not the parent) is still wanted so 994-created files inside that tree stay writable.
3. **On release / `worktree rm` / move to `.orca-worktree-trash`:** `setfacl -x u:orca-worker -k` (drop named + default) or `chmod 0700` the trash entry. Today trash inherits the same worker rwx — we wrote it.
4. **Re-dispatch** to an existing path (`worktree=current`): re-apply the named ACL if release stripped it.
5. **Runbook + installer:** stop printing the recursive `-R` on the workspaces root. The echo at `install-worker-uid.sh:114–115` is the foot-gun.
6. **`.git` pointer:** when applying the tree ACL, immediately `setfacl -x u:orca-worker "$worktreePath/.git"` so variant 2 does not keep the gitdir RCE (§1.8).

**What does *not* need to change for variant 2:** sudoers, systemd, `perDispatchUid`, seed helper, cap files, HMAC, 997-commit model.

**What breaks / degrades**

| Event | Effect |
| --- | --- |
| Release / cleanup | If ACL is not stripped, a later 994 still writes the abandoned tree / trash. If stripped too early while the agent is alive, the worker gets `EACCES` mid-turn. |
| Re-dispatch to same worktree | Must re-grant; today inheritance makes this accidentally work. |
| Bridge restart | ACLs are on disk — **survive**. No in-memory map. This is the good part of variant 2. |
| Operator `worktree create` outside the bridge | New tree under workspaces will **not** be 994-writable once the parent default is gone. Coordinators using raw CLI must grant ACL or go through `action=dispatch`. |
| Existing trees after the strip | Every live worker checkout must be re-granted or in-flight 994 processes break. Needs an attended pass. |
| Read vs write | Variant 2 as “named rwx on one tree” does **not** stop 994 reading sibling `0644` files (`other::r--`). Closing read requires stripping `other`/`group` r-x recursively (breaks 997? no — 997 is owner). Still does not close same-uid process attacks. |

**What variant 2 does not close (honest)**

- `kill` / `ptrace` / `/proc` of sibling grok (same uid)
- Shared `/home/orca-worker` (`auth.json`, `current-cap.json`, grok state)
- `/tmp`, `/dev/shm`
- Reading world-readable checkout files unless other-r is stripped

Ticket option 2 is still worth doing: it removes the write-neighbor hole we just used.

### 4(c) Variant 1 — per-dispatch uid (volume and coupling to NAS-262)

This is the only option that actually creates a worker↔worker **uid** boundary.

**Pool vs dynamic**

- systemd `DynamicUser=` is for long-lived services, not `sudo -u` of a TUI. Do not pretend it maps.
- **Dynamic `useradd` per dispatch** (e.g. `orca-w-<shortid>`): uid exhaustion, leftover homes, NSS/lastlog noise, and a sudoers wildcard (`orca ALL=(orca-w-*)`) that is easy to get wrong.
- **Fixed pool** (`orca-worker-00` … `N`, allocated from the bridge, returned on release): bounded, restart-survivable if the lease is on disk next to dispatch ownership. This is the only operationally sane shape.

**Must design before coding**

| Topic | Requirement | Risk if skipped |
| --- | --- | --- |
| Worktree ownership | Per-uid named ACL **or** `chown` of that tree. `chown` fights 997-commits (997 then needs ACL/group to read/write). Prefer: tree stays `orca:orca`, named ACL for the **lease uid** only. | 997 cannot commit, or 994-class still writes neighbors |
| HOME / creds | Today seed copies **one** `/home/orca-worker/.grok/auth.json`. Per-uid needs either N homes + N seeds, or a root helper that bind-mounts a read-only cred into the child. Shared HOME re-opens the class. | Sibling steals provider creds / current-cap |
| Caps | Already per-`dispatchId` under `/run/orca-mcp/worker-caps` (`0711` root, file `0600` lease-uid). Seed helper currently hard-codes `WORKER_UID=994`. Must take a uid or look up the lease. | Caps installed as the wrong uid |
| Sudoers / wrapper | Live wrapper: `sudo -n -u "${WORKER_USER}"`. Per-dispatch needs a root helper with a **fixed** binary + validated uid from a 997-owned lease file — not a sudoers glob on arbitrary users. | 997 → arbitrary uid |
| Cleanup | Release must: kill processes, drop ACL, return pool slot, purge that uid’s HOME fragments, `markWorkerCapPurge`. Live `purgeWorkerCreds` already skips full `auth.json` purge when another isolated dispatch is `running` — that logic becomes per-uid (good) instead of global (today’s compromise). | Slot leak; next tenant inherits files |
| Bridge restart | Persist `dispatchId → uid` next to signed ownership. In-memory only = after restart two dispatches can be given the same uid while both still alive. | Same-uid collision |
| NAS-262 | **997-commits stays.** Each extra uid must **not** get `.git` write. Checkout-write-only + named ACL for that uid is the compatible pairing. If someone later wants “worker commits,” every pool uid needs the narrow object/ref ACL — blast radius × N. | Recreates hooks/RCE per uid |
| Volume | New: lease table, pool installer, wrapper/helper rewrite, seed-creds uid parameter, release/restart tests, runbook. Roughly a NAS-255-sized feature, not a flag flip. | Half-shipped isolation worse than now |

**Do not start variant 1 until** isolation-ON + 997-commits is the boring path (this ticket + NAS-258 acceptance staying green).

### 4. Recommendation (NAS-259)

**Do variant 2 next. Schedule variant 1 as its own project. Reject variant 3.**

Reasons:

- Variant 3 is already false: we wrote foreign worktrees in this session.
- Variant 2 is a small, disk-durable change at one hook (`worktreePath` after create + strip on release + stop `-R` on the parent). It pairs cleanly with NAS-262.
- Variant 1 is the real answer and is also a new identity, sudo, HOME, and restart problem. Shipping it as a drive-by of NAS-259 will regress NAS-258.

Suggested sequence:

1. Land this document; 997-commit this worktree (NAS-262 decided).
2. Implement variant 2 + gitdir-pointer ACL strip in the same PR as the runbook fix.
3. Open a follow-up for a **pool** of worker uids (not `DynamicUser`), explicitly tied to “997 still commits.”

---

## 5. Unverified (and why)

| Item | Why not verified |
| --- | --- |
| 997 actually running `git add`/`commit` on this file | We are 994; task forbids committing. Predicted to work (997 owns gitdir; file `other::r--`). |
| `git show 7a6110f:<path>` / `git show b722184:<path>` as git | 0700 object fanouts on rahunok-space. Content recovered by other means. |
| Contents of `/etc/sudoers.d/*`, `/etc/orca-mcp/env` | Mode `0600`/`0440`, not readable as 994. NAS-258 apply log claims `orca ALL=(ALL) NOPASSWD:ALL` still present — **requires attended root** to re-read. |
| Whether the recursive ACL was applied in one operator command vs several | Only the resulting default ACL is visible. Code path is “operator, once,” not per-dispatch. |
| Commit path past `index.lock` under 994 | Would require ACL/chmod on `.git` (forbidden). |
| Mac contour | Out of scope. |
| Live `ORCA_BRIDGE_WORKER_ISOLATION` value in env file | Unreadable. Process table / this session’s uid 994 + wrapper path is the runtime proof isolation is ON. |
| chown of 548 root-owned orca-mcp objects | **Requires attended root.** Does not block 997-commits. |

---

## 6. Files created

| Path | Role |
| --- | --- |
| `/home/orca/orca/workspaces/orca-mcp/nas262-259-recon-s6/docs/research/NAS-262-259-RECON-S6.md` | This decision package (uncommitted; 994-owned after write) |

No other durable files. Probe writes were deleted. `.git` pointer restored.
