/**
 * NAS-259 variant 2 — per-worktree ACL.
 *
 * Sibling workers share uid `orca-worker`. Isolation is ACL-narrowed, not
 * uid-split: grant `u:orca-worker:rwx` (and default) on THIS checkout only.
 * Never refresh a default ACL on the parent `workspaces/` directory.
 * Never touch the `.git` pointer (NAS-266).
 *
 * Prefer running as the bridge uid (997) when the tree is orca-owned.
 * No process I/O at import; setfacl/chmod/readdir are injected.
 */

import fs from 'node:fs';
import path from 'node:path';
import { assertSafeGitdir, hardenGitdirPointer } from './gitdir-guard.mjs';

export const DEFAULT_WORKER_USER = 'orca-worker';

/**
 * @param {string} checkoutPath
 * @param {{
 *   workerUser?: string,
 *   expectedGitdir?: string|null,
 *   fsImpl?: Pick<typeof fs, 'lstatSync' | 'readdirSync' | 'realpathSync' | 'readFileSync' | 'chmodSync'>,
 *   setfacl?: (args: string[]) => void,
 *   chmod?: (target: string, mode: number) => void,
 * }} [deps]
 */
export function planWorktreeAcl(checkoutPath, deps = {}) {
  const checkout = path.resolve(String(checkoutPath || ''));
  const parent = path.dirname(checkout);
  const workerUser = String(deps.workerUser || DEFAULT_WORKER_USER).trim() || DEFAULT_WORKER_USER;
  const gitPath = path.join(checkout, '.git');
  return {
    checkout,
    parent,
    workerUser,
    gitPath,
    /** Named + default grant on the checkout root only (not the parent). */
    checkoutNamed: ['-m', `u:${workerUser}:rwx`, checkout],
    checkoutDefault: ['-d', '-m', `u:${workerUser}:rwx`, checkout],
    /** Never issued against parent. */
    forbiddenParent: [
      ['-m', `u:${workerUser}:rwx`, parent],
      ['-d', '-m', `u:${workerUser}:rwx`, parent],
      ['-R', '-m', `u:${workerUser}:rwx`, parent],
      ['-R', '-d', '-m', `u:${workerUser}:rwx`, parent],
    ],
    gitExcluded: gitPath,
  };
}

/**
 * Walk checkout contents, skipping the `.git` pointer (file or anything named `.git`).
 * @param {string} root
 * @param {Pick<typeof fs, 'lstatSync' | 'readdirSync'>} fsImpl
 * @returns {{ files: string[], dirs: string[] }}
 */
export function listCheckoutEntries(root, fsImpl = fs) {
  const files = [];
  const dirs = [];
  const resolved = path.resolve(root);

  function walk(dir) {
    let entries;
    try {
      entries = fsImpl.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      const name = typeof ent === 'string' ? ent : ent.name;
      if (name === '.git') continue;
      const full = path.join(dir, name);
      let isDir = false;
      if (ent && typeof ent.isDirectory === 'function') {
        isDir = ent.isDirectory();
      } else {
        try {
          isDir = fsImpl.lstatSync(full).isDirectory();
        } catch {
          continue;
        }
      }
      if (isDir) {
        dirs.push(full);
        walk(full);
      } else {
        files.push(full);
      }
    }
  }

  dirs.push(resolved);
  walk(resolved);
  return { files, dirs };
}

function runSetfacl(setfacl, args, record) {
  try {
    setfacl(args);
    record.push({ args, ok: true });
    return true;
  } catch (e) {
    record.push({
      args,
      ok: false,
      error: e && e.message ? e.message : String(e),
    });
    return false;
  }
}

/**
 * Apply named + default ACL on one isolated checkout. Parent is never granted.
 *
 * @param {string} checkoutPath
 * @param {{
 *   workerUser?: string,
 *   expectedGitdir?: string|null,
 *   fsImpl?: Pick<typeof fs, 'lstatSync' | 'readdirSync' | 'realpathSync' | 'readFileSync' | 'chmodSync'>,
 *   setfacl?: (args: string[]) => void,
 *   chmod?: (target: string, mode: number) => void,
 * }} [deps]
 */
export function applyWorktreeAcl(checkoutPath, deps = {}) {
  const plan = planWorktreeAcl(checkoutPath, deps);
  const setfacl = deps.setfacl;
  if (typeof setfacl !== 'function') {
    return {
      ok: true,
      skipped: 'setfacl_unavailable',
      parentGranted: false,
      gitGranted: false,
      checkout: plan.checkout,
      parent: plan.parent,
      workerUser: plan.workerUser,
      calls: [],
    };
  }

  const calls = [];
  const { files, dirs } = listCheckoutEntries(plan.checkout, deps.fsImpl || fs);

  for (const dir of dirs) {
    runSetfacl(setfacl, ['-m', `u:${plan.workerUser}:rwx`, dir], calls);
    runSetfacl(setfacl, ['-d', '-m', `u:${plan.workerUser}:rwx`, dir], calls);
  }
  for (const file of files) {
    runSetfacl(setfacl, ['-m', `u:${plan.workerUser}:rwx`, file], calls);
  }

  const parentGranted = calls.some((c) => {
    const target = c.args[c.args.length - 1];
    return target === plan.parent;
  });
  const gitGranted = calls.some((c) => c.args.includes(plan.gitPath));

  return {
    ok: !parentGranted && !gitGranted,
    parentGranted,
    gitGranted,
    checkout: plan.checkout,
    parent: plan.parent,
    workerUser: plan.workerUser,
    calls,
    dirs: dirs.length,
    files: files.length,
  };
}

/**
 * After isolated `worktree create`, harden the pointer and grant per-tree ACL.
 *
 * @param {string} checkoutPath
 * @param {string} expectedGitdir
 * @param {object} [deps]
 */
export function hardenIsolatedWorktree(checkoutPath, expectedGitdir, deps = {}) {
  const checkout = path.resolve(String(checkoutPath || ''));
  let asserted = null;
  if (expectedGitdir) {
    asserted = assertSafeGitdir(checkout, expectedGitdir, deps);
    if (!asserted.ok) return { ok: false, stage: 'gitdir-assert', ...asserted };
  }

  const acl = applyWorktreeAcl(checkout, deps);
  const git = hardenGitdirPointer(checkout, expectedGitdir || asserted?.gitdir, {
    ...deps,
    workerUser: deps.workerUser || DEFAULT_WORKER_USER,
  });

  return {
    ok: acl.ok !== false && git.ok === true,
    checkout,
    acl,
    git,
  };
}

/**
 * Infer `<repo>/.git/worktrees/<basename>` from a checkout `.git` pointer
 * after a successful create. Used when the CLI did not return the gitdir.
 *
 * @param {string} checkoutPath
 * @param {{ fsImpl?: Pick<typeof fs, 'readFileSync'> }} [deps]
 */
export function inferExpectedGitdir(checkoutPath, deps = {}) {
  const fsImpl = deps.fsImpl || fs;
  const gitPath = path.join(path.resolve(String(checkoutPath)), '.git');
  let raw;
  try {
    raw = fsImpl.readFileSync(gitPath, 'utf8');
  } catch {
    return null;
  }
  const line = String(raw).split(/\r?\n/)[0] || '';
  const m = /^gitdir:\s*(\S+)\s*$/.exec(line);
  return m ? m[1] : null;
}
