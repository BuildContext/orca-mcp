/**
 * NAS-266 — linked-worktree gitdir pointer must stay a regular file owned
 * by the bridge uid. A worker that can replace `.git` with a directory of
 * hooks gets RCE the next time the bridge (uid 997) runs git in that cwd.
 *
 * No process I/O at import. FS / chmod / setfacl are injected.
 */

import fs from 'node:fs';
import path from 'node:path';

export const GITDIR_OK = 'ok';
export const GITDIR_MISSING = 'missing';
export const GITDIR_NOT_FILE = 'not_file';
export const GITDIR_SYMLINK = 'symlink';
export const GITDIR_DIRECTORY = 'directory';
export const GITDIR_MALFORMED = 'malformed';
export const GITDIR_MISMATCH = 'mismatch';

const GITDIR_LINE = /^gitdir:\s*(\S+)\s*$/;

/**
 * Parse a linked-worktree pointer file. One `gitdir: <absolute>` line only.
 * @param {string} contents
 * @returns {{ ok: true, gitdir: string } | { ok: false, code: string, message: string }}
 */
export function parseGitdirPointer(contents) {
  const raw = String(contents ?? '');
  const lines = raw.split(/\r?\n/);
  const nonempty = lines.filter((l, i) => l.length > 0 || i < lines.length - 1);
  // Allow a single trailing newline; reject extra blank or non-blank lines.
  const body = raw.endsWith('\n') ? raw.slice(0, -1) : raw;
  if (body.includes('\n')) {
    return {
      ok: false,
      code: GITDIR_MALFORMED,
      message: 'gitdir pointer must be a single line',
    };
  }
  if (/includeIf|\?\(optional\)/i.test(raw)) {
    return {
      ok: false,
      code: GITDIR_MALFORMED,
      message: 'gitdir pointer must not contain includeIf or ?(optional)',
    };
  }
  const m = GITDIR_LINE.exec(body);
  if (!m) {
    return {
      ok: false,
      code: GITDIR_MALFORMED,
      message: 'gitdir pointer must match "^gitdir: <absolute>\\n?"',
    };
  }
  const dest = m[1];
  if (!path.isAbsolute(dest)) {
    return {
      ok: false,
      code: GITDIR_MALFORMED,
      message: 'gitdir pointer must be an absolute path',
    };
  }
  void nonempty;
  return { ok: true, gitdir: dest };
}

/**
 * Assert checkout/.git is a regular file pointing at the expected worktree gitdir.
 *
 * @param {string} checkoutPath
 * @param {string} expected absolute path to <repo>/.git/worktrees/<name>
 * @param {{
 *   fsImpl?: Pick<typeof fs, 'lstatSync' | 'readFileSync' | 'realpathSync'>,
 *   realpath?: (p: string) => string,
 * }} [deps]
 * @returns {{
 *   ok: true,
 *   gitdir: string,
 * } | {
 *   ok: false,
 *   code: string,
 *   message: string,
 * }}
 */
export function assertSafeGitdir(checkoutPath, expected, deps = {}) {
  const fsImpl = deps.fsImpl || fs;
  const realpath =
    typeof deps.realpath === 'function'
      ? deps.realpath
      : (p) => fsImpl.realpathSync(p);
  const checkout = path.resolve(String(checkoutPath || ''));
  const gitPath = path.join(checkout, '.git');
  const expectedAbs = String(expected || '').trim();
  if (!expectedAbs || !path.isAbsolute(expectedAbs)) {
    return {
      ok: false,
      code: GITDIR_MALFORMED,
      message: 'expected gitdir must be an absolute path',
    };
  }

  let st;
  try {
    st = fsImpl.lstatSync(gitPath);
  } catch (e) {
    return {
      ok: false,
      code: GITDIR_MISSING,
      message: `.git missing at ${gitPath}: ${e && e.message ? e.message : e}`,
    };
  }

  if (typeof st.isSymbolicLink === 'function' && st.isSymbolicLink()) {
    return {
      ok: false,
      code: GITDIR_SYMLINK,
      message: `${gitPath} is a symlink; linked worktree pointer must be a regular file`,
    };
  }
  if (typeof st.isDirectory === 'function' && st.isDirectory()) {
    return {
      ok: false,
      code: GITDIR_DIRECTORY,
      message: `${gitPath} is a directory; refusing to run git as the bridge uid`,
    };
  }
  if (typeof st.isFile === 'function' && !st.isFile()) {
    return {
      ok: false,
      code: GITDIR_NOT_FILE,
      message: `${gitPath} is not a regular file`,
    };
  }

  let raw;
  try {
    raw = fsImpl.readFileSync(gitPath, 'utf8');
  } catch (e) {
    return {
      ok: false,
      code: GITDIR_MALFORMED,
      message: `cannot read ${gitPath}: ${e && e.message ? e.message : e}`,
    };
  }

  const parsed = parseGitdirPointer(raw);
  if (!parsed.ok) return parsed;

  let resolvedDest;
  let resolvedExpected;
  try {
    resolvedDest = realpath(parsed.gitdir);
    resolvedExpected = realpath(expectedAbs);
  } catch (e) {
    return {
      ok: false,
      code: GITDIR_MISMATCH,
      message: `cannot realpath gitdir pointer: ${e && e.message ? e.message : e}`,
    };
  }
  if (resolvedDest !== resolvedExpected) {
    return {
      ok: false,
      code: GITDIR_MISMATCH,
      message:
        `gitdir pointer ${resolvedDest} does not match expected ${resolvedExpected}`,
    };
  }
  return { ok: true, gitdir: resolvedDest };
}

/**
 * Pure model of whether a worker uid can unlink / rename / overwrite `.git`
 * after harden. Used by unit tests with injected facts (no live chmod).
 *
 * Sticky on the checkout (01775) + `.git` owned by the bridge uid means the
 * worker cannot unlink or rename it. Mode 0444/0644 without a named write ACL
 * means the worker cannot overwrite the pointer contents.
 *
 * @param {{
 *   checkoutMode: number,
 *   gitIsFile: boolean,
 *   gitOwnerUid: number,
 *   gitMode: number,
 *   gitNamedWriteAcl: boolean,
 *   workerUid: number,
 * }} facts
 */
export function modelWorkerGitdirAccess(facts) {
  const checkoutMode = Number(facts.checkoutMode);
  const sticky = (checkoutMode & 0o1000) !== 0;
  const workerUid = facts.workerUid;
  const gitOwner = facts.gitOwnerUid;
  const gitMode = Number(facts.gitMode);
  const otherWrite = (gitMode & 0o002) !== 0;
  const groupWrite = (gitMode & 0o020) !== 0;
  const ownerWrite = (gitMode & 0o200) !== 0;

  const canUnlink =
    facts.gitIsFile === true &&
    (!sticky || gitOwner === workerUid);
  const canRename = canUnlink;
  const canOverwrite =
    facts.gitNamedWriteAcl === true ||
    otherWrite ||
    (groupWrite && gitOwner === workerUid) ||
    (ownerWrite && gitOwner === workerUid);

  return {
    canUnlink,
    canRename,
    canOverwrite,
    sticky,
    protected: !canUnlink && !canRename && !canOverwrite,
  };
}

/**
 * Strip the worker named ACL from `.git`, make the pointer non-writable, and
 * set the sticky bit on the checkout so the worker cannot unlink a bridge-
 * owned `.git` file.
 *
 * @param {string} checkoutPath
 * @param {string} expected
 * @param {{
 *   workerUser?: string,
 *   fsImpl?: Pick<typeof fs, 'lstatSync' | 'readFileSync' | 'realpathSync' | 'chmodSync'>,
 *   setfacl?: (args: string[]) => void,
 *   chmod?: (target: string, mode: number) => void,
 * }} [deps]
 */
export function hardenGitdirPointer(checkoutPath, expected, deps = {}) {
  const asserted = assertSafeGitdir(checkoutPath, expected, deps);
  if (!asserted.ok) return asserted;

  const fsImpl = deps.fsImpl || fs;
  const checkout = path.resolve(String(checkoutPath));
  const gitPath = path.join(checkout, '.git');
  const workerUser = String(deps.workerUser || 'orca-worker').trim() || 'orca-worker';
  const chmod =
    typeof deps.chmod === 'function'
      ? deps.chmod
      : (target, mode) => fsImpl.chmodSync(target, mode);
  const setfacl =
    typeof deps.setfacl === 'function'
      ? deps.setfacl
      : null;

  const aclOps = [];
  if (setfacl) {
    try {
      setfacl(['-x', `u:${workerUser}`, gitPath]);
      aclOps.push({ op: 'strip-named', target: gitPath, user: workerUser, ok: true });
    } catch (e) {
      const msg = e && e.message ? e.message : String(e);
      // ENOENT / no-acl is fine — pointer may never have had a named entry.
      if (!/ENOENT|No such file|There is no|Operation not supported/i.test(msg)) {
        aclOps.push({ op: 'strip-named', target: gitPath, user: workerUser, ok: false, error: msg });
      } else {
        aclOps.push({ op: 'strip-named', target: gitPath, user: workerUser, ok: true, ignored: msg });
      }
    }
  }

  chmod(gitPath, 0o444);
  chmod(checkout, 0o1775);

  return {
    ok: true,
    gitdir: asserted.gitdir,
    pointerMode: 0o444,
    checkoutMode: 0o1775,
    acl: aclOps,
  };
}

/**
 * Resolve `<repo>/.git/worktrees/<name>` from a checkout path + repo root.
 * @param {string} repoPath
 * @param {string} worktreeName
 */
export function expectedWorktreeGitdir(repoPath, worktreeName) {
  const name = String(worktreeName || '').trim();
  if (!name || name === '.' || name === '..' || name.includes('/') || name.includes('\\')) {
    throw new Error('expectedWorktreeGitdir: worktree name must be a single path segment');
  }
  return path.resolve(String(repoPath), '.git', 'worktrees', name);
}
