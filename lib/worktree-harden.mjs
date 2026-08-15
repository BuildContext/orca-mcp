/**
 * NAS-266 / NAS-259 variant 2 — per-worktree ACL + gitdir-pointer guard.
 *
 * Isolation model (NAS-262, accepted):
 *   - uid 994 (orca-worker) is checkout-write-only
 *   - uid 997 (bridge) performs every git operation from the same linked worktree
 *
 * This module is the worktree-create hook and the only composer of `git add`
 * the bridge is allowed to run. It must never grant ACL on the workspaces
 * root, never recurse into a `.git` directory, and never emit `git add -A`.
 */

import fs from 'node:fs';
import path from 'node:path';
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';

const execFileDefault = promisify(execFileCb);

/** Greppable refusal code — do not wrap this in a generic Error. */
export const GITDIR_POINTER_REFUSED = 'GITDIR_POINTER_REFUSED';

/** Greppable refusal when someone asks the composer for `git add -A`. */
export const GIT_ADD_REFUSED = 'GIT_ADD_REFUSED';

export const DEFAULT_SRC_ROOT = '/home/orca/src';
export const DEFAULT_WORKSPACES_ROOT = '/home/orca/orca/workspaces';
export const DEFAULT_WORKER_USER = 'orca-worker';

export class GitdirPointerError extends Error {
  /**
   * @param {string} reason
   * @param {Record<string, unknown>} [detail]
   */
  constructor(reason, detail = {}) {
    super(`${GITDIR_POINTER_REFUSED}: ${reason}`);
    this.name = 'GitdirPointerError';
    this.code = GITDIR_POINTER_REFUSED;
    this.reason = reason;
    this.detail = detail;
  }
}

export class GitAddRefusedError extends Error {
  /**
   * @param {string} reason
   * @param {Record<string, unknown>} [detail]
   */
  constructor(reason, detail = {}) {
    super(`${GIT_ADD_REFUSED}: ${reason}`);
    this.name = 'GitAddRefusedError';
    this.code = GIT_ADD_REFUSED;
    this.reason = reason;
    this.detail = detail;
  }
}

/**
 * @param {string|null|undefined} repo
 * @returns {string|null} absolute filesystem path, or null for name:/id: selectors
 */
export function resolveRepoFilesystemPath(repo) {
  const raw = String(repo || '').trim();
  if (!raw) return null;
  if (/^path:/i.test(raw)) return path.resolve(raw.slice(raw.indexOf(':') + 1));
  if (raw.startsWith('/')) return path.resolve(raw);
  return null;
}

/**
 * @param {string} checkoutPath
 * @param {{ workspacesRoot?: string, srcRoot?: string }} [opts]
 * @returns {string|null}
 */
export function inferRepoRootFromCheckout(checkoutPath, opts = {}) {
  const checkout = path.resolve(String(checkoutPath || ''));
  const ws = path.resolve(opts.workspacesRoot || DEFAULT_WORKSPACES_ROOT);
  const src = path.resolve(opts.srcRoot || DEFAULT_SRC_ROOT);
  const rel = path.relative(ws, checkout);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return null;
  const repoName = rel.split(path.sep)[0];
  if (!repoName || repoName === '.' || repoName === '..') return null;
  return path.join(src, repoName);
}

/**
 * @param {string} name
 */
export function assertSafeWorktreeName(name) {
  const n = String(name || '');
  if (!n || n === '.' || n === '..' || n.includes('/') || n.includes('\\') || n.includes('\0')) {
    throw new GitdirPointerError('worktree name is not a single path segment', { name: n });
  }
  return n;
}

/**
 * Expected gitdir for a linked worktree:
 *   <repoRoot>/.git/worktrees/<worktreeName>
 *
 * @param {{ repoRoot: string, worktreeName: string }} p
 */
export function expectedGitdirPath({ repoRoot, worktreeName }) {
  const name = assertSafeWorktreeName(worktreeName);
  const root = path.resolve(String(repoRoot || ''));
  if (!root || root === path.sep) {
    throw new GitdirPointerError('repo root is missing', { repoRoot });
  }
  return path.join(root, '.git', 'worktrees', name);
}

/**
 * @param {string} contents
 * @returns {string|null} raw target path (not resolved)
 */
export function parseGitdirPointer(contents) {
  const text = String(contents || '');
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*gitdir:\s*(.+?)\s*$/i.exec(line);
    if (m) return m[1];
  }
  return null;
}

/**
 * Before ANY git operation 997 runs in a worker checkout, call this.
 *
 * Refuses (all with code GITDIR_POINTER_REFUSED):
 *   - `.git` is a directory (fake gitdir / hooks)
 *   - `.git` is a symlink or otherwise not a regular file
 *   - pointer target is not exactly `<repo>/.git/worktrees/<name>`
 *
 * @param {string} checkoutPath
 * @param {{
 *   repoRoot?: string|null,
 *   worktreeName?: string|null,
 *   srcRoot?: string,
 *   workspacesRoot?: string,
 *   fsImpl?: Pick<typeof fs, 'lstatSync'|'readFileSync'|'realpathSync'>,
 * }} [opts]
 * @returns {{
 *   ok: true,
 *   gitKind: 'file',
 *   pointer: string,
 *   expected: string,
 *   checkoutPath: string,
 * }}
 */
export function assertWorktreeGitdirPointer(checkoutPath, opts = {}) {
  const checkout = path.resolve(String(checkoutPath || ''));
  if (!checkout || checkout === path.sep) {
    throw new GitdirPointerError('checkout path is missing', { checkoutPath });
  }
  const fsImpl = opts.fsImpl || fs;
  const gitPath = path.join(checkout, '.git');
  const worktreeName = opts.worktreeName
    ? assertSafeWorktreeName(opts.worktreeName)
    : assertSafeWorktreeName(path.basename(checkout));

  let st;
  try {
    st = fsImpl.lstatSync(gitPath);
  } catch (e) {
    throw new GitdirPointerError('.git is missing', {
      checkoutPath: checkout,
      gitPath,
      cause: String(e && e.message ? e.message : e),
    });
  }

  if (st.isSymbolicLink()) {
    throw new GitdirPointerError('.git is a symlink, not a regular file', {
      checkoutPath: checkout,
      gitPath,
    });
  }
  if (st.isDirectory()) {
    throw new GitdirPointerError('.git is a directory, not a gitdir pointer file', {
      checkoutPath: checkout,
      gitPath,
    });
  }
  if (!st.isFile()) {
    throw new GitdirPointerError('.git is not a regular file', {
      checkoutPath: checkout,
      gitPath,
      mode: st.mode,
    });
  }

  let raw;
  try {
    raw = fsImpl.readFileSync(gitPath, 'utf8');
  } catch (e) {
    throw new GitdirPointerError('.git pointer is unreadable', {
      checkoutPath: checkout,
      gitPath,
      cause: String(e && e.message ? e.message : e),
    });
  }

  const target = parseGitdirPointer(raw);
  if (!target) {
    throw new GitdirPointerError('.git pointer has no gitdir: line', {
      checkoutPath: checkout,
      gitPath,
    });
  }
  if (!path.isAbsolute(target)) {
    throw new GitdirPointerError('gitdir target is not an absolute path', {
      checkoutPath: checkout,
      target,
    });
  }

  const repoRoot =
    (opts.repoRoot && String(opts.repoRoot).trim()) ||
    inferRepoRootFromCheckout(checkout, {
      srcRoot: opts.srcRoot,
      workspacesRoot: opts.workspacesRoot,
    });
  if (!repoRoot) {
    throw new GitdirPointerError('cannot determine expected repo root for gitdir check', {
      checkoutPath: checkout,
    });
  }

  const expected = expectedGitdirPath({ repoRoot, worktreeName });
  const resolvedTarget = path.resolve(target);
  let comparableTarget = resolvedTarget;
  let comparableExpected = path.resolve(expected);
  const realpathSync =
    typeof fsImpl.realpathSync === 'function' ? fsImpl.realpathSync.bind(fsImpl) : fs.realpathSync;
  try {
    comparableTarget = realpathSync(resolvedTarget);
  } catch {
    /* target need not exist — compare lexically */
  }
  try {
    comparableExpected = realpathSync(comparableExpected);
  } catch {
    /* expected need not exist yet */
  }

  if (comparableTarget !== comparableExpected) {
    throw new GitdirPointerError(
      `gitdir target is not the expected worktrees path`,
      {
        checkoutPath: checkout,
        target: comparableTarget,
        expected: comparableExpected,
      },
    );
  }

  return {
    ok: true,
    gitKind: 'file',
    pointer: comparableTarget,
    expected: comparableExpected,
    checkoutPath: checkout,
  };
}

/**
 * Classify checkout `.git` without throwing (create-time ACL walk).
 * @param {string} gitPath
 * @param {Pick<typeof fs, 'lstatSync'>} [fsImpl]
 * @returns {'file'|'directory'|'symlink'|'missing'|'other'}
 */
export function classifyGitEntry(gitPath, fsImpl = fs) {
  try {
    const st = fsImpl.lstatSync(gitPath);
    if (st.isSymbolicLink()) return 'symlink';
    if (st.isDirectory()) return 'directory';
    if (st.isFile()) return 'file';
    return 'other';
  } catch {
    return 'missing';
  }
}

/**
 * ACL argv for ONE checkout. Never targets the workspaces root.
 *
 * The recursive grant is applied per child so a `.git` **directory**
 * (main checkout) is never painted. The pointer file is stripped after.
 *
 * @param {{
 *   checkoutPath: string,
 *   workerUser?: string,
 *   children?: string[],
 *   gitKind?: ReturnType<typeof classifyGitEntry>,
 * }} p
 */
export function planWorktreeAclCommands(p) {
  const checkout = path.resolve(String(p.checkoutPath || ''));
  const user = String(p.workerUser || DEFAULT_WORKER_USER).trim() || DEFAULT_WORKER_USER;
  if (!checkout || checkout === path.sep) {
    throw new Error('planWorktreeAclCommands: checkoutPath required');
  }
  if (checkout === path.resolve(DEFAULT_WORKSPACES_ROOT)) {
    throw new Error('planWorktreeAclCommands: refusing ACL on the workspaces root');
  }

  const named = `u:${user}:rwx`;
  const cmds = [
    {
      id: 'grant-checkout-dir',
      argv: ['setfacl', '-m', named, '-d', '-m', named, checkout],
    },
  ];

  const children = Array.isArray(p.children) ? p.children : [];
  for (const child of children) {
    const base = path.basename(child);
    if (base === '.git') continue;
    cmds.push({
      id: 'grant-child',
      argv: ['setfacl', '-R', '-m', named, '-d', '-m', named, child],
    });
  }

  if (p.gitKind !== 'directory') {
    const gitFile = path.join(checkout, '.git');
    cmds.push({
      id: 'strip-gitdir-pointer',
      argv: ['setfacl', '-x', `u:${user}`, gitFile],
    });
    cmds.push({
      id: 'chmod-gitdir-pointer',
      argv: ['chmod', '0644', gitFile],
    });
  }

  return cmds;
}

/**
 * @param {string} checkoutPath
 * @param {Pick<typeof fs, 'readdirSync'|'lstatSync'>} [fsImpl]
 */
export function listAclChildrenExceptGit(checkoutPath, fsImpl = fs) {
  const checkout = path.resolve(checkoutPath);
  let names;
  try {
    names = fsImpl.readdirSync(checkout);
  } catch {
    return [];
  }
  const out = [];
  for (const name of names) {
    if (name === '.git') continue;
    out.push(path.join(checkout, name));
  }
  return out;
}

/**
 * Revoke the worker named + default ACL from one checkout (release / idle).
 * @param {{ checkoutPath: string, workerUser?: string }} p
 */
export function planWorktreeAclRevoke(p) {
  const checkout = path.resolve(String(p.checkoutPath || ''));
  const user = String(p.workerUser || DEFAULT_WORKER_USER).trim() || DEFAULT_WORKER_USER;
  if (!checkout || checkout === path.sep) {
    throw new Error('planWorktreeAclRevoke: checkoutPath required');
  }
  return [
    {
      id: 'revoke-named',
      argv: ['setfacl', '-R', '-x', `u:${user}`, checkout],
    },
    {
      id: 'revoke-default',
      argv: ['setfacl', '-R', '-k', checkout],
    },
  ];
}

/**
 * @param {{
 *   cmd: string,
 *   argv: string[],
 *   execFile?: typeof execFileDefault,
 * }} p
 */
async function runCmd(p) {
  const execFile = p.execFile || execFileDefault;
  try {
    const result = await execFile(p.cmd, p.argv, { encoding: 'utf8' });
    return { ok: true, cmd: p.cmd, argv: p.argv, stdout: result.stdout || '', stderr: result.stderr || '' };
  } catch (e) {
    return {
      ok: false,
      cmd: p.cmd,
      argv: p.argv,
      error: String(e && e.message ? e.message : e),
      stderr: String((e && e.stderr) || ''),
    };
  }
}

/**
 * Apply per-worktree ACL + pointer strip. Fail-closed: any failed setfacl/chmod
 * is returned as ok:false so dispatch must not start the worker.
 *
 * @param {{
 *   checkoutPath: string,
 *   repoRoot?: string|null,
 *   worktreeName?: string|null,
 *   workerUser?: string,
 *   isolationActive?: boolean,
 *   execFile?: typeof execFileDefault,
 *   fsImpl?: typeof fs,
 *   srcRoot?: string,
 *   workspacesRoot?: string,
 * }} opts
 */
export async function hardenDispatchedWorktree(opts) {
  if (opts.isolationActive === false) {
    return { ok: true, skipped: true, reason: 'isolation_inactive' };
  }
  const checkout = path.resolve(String(opts.checkoutPath || ''));
  if (!checkout || checkout === path.sep) {
    return { ok: false, error: 'hardenDispatchedWorktree: checkoutPath required' };
  }
  const fsImpl = opts.fsImpl || fs;
  const gitPath = path.join(checkout, '.git');
  const gitKind = classifyGitEntry(gitPath, fsImpl);
  const children = listAclChildrenExceptGit(checkout, fsImpl);
  const cmds = planWorktreeAclCommands({
    checkoutPath: checkout,
    workerUser: opts.workerUser,
    children,
    gitKind,
  });

  const ran = [];
  for (const c of cmds) {
    const result = await runCmd({
      cmd: c.argv[0],
      argv: c.argv.slice(1),
      execFile: opts.execFile,
    });
    ran.push({ id: c.id, ...result });
    if (!result.ok) {
      return {
        ok: false,
        error: `${c.id} failed: ${result.error || result.stderr || 'unknown'}`,
        steps: ran,
      };
    }
  }

  let pointer = null;
  if (gitKind === 'file') {
    try {
      pointer = assertWorktreeGitdirPointer(checkout, {
        repoRoot: opts.repoRoot,
        worktreeName: opts.worktreeName,
        srcRoot: opts.srcRoot,
        workspacesRoot: opts.workspacesRoot,
        fsImpl,
      });
    } catch (e) {
      // ACL was applied; pointer is wrong — refuse to start the worker.
      return {
        ok: false,
        error: e && e.message ? e.message : String(e),
        code: e && e.code ? e.code : undefined,
        steps: ran,
      };
    }
  }

  return {
    ok: true,
    skipped: false,
    checkoutPath: checkout,
    gitKind,
    pointer,
    steps: ran,
  };
}

/**
 * @param {{
 *   checkoutPath: string,
 *   workerUser?: string,
 *   execFile?: typeof execFileDefault,
 * }} opts
 */
export async function revokeWorktreeWorkerAcl(opts) {
  const cmds = planWorktreeAclRevoke(opts);
  const ran = [];
  for (const c of cmds) {
    const result = await runCmd({
      cmd: c.argv[0],
      argv: c.argv.slice(1),
      execFile: opts.execFile,
    });
    ran.push({ id: c.id, ...result });
    if (!result.ok) {
      return {
        ok: false,
        error: `${c.id} failed: ${result.error || result.stderr || 'unknown'}`,
        steps: ran,
      };
    }
  }
  return { ok: true, checkoutPath: path.resolve(opts.checkoutPath), steps: ran };
}

const FORBIDDEN_ADD_TOKENS = new Set(['-A', '--all', '-u', '--update', '-a', '.', '..']);

/**
 * The only `git add` argv the bridge may compose.
 * Always `['add', '--', ...paths]`. Never `-A`.
 *
 * @param {string[]} paths relative paths inside the checkout
 * @returns {string[]}
 */
export function composeGitAddArgv(paths) {
  if (!Array.isArray(paths) || paths.length === 0) {
    throw new GitAddRefusedError('git add requires an explicit path list (never -A)');
  }
  const cleaned = [];
  for (const raw of paths) {
    const p = String(raw ?? '');
    if (!p) {
      throw new GitAddRefusedError('empty path');
    }
    if (FORBIDDEN_ADD_TOKENS.has(p) || p.startsWith('-')) {
      throw new GitAddRefusedError(`flag or glob token refused: ${p}`, { path: p });
    }
    if (path.isAbsolute(p)) {
      throw new GitAddRefusedError(`absolute path refused: ${p}`, { path: p });
    }
    if (p.includes('\0')) {
      throw new GitAddRefusedError('NUL in path', { path: p });
    }
    const norm = path.posix.normalize(p.replaceAll('\\', '/'));
    if (norm === '..' || norm.startsWith('../') || path.isAbsolute(norm)) {
      throw new GitAddRefusedError(`path escapes checkout: ${p}`, { path: p, normalized: norm });
    }
    cleaned.push(p);
  }
  return ['add', '--', ...cleaned];
}

/**
 * @param {string[]} argv git argv without the `git` binary
 */
export function assertSafeGitAddArgv(argv) {
  const a = Array.isArray(argv) ? argv : [];
  if (a[0] !== 'add') {
    throw new GitAddRefusedError('not a git add argv', { argv: a });
  }
  if (a.includes('-A') || a.includes('--all') || a.includes('-u') || a.includes('--update')) {
    throw new GitAddRefusedError('git add -A/--all/-u is forbidden', { argv: a });
  }
  const dd = a.indexOf('--');
  if (dd !== 1 || a.length < 3) {
    throw new GitAddRefusedError('git add must be `add -- <paths>`', { argv: a });
  }
  return a;
}

/**
 * Plan the 997 git sequence for a worker checkout.
 * Caller must invoke `guard()` before exec'ing any of the argv lists.
 *
 * @param {{
 *   checkoutPath: string,
 *   repoRoot?: string|null,
 *   worktreeName?: string|null,
 *   paths: string[],
 *   message?: string|null,
 *   fsImpl?: Pick<typeof fs, 'lstatSync'|'readFileSync'|'realpathSync'>,
 * }} p
 */
export function planWorktreeGit(p) {
  const addArgv = composeGitAddArgv(p.paths);
  assertSafeGitAddArgv(addArgv);
  const checkoutPath = path.resolve(String(p.checkoutPath || ''));
  return {
    cwd: checkoutPath,
    addArgv,
    statusArgv: ['status', '-sb'],
    diffArgv: ['diff', '--cached', '--stat'],
    commitArgv: p.message
      ? ['commit', '-m', String(p.message)]
      : null,
    guard() {
      return assertWorktreeGitdirPointer(checkoutPath, {
        repoRoot: p.repoRoot,
        worktreeName: p.worktreeName,
        fsImpl: p.fsImpl,
      });
    },
  };
}

/**
 * Run a git argv in a checkout after the pointer guard.
 * `git add` is re-checked so a caller cannot sneak `-A` past the planner.
 *
 * @param {{
 *   checkoutPath: string,
 *   repoRoot?: string|null,
 *   worktreeName?: string|null,
 *   argv: string[],
 *   execFile?: typeof execFileDefault,
 *   fsImpl?: Pick<typeof fs, 'lstatSync'|'readFileSync'|'realpathSync'>,
 * }} p
 */
export async function runGuardedGit(p) {
  const pointer = assertWorktreeGitdirPointer(p.checkoutPath, {
    repoRoot: p.repoRoot,
    worktreeName: p.worktreeName,
    fsImpl: p.fsImpl,
  });
  const argv = Array.isArray(p.argv) ? [...p.argv] : [];
  if (argv[0] === 'add') {
    assertSafeGitAddArgv(argv);
  }
  const execFile = p.execFile || execFileDefault;
  const result = await execFile('git', argv, {
    cwd: path.resolve(p.checkoutPath),
    encoding: 'utf8',
  });
  return {
    ok: true,
    pointer,
    argv,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
  };
}
