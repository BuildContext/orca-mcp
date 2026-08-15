/**
 * NAS-262 — 994 writes the checkout; 997 commits named paths after a gitdir assert.
 *
 * Never add-all / `.` / `*`. Never sudo to the worker uid to commit.
 * Hostile file *content* that 997 then commits is an accepted residual.
 */

import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { assertSafeGitdir } from './gitdir-guard.mjs';

export const COMMIT_EMPTY_PATHS = 'empty_paths';
export const COMMIT_UNSAFE_PATH = 'unsafe_path';
export const COMMIT_GITDIR = 'unsafe_gitdir';
export const COMMIT_GIT_FAILED = 'git_failed';

/**
 * True when a path is `.git`, escapes the checkout, or is the gitdir itself.
 * @param {string} checkout
 * @param {string} relOrAbs
 * @param {string} [gitdir]
 */
export function isUnsafeCommitPath(checkout, relOrAbs, gitdir = null) {
  const raw = String(relOrAbs || '');
  if (!raw || raw === '.' || raw === '..' || raw === '*' || raw === '-A' || raw === '--all') {
    return { unsafe: true, reason: raw || 'empty' };
  }
  if (raw === '.git' || raw === '/.git' || raw.endsWith('/.git') || raw.split(/[/\\]/).includes('.git')) {
    return { unsafe: true, reason: '.git' };
  }
  const checkoutAbs = path.resolve(checkout);
  const resolved = path.isAbsolute(raw)
    ? path.resolve(raw)
    : path.resolve(checkoutAbs, raw);
  const rel = path.relative(checkoutAbs, resolved);
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
    return { unsafe: true, reason: 'escapes_checkout' };
  }
  if (gitdir) {
    const g = path.resolve(gitdir);
    if (resolved === g || resolved.startsWith(`${g}${path.sep}`)) {
      return { unsafe: true, reason: 'gitdir' };
    }
  }
  return { unsafe: false, resolved, rel };
}

/**
 * @param {string[]} paths
 * @returns {{ ok: true, rels: string[] } | { ok: false, code: string, message: string, path?: string }}
 */
export function normalizeCommitPaths(checkout, paths, gitdir = null) {
  if (!Array.isArray(paths) || paths.length === 0) {
    return {
      ok: false,
      code: COMMIT_EMPTY_PATHS,
      message: 'commit requires a non-empty list of named paths',
    };
  }
  const rels = [];
  for (const p of paths) {
    const check = isUnsafeCommitPath(checkout, p, gitdir);
    if (check.unsafe) {
      return {
        ok: false,
        code: check.reason === 'gitdir' ? COMMIT_GITDIR : COMMIT_UNSAFE_PATH,
        message: `refusing path ${JSON.stringify(p)} (${check.reason})`,
        path: p,
      };
    }
    rels.push(check.rel);
  }
  return { ok: true, rels };
}

function runGit(git, cwd, args) {
  const r = git(['-C', cwd, ...args]);
  return r;
}

function defaultGit(args) {
  const r = spawnSync('git', args, {
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
  });
  return {
    status: r.status,
    stdout: r.stdout || '',
    stderr: r.stderr || '',
    error: r.error ? r.error.message : null,
  };
}

/**
 * Bridge-uid commit of named paths after gitdir assert.
 *
 * @param {{
 *   checkout: string,
 *   expectedGitdir: string,
 *   paths: string[],
 *   message: string,
 *   userName?: string,
 *   userEmail?: string,
 * }} args
 * @param {{
 *   git?: (args: string[]) => { status: number|null, stdout: string, stderr: string, error?: string|null },
 *   assertGitdir?: typeof assertSafeGitdir,
 * }} [deps]
 */
export function commitNamedPaths(args, deps = {}) {
  const checkout = path.resolve(String(args?.checkout || ''));
  const expected = String(args?.expectedGitdir || '');
  const message = String(args?.message || '').trim();
  const assertFn = deps.assertGitdir || assertSafeGitdir;
  const git = deps.git || defaultGit;

  const gate = assertFn(checkout, expected);
  if (!gate.ok) {
    return { ok: false, code: COMMIT_GITDIR, gitdir: gate };
  }

  const norm = normalizeCommitPaths(checkout, args?.paths, gate.gitdir);
  if (!norm.ok) return norm;
  if (!message) {
    return { ok: false, code: 'empty_message', message: 'commit message required' };
  }

  const add = runGit(git, checkout, ['add', '--', ...norm.rels]);
  if ((add.status ?? 1) !== 0) {
    return {
      ok: false,
      code: COMMIT_GIT_FAILED,
      step: 'add',
      stderr: add.stderr,
      error: add.error,
    };
  }

  const diff = runGit(git, checkout, ['diff', '--cached']);
  if ((diff.status ?? 1) !== 0) {
    return {
      ok: false,
      code: COMMIT_GIT_FAILED,
      step: 'diff-cached',
      stderr: diff.stderr,
      error: diff.error,
    };
  }

  const name = String(args.userName || 'orca-bridge').trim() || 'orca-bridge';
  const email = String(args.userEmail || 'orca-bridge@localhost').trim() || 'orca-bridge@localhost';
  const commit = runGit(git, checkout, [
    '-c',
    `user.name=${name}`,
    '-c',
    `user.email=${email}`,
    'commit',
    '-m',
    message,
  ]);
  if ((commit.status ?? 1) !== 0) {
    return {
      ok: false,
      code: COMMIT_GIT_FAILED,
      step: 'commit',
      stderr: commit.stderr,
      error: commit.error,
      diff: diff.stdout,
    };
  }

  return {
    ok: true,
    paths: norm.rels,
    diff: diff.stdout,
    commit: {
      stdout: commit.stdout,
      stderr: commit.stderr,
    },
  };
}
