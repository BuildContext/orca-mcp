import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  isUnsafeCommitPath,
  normalizeCommitPaths,
  commitNamedPaths,
  COMMIT_EMPTY_PATHS,
  COMMIT_UNSAFE_PATH,
} from './isolated-git.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

describe('normalizeCommitPaths', () => {
  const checkout = '/home/orca/workspaces/wt-a';
  const gitdir = '/home/orca/repo/.git/worktrees/wt-a';

  it('refuses an empty path list', () => {
    const r = normalizeCommitPaths(checkout, []);
    assert.equal(r.ok, false);
    assert.equal(r.code, COMMIT_EMPTY_PATHS);
  });

  it('refuses .git, escapes, and the gitdir', () => {
    assert.equal(isUnsafeCommitPath(checkout, '.git', gitdir).unsafe, true);
    assert.equal(isUnsafeCommitPath(checkout, '../x', gitdir).unsafe, true);
    assert.equal(isUnsafeCommitPath(checkout, '/etc/passwd', gitdir).unsafe, true);
    assert.equal(isUnsafeCommitPath(checkout, '.', gitdir).unsafe, true);
    assert.equal(isUnsafeCommitPath(checkout, '*', gitdir).unsafe, true);
    assert.equal(isUnsafeCommitPath(checkout, gitdir, gitdir).unsafe, true);
    assert.equal(normalizeCommitPaths(checkout, ['src/a.js', '.git'], gitdir).ok, false);
    assert.equal(normalizeCommitPaths(checkout, ['src/a.js'], gitdir).ok, true);
  });
});

describe('commitNamedPaths', () => {
  it('asserts gitdir then add -- named paths, returns cached diff, commits as bridge', () => {
    const calls = [];
    const r = commitNamedPaths(
      {
        checkout: '/wt',
        expectedGitdir: '/repo/.git/worktrees/wt',
        paths: ['src/a.js', 'README.md'],
        message: 'worker: named paths',
        userName: 'orca-bridge',
        userEmail: 'orca@localhost',
      },
      {
        assertGitdir: () => ({ ok: true, gitdir: '/repo/.git/worktrees/wt' }),
        git: (args) => {
          calls.push(args.slice());
          if (args.includes('diff')) return { status: 0, stdout: 'diff --git a/src/a.js\n', stderr: '' };
          return { status: 0, stdout: '', stderr: '' };
        },
      },
    );
    assert.equal(r.ok, true);
    assert.equal(r.diff, 'diff --git a/src/a.js\n');
    const add = calls.find((a) => a.includes('add'));
    assert.ok(add);
    assert.ok(add.includes('--'));
    assert.ok(add.includes('src/a.js'));
    assert.ok(!add.includes('-A'));
    assert.ok(!add.includes('.'));
    assert.ok(!add.includes('*'));
    const commit = calls.find((a) => a.includes('commit'));
    assert.ok(commit.includes('-m'));
    assert.ok(commit.some((x) => String(x).startsWith('user.name=')));
  });

  it('does not call git when the gitdir assert fails', () => {
    const calls = [];
    const r = commitNamedPaths(
      { checkout: '/wt', expectedGitdir: '/x', paths: ['a'], message: 'm' },
      {
        assertGitdir: () => ({ ok: false, code: 'directory', message: 'dir' }),
        git: (args) => {
          calls.push(args);
          return { status: 0, stdout: '', stderr: '' };
        },
      },
    );
    assert.equal(r.ok, false);
    assert.deepEqual(calls, []);
  });

  it('source never contains git add -A', () => {
    const src = fs.readFileSync(path.join(HERE, 'isolated-git.mjs'), 'utf8');
    assert.equal(/\badd\b[^\n]*-A/.test(src), false);
    assert.equal(/'add',\s*'-A'/.test(src), false);
    assert.equal(/"add",\s*"-A"/.test(src), false);
  });
});
