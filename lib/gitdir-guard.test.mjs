import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  parseGitdirPointer,
  assertSafeGitdir,
  hardenGitdirPointer,
  modelWorkerGitdirAccess,
  expectedWorktreeGitdir,
  GITDIR_DIRECTORY,
  GITDIR_SYMLINK,
  GITDIR_MALFORMED,
  GITDIR_MISMATCH,
} from './gitdir-guard.mjs';

function makeTree() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-gitdir-'));
  const repo = path.join(root, 'repo');
  const checkout = path.join(root, 'workspaces', 'wt-a');
  const gitdir = path.join(repo, '.git', 'worktrees', 'wt-a');
  fs.mkdirSync(gitdir, { recursive: true });
  fs.mkdirSync(checkout, { recursive: true });
  const pointer = `gitdir: ${gitdir}\n`;
  fs.writeFileSync(path.join(checkout, '.git'), pointer, { mode: 0o644 });
  return { root, repo, checkout, gitdir };
}

describe('parseGitdirPointer', () => {
  it('accepts a single absolute gitdir line with optional trailing newline', () => {
    const ok = parseGitdirPointer('gitdir: /abs/repo/.git/worktrees/n\n');
    assert.equal(ok.ok, true);
    assert.equal(ok.gitdir, '/abs/repo/.git/worktrees/n');
    assert.equal(parseGitdirPointer('gitdir: /abs/repo/.git/worktrees/n').ok, true);
  });

  it('rejects extra lines, includeIf, relative gitdirs, and optional syntax', () => {
    assert.equal(parseGitdirPointer('gitdir: /a\nincludeIf: x\n').ok, false);
    assert.equal(parseGitdirPointer('gitdir: /a\nfoo\n').code, GITDIR_MALFORMED);
    assert.equal(parseGitdirPointer('gitdir: ../.git/worktrees/n\n').ok, false);
    assert.equal(parseGitdirPointer('gitdir: /a?(optional)\n').ok, false);
    assert.equal(parseGitdirPointer('[includeIf "gitdir:/x"]\n').ok, false);
  });
});

describe('assertSafeGitdir', () => {
  it('accepts a happy-path linked worktree pointer', () => {
    const t = makeTree();
    try {
      const r = assertSafeGitdir(t.checkout, t.gitdir);
      assert.equal(r.ok, true);
      assert.equal(fs.realpathSync(r.gitdir), fs.realpathSync(t.gitdir));
    } finally {
      fs.rmSync(t.root, { recursive: true, force: true });
    }
  });

  it('rejects tampered pointer contents', () => {
    const t = makeTree();
    try {
      fs.writeFileSync(path.join(t.checkout, '.git'), 'gitdir: /tmp/evil/.git\n');
      const r = assertSafeGitdir(t.checkout, t.gitdir);
      assert.equal(r.ok, false);
      assert.ok(r.code === GITDIR_MISMATCH || r.code === GITDIR_MALFORMED);
    } finally {
      fs.rmSync(t.root, { recursive: true, force: true });
    }
  });

  it('rejects .git replaced by a directory', () => {
    const t = makeTree();
    try {
      fs.unlinkSync(path.join(t.checkout, '.git'));
      fs.mkdirSync(path.join(t.checkout, '.git'));
      const r = assertSafeGitdir(t.checkout, t.gitdir);
      assert.equal(r.ok, false);
      assert.equal(r.code, GITDIR_DIRECTORY);
    } finally {
      fs.rmSync(t.root, { recursive: true, force: true });
    }
  });

  it('rejects .git as a symlink', () => {
    const t = makeTree();
    try {
      const gitPath = path.join(t.checkout, '.git');
      fs.unlinkSync(gitPath);
      fs.symlinkSync(t.gitdir, gitPath);
      const r = assertSafeGitdir(t.checkout, t.gitdir);
      assert.equal(r.ok, false);
      assert.equal(r.code, GITDIR_SYMLINK);
    } finally {
      fs.rmSync(t.root, { recursive: true, force: true });
    }
  });
});

describe('hardenGitdirPointer + worker access model', () => {
  it('chmods pointer 0444 and checkout 1775; strips named worker ACL', () => {
    const t = makeTree();
    const aclCalls = [];
    try {
      const r = hardenGitdirPointer(t.checkout, t.gitdir, {
        workerUser: 'orca-worker',
        setfacl: (args) => {
          aclCalls.push(args);
        },
      });
      assert.equal(r.ok, true);
      const stGit = fs.lstatSync(path.join(t.checkout, '.git'));
      const stDir = fs.lstatSync(t.checkout);
      assert.equal(stGit.mode & 0o777, 0o444);
      assert.equal(stDir.mode & 0o1777, 0o1775);
      assert.ok(aclCalls.some((a) => a.includes('-x') && a.some((x) => String(x).includes('orca-worker'))));
    } finally {
      fs.rmSync(t.root, { recursive: true, force: true });
    }
  });

  it('model: after harden, worker uid cannot unlink / rename / overwrite .git', () => {
    const access = modelWorkerGitdirAccess({
      checkoutMode: 0o1775,
      gitIsFile: true,
      gitOwnerUid: 997,
      gitMode: 0o444,
      gitNamedWriteAcl: false,
      workerUid: 994,
    });
    assert.equal(access.canUnlink, false);
    assert.equal(access.canRename, false);
    assert.equal(access.canOverwrite, false);
    assert.equal(access.protected, true);
    assert.equal(access.sticky, true);
  });

  it('model: without sticky, worker can unlink a writable checkout .git', () => {
    const access = modelWorkerGitdirAccess({
      checkoutMode: 0o775,
      gitIsFile: true,
      gitOwnerUid: 997,
      gitMode: 0o644,
      gitNamedWriteAcl: true,
      workerUid: 994,
    });
    assert.equal(access.canUnlink, true);
    assert.equal(access.canOverwrite, true);
    assert.equal(access.protected, false);
  });

  it('injected unlink after harden is denied by the access model', () => {
    const unlinks = [];
    const access = modelWorkerGitdirAccess({
      checkoutMode: 0o1775,
      gitIsFile: true,
      gitOwnerUid: 997,
      gitMode: 0o444,
      gitNamedWriteAcl: false,
      workerUid: 994,
    });
    const unlinkAsWorker = (p) => {
      if (!access.canUnlink) {
        const err = new Error('EPERM');
        err.code = 'EPERM';
        unlinks.push({ path: p, denied: true });
        throw err;
      }
      unlinks.push({ path: p, denied: false });
    };
    assert.throws(() => unlinkAsWorker('/checkout/.git'), /EPERM/);
    assert.equal(unlinks[0].denied, true);
  });
});

describe('expectedWorktreeGitdir', () => {
  it('joins repo/.git/worktrees/<name>', () => {
    assert.equal(
      expectedWorktreeGitdir('/home/orca/repo', 'wt-a'),
      path.resolve('/home/orca/repo', '.git', 'worktrees', 'wt-a'),
    );
    assert.throws(() => expectedWorktreeGitdir('/r', '../x'), /single path segment/);
  });
});
