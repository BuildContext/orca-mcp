import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  planWorktreeAcl,
  applyWorktreeAcl,
  listCheckoutEntries,
  hardenIsolatedWorktree,
} from './worktree-acl.mjs';

function makeCheckout() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-acl-'));
  const parent = path.join(root, 'workspaces');
  const checkout = path.join(parent, 'wt-a');
  const repo = path.join(root, 'repo');
  const gitdir = path.join(repo, '.git', 'worktrees', 'wt-a');
  fs.mkdirSync(gitdir, { recursive: true });
  fs.mkdirSync(checkout, { recursive: true });
  fs.writeFileSync(path.join(checkout, 'README.md'), 'hi\n');
  fs.mkdirSync(path.join(checkout, 'src'));
  fs.writeFileSync(path.join(checkout, 'src', 'a.js'), '1\n');
  fs.writeFileSync(path.join(checkout, '.git'), `gitdir: ${gitdir}\n`);
  return { root, parent, checkout, gitdir };
}

describe('planWorktreeAcl', () => {
  it('never lists a parent grant; excludes .git', () => {
    const t = makeCheckout();
    try {
      const plan = planWorktreeAcl(t.checkout, { workerUser: 'orca-worker' });
      assert.equal(plan.parent, t.parent);
      assert.equal(plan.gitExcluded, path.join(t.checkout, '.git'));
      assert.ok(plan.forbiddenParent.length >= 2);
      assert.ok(plan.forbiddenParent.every((args) => args.includes(t.parent)));
      assert.ok(!plan.checkoutNamed.includes(t.parent));
    } finally {
      fs.rmSync(t.root, { recursive: true, force: true });
    }
  });
});

describe('applyWorktreeAcl', () => {
  it('grants only the checkout and its contents; parent and .git are never targets', () => {
    const t = makeCheckout();
    const calls = [];
    try {
      const r = applyWorktreeAcl(t.checkout, {
        workerUser: 'orca-worker',
        setfacl: (args) => {
          calls.push(args.slice());
        },
      });
      assert.equal(r.ok, true);
      assert.equal(r.parentGranted, false);
      assert.equal(r.gitGranted, false);
      const targets = calls.map((a) => a[a.length - 1]);
      assert.ok(targets.includes(t.checkout));
      assert.ok(targets.some((p) => p.endsWith(`${path.sep}README.md`)));
      assert.ok(targets.every((p) => p !== t.parent));
      assert.ok(targets.every((p) => p !== path.join(t.checkout, '.git')));
      assert.ok(calls.some((a) => a[0] === '-d' && a[a.length - 1] === t.checkout));
    } finally {
      fs.rmSync(t.root, { recursive: true, force: true });
    }
  });

  it('listCheckoutEntries skips .git', () => {
    const t = makeCheckout();
    try {
      const { files, dirs } = listCheckoutEntries(t.checkout);
      assert.ok(files.every((f) => path.basename(f) !== '.git'));
      assert.ok(dirs.every((d) => path.basename(d) !== '.git'));
    } finally {
      fs.rmSync(t.root, { recursive: true, force: true });
    }
  });
});

describe('hardenIsolatedWorktree', () => {
  it('applies ACL then hardens the pointer', () => {
    const t = makeCheckout();
    const calls = [];
    try {
      const r = hardenIsolatedWorktree(t.checkout, t.gitdir, {
        workerUser: 'orca-worker',
        setfacl: (args) => {
          calls.push(args.slice());
        },
      });
      assert.equal(r.ok, true);
      assert.equal(r.acl.parentGranted, false);
      assert.equal(r.git.ok, true);
      const gitTargets = calls.filter((a) => a.includes(path.join(t.checkout, '.git')));
      assert.ok(gitTargets.every((a) => a.includes('-x')));
      assert.ok(calls.every((a) => a[a.length - 1] !== t.parent));
    } finally {
      fs.rmSync(t.root, { recursive: true, force: true });
    }
  });
});
