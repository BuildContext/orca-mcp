import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  GITDIR_POINTER_REFUSED,
  GIT_ADD_REFUSED,
  GitdirPointerError,
  GitAddRefusedError,
  DEFAULT_WORKSPACES_ROOT,
  resolveRepoFilesystemPath,
  inferRepoRootFromCheckout,
  expectedGitdirPath,
  parseGitdirPointer,
  assertWorktreeGitdirPointer,
  classifyGitEntry,
  planWorktreeAclCommands,
  planWorktreeAclRevoke,
  listAclChildrenExceptGit,
  hardenDispatchedWorktree,
  revokeWorktreeWorkerAcl,
  composeGitAddArgv,
  assertSafeGitAddArgv,
  planWorktreeGit,
  runGuardedGit,
} from './worktree-harden.mjs';

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writePointer(dir, target) {
  fs.writeFileSync(path.join(dir, '.git'), `gitdir: ${target}\n`, 'utf8');
}

describe('resolveRepoFilesystemPath / inferRepoRootFromCheckout', () => {
  it('resolves path: and absolute selectors', () => {
    assert.equal(resolveRepoFilesystemPath('path:/home/orca/src/orca-mcp'), '/home/orca/src/orca-mcp');
    assert.equal(resolveRepoFilesystemPath('/home/orca/src/orca-mcp'), '/home/orca/src/orca-mcp');
    assert.equal(resolveRepoFilesystemPath('name:orca-mcp'), null);
    assert.equal(resolveRepoFilesystemPath(''), null);
  });

  it('infers /home/orca/src/<repo> from a workspaces checkout', () => {
    assert.equal(
      inferRepoRootFromCheckout('/home/orca/orca/workspaces/orca-mcp/nas266-259-v2-s8'),
      '/home/orca/src/orca-mcp',
    );
    assert.equal(inferRepoRootFromCheckout('/tmp/not-a-workspace/foo'), null);
  });
});

describe('expectedGitdirPath / parseGitdirPointer', () => {
  it('builds <repo>/.git/worktrees/<name>', () => {
    assert.equal(
      expectedGitdirPath({ repoRoot: '/home/orca/src/orca-mcp', worktreeName: 'nas266-259-v2-s8' }),
      '/home/orca/src/orca-mcp/.git/worktrees/nas266-259-v2-s8',
    );
  });

  it('refuses a worktree name with slashes', () => {
    assert.throws(
      () => expectedGitdirPath({ repoRoot: '/home/orca/src/r', worktreeName: 'a/b' }),
      (e) => e instanceof GitdirPointerError && e.code === GITDIR_POINTER_REFUSED,
    );
  });

  it('parses the first gitdir: line', () => {
    assert.equal(parseGitdirPointer('gitdir: /abs/path\n'), '/abs/path');
    assert.equal(parseGitdirPointer('GITDIR: /abs/path'), '/abs/path');
    assert.equal(parseGitdirPointer('not a pointer'), null);
  });
});

describe('assertWorktreeGitdirPointer', () => {
  it('accepts a regular-file pointer aimed at the expected worktrees path', () => {
    const checkout = tmpDir('nas266-ok-');
    const repo = tmpDir('nas266-repo-');
    const name = path.basename(checkout);
    const expected = path.join(repo, '.git', 'worktrees', name);
    fs.mkdirSync(expected, { recursive: true });
    writePointer(checkout, expected);
    const r = assertWorktreeGitdirPointer(checkout, { repoRoot: repo, worktreeName: name });
    assert.equal(r.ok, true);
    assert.equal(r.gitKind, 'file');
    assert.equal(r.pointer, fs.realpathSync(expected));
    fs.rmSync(checkout, { recursive: true, force: true });
    fs.rmSync(repo, { recursive: true, force: true });
  });

  it('rejects a .git that has become a directory', () => {
    const checkout = tmpDir('nas266-dir-');
    fs.mkdirSync(path.join(checkout, '.git'));
    assert.throws(
      () =>
        assertWorktreeGitdirPointer(checkout, {
          repoRoot: '/home/orca/src/orca-mcp',
          worktreeName: path.basename(checkout),
        }),
      (e) => {
        assert.equal(e instanceof GitdirPointerError, true);
        assert.equal(e.code, GITDIR_POINTER_REFUSED);
        assert.match(e.message, /^GITDIR_POINTER_REFUSED: .git is a directory/);
        return true;
      },
    );
    fs.rmSync(checkout, { recursive: true, force: true });
  });

  it('rejects a pointer aimed outside the expected worktrees path', () => {
    const checkout = tmpDir('nas266-evil-');
    const name = path.basename(checkout);
    writePointer(checkout, '/tmp/evil-gitdir-nas266');
    assert.throws(
      () =>
        assertWorktreeGitdirPointer(checkout, {
          repoRoot: '/home/orca/src/orca-mcp',
          worktreeName: name,
        }),
      (e) => {
        assert.equal(e.code, GITDIR_POINTER_REFUSED);
        assert.match(e.message, /^GITDIR_POINTER_REFUSED: gitdir target is not the expected/);
        assert.equal(e.detail.target, '/tmp/evil-gitdir-nas266');
        assert.equal(
          e.detail.expected,
          `/home/orca/src/orca-mcp/.git/worktrees/${name}`,
        );
        return true;
      },
    );
    fs.rmSync(checkout, { recursive: true, force: true });
  });

  it('rejects a pointer aimed at a sibling worktree gitdir', () => {
    const checkout = tmpDir('nas266-sib-');
    const name = path.basename(checkout);
    writePointer(checkout, '/home/orca/src/orca-mcp/.git/worktrees/other-worktree');
    assert.throws(
      () =>
        assertWorktreeGitdirPointer(checkout, {
          repoRoot: '/home/orca/src/orca-mcp',
          worktreeName: name,
        }),
      (e) => e.code === GITDIR_POINTER_REFUSED && /not the expected/.test(e.message),
    );
    fs.rmSync(checkout, { recursive: true, force: true });
  });

  it('rejects a symlink .git', () => {
    const checkout = tmpDir('nas266-link-');
    const target = path.join(checkout, 'somewhere');
    fs.writeFileSync(target, 'gitdir: /tmp/x\n');
    fs.symlinkSync(target, path.join(checkout, '.git'));
    assert.throws(
      () =>
        assertWorktreeGitdirPointer(checkout, {
          repoRoot: '/home/orca/src/r',
          worktreeName: path.basename(checkout),
        }),
      (e) => e.code === GITDIR_POINTER_REFUSED && /symlink/.test(e.message),
    );
    fs.rmSync(checkout, { recursive: true, force: true });
  });

  it('rejects a relative gitdir target', () => {
    const checkout = tmpDir('nas266-rel-');
    writePointer(checkout, '../evil');
    assert.throws(
      () =>
        assertWorktreeGitdirPointer(checkout, {
          repoRoot: '/home/orca/src/r',
          worktreeName: path.basename(checkout),
        }),
      (e) => e.code === GITDIR_POINTER_REFUSED && /not an absolute path/.test(e.message),
    );
    fs.rmSync(checkout, { recursive: true, force: true });
  });

  it('rejects a missing .git', () => {
    const checkout = tmpDir('nas266-miss-');
    assert.throws(
      () =>
        assertWorktreeGitdirPointer(checkout, {
          repoRoot: '/home/orca/src/r',
          worktreeName: path.basename(checkout),
        }),
      (e) => e.code === GITDIR_POINTER_REFUSED && /missing/.test(e.message),
    );
    fs.rmSync(checkout, { recursive: true, force: true });
  });

  it('resolves .. in the pointer so it cannot sneak onto another gitdir', () => {
    const checkout = tmpDir('nas266-dotdot-');
    const name = path.basename(checkout);
    writePointer(
      checkout,
      `/home/orca/src/orca-mcp/.git/worktrees/${name}/../other`,
    );
    assert.throws(
      () =>
        assertWorktreeGitdirPointer(checkout, {
          repoRoot: '/home/orca/src/orca-mcp',
          worktreeName: name,
        }),
      (e) => e.code === GITDIR_POINTER_REFUSED,
    );
    fs.rmSync(checkout, { recursive: true, force: true });
  });
});

describe('planWorktreeAclCommands (NAS-259 variant 2)', () => {
  it('grants only the specific checkout, never the workspaces root', () => {
    const checkout = '/home/orca/orca/workspaces/orca-mcp/nas266-259-v2-s8';
    const cmds = planWorktreeAclCommands({
      checkoutPath: checkout,
      workerUser: 'orca-worker',
      children: [path.join(checkout, 'lib'), path.join(checkout, 'docs')],
      gitKind: 'file',
    });
    const joined = cmds.map((c) => c.argv.join(' '));
    assert.ok(joined.some((s) => s.startsWith('setfacl -m u:orca-worker:rwx -d -m u:orca-worker:rwx ' + checkout)));
    assert.ok(joined.some((s) => s.includes(path.join(checkout, 'lib'))));
    assert.ok(
      !joined.some(
        (s) =>
          s.includes(`-R`) &&
          s.endsWith(` ${DEFAULT_WORKSPACES_ROOT}`),
      ),
    );
    assert.ok(!joined.some((s) => s.endsWith(` ${DEFAULT_WORKSPACES_ROOT}`)));
    const strip = cmds.find((c) => c.id === 'strip-gitdir-pointer');
    assert.deepEqual(strip.argv, ['setfacl', '-x', 'u:orca-worker', path.join(checkout, '.git')]);
    const chmod = cmds.find((c) => c.id === 'chmod-gitdir-pointer');
    assert.deepEqual(chmod.argv, ['chmod', '0644', path.join(checkout, '.git')]);
  });

  it('refuses to plan ACL on the workspaces root itself', () => {
    assert.throws(
      () => planWorktreeAclCommands({ checkoutPath: DEFAULT_WORKSPACES_ROOT }),
      /workspaces root/,
    );
  });

  it('does not strip or recurse into a .git directory', () => {
    const checkout = '/tmp/main-checkout';
    const cmds = planWorktreeAclCommands({
      checkoutPath: checkout,
      children: [path.join(checkout, 'lib'), path.join(checkout, '.git')],
      gitKind: 'directory',
    });
    assert.equal(cmds.some((c) => c.id === 'strip-gitdir-pointer'), false);
    assert.ok(!cmds.some((c) => c.argv.includes(path.join(checkout, '.git'))));
  });

  it('listAclChildrenExceptGit skips the pointer / gitdir', () => {
    const d = tmpDir('nas266-kids-');
    fs.mkdirSync(path.join(d, 'lib'));
    fs.writeFileSync(path.join(d, '.git'), 'gitdir: /x\n');
    fs.writeFileSync(path.join(d, '.gitignore'), 'x\n');
    const kids = listAclChildrenExceptGit(d).map((p) => path.basename(p)).sort();
    assert.deepEqual(kids, ['.gitignore', 'lib']);
    fs.rmSync(d, { recursive: true, force: true });
  });

  it('revoke plans named + default drop on that tree only', () => {
    const cmds = planWorktreeAclRevoke({
      checkoutPath: '/home/orca/orca/workspaces/orca-mcp/foo',
      workerUser: 'orca-worker',
    });
    assert.deepEqual(cmds[0].argv, [
      'setfacl', '-R', '-x', 'u:orca-worker',
      '/home/orca/orca/workspaces/orca-mcp/foo',
    ]);
    assert.deepEqual(cmds[1].argv, [
      'setfacl', '-R', '-k',
      '/home/orca/orca/workspaces/orca-mcp/foo',
    ]);
  });
});

describe('hardenDispatchedWorktree', () => {
  it('skips when isolation is inactive', async () => {
    const r = await hardenDispatchedWorktree({
      checkoutPath: '/tmp/x',
      isolationActive: false,
    });
    assert.equal(r.ok, true);
    assert.equal(r.skipped, true);
  });

  it('runs grant → strip → chmod via injectable execFile and then guards the pointer', async () => {
    const checkout = tmpDir('nas266-hard-');
    const repo = tmpDir('nas266-hard-repo-');
    const name = path.basename(checkout);
    const expected = path.join(repo, '.git', 'worktrees', name);
    fs.mkdirSync(expected, { recursive: true });
    fs.mkdirSync(path.join(checkout, 'lib'));
    writePointer(checkout, expected);

    const ran = [];
    const r = await hardenDispatchedWorktree({
      checkoutPath: checkout,
      repoRoot: repo,
      worktreeName: name,
      workerUser: 'orca-worker',
      isolationActive: true,
      execFile: async (cmd, argv) => {
        ran.push([cmd, ...argv]);
        return { stdout: '', stderr: '' };
      },
    });
    assert.equal(r.ok, true, r.error);
    assert.equal(r.gitKind, 'file');
    assert.equal(r.pointer.ok, true);
    assert.ok(ran[0][0] === 'setfacl' && ran[0].includes(checkout) && !ran[0].includes('-R'));
    assert.ok(ran.some((a) => a[0] === 'setfacl' && a.includes('-x') && a.at(-1).endsWith('/.git')));
    assert.ok(ran.some((a) => a[0] === 'chmod' && a.includes('0644')));
    assert.ok(!ran.some((a) => a.at(-1) === DEFAULT_WORKSPACES_ROOT));
    fs.rmSync(checkout, { recursive: true, force: true });
    fs.rmSync(repo, { recursive: true, force: true });
  });

  it('fails closed when the pointer is already hostile', async () => {
    const checkout = tmpDir('nas266-host-');
    writePointer(checkout, '/tmp/evil');
    const r = await hardenDispatchedWorktree({
      checkoutPath: checkout,
      repoRoot: '/home/orca/src/orca-mcp',
      worktreeName: path.basename(checkout),
      execFile: async () => ({ stdout: '', stderr: '' }),
    });
    assert.equal(r.ok, false);
    assert.match(r.error, /GITDIR_POINTER_REFUSED/);
    fs.rmSync(checkout, { recursive: true, force: true });
  });

  it('revokeWorktreeWorkerAcl runs the revoke argv', async () => {
    const ran = [];
    const r = await revokeWorktreeWorkerAcl({
      checkoutPath: '/tmp/wt-x',
      workerUser: 'orca-worker',
      execFile: async (cmd, argv) => {
        ran.push([cmd, ...argv]);
        return { stdout: '', stderr: '' };
      },
    });
    assert.equal(r.ok, true);
    assert.equal(ran.length, 2);
    assert.equal(ran[0][0], 'setfacl');
  });
});

describe('composeGitAddArgv / planWorktreeGit', () => {
  it('enumerates paths and never emits -A', () => {
    const argv = composeGitAddArgv([
      'lib/worktree-harden.mjs',
      'docs/research/NAS-266-259-v2-s8.md',
    ]);
    assert.deepEqual(argv, [
      'add',
      '--',
      'lib/worktree-harden.mjs',
      'docs/research/NAS-266-259-v2-s8.md',
    ]);
    assert.equal(argv.includes('-A'), false);
    assert.equal(argv.includes('--all'), false);
    assertSafeGitAddArgv(argv);
  });

  it('refuses git add -A / --all / . / empty / absolute / escape', () => {
    const bad = ['-A', '--all', '-u', '.', '..', '/etc/passwd', '../x', ''];
    for (const p of bad) {
      assert.throws(
        () => (p === '' ? composeGitAddArgv([]) : composeGitAddArgv([p])),
        (e) => e instanceof GitAddRefusedError && e.code === GIT_ADD_REFUSED,
      );
    }
    assert.throws(() => composeGitAddArgv([]), /explicit path list/);
    assert.throws(
      () => assertSafeGitAddArgv(['add', '-A']),
      (e) => e.code === GIT_ADD_REFUSED,
    );
  });

  it('planWorktreeGit guards first and diffs before commit', () => {
    const checkout = tmpDir('nas266-plan-');
    const repo = tmpDir('nas266-plan-repo-');
    const name = path.basename(checkout);
    const expected = path.join(repo, '.git', 'worktrees', name);
    fs.mkdirSync(expected, { recursive: true });
    writePointer(checkout, expected);

    const plan = planWorktreeGit({
      checkoutPath: checkout,
      repoRoot: repo,
      worktreeName: name,
      paths: ['docs/research/NAS-266-259-v2-s8.md'],
      message: 'test commit',
    });
    assert.deepEqual(plan.addArgv[0], 'add');
    assert.equal(plan.addArgv.includes('-A'), false);
    assert.deepEqual(plan.diffArgv, ['diff', '--cached', '--stat']);
    assert.deepEqual(plan.statusArgv, ['status', '-sb']);
    assert.deepEqual(plan.commitArgv, ['commit', '-m', 'test commit']);
    const g = plan.guard();
    assert.equal(g.ok, true);

    fs.rmSync(checkout, { recursive: true, force: true });
    fs.rmSync(repo, { recursive: true, force: true });
  });

  it('runGuardedGit refuses to exec when .git is a directory', async () => {
    const checkout = tmpDir('nas266-run-');
    fs.mkdirSync(path.join(checkout, '.git'));
    await assert.rejects(
      () =>
        runGuardedGit({
          checkoutPath: checkout,
          repoRoot: '/home/orca/src/r',
          worktreeName: path.basename(checkout),
          argv: ['add', '--', 'x'],
          execFile: async () => {
            throw new Error('exec must not run');
          },
        }),
      (e) => e.code === GITDIR_POINTER_REFUSED,
    );
    fs.rmSync(checkout, { recursive: true, force: true });
  });

  it('runGuardedGit refuses add -A even after a good pointer', async () => {
    const checkout = tmpDir('nas266-adda-');
    const repo = tmpDir('nas266-adda-repo-');
    const name = path.basename(checkout);
    const expected = path.join(repo, '.git', 'worktrees', name);
    fs.mkdirSync(expected, { recursive: true });
    writePointer(checkout, expected);
    await assert.rejects(
      () =>
        runGuardedGit({
          checkoutPath: checkout,
          repoRoot: repo,
          worktreeName: name,
          argv: ['add', '-A'],
          execFile: async () => {
            throw new Error('exec must not run');
          },
        }),
      (e) => e.code === GIT_ADD_REFUSED,
    );
    fs.rmSync(checkout, { recursive: true, force: true });
    fs.rmSync(repo, { recursive: true, force: true });
  });

  it('runGuardedGit execs git after a good pointer', async () => {
    const checkout = tmpDir('nas266-okrun-');
    const repo = tmpDir('nas266-okrun-repo-');
    const name = path.basename(checkout);
    const expected = path.join(repo, '.git', 'worktrees', name);
    fs.mkdirSync(expected, { recursive: true });
    writePointer(checkout, expected);
    let seen = null;
    const r = await runGuardedGit({
      checkoutPath: checkout,
      repoRoot: repo,
      worktreeName: name,
      argv: ['status', '-sb'],
      execFile: async (cmd, argv, opts) => {
        seen = { cmd, argv, cwd: opts.cwd };
        return { stdout: '## ok\n', stderr: '' };
      },
    });
    assert.equal(r.ok, true);
    assert.equal(seen.cmd, 'git');
    assert.deepEqual(seen.argv, ['status', '-sb']);
    assert.equal(seen.cwd, path.resolve(checkout));
    fs.rmSync(checkout, { recursive: true, force: true });
    fs.rmSync(repo, { recursive: true, force: true });
  });
});

describe('classifyGitEntry', () => {
  it('distinguishes file / directory / symlink / missing', () => {
    const d = tmpDir('nas266-cls-');
    fs.writeFileSync(path.join(d, 'f'), 'x');
    fs.mkdirSync(path.join(d, 'dir'));
    fs.symlinkSync('f', path.join(d, 'l'));
    assert.equal(classifyGitEntry(path.join(d, 'f')), 'file');
    assert.equal(classifyGitEntry(path.join(d, 'dir')), 'directory');
    assert.equal(classifyGitEntry(path.join(d, 'l')), 'symlink');
    assert.equal(classifyGitEntry(path.join(d, 'nope')), 'missing');
    fs.rmSync(d, { recursive: true, force: true });
  });
});
