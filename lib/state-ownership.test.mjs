import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  STATE_FILE_MODE,
  STATE_OK,
  STATE_MISSING,
  STATE_FOREIGN_OWNER,
  STATE_UNREADABLE,
  STATE_UNWRITABLE,
  STATE_LOOSE_MODE,
  classifyStateFile,
  inspectStateFile,
  stateOwnershipWarnings,
  writeFilePreservingOwner,
} from './state-ownership.mjs';

// ---------------------------------------------------------------------------
// classifyStateFile — pure verdicts (the NAS-241 matrix)
// ---------------------------------------------------------------------------

describe('classifyStateFile', () => {
  it('missing file is fine — first boot writes it', () => {
    const v = classifyStateFile({ path: '/x/tokens.json', exists: false });
    assert.equal(v.code, STATE_MISSING);
    assert.equal(v.ok, true);
    assert.equal(v.message, null);
  });

  it('own file with mode 600 is ok', () => {
    const v = classifyStateFile({
      path: '/x/tokens.json',
      exists: true,
      uid: 997,
      gid: 997,
      mode: 0o100600,
      runningUid: 997,
    });
    assert.equal(v.code, STATE_OK);
    assert.equal(v.ok, true);
  });

  it('root-owned store under a non-root service user is unreadable — the NAS-241 case', () => {
    const v = classifyStateFile({
      path: '/home/orca/.orca-bridge-tokens.json',
      exists: true,
      uid: 0,
      gid: 0,
      mode: 0o100600,
      readable: false,
      writable: false,
      runningUid: 997,
    });
    assert.equal(v.code, STATE_UNREADABLE);
    assert.equal(v.ok, false);
    assert.match(v.message, /re-authorize/);
    assert.match(v.message, /chown/);
  });

  it('readable but not writable is still a failure (tokens would be memory-only)', () => {
    const v = classifyStateFile({
      path: '/x/tokens.json',
      exists: true,
      uid: 0,
      gid: 0,
      mode: 0o100644,
      readable: true,
      writable: false,
      runningUid: 997,
    });
    assert.equal(v.code, STATE_UNWRITABLE);
    assert.match(v.message, /memory only/);
  });

  it('foreign owner that happens to be accessible is still flagged', () => {
    const v = classifyStateFile({
      path: '/x/tokens.json',
      exists: true,
      uid: 1000,
      gid: 1000,
      mode: 0o100600,
      readable: true,
      writable: true,
      runningUid: 997,
    });
    assert.equal(v.code, STATE_FOREIGN_OWNER);
    assert.equal(v.ok, false);
  });

  it('root process is not warned about files owned by other users', () => {
    const v = classifyStateFile({
      path: '/x/tokens.json',
      exists: true,
      uid: 997,
      gid: 997,
      mode: 0o100600,
      runningUid: 0,
    });
    assert.equal(v.code, STATE_OK);
  });

  it('the audit directory is told to be 700, not 600', () => {
    const v = classifyStateFile({
      path: '/home/orca/.orca-bridge',
      exists: true,
      uid: 997,
      gid: 997,
      mode: 0o040755,
      isDirectory: true,
      runningUid: 997,
    });
    assert.equal(v.code, STATE_LOOSE_MODE);
    assert.match(v.message, /chmod 700/);
    assert.doesNotMatch(v.message, /600/);
  });

  it('a 700 state directory is ok', () => {
    const v = classifyStateFile({
      path: '/home/orca/.orca-bridge',
      exists: true,
      uid: 997,
      gid: 997,
      mode: 0o040700,
      isDirectory: true,
      runningUid: 997,
    });
    assert.equal(v.code, STATE_OK);
  });

  it('group/world-readable secrets are flagged', () => {
    const v = classifyStateFile({
      path: '/x/tokens.json',
      exists: true,
      uid: 997,
      gid: 997,
      mode: 0o100644,
      runningUid: 997,
    });
    assert.equal(v.code, STATE_LOOSE_MODE);
    assert.match(v.message, /chmod 600/);
  });
});

// ---------------------------------------------------------------------------
// inspectStateFile / stateOwnershipWarnings — against a real temp dir
// ---------------------------------------------------------------------------

describe('inspectStateFile', () => {
  it('reports missing paths as ok', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-state-'));
    const v = inspectStateFile(path.join(dir, 'nope.json'));
    assert.equal(v.code, STATE_MISSING);
    assert.equal(v.ok, true);
  });

  it('accepts a freshly written 600 file owned by this process', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-state-'));
    const p = path.join(dir, 'tokens.json');
    fs.writeFileSync(p, '[]', { mode: STATE_FILE_MODE });
    const v = inspectStateFile(p);
    assert.equal(v.code, STATE_OK, v.message || '');
  });

  it('stateOwnershipWarnings is empty for healthy paths and skips falsy entries', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-state-'));
    const p = path.join(dir, 'pins.json');
    fs.writeFileSync(p, '{}', { mode: STATE_FILE_MODE });
    assert.deepEqual(stateOwnershipWarnings([p, '', null, path.join(dir, 'absent.json')]), []);
  });

  it('surfaces a message per unhealthy path (simulated root-owned store)', () => {
    const fake = {
      statSync: () => ({ uid: 0, gid: 0, mode: 0o100600 }),
      accessSync: () => {
        throw new Error('EACCES');
      },
    };
    const warnings = stateOwnershipWarnings(['/home/orca/.orca-bridge-tokens.json'], {
      fsImpl: fake,
      getuid: () => 997,
    });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /\.orca-bridge-tokens\.json/);
  });
});

// ---------------------------------------------------------------------------
// writeFilePreservingOwner
// ---------------------------------------------------------------------------

describe('writeFilePreservingOwner', () => {
  it('writes with mode 600 and does not chown when not root', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-state-'));
    const p = path.join(dir, 'tokens.json');
    const res = writeFilePreservingOwner(p, '["a"]', { getuid: () => 997 });
    assert.equal(res.ownerRestored, false);
    assert.equal(res.chownError, null);
    assert.equal(fs.readFileSync(p, 'utf8'), '["a"]');
    assert.equal(fs.statSync(p).mode & 0o777, 0o600);
  });

  it('restores the previous owner when running as root over a service-user file', () => {
    const chowns = [];
    const fake = {
      statSync: () => ({ uid: 997, gid: 997, mode: 0o100600 }),
      writeFileSync: () => {},
      chownSync: (f, uid, gid) => chowns.push([f, uid, gid]),
    };
    const res = writeFilePreservingOwner('/home/orca/.orca-bridge-tokens.json', '[]', {
      fsImpl: fake,
      getuid: () => 0,
    });
    assert.equal(res.ownerRestored, true);
    assert.deepEqual(res.previousOwner, { uid: 997, gid: 997 });
    assert.deepEqual(chowns, [['/home/orca/.orca-bridge-tokens.json', 997, 997]]);
  });

  it('does not chown a brand-new file created by root (no previous owner)', () => {
    let chowned = false;
    const fake = {
      statSync: () => {
        throw new Error('ENOENT');
      },
      writeFileSync: () => {},
      chownSync: () => {
        chowned = true;
      },
    };
    const res = writeFilePreservingOwner('/root/.orca-bridge-tokens.json', '[]', {
      fsImpl: fake,
      getuid: () => 0,
    });
    assert.equal(chowned, false);
    assert.equal(res.previousOwner, null);
  });

  it('reports a failed chown instead of throwing — data is already written', () => {
    const fake = {
      statSync: () => ({ uid: 997, gid: 997, mode: 0o100600 }),
      writeFileSync: () => {},
      chownSync: () => {
        throw new Error('EPERM');
      },
    };
    const res = writeFilePreservingOwner('/x/tokens.json', '[]', {
      fsImpl: fake,
      getuid: () => 0,
    });
    assert.equal(res.ownerRestored, false);
    assert.match(res.chownError, /EPERM/);
  });

  it('is a no-op wrapper when the file was already root-owned', () => {
    let chowned = false;
    const fake = {
      statSync: () => ({ uid: 0, gid: 0, mode: 0o100600 }),
      writeFileSync: () => {},
      chownSync: () => {
        chowned = true;
      },
    };
    const res = writeFilePreservingOwner('/root/state.json', '[]', {
      fsImpl: fake,
      getuid: () => 0,
    });
    assert.equal(chowned, false);
    assert.equal(res.ownerRestored, false);
  });
});
