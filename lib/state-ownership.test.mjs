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
  HANDLE_OWNED,
  HANDLE_NOT_OWNED,
  HANDLE_UNKNOWN,
  normalizeTerminalHandle,
  getTerminalHandle,
  listOwnedTerminalHandles,
  resolveTerminalHandleOwnership,
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
    assert.deepEqual(res.previousOwner, { uid: 997, gid: 997, from: 'file' });
    assert.deepEqual(chowns, [['/home/orca/.orca-bridge-tokens.json', 997, 997]]);
  });

  it('a brand-new file created by root inherits the home directory owner', () => {
    const chowns = [];
    const fake = {
      statSync: (p) => {
        if (p.endsWith('.orca-bridge-tokens.json')) throw new Error('ENOENT');
        return { uid: 997, gid: 997, mode: 0o040700 }; // /home/orca
      },
      writeFileSync: () => {},
      chownSync: (f, uid, gid) => chowns.push([f, uid, gid]),
    };
    const res = writeFilePreservingOwner('/home/orca/.orca-bridge-tokens.json', '[]', {
      fsImpl: fake,
      getuid: () => 0,
    });
    assert.equal(res.ownerRestored, true);
    assert.equal(res.previousOwner.from, 'directory');
    assert.deepEqual(chowns, [['/home/orca/.orca-bridge-tokens.json', 997, 997]]);
  });

  it('does not chown when neither the file nor its directory can be stat-ed', () => {
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
    const res = writeFilePreservingOwner('/nowhere/tokens.json', '[]', {
      fsImpl: fake,
      getuid: () => 0,
    });
    assert.equal(chowned, false);
    assert.equal(res.previousOwner, null);
  });

  it('root writing into root-owned HOME stays root (no pointless chown)', () => {
    let chowned = false;
    const fake = {
      statSync: () => ({ uid: 0, gid: 0, mode: 0o040700 }),
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
    assert.equal(res.ownerRestored, false);
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

  it('repairs an already root-owned store sitting in the service account HOME', () => {
    // The NAS-241 end state: a root migration replaced the inode, so the file
    // itself is root:root — the home directory is the only owner signal left.
    const chowns = [];
    const fake = {
      statSync: (p) => (String(p).endsWith('.orca-bridge-tokens.json')
        ? { uid: 0, gid: 0, mode: 0o100600 }
        : { uid: 997, gid: 997, mode: 0o040700 }),
      writeFileSync: () => {},
      chownSync: (f, uid, gid) => chowns.push([f, uid, gid]),
    };
    const res = writeFilePreservingOwner('/home/orca/.orca-bridge-tokens.json', '[]', {
      fsImpl: fake,
      getuid: () => 0,
    });
    assert.equal(res.ownerRestored, true);
    assert.equal(res.previousOwner.from, 'directory (file was root-owned)');
    assert.deepEqual(chowns, [['/home/orca/.orca-bridge-tokens.json', 997, 997]]);
  });

  it('leaves a root-owned file in a root-owned home alone', () => {
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


// ---------------------------------------------------------------------------
// Terminal handle ownership (NAS-247)
// ---------------------------------------------------------------------------

describe('normalizeTerminalHandle / getTerminalHandle', () => {
  it('trims and rejects empty / whitespace handles', () => {
    assert.equal(normalizeTerminalHandle('  term_a  '), 'term_a');
    assert.equal(normalizeTerminalHandle(''), null);
    assert.equal(normalizeTerminalHandle('   '), null);
    assert.equal(normalizeTerminalHandle('term a'), null);
    assert.equal(normalizeTerminalHandle(null), null);
  });

  it('extracts --terminal from argv', () => {
    assert.equal(
      getTerminalHandle(['terminal', 'read', '--terminal', 'term_1', '--limit', '10']),
      'term_1',
    );
    assert.equal(
      getTerminalHandle(['terminal', 'close', '--terminal=term_2', '--tab']),
      'term_2',
    );
    assert.equal(getTerminalHandle(['terminal', 'list']), null);
    assert.equal(getTerminalHandle(['terminal', 'read', '--terminal']), null);
    assert.equal(getTerminalHandle(null), null);
  });
});

describe('resolveTerminalHandleOwnership', () => {
  function makeSources() {
    const senderCaches = new Map([
      ['client-a', { handle: 'term_sender_a', at: 1, source: 'created' }],
      ['client-b', { handle: 'term_sender_b', at: 1, source: 'created' }],
    ]);
    const clientOwnership = new Map([
      [
        'client-a',
        {
          runs: new Set(['run_a']),
          dispatches: new Set(['disp_a']),
          workerHandles: new Set(['term_worker_a']),
          boundRunId: 'run_a',
          boundSender: 'term_sender_a',
        },
      ],
      [
        'client-b',
        {
          runs: new Set(['run_b']),
          dispatches: new Set(['disp_b']),
          workerHandles: new Set(['term_worker_b']),
          boundRunId: 'run_b',
          boundSender: 'term_sender_b',
        },
      ],
    ]);
    const dispatchRegistry = {
      list({ clientKey } = {}) {
        const all = [
          { dispatchId: 'disp_a', clientKey: 'client-a', terminalHandle: 'term_worker_a' },
          { dispatchId: 'disp_b', clientKey: 'client-b', terminalHandle: 'term_worker_b' },
        ];
        if (clientKey) return all.filter((d) => d.clientKey === clientKey);
        return all;
      },
    };
    return { senderCaches, clientOwnership, dispatchRegistry };
  }

  it('owned: caller pin + worker handle', () => {
    const src = makeSources();
    const pin = resolveTerminalHandleOwnership('term_sender_a', 'client-a', src);
    assert.equal(pin.status, HANDLE_OWNED);
    assert.equal(pin.verdict, HANDLE_OWNED);
    assert.equal(pin.handle, 'term_sender_a');
    assert.ok(pin.owned_handles.includes('term_sender_a'));
    assert.ok(pin.owned_handles.includes('term_worker_a'));

    const worker = resolveTerminalHandleOwnership('term_worker_a', 'client-a', src);
    assert.equal(worker.status, HANDLE_OWNED);
    assert.deepEqual(worker.ownedHandles, worker.owned_handles);
  });

  it('not-owned: foreign worker / foreign sender', () => {
    const src = makeSources();
    const r = resolveTerminalHandleOwnership('term_worker_b', 'client-a', src);
    assert.equal(r.status, HANDLE_NOT_OWNED);
    assert.equal(r.reason, 'foreign_handle');
    assert.ok(r.owned_handles.includes('term_worker_a'));
    assert.ok(!r.owned_handles.includes('term_worker_b'));

    const s = resolveTerminalHandleOwnership('term_sender_b', 'client-a', src);
    assert.equal(s.status, HANDLE_NOT_OWNED);
  });

  it('unknown: handle not in any store', () => {
    const src = makeSources();
    const r = resolveTerminalHandleOwnership('term_ghost', 'client-a', src);
    assert.equal(r.status, HANDLE_UNKNOWN);
    assert.equal(r.reason, 'handle_not_in_registry');
  });

  it('unknown: missing registry / no sources', () => {
    const r = resolveTerminalHandleOwnership('term_x', 'client-a', {});
    assert.equal(r.status, HANDLE_UNKNOWN);
    assert.equal(r.reason, 'missing_registry');
    assert.deepEqual(r.owned_handles, []);
  });

  it('unknown: malformed / missing handle', () => {
    const src = makeSources();
    assert.equal(resolveTerminalHandleOwnership('', 'client-a', src).status, HANDLE_UNKNOWN);
    assert.equal(resolveTerminalHandleOwnership('  ', 'client-a', src).status, HANDLE_UNKNOWN);
    assert.equal(resolveTerminalHandleOwnership('term x', 'client-a', src).status, HANDLE_UNKNOWN);
    assert.equal(resolveTerminalHandleOwnership(null, 'client-a', src).reason, 'missing_or_malformed_handle');
  });

  it('listOwnedTerminalHandles unions pin + workers', () => {
    const src = makeSources();
    const owned = listOwnedTerminalHandles('client-a', src);
    assert.deepEqual(owned, ['term_sender_a', 'term_worker_a']);
  });

  it('accepts plain object maps (not only Map)', () => {
    const r = resolveTerminalHandleOwnership('term_s', 'ck', {
      senderCaches: { ck: { handle: 'term_s' } },
      clientOwnership: {
        ck: { workerHandles: new Set(['term_w']), boundSender: 'term_s' },
      },
    });
    assert.equal(r.status, HANDLE_OWNED);
    assert.ok(r.owned_handles.includes('term_w'));
  });
});
