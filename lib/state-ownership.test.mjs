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
  collectTerminalHandlesFromArgv,
  getTerminalHandle,
  listOwnedTerminalHandles,
  resolveTerminalHandleOwnership,
  normalizeDispatchId,
  collectDispatchIdsFromArgv,
  resolveDispatchOwnership,
  requireOwnedHandle,
  requireOwnedDispatch,
  redactTerminalListPayload,
  redactWorktreeListPayload,
  applyOwnershipListRedaction,
  redactTerminalListHumanStdout,
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


  it('collects every --terminal; getTerminalHandle is CLI last-wins', () => {
    // Orca CLI parseArgs last-wins for non-repeatable flags. Ownership gates
    // must still check every value via collectTerminalHandlesFromArgv.
    assert.deepEqual(
      collectTerminalHandlesFromArgv([
        'terminal',
        'read',
        '--terminal',
        'term_own',
        '--terminal',
        'term_foreign',
      ]),
      ['term_own', 'term_foreign'],
    );
    assert.equal(
      getTerminalHandle([
        'terminal',
        'read',
        '--terminal',
        'term_own',
        '--terminal',
        'term_foreign',
      ]),
      'term_foreign',
    );
    assert.deepEqual(
      collectTerminalHandlesFromArgv([
        'terminal',
        'read',
        '--terminal=term_own',
        '--terminal=term_foreign',
      ]),
      ['term_own', 'term_foreign'],
    );
    assert.equal(
      getTerminalHandle([
        'terminal',
        'read',
        '--terminal=term_own',
        '--terminal=term_foreign',
      ]),
      'term_foreign',
    );
    assert.deepEqual(
      collectTerminalHandlesFromArgv([
        'terminal',
        'read',
        '--terminal',
        'term_foreign',
        '--terminal',
        'term_own',
      ]),
      ['term_foreign', 'term_own'],
    );
    assert.equal(
      getTerminalHandle([
        'terminal',
        'read',
        '--terminal',
        'term_foreign',
        '--terminal',
        'term_own',
      ]),
      'term_own',
    );
    assert.deepEqual(
      collectTerminalHandlesFromArgv([
        'terminal',
        'read',
        '--terminal',
        'term_a',
        `--terminal=term_b`,
        '--terminal',
        'term_c',
      ]),
      ['term_a', 'term_b', 'term_c'],
    );
  });

  it('ignores positional handle tokens (CLI rejects that shape)', () => {
    assert.equal(
      getTerminalHandle(['terminal', 'read', 'term_positional', '--limit', '10']),
      null,
    );
  });

  it('normalizes empty / whitespace flag values to null', () => {
    assert.equal(getTerminalHandle(['terminal', 'read', '--terminal', '']), null);
    assert.equal(getTerminalHandle(['terminal', 'read', '--terminal', '   ']), null);
    assert.equal(getTerminalHandle(['terminal', 'read', '--terminal=']), null);
    assert.equal(getTerminalHandle(['terminal', 'read', '--terminal=  ']), null);
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


  it('wrong-prefix single-token handle is unknown when not registered', () => {
    const src = makeSources();
    // normalizeTerminalHandle does not require a term_ prefix; unregistered → unknown.
    const r = resolveTerminalHandleOwnership('not_a_term_handle', 'client-a', src);
    assert.equal(r.status, HANDLE_UNKNOWN);
    assert.equal(r.verdict, HANDLE_UNKNOWN);
    assert.equal(r.handle, 'not_a_term_handle');
    assert.equal(r.reason, 'handle_not_in_registry');
    assert.ok(r.owned_handles.includes('term_worker_a'));
  });

  it('valid handle belonging to a different client is not-owned', () => {
    const src = makeSources();
    const r = resolveTerminalHandleOwnership('term_worker_b', 'client-a', src);
    assert.equal(r.status, HANDLE_NOT_OWNED);
    assert.equal(r.reason, 'foreign_handle');
    assert.equal(r.handle, 'term_worker_b');
    assert.deepEqual(r.owned_handles, ['term_sender_a', 'term_worker_a']);
  });

  it('duplicate-flag: last-wins effective handle; every value still resolvable', () => {
    const src = makeSources();
    const argvOwnThenForeign = [
      'terminal',
      'read',
      '--terminal',
      'term_worker_a',
      '--terminal',
      'term_worker_b',
    ];
    const argvForeignThenOwn = [
      'terminal',
      'read',
      '--terminal',
      'term_worker_b',
      '--terminal',
      'term_worker_a',
    ];
    assert.deepEqual(collectTerminalHandlesFromArgv(argvOwnThenForeign), [
      'term_worker_a',
      'term_worker_b',
    ]);
    assert.equal(getTerminalHandle(argvOwnThenForeign), 'term_worker_b');
    assert.equal(getTerminalHandle(argvForeignThenOwn), 'term_worker_a');

    // Effective (last) handle ownership — what CLI would touch.
    assert.equal(
      resolveTerminalHandleOwnership(
        getTerminalHandle(argvOwnThenForeign),
        'client-a',
        src,
      ).status,
      HANDLE_NOT_OWNED,
    );
    assert.equal(
      resolveTerminalHandleOwnership(
        getTerminalHandle(argvForeignThenOwn),
        'client-a',
        src,
      ).status,
      HANDLE_OWNED,
    );

    // Deny-any: any collected foreign value is not-owned even if last is owned.
    const collected = collectTerminalHandlesFromArgv(argvForeignThenOwn);
    const statuses = collected.map(
      (h) => resolveTerminalHandleOwnership(h, 'client-a', src).status,
    );
    assert.deepEqual(statuses, [HANDLE_NOT_OWNED, HANDLE_OWNED]);
    assert.ok(statuses.some((s) => s !== HANDLE_OWNED));
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

// ---------------------------------------------------------------------------
// NAS-248 — dispatch ownership, release gate, list preview redaction
// ---------------------------------------------------------------------------

describe('collectDispatchIdsFromArgv', () => {
  it('collects every --dispatch / --dispatch= occurrence left-to-right', () => {
    assert.deepEqual(
      collectDispatchIdsFromArgv([
        'orchestration',
        'worker-read',
        '--dispatch',
        'ctx_a',
        '--dispatch',
        'ctx_b',
      ]),
      ['ctx_a', 'ctx_b'],
    );
    assert.deepEqual(
      collectDispatchIdsFromArgv([
        'orchestration',
        'worker-show',
        '--dispatch=ctx_x',
        '--source',
        'terminal',
      ]),
      ['ctx_x'],
    );
  });

  it('records null for bare / empty / flag-shaped values', () => {
    assert.deepEqual(
      collectDispatchIdsFromArgv(['orchestration', 'worker-read', '--dispatch']),
      [null],
    );
    assert.deepEqual(
      collectDispatchIdsFromArgv(['orchestration', 'worker-read', '--dispatch=']),
      [null],
    );
    assert.deepEqual(
      collectDispatchIdsFromArgv([
        'orchestration',
        'worker-read',
        '--dispatch',
        '--json',
      ]),
      [null],
    );
  });

  it('does not collect --terminal (no second extraction implementation)', () => {
    assert.deepEqual(
      collectDispatchIdsFromArgv([
        'terminal',
        'read',
        '--terminal',
        'term_x',
      ]),
      [],
    );
  });
});

describe('normalizeDispatchId', () => {
  it('trims; rejects empty / whitespace / multi-token', () => {
    assert.equal(normalizeDispatchId('  ctx_1  '), 'ctx_1');
    assert.equal(normalizeDispatchId(''), null);
    assert.equal(normalizeDispatchId('  '), null);
    assert.equal(normalizeDispatchId('ctx a'), null);
    assert.equal(normalizeDispatchId(null), null);
  });
});

describe('resolveDispatchOwnership', () => {
  function makeSources() {
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
    const senderCaches = new Map([
      ['client-a', { handle: 'term_sender_a', at: 1, source: 'created' }],
      ['client-b', { handle: 'term_sender_b', at: 1, source: 'created' }],
    ]);
    return { clientOwnership, dispatchRegistry, senderCaches };
  }

  it('owned: caller dispatch id', () => {
    const src = makeSources();
    const r = resolveDispatchOwnership('disp_a', 'client-a', src);
    assert.equal(r.status, HANDLE_OWNED);
    assert.equal(r.verdict, HANDLE_OWNED);
    assert.equal(r.dispatchId, 'disp_a');
    assert.ok(r.owned_dispatches.includes('disp_a'));
    assert.ok(r.owned_handles.includes('term_worker_a'));
  });

  it('not-owned: foreign dispatch id', () => {
    const src = makeSources();
    const r = resolveDispatchOwnership('disp_b', 'client-a', src);
    assert.equal(r.status, HANDLE_NOT_OWNED);
    assert.equal(r.reason, 'foreign_dispatch');
    assert.ok(!r.owned_dispatches.includes('disp_b'));
  });

  it('unknown: missing / ghost / no sources', () => {
    const src = makeSources();
    assert.equal(
      resolveDispatchOwnership('disp_ghost', 'client-a', src).status,
      HANDLE_UNKNOWN,
    );
    assert.equal(
      resolveDispatchOwnership('disp_ghost', 'client-a', src).reason,
      'dispatch_not_in_registry',
    );
    assert.equal(
      resolveDispatchOwnership('', 'client-a', src).reason,
      'missing_or_malformed_dispatch',
    );
    assert.equal(
      resolveDispatchOwnership('disp_x', 'client-a', {}).reason,
      'missing_registry',
    );
  });

  it('does not key on runtimeId — only clientKey + registry', () => {
    // Guard: resolver signature has no runtimeId parameter; passing one as
    // deps noise must not change the verdict.
    const src = makeSources();
    const a = resolveDispatchOwnership('disp_a', 'client-a', {
      ...src,
      runtimeId: 'runtime-changed-mid-session',
    });
    const b = resolveDispatchOwnership('disp_a', 'client-a', src);
    assert.equal(a.status, HANDLE_OWNED);
    assert.equal(b.status, HANDLE_OWNED);
    assert.deepEqual(a.owned_dispatches, b.owned_dispatches);
  });
});

describe('requireOwnedHandle / requireOwnedDispatch', () => {
  function makeSources() {
    return {
      senderCaches: new Map([
        ['client-a', { handle: 'term_sender_a', at: 1 }],
      ]),
      clientOwnership: new Map([
        [
          'client-a',
          {
            dispatches: new Set(['disp_a']),
            workerHandles: new Set(['term_worker_a']),
            boundSender: 'term_sender_a',
          },
        ],
        [
          'client-b',
          {
            dispatches: new Set(['disp_b']),
            workerHandles: new Set(['term_worker_b']),
          },
        ],
      ]),
      dispatchRegistry: {
        list() {
          return [
            { dispatchId: 'disp_a', clientKey: 'client-a', terminalHandle: 'term_worker_a' },
            { dispatchId: 'disp_b', clientKey: 'client-b', terminalHandle: 'term_worker_b' },
          ];
        },
      },
    };
  }

  it('requireOwnedHandle: positive own worker, negative foreign/unknown', () => {
    const src = makeSources();
    assert.equal(requireOwnedHandle('term_worker_a', 'client-a', src).ok, true);
    assert.equal(requireOwnedHandle('term_sender_a', 'client-a', src).ok, true);

    const foreign = requireOwnedHandle('term_worker_b', 'client-a', src);
    assert.equal(foreign.ok, false);
    assert.equal(foreign.ownership.status, HANDLE_NOT_OWNED);

    const unknown = requireOwnedHandle('term_ghost', 'client-a', src);
    assert.equal(unknown.ok, false);
    assert.equal(unknown.ownership.status, HANDLE_UNKNOWN);
  });

  it('requireOwnedHandle: always fail-closed (no soft mode for release)', () => {
    // Soft mode is a cli-policy knob only. requireOwnedHandle never allows
    // not-owned/unknown regardless of any env flag.
    const src = makeSources();
    assert.equal(requireOwnedHandle('term_worker_b', 'client-a', src).ok, false);
    assert.equal(requireOwnedHandle(null, 'client-a', src).ok, false);
  });

  it('requireOwnedDispatch: positive own, negative foreign', () => {
    const src = makeSources();
    assert.equal(requireOwnedDispatch('disp_a', 'client-a', src).ok, true);
    const foreign = requireOwnedDispatch('disp_b', 'client-a', src);
    assert.equal(foreign.ok, false);
    assert.equal(foreign.ownership.reason, 'foreign_dispatch');
  });

  it('bridge-restart posture: wiped clientOwnership → unknown fail-closed', () => {
    // After bridge process restart only sender pins survive. Worker handles
    // become unknown. Release must refuse rather than close foreign-or-ghost.
    const afterRestart = {
      senderCaches: new Map([
        ['client-a', { handle: 'term_sender_a', at: 1, source: 'persisted' }],
      ]),
      // clientOwnership + dispatchRegistry wiped
    };
    const r = requireOwnedHandle('term_worker_a', 'client-a', afterRestart);
    assert.equal(r.ok, false);
    assert.equal(r.ownership.status, HANDLE_UNKNOWN);
    // Pin still owned
    assert.equal(requireOwnedHandle('term_sender_a', 'client-a', afterRestart).ok, true);
  });
});

describe('redactTerminalListPayload', () => {
  const OWN = 'term_own';
  const FOREIGN = 'term_foreign';
  const payload = {
    ok: true,
    result: {
      terminals: [
        {
          handle: OWN,
          title: 'mine',
          preview: 'gh secret set NPM_TOKEN',
          connected: true,
        },
        {
          handle: FOREIGN,
          title: 'theirs',
          preview: 'paste secret here',
          connected: true,
        },
        {
          handle: 'term_other',
          title: 'no-preview-row',
          connected: false,
        },
      ],
    },
  };

  it('omits preview on non-owned rows; keeps row + owned preview', () => {
    const out = redactTerminalListPayload(payload, [OWN]);
    assert.notEqual(out, payload); // shallow copy
    const terms = out.result.terminals;
    assert.equal(terms.length, 3);
    assert.equal(terms[0].handle, OWN);
    assert.equal(terms[0].preview, 'gh secret set NPM_TOKEN');
    assert.equal(terms[1].handle, FOREIGN);
    assert.equal(Object.prototype.hasOwnProperty.call(terms[1], 'preview'), false);
    assert.equal(terms[1].title, 'theirs'); // inventory kept
    assert.equal(Object.prototype.hasOwnProperty.call(terms[2], 'preview'), false);
  });

  it('does not mutate the input payload', () => {
    const clone = JSON.parse(JSON.stringify(payload));
    redactTerminalListPayload(payload, [OWN]);
    assert.deepEqual(payload, clone);
  });

  it('handles bare terminals array and top-level terminals', () => {
    const arr = [
      { handle: OWN, preview: 'mine' },
      { handle: FOREIGN, preview: 'secret' },
    ];
    const outArr = redactTerminalListPayload(arr, new Set([OWN]));
    assert.equal(outArr[0].preview, 'mine');
    assert.equal(Object.prototype.hasOwnProperty.call(outArr[1], 'preview'), false);

    const top = {
      terminals: [{ handle: FOREIGN, preview: 'x', title: 't' }],
    };
    const outTop = redactTerminalListPayload(top, []);
    assert.equal(outTop.terminals[0].title, 't');
    assert.equal(Object.prototype.hasOwnProperty.call(outTop.terminals[0], 'preview'), false);
  });
});

describe('redactWorktreeListPayload', () => {
  it('omits preview on every worktree row', () => {
    const payload = {
      result: {
        worktrees: [
          { id: 'wt_1', path: '/a', preview: 'secret scrollback' },
          { id: 'wt_2', path: '/b' },
        ],
      },
    };
    const out = redactWorktreeListPayload(payload);
    assert.equal(out.result.worktrees[0].path, '/a');
    assert.equal(
      Object.prototype.hasOwnProperty.call(out.result.worktrees[0], 'preview'),
      false,
    );
    assert.equal(out.result.worktrees[1].id, 'wt_2');
  });
});


describe('applyOwnershipListRedaction shape-based (NAS-248 F2)', () => {
  const OWN = 'term_own';
  const FOREIGN = 'term_foreign';
  const terms = [
    { handle: OWN, title: 'mine', preview: 'gh secret set NPM_TOKEN' },
    { handle: FOREIGN, title: 'theirs', preview: 'paste secret here' },
  ];
  const envelope = {
    ok: true,
    result: { terminals: JSON.parse(JSON.stringify(terms)) },
  };

  const ARGV_SPELLINGS = [
    ['terminal', 'list'],
    ['terminal', 'list', '--json'],
    ['terminal', 'list', '--json=true'],
    ['terminal', 'list', '--json='],
    ['--json', 'terminal', 'list'],
    ['terminal', '--json', 'list'],
    ['TERMINAL', 'LIST', '--json'],
  ];

  for (const argv of ARGV_SPELLINGS) {
    it(`redacts envelope terminals regardless of argv ${JSON.stringify(argv)}`, () => {
      // argv is intentionally unused — redaction keys on shape only.
      const described = {
        ok: true,
        envelope: JSON.parse(JSON.stringify(envelope)),
      };
      applyOwnershipListRedaction(described, [OWN]);
      const out = described.envelope.result.terminals;
      assert.equal(out[0].preview, 'gh secret set NPM_TOKEN');
      assert.equal(Object.prototype.hasOwnProperty.call(out[1], 'preview'), false);
      assert.equal(out[1].title, 'theirs');
    });
  }

  it('redacts JSON stdout when envelope is missing (--json=true path)', () => {
    const payload = {
      ok: true,
      result: { terminals: JSON.parse(JSON.stringify(terms)) },
    };
    const described = {
      ok: true,
      stdout: JSON.stringify(payload),
      envelopeMissing: true,
    };
    applyOwnershipListRedaction(described, [OWN]);
    const parsed = JSON.parse(described.stdout);
    assert.equal(parsed.result.terminals[0].preview, 'gh secret set NPM_TOKEN');
    assert.equal(
      Object.prototype.hasOwnProperty.call(parsed.result.terminals[1], 'preview'),
      false,
    );
  });

  it('redacts human terminal list stdout preview lines', () => {
    const human =
      `${OWN}  mine  connected  /wt/a\n` +
      `preview: gh secret set NPM_TOKEN\n\n` +
      `${FOREIGN}  theirs  connected  /wt/b\n` +
      `preview: paste secret here\n`;
    const described = { ok: true, stdout: human };
    applyOwnershipListRedaction(described, [OWN]);
    assert.match(described.stdout, /gh secret set NPM_TOKEN/);
    assert.match(described.stdout, /preview: <redacted>/);
    assert.equal(described.stdout.includes('paste secret here'), false);
  });

  it('redactTerminalListHumanStdout keeps owned preview only', () => {
    const human =
      `${OWN}  mine  connected  /a\npreview: OWN_SECRET\n\n` +
      `${FOREIGN}  theirs  connected  /b\npreview: FOREIGN_SECRET\n`;
    const out = redactTerminalListHumanStdout(human, [OWN]);
    assert.match(out, /OWN_SECRET/);
    assert.equal(out.includes('FOREIGN_SECRET'), false);
  });

  it('does not touch non-list payloads', () => {
    const described = {
      ok: true,
      envelope: { ok: true, result: { status: 'alive', version: '1' } },
      stdout: 'hello',
    };
    const before = JSON.stringify(described);
    applyOwnershipListRedaction(described, [OWN]);
    assert.equal(JSON.stringify(described), before);
  });
});

