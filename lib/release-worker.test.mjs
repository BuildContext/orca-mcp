import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  preflightReleaseOwnership,
  releaseOwnershipDenial,
  executeReleaseWorker,
} from './release-worker.mjs';
import { releaseRefusesCoordinator } from './orch-isolation.mjs';

const OWN_D = 'disp_own';
const FOREIGN_D = 'disp_foreign';
const OWN_H = 'term_own_aaaaaaaa';
const FOREIGN_H = 'term_foreign_bbbbbbbb';
const SENDER = 'term_sender_cccccccc';

function ownershipDeps() {
  return {
    senderCaches: new Map([['alice', { handle: SENDER, at: 1 }]]),
    clientOwnership: new Map([
      [
        'alice',
        {
          dispatches: new Set([OWN_D]),
          workerHandles: new Set([OWN_H]),
          boundSender: SENDER,
        },
      ],
      [
        'bob',
        {
          dispatches: new Set([FOREIGN_D]),
          workerHandles: new Set([FOREIGN_H]),
        },
      ],
    ]),
    dispatchRegistry: {
      list() {
        return [
          { dispatchId: OWN_D, clientKey: 'alice', terminalHandle: OWN_H },
          { dispatchId: FOREIGN_D, clientKey: 'bob', terminalHandle: FOREIGN_H },
        ];
      },
      upsert() {},
    },
    coordinatorHandles: new Set([SENDER]),
  };
}

function pick(obj, ...keys) {
  if (!obj || typeof obj !== 'object') return undefined;
  for (const k of keys) {
    if (obj[k] != null && obj[k] !== '') return obj[k];
  }
  return undefined;
}

function envOk(described) {
  return described && described.ok === true && described.envelope;
}

describe('preflightReleaseOwnership', () => {
  it('denies foreign dispatch before any effect', () => {
    const pre = preflightReleaseOwnership(
      { dispatchId: FOREIGN_D, handle: null },
      'alice',
      ownershipDeps(),
    );
    assert.equal(pre.ok, false);
    assert.equal(pre.kind, 'dispatch');
    const denial = releaseOwnershipDenial(pre);
    assert.equal(denial.ok, false);
    assert.equal(denial.code, 'handle_not_owned');
    assert.equal(denial.ownership_kind, 'dispatch');
  });

  it('allows owned dispatch + handle', () => {
    const pre = preflightReleaseOwnership(
      { dispatchId: OWN_D, handle: OWN_H },
      'alice',
      ownershipDeps(),
    );
    assert.equal(pre.ok, true);
  });

  it('denies foreign handle even with owned dispatch', () => {
    const pre = preflightReleaseOwnership(
      { dispatchId: OWN_D, handle: FOREIGN_H },
      'alice',
      ownershipDeps(),
    );
    assert.equal(pre.ok, false);
    assert.equal(pre.kind, 'handle');
  });
});

describe('executeReleaseWorker effect ordering (NAS-248 F1 / NAS-202)', () => {
  it('foreign dispatchId never reaches worker-release or close', async () => {
    const calls = [];
    const result = await executeReleaseWorker(
      { dispatch_id: FOREIGN_D },
      {
        clientKey: 'alice',
        ownershipDeps: ownershipDeps(),
        runJson: async (argv) => {
          calls.push([...argv]);
          return {
            ok: true,
            envelope: { ok: true, result: { released: true } },
          };
        },
        envOk,
        pick,
        releaseRefusesCoordinator,
        coordinatorHandles: new Set([SENDER]),
        upsertDispatch: () => {
          throw new Error('upsert must not run on deny');
        },
      },
    );
    assert.equal(result.ok, false);
    assert.equal(result.mode, 'ownership_denied');
    assert.equal(result.code, 'handle_not_owned');
    assert.equal(result.dispatch_id, FOREIGN_D);
    assert.deepEqual(calls, [], 'no runJson effects before/without gate');
  });

  it('foreign handleHint never reaches close', async () => {
    const calls = [];
    const result = await executeReleaseWorker(
      { terminal_handle: FOREIGN_H },
      {
        clientKey: 'alice',
        ownershipDeps: ownershipDeps(),
        runJson: async (argv) => {
          calls.push([...argv]);
          return { ok: true, envelope: { ok: true, result: {} } };
        },
        envOk,
        pick,
        releaseRefusesCoordinator,
        coordinatorHandles: new Set([SENDER]),
      },
    );
    assert.equal(result.ok, false);
    assert.equal(result.mode, 'ownership_denied');
    assert.equal(result.terminal_handle, FOREIGN_H);
    assert.deepEqual(calls, []);
  });

  it('owned dispatch may call worker-release after gate', async () => {
    const calls = [];
    const result = await executeReleaseWorker(
      { dispatch_id: OWN_D, terminal_handle: OWN_H },
      {
        clientKey: 'alice',
        ownershipDeps: ownershipDeps(),
        runJson: async (argv) => {
          calls.push(argv.join(' '));
          if (argv[1] === 'worker-release') {
            return {
              ok: true,
              envelope: { ok: true, result: { released: true } },
            };
          }
          return { ok: false, envelope: { ok: false } };
        },
        envOk,
        pick,
        releaseRefusesCoordinator,
        coordinatorHandles: new Set([SENDER]),
        upsertDispatch: () => {},
      },
    );
    assert.equal(result.ok, true);
    assert.equal(result.mode, 'worker-release');
    assert.ok(calls[0].includes('worker-release'));
    assert.ok(calls[0].includes(OWN_D));
    assert.equal(calls.length, 1, 'no lookup/close when worker-release succeeds');
  });

  it('owned handle close-fallback after worker-release miss still works', async () => {
    const calls = [];
    const result = await executeReleaseWorker(
      { dispatch_id: OWN_D, terminal_handle: OWN_H },
      {
        clientKey: 'alice',
        ownershipDeps: ownershipDeps(),
        runJson: async (argv) => {
          calls.push(argv.join(' '));
          if (argv[1] === 'worker-release') {
            return {
              ok: false,
              envelope: {
                ok: false,
                error: { code: 'dispatch_not_found' },
              },
            };
          }
          if (argv[0] === 'terminal' && argv[1] === 'close') {
            return { ok: true, envelope: { ok: true, result: { closed: true } } };
          }
          return { ok: false, envelope: { ok: false } };
        },
        envOk,
        pick,
        releaseRefusesCoordinator,
        coordinatorHandles: new Set([SENDER]),
        upsertDispatch: () => {},
      },
    );
    assert.equal(result.ok, true);
    assert.equal(result.mode, 'terminal-close');
    assert.ok(calls.some((c) => c.includes('worker-release')));
    assert.ok(calls.some((c) => c.includes('terminal close')));
  });

  it('unknown dispatch after bridge wipe fails closed with zero effects', async () => {
    const calls = [];
    const result = await executeReleaseWorker(
      { dispatch_id: OWN_D },
      {
        clientKey: 'alice',
        ownershipDeps: {
          // wiped maps — unknown
          senderCaches: new Map([['alice', { handle: SENDER, at: 1 }]]),
        },
        runJson: async (argv) => {
          calls.push([...argv]);
          return { ok: true, envelope: { ok: true, result: {} } };
        },
        envOk,
        pick,
        releaseRefusesCoordinator,
        coordinatorHandles: new Set([SENDER]),
      },
    );
    assert.equal(result.ok, false);
    assert.equal(result.mode, 'ownership_denied');
    assert.deepEqual(calls, []);
  });
});

describe('NAS-248 P0 #4 claim-path: empty ownership + await-shaped upsert', () => {
  it('empty owned set + claim upsert does not make requireOwnedDispatch owned; release refused', async () => {
    // Drive the real path the second review reproduced:
    // 1. bob owns disp_bob in the registry
    // 2. alice has empty clientOwnership.dispatches (restart / first await)
    // 3. partitionMailbox must fail-closed (no "own" foreign worker_done)
    // 4. even if an await-shaped upsert tries clientKey:alice, registry refuses
    // 5. requireOwnedDispatch still not-owned
    // 6. executeReleaseWorker never calls worker-release
    const { createDispatchRegistry } = await import('./audit.mjs');
    const { partitionMailbox } = await import('./orch-isolation.mjs');
    const { requireOwnedDispatch } = await import('./state-ownership.mjs');

    const registry = createDispatchRegistry();
    assert.equal(
      registry.bindOwner('disp_bob', {
        clientKey: 'bob',
        terminalHandle: 'term_foreign_bbbbbbbb',
        status: 'running',
        runId: 'run_shared',
      }).ok,
      true,
    );

    const aliceOwned = new Set(); // empty — restart posture
    const mailbox = [
      {
        type: 'worker_done',
        dispatchId: 'disp_bob',
        payload: { dispatchId: 'disp_bob', outcome: 'succeeded' },
      },
    ];
    const part = partitionMailbox(mailbox, aliceOwned, pick);
    assert.equal(part.own.length, 0, 'empty owned must not treat foreign as own');
    assert.equal(part.foreign.length, 1);
    assert.equal(part.filtered, true);

    // Simulate the old await claim write against the registry.
    for (const m of part.own) {
      registry.upsert(m.dispatchId, {
        status: 'worker_done',
        clientKey: 'alice',
        runId: 'run_shared',
      });
    }
    // Defense in depth: even a direct claim upsert must not stick.
    registry.upsert('disp_bob', {
      status: 'worker_done',
      clientKey: 'alice',
      runId: 'run_shared',
    });

    assert.equal(registry.get('disp_bob').clientKey, 'bob', 'owner unchanged');

    const deps = {
      dispatchRegistry: registry,
      clientOwnership: new Map([
        // alice empty dispatches — the fail-open precondition
        ['alice', { dispatches: new Set(), workerHandles: new Set(), runs: new Set() }],
        [
          'bob',
          {
            dispatches: new Set(['disp_bob']),
            workerHandles: new Set(['term_foreign_bbbbbbbb']),
            runs: new Set(['run_shared']),
          },
        ],
      ]),
      senderCaches: new Map([
        ['alice', { handle: SENDER, at: 1 }],
        ['bob', { handle: 'term_bob_sender', at: 1 }],
      ]),
    };

    const gate = requireOwnedDispatch('disp_bob', 'alice', deps);
    assert.equal(gate.ok, false);
    assert.ok(
      gate.ownership.status === 'not-owned' || gate.ownership.status === 'unknown',
      `expected not-owned/unknown, got ${gate.ownership.status}`,
    );

    const calls = [];
    const result = await executeReleaseWorker(
      { dispatch_id: 'disp_bob' },
      {
        clientKey: 'alice',
        ownershipDeps: deps,
        runJson: async (argv) => {
          calls.push([...argv]);
          return { ok: true, envelope: { ok: true, result: { released: true } } };
        },
        envOk,
        pick,
        releaseRefusesCoordinator,
        coordinatorHandles: new Set([SENDER]),
        upsertDispatch: (id, row) => registry.upsert(id, row),
      },
    );
    assert.equal(result.ok, false);
    assert.equal(result.mode, 'ownership_denied');
    assert.deepEqual(calls, [], 'release must not fire after failed claim');
    assert.equal(registry.get('disp_bob').clientKey, 'bob');
  });

  it('legitimate owner can still release after durable hydrate (restart)', async () => {
    // Simulate: dispatch bound + persisted, process "restarts" into fresh maps
    // hydrated only from listOwnershipBindings snapshot (no runtimeId).
    const { createDispatchRegistry } = await import('./audit.mjs');
    const { requireOwnedDispatch } = await import('./state-ownership.mjs');

    const live = createDispatchRegistry();
    assert.equal(
      live.bindOwner(OWN_D, {
        clientKey: 'alice',
        terminalHandle: OWN_H,
        status: 'worker_done',
        runId: 'run_1',
      }).ok,
      true,
    );
    const snapshot = live.listOwnershipBindings();
    assert.equal(snapshot.length, 1);

    // Fresh process maps.
    const restored = createDispatchRegistry();
    const clientOwnership = new Map();
    for (const b of snapshot) {
      const r = restored.bindOwner(b.dispatchId, { ...b });
      assert.equal(r.ok, true);
      let reg = clientOwnership.get(b.clientKey);
      if (!reg) {
        reg = { dispatches: new Set(), workerHandles: new Set(), runs: new Set() };
        clientOwnership.set(b.clientKey, reg);
      }
      reg.dispatches.add(b.dispatchId);
      if (b.terminalHandle) reg.workerHandles.add(b.terminalHandle);
      if (b.runId) reg.runs.add(b.runId);
    }

    const deps = {
      dispatchRegistry: restored,
      clientOwnership,
      senderCaches: new Map([['alice', { handle: SENDER, at: 1, source: 'persisted' }]]),
      // runtimeId deliberately absent / noise — must not be required
      runtimeId: 'runtime_after_restart_zzzz',
    };

    const gate = requireOwnedDispatch(OWN_D, 'alice', deps);
    assert.equal(gate.ok, true, 'hydrated owner must still own');

    const calls = [];
    const result = await executeReleaseWorker(
      { dispatch_id: OWN_D, terminal_handle: OWN_H },
      {
        clientKey: 'alice',
        ownershipDeps: deps,
        runJson: async (argv) => {
          calls.push(argv.join(' '));
          if (argv[1] === 'worker-release') {
            return { ok: true, envelope: { ok: true, result: { released: true } } };
          }
          return { ok: false, envelope: { ok: false } };
        },
        envOk,
        pick,
        releaseRefusesCoordinator,
        coordinatorHandles: new Set([SENDER]),
        upsertDispatch: (id, row) => restored.upsert(id, row),
      },
    );
    assert.equal(result.ok, true);
    assert.equal(result.mode, 'worker-release');
    assert.ok(calls.some((c) => c.includes('worker-release') && c.includes(OWN_D)));
    // Status write must not clear owner.
    assert.equal(restored.get(OWN_D).clientKey, 'alice');
  });

  it('empty store with no hydrate still fail-closes release (availability tradeoff if persist missing)', async () => {
    const calls = [];
    const result = await executeReleaseWorker(
      { dispatch_id: OWN_D },
      {
        clientKey: 'alice',
        ownershipDeps: {
          senderCaches: new Map([['alice', { handle: SENDER, at: 1 }]]),
          clientOwnership: new Map(),
          dispatchRegistry: {
            list() {
              return [];
            },
          },
        },
        runJson: async (argv) => {
          calls.push([...argv]);
          return { ok: true, envelope: { ok: true, result: {} } };
        },
        envOk,
        pick,
        releaseRefusesCoordinator,
        coordinatorHandles: new Set([SENDER]),
      },
    );
    assert.equal(result.ok, false);
    assert.equal(result.mode, 'ownership_denied');
    assert.deepEqual(calls, []);
  });
});

