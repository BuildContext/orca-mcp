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
