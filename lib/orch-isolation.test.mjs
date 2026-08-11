import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveClientKey,
  senderTitleForClient,
  shouldUseSharedSenderPin,
  partitionMailbox,
  releaseRefusesCoordinator,
  senderPinPlan,
  shouldRunUseBeforeAwait,
  createSerialLockMap,
} from './orch-isolation.mjs';

function pick(obj, ...keys) {
  if (!obj || typeof obj !== 'object') return undefined;
  for (const k of keys) {
    if (obj[k] != null && obj[k] !== '') return obj[k];
  }
  return undefined;
}

describe('deriveClientKey', () => {
  it('prefers stored session client key', () => {
    assert.equal(
      deriveClientKey({
        authKind: 'bearer-oauth',
        bearer: 'obt_abc',
        sessionId: 'sid1',
        sessionClientKey: 'oauth:deadbeef',
      }),
      'oauth:deadbeef',
    );
  });

  it('hashes oauth bearer stably', () => {
    const a = deriveClientKey({ authKind: 'bearer-oauth', bearer: 'obt_same' });
    const b = deriveClientKey({ authKind: 'bearer-oauth', bearer: 'obt_same' });
    const c = deriveClientKey({ authKind: 'bearer-oauth', bearer: 'obt_other' });
    assert.equal(a, b);
    assert.notEqual(a, c);
    assert.match(a, /^oauth:[0-9a-f]{16}$/);
  });

  it('uses session when no bearer oauth', () => {
    const k = deriveClientKey({ authKind: 'session', sessionId: 'mcp-sess-1' });
    assert.match(k, /^sid:[0-9a-f]{16}$/);
  });

  it('master / path-token collapse to master without session', () => {
    assert.equal(deriveClientKey({ authKind: 'bearer-master' }), 'master');
    assert.equal(deriveClientKey({ authKind: 'path-token' }), 'master');
  });
});

describe('senderTitleForClient', () => {
  it('keeps base title for shared identities', () => {
    assert.equal(senderTitleForClient('orca-bridge-coordinator', 'master'), 'orca-bridge-coordinator');
    assert.equal(senderTitleForClient('orca-bridge-coordinator', 'anonymous'), 'orca-bridge-coordinator');
  });

  it('suffixes oauth/sid keys', () => {
    assert.equal(
      senderTitleForClient('orca-bridge-coordinator', 'oauth:abcdef0123456789'),
      'orca-bridge-coordinator-abcdef0123',
    );
  });
});

describe('shouldUseSharedSenderPin', () => {
  it('never without env pin', () => {
    assert.equal(shouldUseSharedSenderPin('oauth:x', { senderEnv: '', senderShared: true }), false);
  });

  it('shared flag forces pin for any client', () => {
    assert.equal(
      shouldUseSharedSenderPin('oauth:x', { senderEnv: 'term_1', senderShared: true }),
      true,
    );
  });

  it('without shared flag only master-like keys use pin', () => {
    assert.equal(
      shouldUseSharedSenderPin('master', { senderEnv: 'term_1', senderShared: false }),
      true,
    );
    assert.equal(
      shouldUseSharedSenderPin('oauth:x', { senderEnv: 'term_1', senderShared: false }),
      false,
    );
  });
});

describe('partitionMailbox', () => {
  const msgs = [
    { type: 'worker_done', dispatchId: 'd1', subject: 'mine' },
    { type: 'worker_done', dispatchId: 'd2', subject: 'theirs' },
    { type: 'question', payload: { dispatch_id: 'd1' } },
  ];

  it('fail-open when ownership empty', () => {
    const r = partitionMailbox(msgs, new Set(), pick);
    assert.equal(r.filtered, false);
    assert.equal(r.own.length, 3);
    assert.equal(r.foreign.length, 0);
  });

  it('splits foreign dispatch ids', () => {
    const r = partitionMailbox(msgs, new Set(['d1']), pick);
    assert.equal(r.filtered, true);
    assert.equal(r.own.length, 2);
    assert.equal(r.foreign.length, 1);
    assert.equal(r.foreign[0].subject, 'theirs');
  });
});

describe('releaseRefusesCoordinator', () => {
  it('refuses known coordinator handles', () => {
    const set = new Set(['term_coord']);
    assert.equal(releaseRefusesCoordinator('term_coord', set), true);
    assert.equal(releaseRefusesCoordinator('term_worker', set), false);
    assert.equal(releaseRefusesCoordinator('', set), false);
  });
});

describe('shouldRunUseBeforeAwait', () => {
  it('skips when same run and sender already bound', () => {
    assert.equal(
      shouldRunUseBeforeAwait({
        boundRunId: 'run_a',
        boundSender: 'term_1',
        runId: 'run_a',
        senderHandle: 'term_1',
      }),
      false,
    );
  });

  it('runs use when run changes or sender changes or unbound', () => {
    assert.equal(
      shouldRunUseBeforeAwait({
        boundRunId: 'run_a',
        boundSender: 'term_1',
        runId: 'run_b',
        senderHandle: 'term_1',
      }),
      true,
    );
    assert.equal(
      shouldRunUseBeforeAwait({
        boundRunId: 'run_a',
        boundSender: 'term_1',
        runId: 'run_a',
        senderHandle: 'term_2',
      }),
      true,
    );
    assert.equal(shouldRunUseBeforeAwait({ runId: 'run_a', senderHandle: 'term_1' }), true);
  });
});

describe('senderPinPlan', () => {
  it('resolves when no pin', () => {
    assert.equal(senderPinPlan(null).mode, 'resolve');
    assert.equal(senderPinPlan({ handle: '' }).mode, 'resolve');
  });

  it('trusts fresh cache without revalidate', () => {
    const plan = senderPinPlan(
      { handle: 'term_a', at: 1_000, source: 'created' },
      { now: 1_000 + 5_000, ttlMs: 15_000 },
    );
    assert.equal(plan.mode, 'trust_cache');
    assert.equal(plan.handle, 'term_a');
  });

  it('revalidates same handle after TTL (does not resolve/create)', () => {
    const plan = senderPinPlan(
      { handle: 'term_a', at: 1_000, source: 'created' },
      { now: 1_000 + 60_000, ttlMs: 15_000 },
    );
    assert.equal(plan.mode, 'revalidate_pin');
    assert.equal(plan.handle, 'term_a');
  });

  it('force still revalidates pin rather than blind resolve', () => {
    const plan = senderPinPlan(
      { handle: 'term_a', at: Date.now(), source: 'created' },
      { force: true },
    );
    assert.equal(plan.mode, 'revalidate_pin');
  });
});

describe('createSerialLockMap', () => {
  it('serializes same key', async () => {
    const lock = createSerialLockMap();
    const order = [];
    await Promise.all([
      lock('a', async () => {
        order.push('a1-start');
        await new Promise((r) => setTimeout(r, 30));
        order.push('a1-end');
      }),
      lock('a', async () => {
        order.push('a2-start');
        order.push('a2-end');
      }),
    ]);
    assert.deepEqual(order, ['a1-start', 'a1-end', 'a2-start', 'a2-end']);
  });

  it('allows different keys to interleave', async () => {
    const lock = createSerialLockMap();
    const order = [];
    await Promise.all([
      lock('a', async () => {
        order.push('a-start');
        await new Promise((r) => setTimeout(r, 40));
        order.push('a-end');
      }),
      lock('b', async () => {
        order.push('b');
      }),
    ]);
    assert.ok(order.indexOf('b') < order.indexOf('a-end'));
    assert.ok(order.includes('a-start'));
  });
});
