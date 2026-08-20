/**
 * NAS-271 lifecycle: ack must consume a delivery; await windows must
 * release on client abort; waitMs hard max must not trap ~60s clients.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import {
  CHECK_WAIT_DEFAULT_MS,
  CHECK_WAIT_MAX_MS,
  clampWaitMs,
} from './security-core.mjs';
import { PREFERRED_WAIT_MS, WAIT_MS_HARD_MAX } from './coordinator-doctrine.mjs';
import { createSerialLockMap } from './orch-isolation.mjs';
import {
  planAwaitBindAndAck,
  planAckWaitCalls,
  decideStaleAckAction,
  withAbortableLock,
  bindHttpRequestAbort,
  AWAIT_WINDOW_ABORTED,
} from './await-lifecycle.mjs';

const WORKER_DONE = {
  type: 'worker_done',
  body: 'Wrote the isolation harden and left gitdir sticky.',
  payload: { outcome: 'succeeded', dispatchId: 'ctx_e686' },
};

function createFakeMailbox(initialPayload) {
  let generation = 1;
  let seq = 176;
  const queue = [];
  const acked = new Set();

  function push(payload) {
    seq += 1;
    const row = {
      deliveryId: `delivery_${seq.toString(16)}`,
      messageId: `msg_${seq.toString(16)}`,
      sequence: seq,
      payload,
      generation,
    };
    queue.push(row);
    return row;
  }

  if (initialPayload) push(initialPayload);

  return {
    push,
    runUse() {
      generation += 1;
      for (const row of queue) {
        if (acked.has(row.deliveryId)) continue;
        seq += 1;
        row.deliveryId = `delivery_${seq.toString(16)}`;
        row.messageId = `msg_${seq.toString(16)}`;
        row.sequence = seq;
        row.generation = generation;
      }
    },
    check({ ack = null, waitMs = 0 } = {}) {
      if (ack) {
        const row = queue.find((r) => r.deliveryId === ack);
        if (!row || row.generation !== generation || acked.has(ack)) {
          return {
            stale: true,
            hint: 'delivery_not_in_run_or_wrong_generation',
            error: { code: 'stale_delivery' },
            count: 0,
            deliveryId: null,
            messages: [],
          };
        }
        acked.add(ack);
        queue.splice(queue.indexOf(row), 1);
        if (!waitMs) {
          return { timedOut: false, deliveryId: null, messages: [], count: 0 };
        }
      }
      if (queue.length) {
        const row = queue[0];
        return {
          timedOut: false,
          deliveryId: row.deliveryId,
          messages: [row],
          count: 1,
        };
      }
      return { timedOut: true, deliveryId: null, messages: [], count: 0 };
    },
  };
}

function runAwaitWindow(mailbox, { bound, ack, waitMs }) {
  const plan = planAwaitBindAndAck({ bound, ack });
  if (plan.runUse) mailbox.runUse();
  let result;
  for (const call of planAckWaitCalls({ ack: plan.ack, waitMs })) {
    result = mailbox.check(call);
    if (result.stale && call.ack) {
      const action = decideStaleAckAction({
        ackId: call.ack,
        staleHint: result.hint,
      });
      if (action === 'idempotent') {
        result = { timedOut: false, deliveryId: null, messages: [], count: 0 };
        continue;
      }
      if (action === 'retry_without_ack') {
        result = mailbox.check({ ack: null, waitMs: call.waitMs });
      }
    }
  }
  return result;
}

describe('NAS-271 bug 3: ack consumes delivery', () => {
  it('acked worker_done is not reopened under a new id', () => {
    const box = createFakeMailbox(WORKER_DONE);
    const first = box.check({ ack: null, waitMs: 1_000 });
    assert.equal(first.count, 1);
    assert.equal(first.messages[0].payload.body, WORKER_DONE.body);
    const deliveryId = first.deliveryId;
    const sequence = first.messages[0].sequence;

    // Live bug: unbound pin (lost in-memory bind / first-bind) drops ack,
    // run-use bumps consumer_generation, check without ack reopens the same
    // worker_done under a new message id + sequence.
    const second = runAwaitWindow(box, {
      bound: false,
      ack: deliveryId,
      waitMs: 1_000,
    });

    const reopened = (second.messages || []).find(
      (m) => m.payload?.body === WORKER_DONE.body && m.deliveryId !== deliveryId,
    );
    assert.equal(
      second.count,
      0,
      `acked delivery must leave the queue, not reopen (got count=${second.count} deliveryId=${second.deliveryId} seq=${second.messages?.[0]?.sequence} prior=${deliveryId}/${sequence})`,
    );
    assert.equal(
      reopened,
      undefined,
      `acked worker_done reopened under ${reopened?.messageId} seq ${reopened?.sequence} (was ${deliveryId} seq ${sequence})`,
    );
  });

  it('repeat ack of the same deliveryId is idempotent', () => {
    const box = createFakeMailbox(WORKER_DONE);
    const first = box.check({ ack: null, waitMs: 0 });
    const once = runAwaitWindow(box, {
      bound: true,
      ack: first.deliveryId,
      waitMs: 0,
    });
    assert.equal(once.error, undefined);
    const twice = runAwaitWindow(box, {
      bound: true,
      ack: first.deliveryId,
      waitMs: 0,
    });
    assert.equal(twice.error, undefined, 're-ack must not surface stale_delivery as a hard error');
    assert.equal(
      decideStaleAckAction({
        ackId: first.deliveryId,
        staleHint: 'delivery_not_in_run_or_wrong_generation',
      }),
      'idempotent',
      're-ack of a deliveryId must be idempotent, not retry-without-ack',
    );
    assert.equal(twice.count, 0);
  });
});

describe('NAS-271 bug 4: await window on client disconnect', () => {
  it('aborted await window does not block the next await on the same run', async () => {
    const lock = createSerialLockMap();
    const ac = new AbortController();
    let firstFinished = false;

    const first = withAbortableLock(lock, 'run_stuck', ac.signal, async () => {
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      firstFinished = true;
    });

    await new Promise((r) => setTimeout(r, 30));
    ac.abort();

    const t0 = Date.now();
    await withAbortableLock(lock, 'run_stuck', undefined, async () => {});
    const elapsed = Date.now() - t0;
    assert.ok(
      elapsed < 500,
      `next await blocked ${elapsed}ms after client abort — window was not released`,
    );
    assert.equal(firstFinished, false, 'aborted window must not run to completion');
    await first.then(
      () => {
        throw new Error('aborted await must reject, not succeed');
      },
      (err) => {
        assert.equal(err?.code, AWAIT_WINDOW_ABORTED);
      },
    );
  });

  it('waitMs hard max is not a 240s client-wrapper trap', () => {
    assert.ok(
      CHECK_WAIT_MAX_MS <= PREFERRED_WAIT_MS,
      `CHECK_WAIT_MAX_MS=${CHECK_WAIT_MAX_MS} exceeds preferred ${PREFERRED_WAIT_MS} and traps ~60s client wrappers`,
    );
    assert.equal(WAIT_MS_HARD_MAX, CHECK_WAIT_MAX_MS);
    assert.equal(clampWaitMs(240_000), CHECK_WAIT_MAX_MS);
    assert.ok(
      clampWaitMs(240_000) <= PREFERRED_WAIT_MS,
      `clampWaitMs(240000)=${clampWaitMs(240_000)} still advertises a window that breaks the channel`,
    );
    assert.ok(
      CHECK_WAIT_DEFAULT_MS <= PREFERRED_WAIT_MS,
      `default waitMs ${CHECK_WAIT_DEFAULT_MS} is already a ~60s wrapper trap`,
    );
  });

  it('HTTP client disconnect aborts the in-flight window', () => {
    const req = new EventEmitter();
    const res = new EventEmitter();
    res.writableEnded = false;
    const controller = bindHttpRequestAbort(req, res);
    assert.equal(controller.signal.aborted, false);
    req.emit('aborted');
    assert.equal(controller.signal.aborted, true, 'request aborted before response end must abort');
  });
});
