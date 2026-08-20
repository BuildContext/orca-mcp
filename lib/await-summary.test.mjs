import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { summarizeMessages, nextStepForAwait } from './await-summary.mjs';

const ORIGINAL_BODY =
  'Wrote the isolation harden and left gitdir sticky. Tests pass. Ready to tag.';
const REJECTED_BODY =
  `Orca rejected this worker_done: The Dispatch capability is missing.\n${ORIGINAL_BODY}`;

function rejectedWorkerDone(overrides = {}) {
  return {
    type: 'worker_done',
    subject: 'Rejected worker_done: isolation harden landed',
    body: REJECTED_BODY,
    payload: {
      taskId: 'task_ce5a70e4267f',
      dispatchId: 'ctx_0599eada41b4',
      outcome: 'succeeded',
      _orcaLifecycleRejection: {
        code: 'dispatch_capability_invalid',
        reason: 'The Dispatch capability is missing.',
      },
    },
    ...overrides,
  };
}

describe('NAS-271 lifecycle-rejected worker_done', () => {
  it('does not report a runtime-rejected worker_done as succeeded', () => {
    const summary = summarizeMessages([rejectedWorkerDone()]);
    assert.notEqual(summary.status, 'worker_done');
    assert.notEqual(summary.worker_done?.outcome, 'succeeded');
    assert.ok(
      summary.rejected_worker_done,
      'rejection must be visible on summary, not only in the message body',
    );
    const code =
      summary.rejected_worker_done?.code || summary.rejected_worker_done;
    assert.equal(code, 'dispatch_capability_invalid');
  });

  it('keeps the original worker body recoverable', () => {
    const summary = summarizeMessages([rejectedWorkerDone()]);
    assert.equal(summary.worker_done.body, REJECTED_BODY);
    assert.match(summary.worker_done.body, /Wrote the isolation harden/);
  });

  it('does not hint release for a rejected worker_done', () => {
    const summary = summarizeMessages([rejectedWorkerDone()]);
    const next = nextStepForAwait(summary, { timedOut: false, deliveryId: 'del_1' });
    assert.notEqual(next.action, 'release');
  });

  it('still treats a genuine accepted worker_done as success', () => {
    const summary = summarizeMessages([
      {
        type: 'worker_done',
        subject: 'isolation harden landed',
        body: ORIGINAL_BODY,
        payload: {
          taskId: 'task_ok',
          dispatchId: 'ctx_ok',
          outcome: 'succeeded',
        },
      },
    ]);
    assert.equal(summary.status, 'worker_done');
    assert.equal(summary.worker_done.outcome, 'succeeded');
    assert.equal(summary.rejected_worker_done, undefined);
    const next = nextStepForAwait(summary, { timedOut: false, deliveryId: 'del_1' });
    assert.equal(next.action, 'release');
  });

  it('parses _orcaLifecycleRejection from a JSON-string payload', () => {
    const summary = summarizeMessages([
      rejectedWorkerDone({
        payload: JSON.stringify({
          taskId: 'task_ce5a70e4267f',
          dispatchId: 'ctx_0599eada41b4',
          outcome: 'succeeded',
          _orcaLifecycleRejection: {
            code: 'dispatch_capability_invalid',
            reason: 'The Dispatch capability is missing.',
          },
        }),
      }),
    ]);
    assert.notEqual(summary.status, 'worker_done');
    assert.notEqual(summary.worker_done?.outcome, 'succeeded');
  });
});
