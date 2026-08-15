import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseWorkerOrchArgv,
  authorizeWorkerOrch,
  getArgFlag,
} from './worker-orch-relay.mjs';

describe('worker-orch-relay', () => {
  it('parses orca orchestration send worker_done', () => {
    const p = parseWorkerOrchArgv([
      'orchestration', 'send',
      '--type', 'worker_done',
      '--subject', 'done',
      '--task-id', 'task_1',
      '--dispatch-id', 'ctx_abc',
      '--outcome', 'succeeded',
    ]);
    assert.equal(p.ok, true);
    assert.equal(p.verb, 'send');
    assert.equal(p.type, 'worker_done');
    assert.equal(p.dispatchId, 'ctx_abc');
    assert.equal(p.taskId, 'task_1');
    assert.deepEqual(p.relayArgv.slice(0, 2), ['orchestration', 'send']);
  });

  it('maps bare helper verb worker_done to send --type', () => {
    const p = parseWorkerOrchArgv(['worker_done', '--subject', 'done']);
    assert.equal(p.ok, true);
    assert.equal(p.verb, 'send');
    assert.equal(p.type, 'worker_done');
  });

  it('rejects terminal close and other coordinator verbs', () => {
    const p = parseWorkerOrchArgv(['orchestration', 'worker-release', '--dispatch', 'ctx_abc']);
    assert.equal(p.ok, false);
    assert.equal(p.code, 'verb_not_allowed');
  });

  it('rejects send without an allowlisted type', () => {
    const p = parseWorkerOrchArgv(['orchestration', 'send', '--subject', 'x']);
    assert.equal(p.ok, false);
    assert.equal(p.code, 'type_not_allowed');
  });

  it('authorize requires op in capability and matching ids', () => {
    const parsed = parseWorkerOrchArgv([
      'orchestration', 'send', '--type', 'heartbeat',
      '--dispatch-id', 'ctx_abc', '--task-id', 'task_1',
    ]);
    const ok = authorizeWorkerOrch({
      parsed,
      payload: { dispatchId: 'ctx_abc', taskId: 'task_1', ops: ['worker_done', 'heartbeat'] },
    });
    assert.equal(ok.ok, true);
    const badOp = authorizeWorkerOrch({
      parsed,
      payload: { dispatchId: 'ctx_abc', taskId: 'task_1', ops: ['worker_done'] },
    });
    assert.equal(badOp.ok, false);
    assert.equal(badOp.code, 'op_not_allowed');
    const badId = authorizeWorkerOrch({
      parsed,
      payload: { dispatchId: 'ctx_FOREIGN', taskId: 'task_1', ops: ['heartbeat'] },
    });
    assert.equal(badId.ok, false);
    assert.equal(badId.code, 'dispatch_mismatch');
  });

  it('getArgFlag skips a dangling flag', () => {
    assert.equal(getArgFlag(['--type'], '--type'), null);
    assert.equal(getArgFlag(['--type', '--json'], '--type'), null);
    assert.equal(getArgFlag(['--type', 'heartbeat'], '--type'), 'heartbeat');
  });
});
