import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  isSafeCapId,
  capFilePath,
  capByTaskPath,
  capStagePath,
  capPurgeMarkerPath,
  buildWorkerCapRecord,
  serializeWorkerCapFile,
  parseWorkerCapFile,
  DEFAULT_BRIDGE_ORIGIN,
} from './worker-cap-file.mjs';
import {
  mintWorkerCapability,
  workerCapabilityEnv,
} from './worker-isolation.mjs';

describe('worker-cap-file', () => {
  it('accepts dispatch/task id alphabet and rejects traversal', () => {
    assert.equal(isSafeCapId('ctx_ea312e430e96'), true);
    assert.equal(isSafeCapId('task_582ffae59441'), true);
    assert.equal(isSafeCapId('../etc/passwd'), false);
    assert.equal(isSafeCapId('a/b'), false);
    assert.equal(isSafeCapId(''), false);
  });

  it('paths are bound to dispatchId / taskId', () => {
    assert.equal(capFilePath('ctx_abc'), '/run/orca-mcp/worker-caps/ctx_abc.json');
    assert.equal(capByTaskPath('task_1'), '/run/orca-mcp/worker-caps/by-task/task_1');
    assert.equal(capStagePath('ctx_abc'), '/run/orca-mcp/cap-stage/ctx_abc.json');
    assert.equal(capPurgeMarkerPath('ctx_abc'), '/run/orca-mcp/cap-stage/ctx_abc.purge');
    assert.throws(() => capFilePath('../x'), /invalid/);
  });

  it('serialize goes through workerCapabilityEnv field map', () => {
    const token = mintWorkerCapability(
      { dispatchId: 'ctx_abc', taskId: 'task_1', nowMs: 1_700_000_000_000 },
      'unit-test-secret-not-for-production-use-32b',
    );
    const env = workerCapabilityEnv({
      capability: token,
      bridgeOrigin: 'http://127.0.0.1:8787',
    });
    const raw = serializeWorkerCapFile({
      capability: env.ORCA_WORKER_CAPABILITY,
      dispatchId: 'ctx_abc',
      taskId: 'task_1',
      bridgeOrigin: env.ORCA_WORKER_BRIDGE_ORIGIN,
      orchHelper: env.ORCA_WORKER_ORCH_HELPER,
      terminalHandle: 'term_w',
    });
    const rec = parseWorkerCapFile(raw);
    assert.equal(rec.v, 1);
    assert.equal(rec.dispatchId, 'ctx_abc');
    assert.equal(rec.taskId, 'task_1');
    assert.equal(rec.capability, token);
    assert.equal(rec.bridgeOrigin, DEFAULT_BRIDGE_ORIGIN);
    assert.equal(rec.orchHelper, '/usr/local/lib/orca-mcp/orca-worker-orch.sh');
    assert.equal(rec.terminalHandle, 'term_w');
    assert.equal(raw.includes('ORCA_BRIDGE_TOKEN'), false);
  });

  it('parse rejects missing capability and bad version', () => {
    assert.throws(() => parseWorkerCapFile('{"v":2}'), /unsupported version/);
    assert.throws(
      () => parseWorkerCapFile(JSON.stringify({
        v: 1, dispatchId: 'ctx_a', taskId: 'task_1', capability: 'x',
        bridgeOrigin: 'http://127.0.0.1:8787', orchHelper: '/x',
      })),
      /capability missing/,
    );
  });

  it('buildWorkerCapRecord refuses unsafe ids', () => {
    assert.throws(() => buildWorkerCapRecord({
      capability: 'v1.xxxxx.yyyy',
      dispatchId: '../x',
      taskId: 'task_1',
    }), /invalid dispatchId/);
  });
});

describe('NAS-258 live mint/purge contract', () => {
  it('dispatch response path is /run/orca-mcp/worker-caps/<dispatchId>.json', () => {
    const dispatchId = 'ctx_bfedc4d60376';
    assert.equal(
      capFilePath(dispatchId),
      `/run/orca-mcp/worker-caps/${dispatchId}.json`,
    );
  });

  it('staging write is owner-only 0600 and never world-readable', async () => {
    const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'nas258-cap-'));
    const dest = path.join(dir, 'ctx_unit.json');
    const tmp = `${dest}.tmp.${process.pid}`;
    const body = serializeWorkerCapFile({
      capability: 'v1.unit.capabilitytoken',
      dispatchId: 'ctx_unit',
      taskId: 'task_unit',
      bridgeOrigin: DEFAULT_BRIDGE_ORIGIN,
      orchHelper: '/usr/local/lib/orca-mcp/orca-worker-orch.sh',
    });
    await fs.promises.writeFile(tmp, body, { mode: 0o600, flag: 'w' });
    await fs.promises.chmod(tmp, 0o600);
    await fs.promises.rename(tmp, dest);
    const st = await fs.promises.stat(dest);
    assert.equal(st.mode & 0o777, 0o600);
    assert.equal(st.mode & 0o077, 0, 'group/other must have no bits');
    const rec = parseWorkerCapFile(await fs.promises.readFile(dest, 'utf8'));
    assert.equal(rec.capability, 'v1.unit.capabilitytoken');
    assert.equal(JSON.stringify(rec).includes('ORCA_BRIDGE_TOKEN'), false);
    await fs.promises.rm(dir, { recursive: true, force: true });
  });

  it('purge marker is a sibling of the staging file, not the 994-owned dest', () => {
    assert.equal(
      capPurgeMarkerPath('ctx_abc'),
      '/run/orca-mcp/cap-stage/ctx_abc.purge',
    );
    assert.notEqual(path.dirname(capPurgeMarkerPath('ctx_abc')), path.dirname(capFilePath('ctx_abc')));
  });
});
