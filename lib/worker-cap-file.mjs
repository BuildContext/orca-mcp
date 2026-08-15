/**
 * NAS-258 — file-based worker capability (not env).
 *
 * Owner decision: sudo env_reset strips ORCA_WORKER_*; do not add env_keep.
 * The privileged seed helper materializes 994:994 mode-0600 files under
 * /run/orca-mcp/worker-caps/<dispatchId>.json. This module is the pure
 * path/JSON contract used by the bridge and unit tests.
 */

import path from 'node:path';

export const WORKER_CAP_ROOT = '/run/orca-mcp/worker-caps';
export const WORKER_CAP_STAGE = '/run/orca-mcp/cap-stage';
export const WORKER_CAP_HOME_DIR = '/home/orca-worker/.orca-worker';
export const WORKER_CAP_HOME_CURRENT = path.join(WORKER_CAP_HOME_DIR, 'current-cap.json');
export const DEFAULT_BRIDGE_ORIGIN = 'http://127.0.0.1:8787';
export const SEED_HELPER = '/usr/local/lib/orca-mcp/orca-seed-worker-creds';

const SAFE_ID = /^[A-Za-z0-9._:-]{1,128}$/;

export function isSafeCapId(value) {
  return typeof value === 'string' && SAFE_ID.test(value);
}

export function capFilePath(dispatchId) {
  if (!isSafeCapId(dispatchId)) {
    throw new Error('capFilePath: invalid dispatchId');
  }
  return path.join(WORKER_CAP_ROOT, `${dispatchId}.json`);
}

export function capByTaskPath(taskId) {
  if (!isSafeCapId(taskId)) {
    throw new Error('capByTaskPath: invalid taskId');
  }
  return path.join(WORKER_CAP_ROOT, 'by-task', taskId);
}

export function capStagePath(dispatchId) {
  if (!isSafeCapId(dispatchId)) {
    throw new Error('capStagePath: invalid dispatchId');
  }
  return path.join(WORKER_CAP_STAGE, `${dispatchId}.json`);
}

export function capPurgeMarkerPath(dispatchId) {
  if (!isSafeCapId(dispatchId)) {
    throw new Error('capPurgeMarkerPath: invalid dispatchId');
  }
  return path.join(WORKER_CAP_STAGE, `${dispatchId}.purge`);
}

/**
 * Build the on-disk record. Callers should pass the output of
 * workerCapabilityEnv() so that helper stays the single field map.
 *
 * @param {{
 *   capability: string,
 *   dispatchId: string,
 *   taskId: string,
 *   bridgeOrigin?: string|null,
 *   orchHelper?: string|null,
 *   terminalHandle?: string|null,
 * }} p
 */
export function buildWorkerCapRecord(p) {
  if (!isSafeCapId(p.dispatchId)) throw new Error('buildWorkerCapRecord: invalid dispatchId');
  if (!isSafeCapId(p.taskId)) throw new Error('buildWorkerCapRecord: invalid taskId');
  if (!p.capability || typeof p.capability !== 'string') {
    throw new Error('buildWorkerCapRecord: capability required');
  }
  return {
    v: 1,
    dispatchId: String(p.dispatchId),
    taskId: String(p.taskId),
    capability: String(p.capability),
    bridgeOrigin: String(p.bridgeOrigin || DEFAULT_BRIDGE_ORIGIN),
    orchHelper: String(p.orchHelper || '/usr/local/lib/orca-mcp/orca-worker-orch.sh'),
    terminalHandle: p.terminalHandle ? String(p.terminalHandle) : null,
  };
}

export function serializeWorkerCapFile(p) {
  return `${JSON.stringify(buildWorkerCapRecord(p))}\n`;
}

export function parseWorkerCapFile(raw) {
  const text = typeof raw === 'string' ? raw : String(raw || '');
  let obj;
  try {
    obj = JSON.parse(text);
  } catch {
    throw new Error('parseWorkerCapFile: invalid JSON');
  }
  if (!obj || typeof obj !== 'object' || obj.v !== 1) {
    throw new Error('parseWorkerCapFile: unsupported version');
  }
  if (!isSafeCapId(obj.dispatchId)) throw new Error('parseWorkerCapFile: invalid dispatchId');
  if (!isSafeCapId(obj.taskId)) throw new Error('parseWorkerCapFile: invalid taskId');
  if (!obj.capability || typeof obj.capability !== 'string' || obj.capability.length < 8) {
    throw new Error('parseWorkerCapFile: capability missing');
  }
  if (!obj.bridgeOrigin || typeof obj.bridgeOrigin !== 'string') {
    throw new Error('parseWorkerCapFile: bridgeOrigin missing');
  }
  if (!obj.orchHelper || typeof obj.orchHelper !== 'string') {
    throw new Error('parseWorkerCapFile: orchHelper missing');
  }
  return {
    v: 1,
    dispatchId: obj.dispatchId,
    taskId: obj.taskId,
    capability: obj.capability,
    bridgeOrigin: obj.bridgeOrigin,
    orchHelper: obj.orchHelper,
    terminalHandle: obj.terminalHandle ? String(obj.terminalHandle) : null,
  };
}
