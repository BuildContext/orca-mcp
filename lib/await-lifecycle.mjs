/**
 * Await mailbox window helpers (NAS-271).
 *
 * Ack consumption, wait-window abort, and waitMs policy that await/check
 * share. Kept free of process I/O so unit tests can import without
 * ORCA_BRIDGE_TOKEN.
 */

export const AWAIT_WINDOW_ABORTED = 'await_window_aborted';

/**
 * Whether await should call run-use, and which ack (if any) survives.
 *
 * run-use bumps consumer_generation and re-issues unacked mailbox rows under
 * new delivery/message ids. Never run-use while consuming an ack — that is
 * NAS-271 bug 3 (same worker_done reopened under a new id).
 *
 * @param {{ bound?: boolean, ack?: string|null }} p
 */
export function planAwaitBindAndAck({ bound = false, ack = null } = {}) {
  const trimmed = ack != null && String(ack).trim() !== '' ? String(ack).trim() : null;
  if (trimmed) {
    return { runUse: false, ack: trimmed, ackDropped: null };
  }
  if (bound) {
    return { runUse: false, ack: null, ackDropped: null };
  }
  return { runUse: true, ack: null, ackDropped: null };
}

/**
 * Check invocations for one await window.
 * Consume first (`--ack` without `--wait`), then wait for the next batch.
 * Peek stays a single combined call.
 *
 * @param {{ ack?: string|null, waitMs?: number, peek?: boolean }} p
 */
export function planAckWaitCalls({ ack = null, waitMs = 0, peek = false } = {}) {
  const trimmed = ack != null && String(ack).trim() !== '' ? String(ack).trim() : null;
  if (peek === true) {
    return [{ ack: trimmed, waitMs, peek: true }];
  }
  if (trimmed && waitMs > 0) {
    return [
      { ack: trimmed, waitMs: 0, peek: false },
      { ack: null, waitMs, peek: false },
    ];
  }
  return [{ ack: trimmed, waitMs, peek: false }];
}

/**
 * What to do when check --ack returns stale_delivery.
 * Re-ack of a deliveryId is idempotent (already consumed / gone).
 * A msg_ token is the wrong class — retry once without ack.
 *
 * @param {{ ackId?: string|null, staleHint?: string|null }} p
 */
export function decideStaleAckAction({ ackId = null, staleHint = null } = {}) {
  if (staleHint === 'ack_message_id_not_delivery_id') return 'retry_without_ack';
  const ack = ackId != null ? String(ackId).trim() : '';
  if (/^msg[_-]/i.test(ack)) return 'retry_without_ack';
  return 'idempotent';
}

export function abortWindowError(message = 'await window aborted') {
  const err = new Error(message);
  err.code = AWAIT_WINDOW_ABORTED;
  err.name = 'AbortError';
  return err;
}

/**
 * Settle `fn` or reject as soon as `signal` aborts so the serial lock
 * releases instead of waiting out the leftover waitMs window.
 *
 * @param {AbortSignal|null|undefined} signal
 * @param {(signal?: AbortSignal) => Promise<any>} fn
 */
export async function runWithAbortSignal(signal, fn) {
  if (!signal) return fn();
  if (signal.aborted) throw abortWindowError();
  let onAbort;
  const abortP = new Promise((_, reject) => {
    onAbort = () => reject(abortWindowError());
    signal.addEventListener('abort', onAbort, { once: true });
  });
  try {
    return await Promise.race([Promise.resolve().then(() => fn(signal)), abortP]);
  } finally {
    if (onAbort) signal.removeEventListener('abort', onAbort);
  }
}

/**
 * Per-key serial lock that yields on client abort so the next await can run.
 *
 * @param {(key: string, fn: () => Promise<any>) => Promise<any>} withLock
 * @param {string} key
 * @param {AbortSignal|null|undefined} signal
 * @param {(signal?: AbortSignal) => Promise<any>} fn
 */
export async function withAbortableLock(withLock, key, signal, fn) {
  return withLock(key, () => runWithAbortSignal(signal, fn));
}

/**
 * Abort an in-flight MCP HTTP request when the client disconnects before
 * the response is written. No-op if the response already finished.
 *
 * @param {{ on?: Function }} req
 * @param {{ on?: Function, writableEnded?: boolean }} res
 * @param {AbortController} [controller]
 */
export function bindHttpRequestAbort(req, res, controller = new AbortController()) {
  const abort = () => {
    if (!controller.signal.aborted) controller.abort();
  };
  const onResponseClose = () => {
    if (!res.writableEnded) abort();
  };
  if (req && typeof req.on === 'function') req.on('aborted', abort);
  if (res && typeof res.on === 'function') {
    res.on('close', onResponseClose);
    res.on('error', abort);
  }
  return controller;
}
