/**
 * Pure helpers for multi-coordinator isolation.
 * Kept free of process I/O so unit tests can import without ORCA_BRIDGE_TOKEN.
 */

import { createHash } from 'node:crypto';

/**
 * Stable client identity for sender terminal + orch lock + ownership.
 * Prefer OAuth access token (survives MCP session rotate); else session; else master.
 *
 * @param {{ authKind?: string, bearer?: string, sessionId?: string, sessionClientKey?: string|null }} p
 */
export function deriveClientKey({
  authKind = '',
  bearer = '',
  sessionId = '',
  sessionClientKey = null,
} = {}) {
  if (sessionClientKey && typeof sessionClientKey === 'string') {
    return sessionClientKey;
  }
  if (authKind === 'bearer-oauth' && bearer) {
    return `oauth:${sha16(bearer)}`;
  }
  if (sessionId) {
    return `sid:${sha16(sessionId)}`;
  }
  if (authKind === 'bearer-master' || authKind === 'path-token') {
    return 'master';
  }
  return 'anonymous';
}

function sha16(s) {
  return createHash('sha256').update(String(s)).digest('hex').slice(0, 16);
}

/**
 * Per-client durable coordinator tab title.
 * Shared keys keep the base title for backward-compatible single-tenant deploys.
 */
export function senderTitleForClient(baseTitle, clientKey) {
  const base = String(baseTitle || 'orca-bridge-coordinator').trim() || 'orca-bridge-coordinator';
  const k = String(clientKey || 'default');
  if (k === 'default' || k === 'master' || k === 'anonymous') return base;
  const short = k.replace(/^(oauth|sid):/, '').slice(0, 10);
  return `${base}-${short}`;
}

/**
 * Whether this clientKey should use a process-wide env pin (single-tenant mode).
 * Shared pin is only for master/default/anonymous unless ORCA_BRIDGE_SENDER_SHARED=1.
 */
export function shouldUseSharedSenderPin(clientKey, { senderEnv, senderShared } = {}) {
  if (!senderEnv) return false;
  if (senderShared) return true;
  const k = String(clientKey || 'default');
  return k === 'default' || k === 'master' || k === 'anonymous';
}

/**
 * Split mailbox messages into owned vs foreign by dispatch id.
 * Fail-open: empty owned set → all messages treated as own (bridge restart / first await).
 *
 * @param {unknown[]} messages
 * @param {Set<string>|string[]} ownedDispatchIds
 * @param {(obj: object, ...keys: string[]) => unknown} pick
 */
export function partitionMailbox(messages, ownedDispatchIds, pick) {
  const list = Array.isArray(messages) ? messages : [];
  const owned = ownedDispatchIds instanceof Set
    ? ownedDispatchIds
    : new Set(Array.isArray(ownedDispatchIds) ? ownedDispatchIds : []);

  if (owned.size === 0) {
    return { own: list, foreign: [], filtered: false };
  }

  const own = [];
  const foreign = [];
  for (const m of list) {
    if (!m || typeof m !== 'object') {
      own.push(m);
      continue;
    }
    const payload = m.payload && typeof m.payload === 'object' ? m.payload : {};
    const did = String(
      pick(m, 'dispatchId', 'dispatch_id') ||
      pick(payload, 'dispatchId', 'dispatch_id') ||
      '',
    ).trim();
    if (did && !owned.has(did)) foreign.push(m);
    else own.push(m);
  }
  return { own, foreign, filtered: foreign.length > 0 };
}

/**
 * Refuse closing a handle that is a bridge coordinator sender (mechanism B).
 */
export function releaseRefusesCoordinator(handle, coordinatorHandles) {
  const h = String(handle || '').trim();
  if (!h) return false;
  if (coordinatorHandles instanceof Set) return coordinatorHandles.has(h);
  if (Array.isArray(coordinatorHandles)) return coordinatorHandles.includes(h);
  return false;
}

/**
 * How resolveSenderTerminal should treat a cached pin.
 * - trust_cache: return handle without re-show (fresh TTL)
 * - revalidate_pin: terminal show the same handle; never create a sibling while pin may live
 * - resolve: no pin — title/env/create path
 *
 * Orca shell tabs often rewrite --title to "user@host: path", so title re-discovery
 * is unreliable; pin-by-handle is the durable identity (multi-coordinator isolation regression).
 *
 * @param {{ handle?: string|null, at?: number, source?: string|null }|null|undefined} cached
 * @param {{ force?: boolean, now?: number, ttlMs?: number }} opts
 */
/**
 * Whether await should call run-use before check.
 * run-use bumps consumer_generation and invalidates prior deliveryIds (ack).
 * Skip when this pin is already bound to the same run.
 */
export function shouldRunUseBeforeAwait({
  boundRunId = null,
  boundSender = null,
  runId = '',
  senderHandle = '',
} = {}) {
  const run = String(runId || '');
  const sender = String(senderHandle || '');
  if (!run || !sender) return true;
  return !(boundRunId === run && boundSender === sender);
}

export function senderPinPlan(cached, { force = false, now = Date.now(), ttlMs = 15_000 } = {}) {
  const handle = cached?.handle ? String(cached.handle) : '';
  if (!handle) return { mode: 'resolve', handle: null };
  if (force) return { mode: 'revalidate_pin', handle };
  const at = typeof cached.at === 'number' ? cached.at : 0;
  if (now - at < ttlMs) return { mode: 'trust_cache', handle, source: cached.source || 'cache' };
  return { mode: 'revalidate_pin', handle, source: cached.source || 'pinned' };
}

/**
 * FIFO serial lock factory: same key serializes; different keys interleave.
 * @returns {(key: string, fn: () => Promise<any>) => Promise<any>}
 */
export function createSerialLockMap() {
  /** @type {Map<string, Promise<unknown>>} */
  const tails = new Map();
  return async function withSerialLock(key, fn) {
    const k = String(key || 'default');
    const prev = tails.get(k) || Promise.resolve();
    let unlock;
    const gate = new Promise((resolve) => {
      unlock = resolve;
    });
    // Chain so the next waiter blocks on our unlock even if we throw.
    tails.set(
      k,
      prev.then(
        () => gate,
        () => gate,
      ),
    );
    try {
      await prev.catch(() => {});
      return await fn();
    } finally {
      unlock();
    }
  };
}
