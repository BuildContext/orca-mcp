/**
 * Authenticated bridge state stores (NAS-249 / NAS-253).
 *
 * Threat: any same-uid worker can rewrite
 *   ~/.orca-bridge-sender-pins.json
 *   ~/.orca-bridge/dispatch-ownership.json
 * and mint ownership. File mode 0600 is not an integrity boundary.
 *
 * Countermeasure: a signer process under a *different* uid holds an HMAC key
 * and exposes only sign/verify on a unix socket the bridge can reach and
 * workers cannot (socket ownership + mode; see deploy/linux/).
 *
 * The bridge signs every write and verifies every read. Unsigned, corrupt, or
 * foreign-key signatures are REJECTED — never accepted with a warning.
 *
 * Deliberately out of scope for v1: key rotation, expiry, PKI, trust chains.
 * HMAC-SHA256 is the algorithm (simpler than Ed25519 for a single shared key
 * held only by the signer uid).
 *
 * Two signer modes (never mixed in one class):
 *   createLocalHmacSigner(key)  — in-process, tests / isolated HOME only
 *   createSocketSigner(path)    — production; one short-lived connection per call
 *
 * Wire protocol: newline-delimited JSON (one JSON.stringify(req)+"\\n" per
 * request; buffer until \\n on read). No length-prefix framing.
 *
 * No process I/O at import time. Socket/key deps are injected or resolved from
 * env by {@link resolveStoreSigner}.
 */

import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { createHmac, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { writeFilePreservingOwner, STATE_FILE_MODE } from './state-ownership.mjs';

export const STORE_SIG_ALG = 'hmac-sha256';
export const STORE_SIG_VERSION = 2;

/** Default socket path used by the systemd unit. */
export const DEFAULT_STORE_SIGNER_SOCKET = '/run/orca-bridge/store-signer.sock';

/** Rejection / error codes for signed-store IO. */
export const SIGNED_STORE_MISSING = 'missing';
export const SIGNED_STORE_UNREADABLE = 'unreadable';
export const SIGNED_STORE_UNSIGNED = 'unsigned';
export const SIGNED_STORE_MALFORMED = 'malformed';
export const SIGNED_STORE_BAD_SIG = 'bad-signature';
export const SIGNED_STORE_SIGNER_UNAVAILABLE = 'signer-unavailable';
export const SIGNED_STORE_REJECTED = 'rejected';
export const SIGNED_STORE_STALE = 'stale';

/** Default in-process / daemon store id when the caller does not name one. */
export const DEFAULT_STORE_ID = 'default';

/** On-disk monotonic counters, signer-owned 0600. */
export const DEFAULT_STORE_SEQ_PATH = '/var/lib/orca-bridge-signer/store-seq.json';

/**
 * Stable JSON bytes for signing. Object keys sorted recursively; arrays keep
 * order. Matches what the daemon and the bridge both feed into HMAC.
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalJson(value) {
  return JSON.stringify(sortValue(value));
}

function sortValue(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(sortValue);
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = sortValue(value[key]);
  }
  return out;
}

/**
 * One-shot HMAC-SHA256. createHmac is not reusable across calls — always
 * construct a fresh instance per sign/verify.
 * @param {Buffer|string} key
 * @param {string} payloadCanonical utf8
 * @returns {string} base64url signature
 */
export function hmacSign(key, payloadCanonical) {
  return createHmac('sha256', key)
    .update(String(payloadCanonical), 'utf8')
    .digest('base64url');
}

/**
 * @param {Buffer|string} key
 * @param {string} payloadCanonical utf8
 * @param {string} signature base64url
 * @returns {boolean}
 */
export function hmacVerify(key, payloadCanonical, signature) {
  if (typeof signature !== 'string' || !signature) return false;
  let expected;
  let actual;
  try {
    // Compare the base64url text of the mac (constant-time on equal-length buffers).
    expected = Buffer.from(hmacSign(key, payloadCanonical), 'utf8');
    actual = Buffer.from(signature, 'utf8');
  } catch {
    return false;
  }
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
}

/**
 * SHA-256 hex of the canonical payload (freshness digest).
 * @param {unknown} payload
 */
export function payloadDigest(payload) {
  return createHash('sha256').update(canonicalJson(payload), 'utf8').digest('hex');
}

/**
 * Bytes the v2 MAC is taken over.
 * @param {{ n: number, ts: number, payload: unknown }} parts
 */
export function envelopeMacInput(parts) {
  return { n: parts.n, ts: parts.ts, payload: parts.payload };
}

/**
 * Infer the signer-held store id from a file path.
 * @param {string} filePath
 */
export function inferStoreId(filePath) {
  const base = path.basename(String(filePath || ''));
  if (/sender-pins/.test(base)) return 'pins';
  if (/dispatch-ownership/.test(base) || /ownership/.test(base)) return 'ownership';
  const stem = base.replace(/\.json$/i, '').replace(/[^A-Za-z0-9._-]+/g, '_') || DEFAULT_STORE_ID;
  return stem;
}

/**
 * True when value is a v1 envelope (payload-only MAC). Runtime rejects these.
 * @param {unknown} value
 */
export function isV1SignedEnvelope(value) {
  return Boolean(
    value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      Number(value.v) === 1 &&
      value.alg === STORE_SIG_ALG &&
      Object.prototype.hasOwnProperty.call(value, 'payload') &&
      typeof value.sig === 'string',
  );
}

/**
 * Wrap a store payload into the on-disk signed envelope.
 * @param {unknown} payload
 * @param {string} sig
 * @param {{ n: number, ts: number }} extras
 */
export function makeSignedEnvelope(payload, sig, extras = {}) {
  return {
    v: STORE_SIG_VERSION,
    alg: STORE_SIG_ALG,
    n: extras.n,
    ts: extras.ts,
    payload,
    sig: String(sig),
  };
}

function isNonNegInt(value) {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && Number.isFinite(value);
}

/**
 * True when value looks like our v2 signed envelope (shape only, no crypto).
 * Requires integer `n` and `ts`. v1 and n-less objects are not accepted.
 * @param {unknown} value
 */
export function isSignedEnvelope(value) {
  return Boolean(
    value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      Number(value.v) === STORE_SIG_VERSION &&
      value.alg === STORE_SIG_ALG &&
      Object.prototype.hasOwnProperty.call(value, 'payload') &&
      typeof value.sig === 'string' &&
      isNonNegInt(value.n) &&
      isNonNegInt(value.ts),
  );
}

/**
 * In-memory monotonic counter used by the local signer and as the daemon core.
 * @param {Record<string, { n: number, digest: string|null }>} [initial]
 */
export function createMemorySeqStore(initial = {}) {
  /** @type {Record<string, { n: number, digest: string|null }>} */
  const last = {};
  for (const [id, rec] of Object.entries(initial || {})) {
    if (typeof rec === 'number') {
      last[id] = { n: rec, digest: null };
    } else if (rec && typeof rec === 'object') {
      last[id] = { n: Number(rec.n) || 0, digest: rec.digest ? String(rec.digest) : null };
    }
  }
  return {
    snapshot() {
      const out = {};
      for (const [id, rec] of Object.entries(last)) out[id] = { ...rec };
      return out;
    },
    peek(storeId) {
      const id = String(storeId || DEFAULT_STORE_ID);
      return last[id] ? { ...last[id] } : { n: 0, digest: null };
    },
    /**
     * Allocate the next n for a sign. Persists digest of this payload.
     */
    bump(storeId, payload) {
      const id = String(storeId || DEFAULT_STORE_ID);
      const prev = last[id] || { n: 0, digest: null };
      const n = prev.n + 1;
      const digest = payloadDigest(payload);
      last[id] = { n, digest };
      return { n, digest };
    },
    /**
     * Freshness: n < last → stale; n === last → digest must match;
     * n > last → accept and advance (crash recovery).
     */
    check(storeId, n, payload) {
      const id = String(storeId || DEFAULT_STORE_ID);
      const prev = last[id] || { n: 0, digest: null };
      const digest = payloadDigest(payload);
      if (n < prev.n) {
        return { ok: false, reason: SIGNED_STORE_STALE };
      }
      if (n === prev.n) {
        if (prev.digest && prev.digest !== digest) {
          return { ok: false, reason: SIGNED_STORE_STALE };
        }
        if (!prev.digest) last[id] = { n, digest };
        return { ok: true, digest };
      }
      last[id] = { n, digest };
      return { ok: true, advanced: true, digest };
    },
  };
}

/**
 * Load a signer-owned seq file. Missing → empty store.
 * @param {string} seqPath
 * @param {typeof fs} [fsImpl]
 */
export function loadSeqFile(seqPath, fsImpl = fs) {
  try {
    if (!fsImpl.existsSync(seqPath)) return {};
    const parsed = JSON.parse(fsImpl.readFileSync(seqPath, 'utf8'));
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

/**
 * Persist seq snapshot as 0600 JSON.
 * @param {string} seqPath
 * @param {Record<string, { n: number, digest: string|null }>} snapshot
 * @param {typeof fs} [fsImpl]
 */
export function persistSeqFile(seqPath, snapshot, fsImpl = fs) {
  const dir = path.dirname(seqPath);
  fsImpl.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = `${seqPath}.tmp.${process.pid}`;
  fsImpl.writeFileSync(tmp, `${JSON.stringify(snapshot, null, 2)}\n`, { mode: 0o600 });
  fsImpl.renameSync(tmp, seqPath);
  try {
    fsImpl.chmodSync(seqPath, 0o600);
  } catch {
    // best-effort
  }
}

/**
 * In-process HMAC signer (unit tests / isolated HOME dev only).
 * Production MUST use the socket signer under a separate uid.
 * @param {Buffer|string} key
 */
export function createLocalHmacSigner(key, opts = {}) {
  if (key == null || (typeof key === 'string' && !key) || (Buffer.isBuffer(key) && key.length === 0)) {
    throw new Error('createLocalHmacSigner: empty key');
  }
  const keyBuf = Buffer.isBuffer(key) ? key : parseSignerKey(String(key));
  const seq = opts.seq || createMemorySeqStore(opts.initialSeq || {});
  const now = typeof opts.now === 'function' ? opts.now : () => Date.now();
  return {
    kind: 'local-hmac',
    seq,
    async sign(payload, signOpts = {}) {
      const storeId = signOpts.storeId || DEFAULT_STORE_ID;
      const bumped = seq.bump(storeId, payload);
      const ts = now();
      const canonical = canonicalJson(envelopeMacInput({ n: bumped.n, ts, payload }));
      return { ok: true, sig: hmacSign(keyBuf, canonical), n: bumped.n, ts, canonical };
    },
    async verify(payload, sig, verifyOpts = {}) {
      const n = verifyOpts.n;
      const ts = verifyOpts.ts;
      if (!isNonNegInt(n) || !isNonNegInt(ts)) {
        return { ok: true, valid: false, reason: SIGNED_STORE_MALFORMED };
      }
      const canonical = canonicalJson(envelopeMacInput({ n, ts, payload }));
      const valid = hmacVerify(keyBuf, canonical, sig);
      if (!valid) return { ok: true, valid: false, canonical };
      if (verifyOpts.storeId) {
        const fresh = seq.check(verifyOpts.storeId, n, payload);
        if (!fresh.ok) return { ok: true, valid: false, reason: fresh.reason, canonical };
      }
      return { ok: true, valid: true, canonical };
    },
    async verifyLegacyV1(payload, sig) {
      const canonical = canonicalJson(payload);
      return { ok: true, valid: hmacVerify(keyBuf, canonical, sig), canonical };
    },
  };
}

/**
 * Parse a hex or raw key string into a Buffer.
 * @param {string} raw
 * @returns {Buffer}
 */
export function parseSignerKey(raw) {
  const s = String(raw || '').trim();
  if (!s) throw new Error('empty signer key');
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) {
    return Buffer.from(s, 'hex');
  }
  return Buffer.from(s, 'utf8');
}

/**
 * Generate a fresh 32-byte HMAC key (hex).
 * @returns {string}
 */
export function generateSignerKeyHex() {
  return randomBytes(32).toString('hex');
}

/**
 * Unix-socket signer client. One short-lived connection per request (bridge
 * traffic is low). Protocol: one JSON object per line (NDJSON).
 *
 * @param {string} socketPath
 * @param {object} [opts]
 * @param {typeof net.connect} [opts.connect]
 * @param {number} [opts.timeoutMs]
 */
export function createSocketSigner(socketPath, opts = {}) {
  const {
    connect = net.connect.bind(net),
    timeoutMs = 5_000,
  } = opts;
  if (!socketPath) throw new Error('createSocketSigner: socketPath required');

  let nextId = 1;

  function request(body) {
    const id = nextId++;
    const line = JSON.stringify({ ...body, id }) + '\n';
    return new Promise((resolve, reject) => {
      let settled = false;
      /** @type {import('node:net').Socket} */
      const socket = connect(socketPath);
      let buf = '';
      const timer = setTimeout(() => {
        fail(new Error(`store-signer socket timeout after ${timeoutMs}ms`));
      }, timeoutMs);

      function fail(err) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { socket.destroy(); } catch { /* ignore */ }
        reject(err);
      }

      function succeed(value) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { socket.end(); } catch { /* ignore */ }
        resolve(value);
      }

      socket.setEncoding('utf8');
      socket.on('error', (e) => fail(e));
      socket.on('connect', () => {
        socket.write(line);
      });
      socket.on('data', (chunk) => {
        buf += chunk;
        const nl = buf.indexOf('\n');
        if (nl === -1) return;
        const raw = buf.slice(0, nl).trim();
        let msg;
        try {
          msg = JSON.parse(raw);
        } catch (e) {
          fail(new Error(`store-signer bad response: ${e.message}`));
          return;
        }
        if (msg && msg.id != null && Number(msg.id) !== id) {
          fail(new Error('store-signer response id mismatch'));
          return;
        }
        succeed(msg);
      });
      socket.on('end', () => {
        if (!settled) fail(new Error('store-signer socket closed before response'));
      });
    });
  }

  return {
    kind: 'socket',
    socketPath,
    async sign(payload, signOpts = {}) {
      const msg = await request({
        op: 'sign',
        payload,
        storeId: signOpts.storeId || DEFAULT_STORE_ID,
      });
      if (!msg || msg.ok !== true || typeof msg.sig !== 'string') {
        return {
          ok: false,
          error: (msg && msg.error) || 'sign failed',
        };
      }
      return { ok: true, sig: msg.sig, n: msg.n, ts: msg.ts };
    },
    async verify(payload, sig, verifyOpts = {}) {
      const msg = await request({
        op: 'verify',
        payload,
        sig,
        n: verifyOpts.n,
        ts: verifyOpts.ts,
        storeId: verifyOpts.storeId,
      });
      if (!msg || msg.ok !== true) {
        return {
          ok: false,
          valid: false,
          error: (msg && msg.error) || 'verify failed',
          reason: msg && msg.reason,
        };
      }
      return { ok: true, valid: msg.valid === true, reason: msg.reason };
    },
    async verifyLegacyV1(payload, sig) {
      const msg = await request({ op: 'verify-v1', payload, sig });
      if (!msg || msg.ok !== true) {
        return { ok: false, valid: false, error: (msg && msg.error) || 'verify-v1 failed' };
      }
      return { ok: true, valid: msg.valid === true };
    },
  };
}

/**
 * Resolve a signer from env.
 *
 * Priority:
 *   1. ORCA_BRIDGE_STORE_SIGNER_SOCKET — production unix socket
 *   2. ORCA_BRIDGE_STORE_SIGNER_KEY — in-process HMAC (tests / isolated HOME only)
 *   3. null (caller must fail closed on sign/verify)
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @param {object} [opts]
 */
export function resolveStoreSigner(env = process.env, opts = {}) {
  const socket = (env.ORCA_BRIDGE_STORE_SIGNER_SOCKET || '').trim();
  if (socket) {
    return createSocketSigner(socket, opts.socket || {});
  }
  const key = (env.ORCA_BRIDGE_STORE_SIGNER_KEY || '').trim();
  if (key) {
    return createLocalHmacSigner(parseSignerKey(key));
  }
  return null;
}

/**
 * Sign a payload and return the on-disk envelope.
 * @param {unknown} payload
 * @param {{ sign: Function }} signer
 * @param {{ storeId?: string }} [opts]
 */
export async function signPayload(payload, signer, opts = {}) {
  if (!signer || typeof signer.sign !== 'function') {
    return { ok: false, reason: SIGNED_STORE_SIGNER_UNAVAILABLE };
  }
  const storeId = opts.storeId || DEFAULT_STORE_ID;
  let result;
  try {
    result = await signer.sign(payload, { storeId });
  } catch (e) {
    return {
      ok: false,
      reason: SIGNED_STORE_SIGNER_UNAVAILABLE,
      error: e && e.message ? e.message : String(e),
    };
  }
  if (!result || result.ok !== true || typeof result.sig !== 'string') {
    return {
      ok: false,
      reason: SIGNED_STORE_SIGNER_UNAVAILABLE,
      error: (result && result.error) || 'sign failed',
    };
  }
  if (!isNonNegInt(result.n) || !isNonNegInt(result.ts)) {
    return {
      ok: false,
      reason: SIGNED_STORE_MALFORMED,
      error: 'signer did not return integer n/ts',
    };
  }
  return {
    ok: true,
    envelope: makeSignedEnvelope(payload, result.sig, { n: result.n, ts: result.ts }),
  };
}

/**
 * Verify a signed envelope. Rejects unsigned / malformed / bad sig / stale.
 * Without storeId: MAC + required n/ts types only.
 * With storeId: also signer-held freshness.
 * @param {unknown} envelope
 * @param {{ verify: Function }} signer
 * @param {{ storeId?: string }} [opts]
 */
export async function verifyEnvelope(envelope, signer, opts = {}) {
  if (!signer || typeof signer.verify !== 'function') {
    return { ok: false, reason: SIGNED_STORE_SIGNER_UNAVAILABLE };
  }
  if (!isSignedEnvelope(envelope)) {
    if (envelope && typeof envelope === 'object' && !Array.isArray(envelope) &&
        (Object.prototype.hasOwnProperty.call(envelope, 'sig') ||
         Object.prototype.hasOwnProperty.call(envelope, 'payload') ||
         Object.prototype.hasOwnProperty.call(envelope, 'alg') ||
         Object.prototype.hasOwnProperty.call(envelope, 'n') ||
         Object.prototype.hasOwnProperty.call(envelope, 'ts'))) {
      return { ok: false, reason: SIGNED_STORE_MALFORMED };
    }
    return { ok: false, reason: SIGNED_STORE_UNSIGNED };
  }
  let result;
  try {
    result = await signer.verify(envelope.payload, envelope.sig, {
      n: envelope.n,
      ts: envelope.ts,
      storeId: opts.storeId,
    });
  } catch (e) {
    return {
      ok: false,
      reason: SIGNED_STORE_SIGNER_UNAVAILABLE,
      error: e && e.message ? e.message : String(e),
    };
  }
  if (!result || result.ok !== true) {
    return {
      ok: false,
      reason: SIGNED_STORE_SIGNER_UNAVAILABLE,
      error: (result && result.error) || 'verify failed',
    };
  }
  if (result.valid !== true) {
    if (result.reason === SIGNED_STORE_STALE) {
      return { ok: false, reason: SIGNED_STORE_STALE };
    }
    if (result.reason === SIGNED_STORE_MALFORMED) {
      return { ok: false, reason: SIGNED_STORE_MALFORMED };
    }
    return { ok: false, reason: SIGNED_STORE_BAD_SIG };
  }
  return { ok: true, payload: envelope.payload, n: envelope.n, ts: envelope.ts };
}

/**
 * Read + verify a signed JSON store file.
 * Missing file → `{ ok:false, reason:'missing' }` (caller decides empty-vs-error).
 * Anything else invalid → rejected.
 *
 * @param {string} filePath
 * @param {object} signer
 * @param {object} [deps]
 * @param {typeof fs} [deps.fsImpl]
 */
export async function readSignedJsonFile(filePath, signer, deps = {}) {
  const fsImpl = deps.fsImpl || fs;
  let rawText;
  try {
    if (!fsImpl.existsSync(filePath)) {
      return { ok: false, reason: SIGNED_STORE_MISSING };
    }
    rawText = fsImpl.readFileSync(filePath, 'utf8');
  } catch (e) {
    return {
      ok: false,
      reason: SIGNED_STORE_UNREADABLE,
      error: e && e.message ? e.message : String(e),
    };
  }
  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return { ok: false, reason: SIGNED_STORE_MALFORMED };
  }
  const storeId = deps.storeId || inferStoreId(filePath);
  const verified = await verifyEnvelope(parsed, signer, { storeId });
  if (!verified.ok) return verified;
  return { ok: true, payload: verified.payload, path: filePath, n: verified.n };
}

/**
 * Sign + write a JSON store file (ownership-preserving write).
 * @param {string} filePath
 * @param {unknown} payload
 * @param {object} signer
 * @param {object} [deps]
 * @param {typeof writeFilePreservingOwner} [deps.writeFile]
 * @param {number} [deps.mode]
 */
export async function writeSignedJsonFile(filePath, payload, signer, deps = {}) {
  const writeFile = deps.writeFile || writeFilePreservingOwner;
  const mode = deps.mode ?? STATE_FILE_MODE;
  const storeId = deps.storeId || inferStoreId(filePath);
  const signed = await signPayload(payload, signer, { storeId });
  if (!signed.ok) return signed;
  const dir = path.dirname(filePath);
  if (deps.mkdir) {
    deps.mkdir(dir);
  } else {
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    } catch {
      // writeFile will surface real errors
    }
  }
  try {
    const res = writeFile(filePath, `${JSON.stringify(signed.envelope, null, 2)}\n`, { mode });
    return { ok: true, path: filePath, write: res };
  } catch (e) {
    return {
      ok: false,
      reason: SIGNED_STORE_REJECTED,
      error: e && e.message ? e.message : String(e),
    };
  }
}

/**
 * Handle one daemon request body (pure aside from crypto). Used by the daemon
 * and by unit tests of the wire protocol shape.
 * @param {object} msg
 * @param {Buffer} key
 */
/**
 * @param {object} msg
 * @param {Buffer} key
 * @param {{ seq?: ReturnType<typeof createMemorySeqStore>, now?: () => number, persist?: () => void }} [ctx]
 */
export function handleSignerRequest(msg, key, ctx = {}) {
  if (!msg || typeof msg !== 'object') {
    return { ok: false, error: 'invalid request' };
  }
  const seq = ctx.seq || createMemorySeqStore();
  const now = typeof ctx.now === 'function' ? ctx.now : () => Date.now();
  const persist = typeof ctx.persist === 'function' ? ctx.persist : () => {};
  const op = msg.op;
  if (op === 'sign') {
    if (!Object.prototype.hasOwnProperty.call(msg, 'payload')) {
      return { id: msg.id, ok: false, error: 'missing payload' };
    }
    const storeId = msg.storeId || DEFAULT_STORE_ID;
    const bumped = seq.bump(storeId, msg.payload);
    const ts = now();
    const sig = hmacSign(key, canonicalJson(envelopeMacInput({
      n: bumped.n,
      ts,
      payload: msg.payload,
    })));
    persist();
    return { id: msg.id, ok: true, sig, n: bumped.n, ts, alg: STORE_SIG_ALG };
  }
  if (op === 'verify') {
    if (!Object.prototype.hasOwnProperty.call(msg, 'payload') || typeof msg.sig !== 'string') {
      return { id: msg.id, ok: false, error: 'missing payload or sig' };
    }
    if (!isNonNegInt(msg.n) || !isNonNegInt(msg.ts)) {
      return { id: msg.id, ok: true, valid: false, reason: SIGNED_STORE_MALFORMED };
    }
    const validMac = hmacVerify(
      key,
      canonicalJson(envelopeMacInput({ n: msg.n, ts: msg.ts, payload: msg.payload })),
      msg.sig,
    );
    if (!validMac) {
      return { id: msg.id, ok: true, valid: false };
    }
    if (msg.storeId) {
      const fresh = seq.check(msg.storeId, msg.n, msg.payload);
      if (!fresh.ok) {
        return { id: msg.id, ok: true, valid: false, reason: fresh.reason };
      }
      persist();
    }
    return { id: msg.id, ok: true, valid: true };
  }
  if (op === 'verify-v1') {
    if (!Object.prototype.hasOwnProperty.call(msg, 'payload') || typeof msg.sig !== 'string') {
      return { id: msg.id, ok: false, error: 'missing payload or sig' };
    }
    const valid = hmacVerify(key, canonicalJson(msg.payload), msg.sig);
    return { id: msg.id, ok: true, valid };
  }
  if (op === 'ping') {
    return { id: msg.id, ok: true, pong: true };
  }
  return { id: msg.id, ok: false, error: `unknown op: ${op}` };
}

/**
 * Create a line-protocol server on an existing listening server or path.
 * @param {object} opts
 * @param {Buffer} opts.key
 * @param {string} [opts.socketPath]
 * @param {import('node:net').Server} [opts.server] pre-built server (tests)
 * @returns {{ server: import('node:net').Server, close: () => Promise<void> }}
 */
export function createSignerDaemon(opts) {
  const key = opts.key;
  if (!Buffer.isBuffer(key) || key.length < 16) {
    throw new Error('createSignerDaemon: key must be Buffer >= 16 bytes');
  }
  const seqPath = opts.seqPath || null;
  const fsImpl = opts.fsImpl || fs;
  const seq = opts.seq || createMemorySeqStore(seqPath ? loadSeqFile(seqPath, fsImpl) : {});
  const persist = () => {
    if (!seqPath) return;
    try {
      persistSeqFile(seqPath, seq.snapshot(), fsImpl);
    } catch {
      // caller sees sign/verify success; next restart reloads last good file
    }
  };
  const now = typeof opts.now === 'function' ? opts.now : () => Date.now();
  const server = opts.server || net.createServer();
  server.on('connection', (socket) => {
    let buf = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => {
      buf += chunk;
      let nl;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          socket.write(JSON.stringify({ ok: false, error: 'invalid json' }) + '\n');
          continue;
        }
        let response;
        try {
          response = handleSignerRequest(msg, key, { seq, persist, now });
        } catch (e) {
          response = {
            id: msg && msg.id,
            ok: false,
            error: e && e.message ? e.message : String(e),
          };
        }
        try {
          socket.write(JSON.stringify(response) + '\n');
        } catch {
          // peer gone
        }
      }
    });
  });

  function close() {
    return new Promise((resolve) => {
      server.close(() => resolve());
      // destroy open connections so close settles under node:test
      if (typeof server.closeAllConnections === 'function') {
        try { server.closeAllConnections(); } catch { /* ignore */ }
      }
    });
  }

  if (opts.socketPath) {
    try {
      if (fs.existsSync(opts.socketPath)) fs.unlinkSync(opts.socketPath);
    } catch { /* ignore */ }
    const dir = path.dirname(opts.socketPath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o750 });
    server.listen(opts.socketPath);
  }

  return { server, close, seq };
}
