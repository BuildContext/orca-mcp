/**
 * NAS-249 / NAS-253 — signed ownership + sender-pin stores.
 *
 * Forgery of either on-disk file must be rejected (not warn-and-accept).
 * Tests use createLocalHmacSigner (in-process) and a real unix-socket daemon
 * under the same uid; production isolation is the separate-uid unit + 0660
 * socket group, not something node:test can assert on this host.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  STORE_SIG_ALG,
  STORE_SIG_VERSION,
  SIGNED_STORE_MISSING,
  SIGNED_STORE_UNSIGNED,
  SIGNED_STORE_MALFORMED,
  SIGNED_STORE_BAD_SIG,
  SIGNED_STORE_STALE,
  isV1SignedEnvelope,
  canonicalJson,
  hmacSign,
  hmacVerify,
  createLocalHmacSigner,
  createSocketSigner,
  createSignerDaemon,
  handleSignerRequest,
  makeSignedEnvelope,
  isSignedEnvelope,
  signPayload,
  verifyEnvelope,
  readSignedJsonFile,
  writeSignedJsonFile,
  resolveStoreSigner,
  parseSignerKey,
  generateSignerKeyHex,
} from './store-signer.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const KEY_A = parseSignerKey(generateSignerKeyHex());
const KEY_B = parseSignerKey(generateSignerKeyHex()); // foreign key

describe('canonicalJson + hmac', () => {
  it('sorts object keys so sign order is stable', () => {
    assert.equal(
      canonicalJson({ b: 1, a: { d: 2, c: 3 } }),
      canonicalJson({ a: { c: 3, d: 2 }, b: 1 }),
    );
  });

  it('hmacSign is one-shot reusable across many calls', () => {
    const p = canonicalJson({ x: 1 });
    const s1 = hmacSign(KEY_A, p);
    const s2 = hmacSign(KEY_A, p);
    assert.equal(s1, s2);
    assert.equal(hmacVerify(KEY_A, p, s1), true);
    assert.equal(hmacVerify(KEY_B, p, s1), false);
  });
});

describe('createLocalHmacSigner envelope', () => {
  const signer = createLocalHmacSigner(KEY_A);
  const foreign = createLocalHmacSigner(KEY_B);

  it('sign + verify round-trip', async () => {
    const payload = { pins: { 'oauth:x': { handle: 'term_1' } } };
    const signed = await signPayload(payload, signer);
    assert.equal(signed.ok, true);
    assert.equal(isSignedEnvelope(signed.envelope), true);
    assert.equal(signed.envelope.v, STORE_SIG_VERSION);
    assert.equal(signed.envelope.alg, STORE_SIG_ALG);
    assert.equal(typeof signed.envelope.n, 'number');
    assert.equal(typeof signed.envelope.ts, 'number');
    const v = await verifyEnvelope(signed.envelope, signer);
    assert.equal(v.ok, true);
    assert.deepEqual(v.payload, payload);
  });

  it('rejects unsigned payload', async () => {
    const v = await verifyEnvelope({ oauth: { handle: 'term_forged' } }, signer);
    assert.equal(v.ok, false);
    assert.equal(v.reason, SIGNED_STORE_UNSIGNED);
  });

  it('rejects foreign-key signature', async () => {
    const payload = { bindings: [{ dispatchId: 'ctx_1', clientKey: 'oauth:evil' }] };
    const signed = await signPayload(payload, foreign);
    const v = await verifyEnvelope(signed.envelope, signer);
    assert.equal(v.ok, false);
    assert.equal(v.reason, SIGNED_STORE_BAD_SIG);
  });

  it('rejects tampered payload with intact-looking sig field', async () => {
    const payload = { a: 1 };
    const signed = await signPayload(payload, signer);
    signed.envelope.payload = { a: 2 };
    const v = await verifyEnvelope(signed.envelope, signer);
    assert.equal(v.ok, false);
    assert.equal(v.reason, SIGNED_STORE_BAD_SIG);
  });

  it('rejects malformed envelope', async () => {
    const v = await verifyEnvelope({ v: 1, alg: STORE_SIG_ALG, payload: {}, sig: 12 }, signer);
    assert.equal(v.ok, false);
    assert.ok(v.reason === SIGNED_STORE_MALFORMED || v.reason === SIGNED_STORE_UNSIGNED);
  });

  it('rejects v1 envelope even with a valid payload-only MAC', async () => {
    const payload = { a: 1 };
    const v1sig = hmacSign(KEY_A, canonicalJson(payload));
    const v1 = { v: 1, alg: STORE_SIG_ALG, payload, sig: v1sig };
    assert.equal(isV1SignedEnvelope(v1), true);
    assert.equal(isSignedEnvelope(v1), false);
    const v = await verifyEnvelope(v1, signer);
    assert.equal(v.ok, false);
    assert.equal(v.reason, SIGNED_STORE_MALFORMED);
  });

  it('rejects missing n', async () => {
    const signed = await signPayload({ a: 1 }, signer);
    delete signed.envelope.n;
    const v = await verifyEnvelope(signed.envelope, signer);
    assert.equal(v.ok, false);
    assert.equal(v.reason, SIGNED_STORE_MALFORMED);
  });

  it('replay of a previously valid v2 envelope after a newer sign is stale', async () => {
    const first = await signPayload({ k: 1 }, signer, { storeId: 'pins' });
    const second = await signPayload({ k: 2 }, signer, { storeId: 'pins' });
    assert.equal(second.envelope.n > first.envelope.n, true);
    const later = await verifyEnvelope(second.envelope, signer, { storeId: 'pins' });
    assert.equal(later.ok, true);
    const replay = await verifyEnvelope(first.envelope, signer, { storeId: 'pins' });
    assert.equal(replay.ok, false);
    assert.equal(replay.reason, SIGNED_STORE_STALE);
  });

  it('legitimate re-sign advances n and accepts', async () => {
    const a = await signPayload({ x: 1 }, signer, { storeId: 'ownership' });
    const b = await signPayload({ x: 2 }, signer, { storeId: 'ownership' });
    assert.equal(b.envelope.n, a.envelope.n + 1);
    const v = await verifyEnvelope(b.envelope, signer, { storeId: 'ownership' });
    assert.equal(v.ok, true);
    assert.deepEqual(v.payload, { x: 2 });
  });
});

describe('unix socket signer daemon', () => {
  let dir;
  let sock;
  let daemon;
  let client;

  before(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-signer-'));
    sock = path.join(dir, 'signer.sock');
    daemon = createSignerDaemon({ key: KEY_A, socketPath: sock });
    await new Promise((resolve, reject) => {
      daemon.server.once('listening', resolve);
      daemon.server.once('error', reject);
    });
    client = createSocketSigner(sock);
  });

  after(async () => {
    if (daemon) await daemon.close();
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('sign/verify over NDJSON socket', async () => {
    const payload = { hello: 'world', count: 3 };
    const s = await client.sign(payload, { storeId: 'pins' });
    assert.equal(s.ok, true);
    assert.equal(typeof s.n, 'number');
    const v = await client.verify(payload, s.sig, { n: s.n, ts: s.ts, storeId: 'pins' });
    assert.equal(v.ok, true);
    assert.equal(v.valid, true);
    const bad = await client.verify({ hello: 'nope' }, s.sig, { n: s.n, ts: s.ts, storeId: 'pins' });
    assert.equal(bad.valid, false);
  });

  it('socket daemon rejects stale n after a newer sign', async () => {
    const first = await client.sign({ a: 1 }, { storeId: 'ownership' });
    await client.sign({ a: 2 }, { storeId: 'ownership' });
    const replay = await client.verify({ a: 1 }, first.sig, {
      n: first.n,
      ts: first.ts,
      storeId: 'ownership',
    });
    assert.equal(replay.valid, false);
    assert.equal(replay.reason, SIGNED_STORE_STALE);
  });

  it('handleSignerRequest rejects unknown op', () => {
    const r = handleSignerRequest({ op: 'mint-root', id: 1 }, KEY_A);
    assert.equal(r.ok, false);
  });
});

describe('signed JSON files — forge rejection (one per store)', () => {
  let dir;
  const signer = createLocalHmacSigner(KEY_A);
  const attacker = createLocalHmacSigner(KEY_B);

  before(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-signed-store-'));
  });

  after(() => {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('NAS-253: forged ~/.orca-bridge-sender-pins.json is rejected', async () => {
    const pinPath = path.join(dir, '.orca-bridge-sender-pins.json');
    // Honest write first (proves the happy path works).
    const honest = {
      'oauth:legit': {
        handle: 'term_coord_legit',
        title: 'coord',
        source: 'pinned',
        at: '2026-08-14T00:00:00.000Z',
      },
    };
    const w = await writeSignedJsonFile(pinPath, honest, signer);
    assert.equal(w.ok, true);
    const ok = await readSignedJsonFile(pinPath, signer);
    assert.equal(ok.ok, true);
    assert.equal(ok.payload['oauth:legit'].handle, 'term_coord_legit');

    // Attacker forges the pin map under the same uid (no signer key).
    fs.writeFileSync(
      pinPath,
      JSON.stringify({
        'oauth:attacker': {
          handle: 'term_stolen_coord',
          title: 'pwned',
          source: 'forged',
          at: '2026-08-14T00:00:01.000Z',
        },
      }),
      { mode: 0o600 },
    );
    const forged = await readSignedJsonFile(pinPath, signer);
    assert.equal(forged.ok, false);
    assert.equal(forged.reason, SIGNED_STORE_UNSIGNED);

    // Attacker signs with a foreign key — still rejected.
    const foreign = await signPayload(
      {
        'oauth:attacker': { handle: 'term_stolen_coord', title: 'pwned', source: 'forged' },
      },
      attacker,
    );
    fs.writeFileSync(pinPath, JSON.stringify(foreign.envelope), { mode: 0o600 });
    const foreignRead = await readSignedJsonFile(pinPath, signer);
    assert.equal(foreignRead.ok, false);
    assert.equal(foreignRead.reason, SIGNED_STORE_BAD_SIG);
  });

  it('NAS-249: forged ~/.orca-bridge/dispatch-ownership.json is rejected', async () => {
    const ownPath = path.join(dir, 'dispatch-ownership.json');
    const honest = {
      version: 1,
      updatedAt: '2026-08-14T00:00:00.000Z',
      bindings: [
        {
          dispatchId: 'ctx_legit',
          clientKey: 'oauth:legit',
          runId: 'run_1',
          taskId: 'task_1',
          terminalHandle: 'term_worker_1',
          status: 'running',
        },
      ],
    };
    const w = await writeSignedJsonFile(ownPath, honest, signer);
    assert.equal(w.ok, true);
    const ok = await readSignedJsonFile(ownPath, signer);
    assert.equal(ok.ok, true);
    assert.equal(ok.payload.bindings[0].dispatchId, 'ctx_legit');

    // Attacker plants a binding claiming a foreign dispatch.
    fs.writeFileSync(
      ownPath,
      JSON.stringify({
        version: 1,
        updatedAt: '2026-08-14T00:00:02.000Z',
        bindings: [
          {
            dispatchId: 'ctx_victim',
            clientKey: 'oauth:attacker',
            runId: 'run_x',
            taskId: 'task_x',
            terminalHandle: 'term_x',
            status: 'running',
          },
        ],
      }, null, 2),
      { mode: 0o600 },
    );
    const forged = await readSignedJsonFile(ownPath, signer);
    assert.equal(forged.ok, false);
    assert.equal(forged.reason, SIGNED_STORE_UNSIGNED);

    // Foreign-key-signed forge.
    const foreign = await signPayload(
      {
        version: 1,
        bindings: [{ dispatchId: 'ctx_victim', clientKey: 'oauth:attacker' }],
      },
      attacker,
    );
    fs.writeFileSync(ownPath, JSON.stringify(foreign.envelope), { mode: 0o600 });
    const foreignRead = await readSignedJsonFile(ownPath, signer);
    assert.equal(foreignRead.ok, false);
    assert.equal(foreignRead.reason, SIGNED_STORE_BAD_SIG);
  });

  it('missing file is distinct from forge', async () => {
    const res = await readSignedJsonFile(path.join(dir, 'nope.json'), signer);
    assert.equal(res.ok, false);
    assert.equal(res.reason, SIGNED_STORE_MISSING);
  });
});

describe('resolveStoreSigner', () => {
  it('prefers socket over key env', () => {
    const s = resolveStoreSigner({
      ORCA_BRIDGE_STORE_SIGNER_SOCKET: '/tmp/x.sock',
      ORCA_BRIDGE_STORE_SIGNER_KEY: generateSignerKeyHex(),
    });
    assert.equal(s.kind, 'socket');
    assert.equal(s.socketPath, '/tmp/x.sock');
  });

  it('falls back to local key', () => {
    const hex = generateSignerKeyHex();
    const s = resolveStoreSigner({ ORCA_BRIDGE_STORE_SIGNER_KEY: hex });
    assert.equal(s.kind, 'local-hmac');
  });

  it('returns null when neither configured', () => {
    assert.equal(resolveStoreSigner({}), null);
  });
});

describe('NAS-257 signer unit has no ExecStartPost', () => {
  const unitPath = path.join(HERE, '..', 'deploy/linux/orca-bridge-store-signer.service');
  const daemonPath = path.join(HERE, '..', 'scripts/store-signer-daemon.mjs');

  it('unit file has no ExecStartPost (race with Type=simple)', () => {
    const unit = fs.readFileSync(unitPath, 'utf8');
    assert.equal(
      /^\s*ExecStartPost=/m.test(unit),
      false,
      'ExecStartPost races async listen() under Type=simple',
    );
    assert.match(unit, /^Type=simple$/m);
    assert.match(unit, /^ProtectHome=true$/m);
    assert.match(unit, /^NoNewPrivileges=true$/m);
    assert.match(unit, /^ProtectSystem=strict$/m);
    assert.match(unit, /^WorkingDirectory=\/opt\/orca-mcp$/m);
  });

  it('daemon chmodSync 0660 after listen()', () => {
    const src = fs.readFileSync(daemonPath, 'utf8');
    assert.match(src, /server\.on\(\s*'listening'/);
    assert.match(src, /chmodSync\(\s*socketPath\s*,\s*0o660\s*\)/);
  });
});

describe('makeSignedEnvelope shape', () => {
  it('isSignedEnvelope rejects bare store objects', () => {
    assert.equal(isSignedEnvelope({ 'oauth:x': { handle: 't' } }), false);
    assert.equal(
      isSignedEnvelope(makeSignedEnvelope({ a: 1 }, 'sig', { n: 1, ts: 1 })),
      true,
    );
    assert.equal(
      isSignedEnvelope(makeSignedEnvelope({ a: 1 }, 'sig')),
      false,
    );
  });
});
