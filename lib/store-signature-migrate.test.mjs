/**
 * One-shot unsigned → signed ownership store migrator.
 *
 * Fail-closed runtime load is unchanged: unsigned stores stay rejected until
 * an operator runs the migrator. These tests pin that contract.
 *
 * C5 forgery bound:
 * - Already-signed envelope with bad/foreign sig → refuse (no overwrite).
 * - Bare unsigned JSON has no MAC to check (0.3.0 legacy). Migrator will sign
 *   it; residual risk requires the bridge stopped so no concurrent attacker
 *   write races the read→sign→write window. Documented, not papered over.
 */
import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  SIGNED_STORE_UNSIGNED,
  SIGNED_STORE_BAD_SIG,
  STORE_SIG_ALG,
  hmacSign,
  canonicalJson,
  createLocalHmacSigner,
  createSocketSigner,
  generateSignerKeyHex,
  parseSignerKey,
  readSignedJsonFile,
  signPayload,
} from './store-signer.mjs';
import {
  DEFAULT_OWNERSHIP_BASENAME,
  DEFAULT_PINS_BASENAME,
  migrateUnsignedStores,
  resolveMigrateStorePaths,
} from './store-signature-migrate.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'scripts', 'migrate-store-signatures.mjs');
const DAEMON = path.join(HERE, '..', 'scripts', 'store-signer-daemon.mjs');
const KEY = parseSignerKey(generateSignerKeyHex());
const FOREIGN_KEY = parseSignerKey(generateSignerKeyHex());


const LEGACY_PINS = {
  'oauth:coord': {
    handle: 'term_coord_live',
    title: 'coord',
    source: 'pinned',
    at: '2026-08-13T12:00:00.000Z',
  },
};

const LEGACY_OWNERSHIP = {
  version: 1,
  updatedAt: '2026-08-13T12:00:00.000Z',
  bindings: [
    {
      dispatchId: 'ctx_live',
      clientKey: 'oauth:coord',
      runId: 'run_live',
      taskId: 'task_live',
      terminalHandle: 'term_worker_live',
      status: 'running',
    },
  ],
};

const FORGED_UNSIGNED_PINS = {
  'oauth:attacker': {
    handle: 'term_stolen',
    title: 'pwned',
    source: 'forged',
    at: '2026-08-14T00:00:01.000Z',
  },
};

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function readRaw(filePath) {
  return fs.readFileSync(filePath, 'utf8');
}

describe('resolveMigrateStorePaths', () => {
  it('defaults to HOME pins + ~/.orca-bridge/dispatch-ownership.json', () => {
    const home = '/tmp/iso-home-migrate';
    const paths = resolveMigrateStorePaths({ home });
    assert.equal(paths.pinsPath, path.join(home, DEFAULT_PINS_BASENAME));
    assert.equal(
      paths.ownershipPath,
      path.join(home, '.orca-bridge', DEFAULT_OWNERSHIP_BASENAME),
    );
  });

  it('honours ORCA_BRIDGE_AUDIT_DIR for ownership store only', () => {
    const home = '/tmp/iso-home-migrate';
    const auditDir = '/tmp/iso-audit-dir';
    const paths = resolveMigrateStorePaths({ home, auditDir });
    assert.equal(paths.pinsPath, path.join(home, DEFAULT_PINS_BASENAME));
    assert.equal(paths.ownershipPath, path.join(auditDir, DEFAULT_OWNERSHIP_BASENAME));
  });
});

describe('migrateUnsignedStores — bridge load path contracts', () => {
  /** @type {string} */
  let home;
  /** @type {ReturnType<typeof createLocalHmacSigner>} */
  let signer;
  /** @type {string} */
  let pinsPath;
  /** @type {string} */
  let ownershipPath;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-migrate-home-'));
    signer = createLocalHmacSigner(KEY);
    const paths = resolveMigrateStorePaths({ home });
    pinsPath = paths.pinsPath;
    ownershipPath = paths.ownershipPath;
  });

  afterEach(() => {
    try { fs.rmSync(home, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('C2 fail-closed: unsigned fixture is REJECTED by bridge load path without migration', async () => {
    writeJson(pinsPath, LEGACY_PINS);
    writeJson(ownershipPath, LEGACY_OWNERSHIP);

    const pins = await readSignedJsonFile(pinsPath, signer);
    assert.equal(pins.ok, false);
    assert.equal(pins.reason, SIGNED_STORE_UNSIGNED);

    const ownership = await readSignedJsonFile(ownershipPath, signer);
    assert.equal(ownership.ok, false);
    assert.equal(ownership.reason, SIGNED_STORE_UNSIGNED);
  });

  it('C1: after migration, the same unsigned fixture is ACCEPTED by bridge load path', async () => {
    writeJson(pinsPath, LEGACY_PINS);
    writeJson(ownershipPath, LEGACY_OWNERSHIP);

    const result = await migrateUnsignedStores({
      home,
      signer,
      dryRun: false,
    });
    assert.equal(result.ok, true);
    assert.equal(result.files.pins.action, 'signed');
    assert.equal(result.files.ownership.action, 'signed');

    const pins = await readSignedJsonFile(pinsPath, signer);
    assert.equal(pins.ok, true);
    assert.equal(pins.payload['oauth:coord'].handle, 'term_coord_live');

    const ownership = await readSignedJsonFile(ownershipPath, signer);
    assert.equal(ownership.ok, true);
    assert.equal(ownership.payload.bindings[0].dispatchId, 'ctx_live');
  });

  it('C3: second migration is a no-op (idempotent)', async () => {
    writeJson(pinsPath, LEGACY_PINS);
    writeJson(ownershipPath, LEGACY_OWNERSHIP);

    const first = await migrateUnsignedStores({ home, signer, dryRun: false });
    assert.equal(first.ok, true);
    const afterFirstPins = readRaw(pinsPath);
    const afterFirstOwn = readRaw(ownershipPath);

    const second = await migrateUnsignedStores({ home, signer, dryRun: false });
    assert.equal(second.ok, true);
    assert.equal(second.files.pins.action, 'already-signed');
    assert.equal(second.files.ownership.action, 'already-signed');
    assert.equal(readRaw(pinsPath), afterFirstPins);
    assert.equal(readRaw(ownershipPath), afterFirstOwn);
  });

  it('dry-run reports would-sign and changes nothing', async () => {
    writeJson(pinsPath, LEGACY_PINS);
    const before = readRaw(pinsPath);
    const result = await migrateUnsignedStores({ home, signer, dryRun: true });
    assert.equal(result.ok, true);
    assert.equal(result.dryRun, true);
    assert.equal(result.files.pins.action, 'would-sign');
    assert.equal(readRaw(pinsPath), before);
    const still = await readSignedJsonFile(pinsPath, signer);
    assert.equal(still.ok, false);
    assert.equal(still.reason, SIGNED_STORE_UNSIGNED);
  });

  it('absent or empty stores do not crash', async () => {
    fs.mkdirSync(path.dirname(ownershipPath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(ownershipPath, '', { mode: 0o600 });

    const result = await migrateUnsignedStores({ home, signer, dryRun: false });
    assert.equal(result.ok, true);
    assert.equal(result.files.pins.action, 'missing');
    assert.ok(
      result.files.ownership.action === 'empty' ||
        result.files.ownership.action === 'missing' ||
        result.files.ownership.action === 'skipped-empty',
    );
    assert.equal(fs.existsSync(pinsPath), false);
  });

  it('backs up original file before writing signed envelope', async () => {
    writeJson(pinsPath, LEGACY_PINS);
    const result = await migrateUnsignedStores({ home, signer, dryRun: false });
    assert.equal(result.ok, true);
    assert.equal(typeof result.files.pins.backupPath, 'string');
    assert.ok(fs.existsSync(result.files.pins.backupPath));
    const backup = JSON.parse(fs.readFileSync(result.files.pins.backupPath, 'utf8'));
    assert.deepEqual(backup, LEGACY_PINS);
  });

  it('C4: fails loudly when signer socket is unreachable (no silent no-op)', async () => {
    writeJson(pinsPath, LEGACY_PINS);
    const deadSocket = path.join(home, 'no-such-signer.sock');
    const unreachable = createSocketSigner(deadSocket, { timeoutMs: 200 });

    const result = await migrateUnsignedStores({
      home,
      signer: unreachable,
      dryRun: false,
    });
    assert.equal(result.ok, false);
    assert.match(String(result.error || result.reason || ''), /signer|unreachable|ECONNREFUSED|ENOENT|timeout/i);
    const still = await readSignedJsonFile(pinsPath, signer);
    assert.equal(still.ok, false);
    assert.equal(still.reason, SIGNED_STORE_UNSIGNED);
  });

  it('C5 bound: foreign-key signed forge is NOT re-signed into a valid record', async () => {
    const attacker = createLocalHmacSigner(FOREIGN_KEY);
    const forged = await signPayload(FORGED_UNSIGNED_PINS, attacker);
    assert.equal(forged.ok, true);
    fs.writeFileSync(pinsPath, `${JSON.stringify(forged.envelope, null, 2)}\n`, { mode: 0o600 });

    const before = await readSignedJsonFile(pinsPath, signer);
    assert.equal(before.ok, false);
    assert.equal(before.reason, SIGNED_STORE_BAD_SIG);

    const result = await migrateUnsignedStores({ home, signer, dryRun: false });
    assert.equal(result.files.pins.action, 'refused-bad-signature');
    assert.notEqual(result.files.pins.action, 'signed');
    // Overall must not claim full success when a present store was refused.
    assert.equal(result.ok, false);

    const after = await readSignedJsonFile(pinsPath, signer);
    assert.equal(after.ok, false);
    assert.equal(after.reason, SIGNED_STORE_BAD_SIG);
    assert.equal(JSON.parse(readRaw(pinsPath)).sig, forged.envelope.sig);
  });

  it('C5 residual: bare unsigned attacker JSON has no MAC — only safe with bridge stopped', async () => {
    // Pre-signer 0.3.0 stores have no integrity tag. Migrator signs bare JSON
    // payloads (reason===unsigned). That is intentional and residual-risk:
    // cutover must stop the bridge first so a concurrent same-uid attacker
    // cannot race a forge into the file between read and sign.
    writeJson(pinsPath, FORGED_UNSIGNED_PINS);
    const result = await migrateUnsignedStores({ home, signer, dryRun: false });
    assert.equal(result.ok, true);
    assert.equal(result.files.pins.action, 'signed');
    assert.equal(result.files.pins.legacyUnsignedTrust, true);

    const accepted = await readSignedJsonFile(pinsPath, signer);
    assert.equal(accepted.ok, true);
    assert.equal(accepted.payload['oauth:attacker'].handle, 'term_stolen');
  });

  it('valid v1 envelope is re-signed as v2; invalid v1 is refused', async () => {
    const v1sig = hmacSign(KEY, canonicalJson(LEGACY_PINS));
    writeJson(pinsPath, {
      v: 1,
      alg: STORE_SIG_ALG,
      payload: LEGACY_PINS,
      sig: v1sig,
    });
    const first = await migrateUnsignedStores({ home, signer, dryRun: false });
    assert.equal(first.ok, true);
    assert.equal(first.files.pins.action, 'upgraded-v1');
    const loaded = await readSignedJsonFile(pinsPath, signer);
    assert.equal(loaded.ok, true);
    assert.equal(loaded.payload['oauth:coord'].handle, 'term_coord_live');

    writeJson(pinsPath, {
      v: 1,
      alg: STORE_SIG_ALG,
      payload: FORGED_UNSIGNED_PINS,
      sig: 'not-a-real-mac',
    });
    const bad = await migrateUnsignedStores({ home, signer, dryRun: false });
    assert.equal(bad.files.pins.action, 'refused-bad-signature');
    assert.equal(bad.ok, false);
  });
});

describe('migrate-store-signatures CLI', () => {
  /** @type {string} */
  let home;
  /** @type {string} */
  let keyHex;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-migrate-cli-'));
    keyHex = generateSignerKeyHex();
  });

  afterEach(() => {
    try { fs.rmSync(home, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('CLI dry-run exits 0 and leaves unsigned store rejected', async () => {
    const pinsPath = path.join(home, DEFAULT_PINS_BASENAME);
    writeJson(pinsPath, LEGACY_PINS);
    const r = spawnSync(process.execPath, [CLI, '--dry-run', '--home', home], {
      env: {
        ...process.env,
        ORCA_BRIDGE_STORE_SIGNER_KEY: keyHex,
        ORCA_BRIDGE_STORE_SIGNER_SOCKET: '',
      },
      encoding: 'utf8',
    });
    assert.equal(r.status, 0, r.stderr || r.stdout);
    assert.match(r.stdout + r.stderr, /would-sign|dry-run/i);
    const signer = createLocalHmacSigner(parseSignerKey(keyHex));
    const res = await readSignedJsonFile(pinsPath, signer);
    assert.equal(res.ok, false);
    assert.equal(res.reason, SIGNED_STORE_UNSIGNED);
  });

  it('CLI exits non-zero when signer socket is unreachable', () => {
    const pinsPath = path.join(home, DEFAULT_PINS_BASENAME);
    writeJson(pinsPath, LEGACY_PINS);
    const dead = path.join(home, 'missing.sock');
    const r = spawnSync(process.execPath, [CLI, '--home', home], {
      env: {
        ...process.env,
        ORCA_BRIDGE_STORE_SIGNER_SOCKET: dead,
        ORCA_BRIDGE_STORE_SIGNER_KEY: '',
      },
      encoding: 'utf8',
    });
    assert.notEqual(r.status, 0);
    assert.match(r.stdout + r.stderr, /signer|unreachable|ECONNREFUSED|ENOENT|timeout|refusing/i);
  });

  it('CLI signs via live socket signer daemon', async () => {
    // Daemon must be a separate process: spawnSync would block this event loop
    // and an in-process createSignerDaemon could not answer.
    const sock = path.join(home, 'signer.sock');
    const keyFile = path.join(home, 'hmac.key');
    fs.writeFileSync(keyFile, `${keyHex}\n`, { mode: 0o600 });
    const child = spawn(process.execPath, [DAEMON], {
      env: {
        ...process.env,
        ORCA_BRIDGE_STORE_SIGNER_SOCKET: sock,
        ORCA_BRIDGE_STORE_SIGNER_KEY_FILE: keyFile,
        ORCA_BRIDGE_STORE_SIGNER_KEY: '',
      },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (c) => { stderr += c; });
    try {
      await new Promise((resolve, reject) => {
        const t0 = Date.now();
        const tick = () => {
          if (fs.existsSync(sock)) return resolve();
          if (Date.now() - t0 > 5000) {
            return reject(new Error(`daemon sock missing: ${stderr}`));
          }
          setTimeout(tick, 20);
        };
        child.once('error', reject);
        child.once('exit', (code) => {
          reject(new Error(`daemon exited ${code}: ${stderr}`));
        });
        tick();
      });

      const pinsPath = path.join(home, DEFAULT_PINS_BASENAME);
      writeJson(pinsPath, LEGACY_PINS);
      const r = spawnSync(process.execPath, [CLI, '--home', home], {
        env: {
          ...process.env,
          ORCA_BRIDGE_STORE_SIGNER_SOCKET: sock,
          ORCA_BRIDGE_STORE_SIGNER_KEY: '',
        },
        encoding: 'utf8',
      });
      assert.equal(r.status, 0, r.stderr || r.stdout);
      const client = createSocketSigner(sock, { timeoutMs: 1000 });
      const loaded = await readSignedJsonFile(pinsPath, client);
      assert.equal(loaded.ok, true);
      assert.equal(loaded.payload['oauth:coord'].handle, 'term_coord_live');
    } finally {
      try { child.kill('SIGTERM'); } catch { /* ignore */ }
      await new Promise((resolve) => {
        if (child.exitCode != null || child.signalCode != null) return resolve();
        child.once('exit', () => resolve());
        setTimeout(() => {
          try { child.kill('SIGKILL'); } catch { /* ignore */ }
          resolve();
        }, 1000);
      });
      try { fs.rmSync(sock, { force: true }); } catch { /* ignore */ }
    }
  });
});
