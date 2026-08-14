import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  DEFAULT_WORKER_USER,
  WORKER_ISOLATION_ENV,
  WORKER_USER_ENV,
  WORKER_UID_ENV,
  WORKER_LAUNCH_WRAPPER_ENV,
  WORKER_HMAC_SECRET_ENV,
  DEFAULT_LINUX_LAUNCH_WRAPPER,
  DEFAULT_CAPABILITY_TTL_SEC,
  resolveWorkerIsolationConfig,
  listBridgeSecretPaths,
  classifyWorkerSecretAccess,
  inspectWorkerSecretAccess,
  assertWorkerDeniedBridgeSecrets,
  shouldWrapAgentLaunch,
  buildWorkerLaunchCommand,
  planIsolatedAgentPlacement,
  buildIsolatedTerminalCreateArgv,
  canonicalCapabilityPayload,
  mintWorkerCapability,
  verifyWorkerCapability,
  workerCapabilityEnv,
  WORKER_UID_ATTACK_CATALOGUE,
  evaluateAttackAsWorker,
  evaluateAttackCatalogueAsWorker,
  workerIsolationHealth,
} from './worker-isolation.mjs';

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

describe('resolveWorkerIsolationConfig', () => {
  it('defaults isolation off (legacy same-uid workers)', () => {
    const c = resolveWorkerIsolationConfig({}, { getuid: () => 997, platform: 'linux' });
    assert.equal(c.enabled, false);
    assert.equal(c.active, false);
    assert.equal(c.workerUser, DEFAULT_WORKER_USER);
    assert.equal(c.launchWrapper, DEFAULT_LINUX_LAUNCH_WRAPPER);
    assert.equal(c.bridgeUid, 997);
  });

  it('enables only when ORCA_BRIDGE_WORKER_ISOLATION=1', () => {
    const off = resolveWorkerIsolationConfig(
      { [WORKER_ISOLATION_ENV]: 'true' },
      { getuid: () => 997, platform: 'linux' },
    );
    assert.equal(off.enabled, false);
    const on = resolveWorkerIsolationConfig(
      {
        [WORKER_ISOLATION_ENV]: '1',
        [WORKER_UID_ENV]: '1501',
        [WORKER_HMAC_SECRET_ENV]: 's'.repeat(32),
      },
      { getuid: () => 997, platform: 'linux' },
    );
    assert.equal(on.enabled, true);
    assert.equal(on.active, true);
    assert.equal(on.workerUid, 1501);
    assert.equal(on.sameUid, false);
    assert.equal(on.hmacSecret.length, 32);
  });

  it('detects sameUid misconfig', () => {
    const c = resolveWorkerIsolationConfig(
      {
        [WORKER_ISOLATION_ENV]: '1',
        [WORKER_UID_ENV]: '997',
      },
      { getuid: () => 997, platform: 'linux' },
    );
    assert.equal(c.sameUid, true);
    assert.equal(shouldWrapAgentLaunch('omp', c), false);
  });

  it('honours custom wrapper + user name', () => {
    const c = resolveWorkerIsolationConfig(
      {
        [WORKER_ISOLATION_ENV]: '1',
        [WORKER_USER_ENV]: 'agents',
        [WORKER_LAUNCH_WRAPPER_ENV]: '/opt/bin/wrap-agent',
      },
      { getuid: () => 1, platform: 'linux' },
    );
    assert.equal(c.workerUser, 'agents');
    assert.equal(c.launchWrapper, '/opt/bin/wrap-agent');
  });
});

// ---------------------------------------------------------------------------
// FS denial (bridge secrets)
// ---------------------------------------------------------------------------

describe('classifyWorkerSecretAccess', () => {
  const bridgeUid = 997;
  const workerUid = 1501;

  it('missing secret is blocked (nothing to leak)', () => {
    const v = classifyWorkerSecretAccess({
      path: '/home/orca/.orca-bridge-tokens.json',
      exists: false,
      workerUid,
    });
    assert.equal(v.code, 'missing');
    assert.equal(v.blocked, true);
    assert.equal(v.ok, true);
  });

  it('bridge-owned 0600 is blocked for worker', () => {
    const v = classifyWorkerSecretAccess({
      path: '/home/orca/.orca-bridge-tokens.json',
      exists: true,
      uid: bridgeUid,
      gid: bridgeUid,
      mode: 0o100600,
      workerUid,
      workerGid: workerUid,
    });
    assert.equal(v.code, 'blocked');
    assert.equal(v.canRead, false);
    assert.equal(v.canWrite, false);
    assert.equal(v.ok, true);
  });

  it('bridge-owned audit dir 0700 is blocked for worker', () => {
    const v = classifyWorkerSecretAccess({
      path: '/home/orca/.orca-bridge',
      exists: true,
      uid: bridgeUid,
      gid: bridgeUid,
      mode: 0o040700,
      isDirectory: true,
      workerUid,
      workerGid: workerUid,
    });
    assert.equal(v.code, 'blocked');
    assert.equal(v.ok, true);
  });

  it('world-readable secret is exposed', () => {
    const v = classifyWorkerSecretAccess({
      path: '/home/orca/.orca-bridge-sender-pins.json',
      exists: true,
      uid: bridgeUid,
      gid: bridgeUid,
      mode: 0o100644,
      workerUid,
      workerGid: workerUid,
    });
    assert.equal(v.code, 'exposed');
    assert.equal(v.canRead, true);
    assert.equal(v.ok, false);
  });

  it('worker-owned secret is exposed (same-uid class)', () => {
    const v = classifyWorkerSecretAccess({
      path: '/home/orca/.orca-bridge-sender-pins.json',
      exists: true,
      uid: workerUid,
      gid: workerUid,
      mode: 0o100600,
      workerUid,
    });
    assert.equal(v.code, 'exposed');
    assert.equal(v.canWrite, true);
  });

  it('shared-group readable secret is exposed', () => {
    const v = classifyWorkerSecretAccess({
      path: '/home/orca/.orca-bridge-tokens.json',
      exists: true,
      uid: bridgeUid,
      gid: 42,
      mode: 0o100640,
      workerUid,
      workerGid: 42,
    });
    assert.equal(v.code, 'exposed');
    assert.equal(v.canRead, true);
  });
});

describe('assertWorkerDeniedBridgeSecrets (hermetic fs)', () => {
  it('reports ok when every secret is owner-only bridge-owned', () => {
    const home = '/home/bridge';
    const files = new Map([
      [
        path.join(home, '.orca-bridge-tokens.json'),
        { uid: 997, gid: 997, mode: 0o100600, isDirectory: () => false },
      ],
      [
        path.join(home, '.orca-bridge-sender-pins.json'),
        { uid: 997, gid: 997, mode: 0o100600, isDirectory: () => false },
      ],
      [
        path.join(home, '.orca-bridge'),
        { uid: 997, gid: 997, mode: 0o040700, isDirectory: () => true },
      ],
      [
        path.join(home, '.orca-bridge', 'dispatch-ownership.json'),
        { uid: 997, gid: 997, mode: 0o100600, isDirectory: () => false },
      ],
      [
        path.join(home, '.orca-bridge', 'audit.ndjson'),
        { uid: 997, gid: 997, mode: 0o100600, isDirectory: () => false },
      ],
      [
        path.join(home, '.config', 'orca', 'orca-runtime.json'),
        { uid: 997, gid: 997, mode: 0o100600, isDirectory: () => false },
      ],
      [
        path.join(home, '.config', 'orca', 'daemon', 'daemon-v32.token'),
        { uid: 997, gid: 997, mode: 0o100600, isDirectory: () => false },
      ],
    ]);
    const fsImpl = {
      statSync(p) {
        const st = files.get(p);
        if (!st) {
          const err = new Error('ENOENT');
          err.code = 'ENOENT';
          throw err;
        }
        return st;
      },
    };
    const r = assertWorkerDeniedBridgeSecrets({
      homeDir: home,
      workerUid: 1501,
      workerGid: 1501,
      fsImpl,
    });
    assert.equal(r.ok, true, JSON.stringify(r.exposed, null, 2));
    assert.equal(r.exposed.length, 0);
  });

  it('fails when sender-pins is world-readable', () => {
    const home = '/home/bridge';
    const pins = path.join(home, '.orca-bridge-sender-pins.json');
    const fsImpl = {
      statSync(p) {
        if (p === pins) {
          return { uid: 997, gid: 997, mode: 0o100644, isDirectory: () => false };
        }
        const err = new Error('ENOENT');
        err.code = 'ENOENT';
        throw err;
      },
    };
    const r = assertWorkerDeniedBridgeSecrets({
      homeDir: home,
      workerUid: 1501,
      fsImpl,
    });
    assert.equal(r.ok, false);
    assert.ok(r.exposed.some((e) => e.path === pins));
  });
});

describe('listBridgeSecretPaths', () => {
  it('covers tokens, pins, audit dir, ownership store, runtime token', () => {
    const paths = listBridgeSecretPaths('/home/orca');
    assert.ok(paths.includes('/home/orca/.orca-bridge-tokens.json'));
    assert.ok(paths.includes('/home/orca/.orca-bridge-sender-pins.json'));
    assert.ok(paths.includes('/home/orca/.orca-bridge'));
    assert.ok(paths.includes('/home/orca/.orca-bridge/dispatch-ownership.json'));
    assert.ok(paths.includes('/home/orca/.orca-bridge/audit.ndjson'));
    assert.ok(paths.some((p) => p.endsWith('orca-runtime.json')));
    assert.ok(paths.some((p) => p.endsWith('daemon-v32.token')));
  });
});

// ---------------------------------------------------------------------------
// launch wrap
// ---------------------------------------------------------------------------

describe('planIsolatedAgentPlacement', () => {
  const cfgOn = resolveWorkerIsolationConfig(
    {
      [WORKER_ISOLATION_ENV]: '1',
      [WORKER_UID_ENV]: '1501',
      [WORKER_LAUNCH_WRAPPER_ENV]: '/usr/local/lib/orca-mcp/orca-omp-as-worker.sh',
      [WORKER_HMAC_SECRET_ENV]: 'x'.repeat(32),
    },
    { getuid: () => 997, platform: 'linux' },
  );

  it('legacy mode when isolation off — no wrap', () => {
    const cfgOff = resolveWorkerIsolationConfig({}, { getuid: () => 997, platform: 'linux' });
    const p = planIsolatedAgentPlacement(
      { worktree: 'new-top-level', agent: 'omp', name: 'n', repo: 'path:/r' },
      cfgOff,
    );
    assert.equal(p.mode, 'legacy-agent');
    assert.equal(p.launchCommand, null);
  });

  it('isolated: worktree create WITHOUT --agent, then wrapper command', () => {
    const p = planIsolatedAgentPlacement(
      {
        worktree: 'new-top-level',
        agent: 'omp',
        name: 'nas255',
        repo: 'path:/home/orca/src/orca-mcp',
        setup: 'skip',
      },
      cfgOn,
    );
    assert.equal(p.mode, 'isolated-command');
    assert.ok(p.worktreeArgv);
    assert.equal(p.worktreeArgv.includes('--agent'), false);
    assert.ok(p.worktreeArgv.includes('--no-parent'));
    assert.ok(p.worktreeArgv.includes('skip'));
    assert.match(p.launchCommand, /orca-omp-as-worker\.sh omp$/);
    const term = buildIsolatedTerminalCreateArgv({
      worktreeSelector: 'path:/tmp/wt',
      name: 'nas255',
      launchCommand: p.launchCommand,
    });
    assert.deepEqual(term.slice(0, 3), ['terminal', 'create', '--worktree']);
    assert.equal(term[term.indexOf('--command') + 1], p.launchCommand);
  });

  it('isolated current: terminal create --command wrapper only', () => {
    const p = planIsolatedAgentPlacement(
      {
        worktree: 'current',
        agent: 'grok',
        name: 't',
        repo: '/home/orca/repo',
      },
      cfgOn,
    );
    assert.equal(p.mode, 'isolated-command');
    assert.equal(p.worktreeArgv, null);
    assert.ok(p.terminalArgv);
    assert.equal(p.terminalArgv[p.terminalArgv.indexOf('--worktree') + 1], 'path:/home/orca/repo');
    assert.match(p.terminalArgv[p.terminalArgv.indexOf('--command') + 1], /grok$/);
  });

  it('buildWorkerLaunchCommand prefixes wrapper', () => {
    assert.equal(
      buildWorkerLaunchCommand('omp', cfgOn),
      '/usr/local/lib/orca-mcp/orca-omp-as-worker.sh omp',
    );
  });
});

// ---------------------------------------------------------------------------
// HMAC capability
// ---------------------------------------------------------------------------

describe('mintWorkerCapability / verifyWorkerCapability', () => {
  const secret = 'test-hmac-secret-not-for-production-use-32b';

  it('round-trips a valid capability', () => {
    const token = mintWorkerCapability(
      {
        dispatchId: 'ctx_abc',
        taskId: 'task_1',
        terminalHandle: 'term_w',
        clientKey: 'oauth:clientA',
        nowMs: 1_700_000_000_000,
      },
      secret,
    );
    assert.match(token, /^v1\./);
    const v = verifyWorkerCapability(token, secret, {
      nowMs: 1_700_000_000_000 + 1000,
      expectedDispatchId: 'ctx_abc',
      expectedTaskId: 'task_1',
      op: 'worker_done',
    });
    assert.equal(v.ok, true);
    assert.equal(v.payload.dispatchId, 'ctx_abc');
    assert.ok(v.payload.ops.includes('worker_done'));
  });

  it('rejects forged signature (worker cannot mint without secret)', () => {
    const token = mintWorkerCapability(
      { dispatchId: 'ctx_1', taskId: 'task_1', nowMs: 1_700_000_000_000 },
      secret,
    );
    const parts = token.split('.');
    const forged = `${parts[0]}.${parts[1]}.${Buffer.from('nope').toString('base64url')}`;
    const v = verifyWorkerCapability(forged, secret, { nowMs: 1_700_000_000_000 });
    assert.equal(v.ok, false);
    assert.equal(v.code, 'bad_signature');
  });

  it('rejects capability minted with wrong secret (clientKey forge path)', () => {
    const token = mintWorkerCapability(
      { dispatchId: 'ctx_1', taskId: 'task_1', clientKey: 'oauth:victim', nowMs: 1_700_000_000_000 },
      'attacker-guess',
    );
    const v = verifyWorkerCapability(token, secret, { nowMs: 1_700_000_000_000 });
    assert.equal(v.ok, false);
    assert.equal(v.code, 'bad_signature');
  });

  it('rejects expired capability', () => {
    const token = mintWorkerCapability(
      {
        dispatchId: 'ctx_1',
        taskId: 'task_1',
        ttlSec: 10,
        nowMs: 1_700_000_000_000,
      },
      secret,
    );
    const v = verifyWorkerCapability(token, secret, {
      nowMs: 1_700_000_000_000 + 60_000,
    });
    assert.equal(v.ok, false);
    assert.equal(v.code, 'expired');
  });

  it('rejects dispatchId mismatch (cannot reuse on foreign dispatch)', () => {
    const token = mintWorkerCapability(
      { dispatchId: 'ctx_own', taskId: 'task_1', nowMs: 1_700_000_000_000 },
      secret,
    );
    const v = verifyWorkerCapability(token, secret, {
      nowMs: 1_700_000_000_000,
      expectedDispatchId: 'ctx_FOREIGN',
    });
    assert.equal(v.ok, false);
    assert.equal(v.code, 'dispatch_mismatch');
  });

  it('rejects op not in allow list', () => {
    const token = mintWorkerCapability(
      {
        dispatchId: 'ctx_1',
        taskId: 'task_1',
        ops: ['worker_done'],
        nowMs: 1_700_000_000_000,
      },
      secret,
    );
    const v = verifyWorkerCapability(token, secret, {
      nowMs: 1_700_000_000_000,
      op: 'release',
    });
    assert.equal(v.ok, false);
    assert.equal(v.code, 'op_not_allowed');
  });

  it('canonical payload is key-sorted stable', () => {
    const a = canonicalCapabilityPayload({ b: 1, a: 2 });
    const b = canonicalCapabilityPayload({ a: 2, b: 1 });
    assert.equal(a, b);
    assert.equal(a, '{"a":2,"b":1}');
  });

  it('bit-flip of payload body fails signature', () => {
    const token = mintWorkerCapability(
      { dispatchId: 'ctx_1', taskId: 'task_1', nowMs: 1_700_000_000_000 },
      secret,
    );
    const parts = token.split('.');
    const body = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    body.dispatchId = 'ctx_FOREIGN';
    const evilBody = canonicalCapabilityPayload(body);
    const evil = `v1.${Buffer.from(evilBody).toString('base64url')}.${parts[2]}`;
    const v = verifyWorkerCapability(evil, secret, { nowMs: 1_700_000_000_000 });
    assert.equal(v.ok, false);
    assert.equal(v.code, 'bad_signature');
  });

  it('workerCapabilityEnv never embeds bridge master token', () => {
    const env = workerCapabilityEnv({ capability: 'v1.x.y', bridgeOrigin: 'http://127.0.0.1:8787' });
    assert.equal(env.ORCA_WORKER_CAPABILITY, 'v1.x.y');
    assert.equal(env.ORCA_BRIDGE_TOKEN, undefined);
    assert.equal(env.ORCA_WORKER_BRIDGE_ORIGIN, 'http://127.0.0.1:8787');
  });

  it('default TTL is 24h', () => {
    assert.equal(DEFAULT_CAPABILITY_TTL_SEC, 86400);
  });
});

// ---------------------------------------------------------------------------
// Attack catalogue — PRIMARY criterion (argv gate DISABLED)
// ---------------------------------------------------------------------------

describe('NAS-255 attack catalogue as unprivileged worker (argv gate disabled)', () => {
  const bridgeUid = 997;
  const workerUid = 1501;

  function blockedSecretsMap(home = '/home/orca') {
    const map = new Map();
    for (const p of listBridgeSecretPaths(home)) {
      map.set(
        p,
        classifyWorkerSecretAccess({
          path: p,
          exists: true,
          uid: bridgeUid,
          gid: bridgeUid,
          mode: p.endsWith('.orca-bridge') ? 0o040700 : 0o100600,
          isDirectory: p.endsWith('.orca-bridge'),
          workerUid,
          workerGid: workerUid,
        }),
      );
    }
    return map;
  }

  it('catalogue is non-empty and covers forge + secret classes', () => {
    assert.ok(WORKER_UID_ATTACK_CATALOGUE.length >= 10);
    assert.ok(WORKER_UID_ATTACK_CATALOGUE.some((a) => a.forgesClientKey));
    assert.ok(WORKER_UID_ATTACK_CATALOGUE.some((a) => a.requiresBridgeSecret));
    assert.ok(WORKER_UID_ATTACK_CATALOGUE.some((a) => a.id.includes('runtime-token')));
  });

  it('PRIMARY: with distinct worker uid + blocked secrets, NOT ONE attack passes', () => {
    const report = evaluateAttackCatalogueAsWorker({
      workerUid,
      bridgeUid,
      secretAccessByPath: blockedSecretsMap(),
    });
    assert.equal(report.argvGate, 'disabled');
    assert.equal(
      report.passedCount,
      0,
      `attacks still pass as worker: ${JSON.stringify(report.passed, null, 2)}`,
    );
    assert.equal(report.ok, true);
    assert.equal(report.total, WORKER_UID_ATTACK_CATALOGUE.length);
  });

  it('PRE-FIX baseline: same uid ⇒ catalogue attacks PASS (single-uid trust)', () => {
    const report = evaluateAttackCatalogueAsWorker({
      workerUid: bridgeUid,
      bridgeUid,
      secretAccessByPath: blockedSecretsMap(),
    });
    assert.equal(report.ok, false);
    assert.ok(
      report.passedCount > 0,
      'pre-fix same-uid must leave attacks passing so the new test fails on baseline',
    );
    const secretAttacks = WORKER_UID_ATTACK_CATALOGUE.filter(
      (a) => a.requiresBridgeSecret || a.forgesClientKey || a.requiresBridgeUid,
    );
    for (const a of secretAttacks) {
      const r = report.results.find((x) => x.id === a.id);
      assert.equal(r.passes, true, `${a.id} should pass under same uid`);
    }
  });

  it('exposed sender-pins lets clientKey forge pass even with distinct uid', () => {
    const map = blockedSecretsMap();
    const pins = '/home/orca/.orca-bridge-sender-pins.json';
    map.set(
      pins,
      classifyWorkerSecretAccess({
        path: pins,
        exists: true,
        uid: bridgeUid,
        gid: bridgeUid,
        mode: 0o100666,
        workerUid,
      }),
    );
    const forge = WORKER_UID_ATTACK_CATALOGUE.find((a) => a.id === 'nas255-forge-clientkey-via-pin-file');
    const r = evaluateAttackAsWorker(forge, {
      workerUid,
      bridgeUid,
      secretAccessByPath: map,
    });
    assert.equal(r.passes, true);
  });

  it('worker cannot forge clientKey when pins are 0600 bridge-owned', () => {
    const forge = WORKER_UID_ATTACK_CATALOGUE.find((a) => a.id === 'nas248-steal-sender-pins');
    const r = evaluateAttackAsWorker(forge, {
      workerUid,
      bridgeUid,
      secretAccessByPath: blockedSecretsMap(),
    });
    assert.equal(r.passes, false);
    assert.equal(r.blockedBy, 'fs');
  });
});

// ---------------------------------------------------------------------------
// Live disposable-uid FS proof (isolated HOME; never touches live ~/.orca-bridge*)
// ---------------------------------------------------------------------------

describe('live disposable worker uid FS denial', () => {
  it('worker uid cannot read bridge secrets on a real disposable account', () => {
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'nas255-bridge-home-'));
    let liveUser = null;
    try {
      fs.writeFileSync(path.join(tmpHome, '.orca-bridge-tokens.json'), '{"t":1}', { mode: 0o600 });
      fs.writeFileSync(path.join(tmpHome, '.orca-bridge-sender-pins.json'), '{"p":1}', { mode: 0o600 });
      fs.mkdirSync(path.join(tmpHome, '.orca-bridge'), { mode: 0o700 });
      fs.writeFileSync(path.join(tmpHome, '.orca-bridge', 'audit.ndjson'), '{}\n', { mode: 0o600 });
      fs.writeFileSync(
        path.join(tmpHome, '.orca-bridge', 'dispatch-ownership.json'),
        '{"bindings":[]}',
        { mode: 0o600 },
      );
      fs.mkdirSync(path.join(tmpHome, '.config', 'orca', 'daemon'), { recursive: true, mode: 0o700 });
      fs.writeFileSync(
        path.join(tmpHome, '.config', 'orca', 'orca-runtime.json'),
        '{"authToken":"secret-runtime-token"}',
        { mode: 0o600 },
      );
      fs.writeFileSync(
        path.join(tmpHome, '.config', 'orca', 'daemon', 'daemon-v32.token'),
        'daemon-token-secret',
        { mode: 0o600 },
      );

      const bridge = typeof process.getuid === 'function' ? process.getuid() : 997;
      let workerUid = bridge + 501;

      try {
        liveUser = `nas255w${process.pid % 100000}`;
        execFileSync(
          'useradd',
          ['--system', '--no-create-home', '--shell', '/usr/sbin/nologin', liveUser],
          { stdio: 'pipe' },
        );
        workerUid = Number(execFileSync('id', ['-u', liveUser], { encoding: 'utf8' }).trim());

        const tokens = path.join(tmpHome, '.orca-bridge-tokens.json');
        let denied = false;
        try {
          execFileSync(
            'setpriv',
            [`--reuid=${workerUid}`, `--regid=${workerUid}`, '--clear-groups', '--', 'cat', tokens],
            { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
          );
        } catch (e) {
          denied = true;
          const errText = String(e.stderr || e.message || e);
          assert.match(errText, /Permission denied|EACCES|denied/i);
        }
        assert.equal(denied, true, 'worker uid must not cat bridge tokens');

        const runtime = path.join(tmpHome, '.config', 'orca', 'orca-runtime.json');
        denied = false;
        try {
          execFileSync(
            'setpriv',
            [`--reuid=${workerUid}`, `--regid=${workerUid}`, '--clear-groups', '--', 'cat', runtime],
            { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
          );
        } catch {
          denied = true;
        }
        assert.equal(denied, true, 'worker uid must not cat runtime token');
      } catch (e) {
        // No root / useradd — still prove via mode bits on the isolated HOME files.
        if (!/useradd|setpriv|Permission|EPERM|denied/i.test(String(e.stderr || e.message || e)) && liveUser) {
          throw e;
        }
        // classify against fictional distinct worker uid
        workerUid = bridge + 501;
      }

      const report = evaluateAttackCatalogueAsWorker({
        workerUid,
        bridgeUid: bridge,
        homeDir: tmpHome,
      });
      assert.equal(report.ok, true, JSON.stringify(report.passed, null, 2));

      // Same uid against these files is exposed (owner is current process).
      const same = inspectWorkerSecretAccess(
        path.join(tmpHome, '.orca-bridge-tokens.json'),
        bridge,
      );
      assert.equal(same.code, 'exposed');
    } finally {
      try {
        fs.rmSync(tmpHome, { recursive: true, force: true });
      } catch { /* ignore */ }
      if (liveUser) {
        try {
          execFileSync('userdel', [liveUser], { stdio: 'ignore' });
        } catch { /* ignore */ }
      }
    }
  });
});

// ---------------------------------------------------------------------------
// health snapshot
// ---------------------------------------------------------------------------

describe('workerIsolationHealth', () => {
  it('states per-dispatch uid is NOT shipped', () => {
    const h = workerIsolationHealth(
      resolveWorkerIsolationConfig(
        { [WORKER_ISOLATION_ENV]: '1' },
        { getuid: () => 997, platform: 'linux' },
      ),
    );
    assert.equal(h.perDispatchUid, false);
    assert.match(h.note, /NOT shipped/);
    assert.equal(h.enabled, true);
  });
});
