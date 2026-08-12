import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  versionGte,
  parseSemver,
  RuntimeGuardError,
  createRuntimeProbeCache,
  assertRuntimeReady,
  compactHealthPayload,
  computeLiveness,
  nextStepForLiveness,
  pickLastActivityAt,
  isDeadRuntimeSignal,
  deadRuntimeFailure,
  LIVENESS_THRESHOLDS,
  RUNTIME_PROBE_TTL_MS,
  HEALTH_DIAGNOSTICS_HINT,
} from './runtime-guard.mjs';
import {
  DOCTRINE,
  buildToolDescription,
  buildCoordinatorGuide,
  AWAIT_EMPTY_ESCALATE_AFTER,
} from './coordinator-doctrine.mjs';

// ---------------------------------------------------------------------------
// Semver / version gate
// ---------------------------------------------------------------------------

describe('versionGte / parseSemver', () => {
  it('parses plain versions; rejects non-semver prefixes', () => {
    assert.deepEqual(parseSemver('0.3.0'), [0, 3, 0]);
    assert.deepEqual(parseSemver('1.2.3-beta'), [1, 2, 3]);
    assert.equal(parseSemver('v1.2.3'), null);
    assert.equal(parseSemver('nope'), null);
  });

  it('compares major.minor.patch', () => {
    assert.equal(versionGte('0.3.0', '0.2.0'), true);
    assert.equal(versionGte('0.2.0', '0.2.0'), true);
    assert.equal(versionGte('0.1.9', '0.2.0'), false);
    assert.equal(versionGte('bad', '0.2.0'), false);
  });
});

// ---------------------------------------------------------------------------
// Runtime guard (self-diagnosing errors)
// ---------------------------------------------------------------------------

describe('assertRuntimeReady', () => {
  it('passes when version ok and no probe', () => {
    const r = assertRuntimeReady({ version: '0.3.0', minVersion: '0.2.0' });
    assert.equal(r.ok, true);
    assert.equal(r.versionOk, true);
  });

  it('throws bridge_version_too_old with recovery', () => {
    assert.throws(
      () => assertRuntimeReady({ version: '0.1.0', minVersion: '0.2.0' }),
      (err) => {
        assert.equal(err instanceof RuntimeGuardError, true);
        assert.equal(err.code, 'bridge_version_too_old');
        assert.match(err.recovery, /upgrade|restart/i);
        assert.match(err.recovery, /action=health|Call action=health/i);
        const json = err.toJSON();
        assert.equal(json.ok, false);
        assert.equal(json.error.code, 'bridge_version_too_old');
        assert.equal(json.next.action, 'diagnose');
        return true;
      },
    );
  });

  it('throws runtime_unavailable when status probe fails', () => {
    assert.throws(
      () =>
        assertRuntimeReady({
          version: '0.3.0',
          minVersion: '0.2.0',
          probe: { ok: false, exitCode: 1, error: 'orca missing', spawnError: null },
        }),
      (err) => {
        assert.equal(err.code, 'runtime_unavailable');
        assert.match(err.reason, /exit 1|orca missing/i);
        assert.match(err.recovery, /ORCA_CLI_COMMAND|status --json|action=health/i);
        return true;
      },
    );
  });

  it('throws on spawnError even if exitCode null', () => {
    assert.throws(
      () =>
        assertRuntimeReady({
          version: '0.3.0',
          minVersion: '0.2.0',
          probe: { ok: false, spawnError: 'ENOENT', exitCode: null },
        }),
      (err) => err.code === 'runtime_unavailable' && /ENOENT/.test(err.reason),
    );
  });

  it('accepts ok probe', () => {
    const r = assertRuntimeReady({
      version: '0.3.0',
      minVersion: '0.2.0',
      probe: { ok: true, exitCode: 0, envelope: { ok: true } },
    });
    assert.equal(r.ok, true);
  });
});

describe('createRuntimeProbeCache', () => {
  it('honors TTL', () => {
    let t = 1_000;
    const cache = createRuntimeProbeCache({ ttlMs: 100, now: () => t });
    cache.set({ ok: true });
    assert.deepEqual(cache.get(), { ok: true });
    t += 50;
    assert.deepEqual(cache.get(), { ok: true });
    t += 60;
    assert.equal(cache.get(), null);
  });

  it('default TTL is RUNTIME_PROBE_TTL_MS', () => {
    const cache = createRuntimeProbeCache();
    assert.equal(cache.ttlMs, RUNTIME_PROBE_TTL_MS);
  });
});

// ---------------------------------------------------------------------------
// Compact health
// ---------------------------------------------------------------------------

describe('compactHealthPayload', () => {
  const full = {
    bridge: {
      version: '0.3.0',
      minVersion: '0.2.0',
      versionOk: true,
      uptimeSec: 12,
      node: 'v20.0.0',
      platform: 'linux',
      transport: 'stdio',
      protocolTarget: '2025-11-25',
    },
    orcaBinary: '/usr/bin/orca',
    defaultAgent: 'omp',
    defaultRepo: '/home/orca/src/foo',
    senderTerminal: { ok: true, handle: 'term_abc', source: 'pin', clientKey: 'ck', title: 't' },
    isolation: { perClientSender: true, note: 'long' },
    hindsightTarget: 'http://127.0.0.1:8888/',
    actions: ['health', 'dispatch', 'await'],
    toolsets: { mode: 'all', enabled: ['orchestration', 'worktree'] },
    actionAnnotations: { health: { readOnlyHint: true }, dispatch: { destructiveHint: true } },
    audit: { path: '/tmp/a', bytes: 99 },
    resources: ['orca-bridge://audit/log'],
    statusProbe: {
      ok: true,
      exitCode: 0,
      spawnError: null,
      stdout: 'x'.repeat(5000),
      envelope: { ok: true, result: { capabilities: { a: 1, b: 2, c: 3 } } },
    },
    coordinator: {
      stop_if_version_below: '0.2.0',
      flow: 'long flow text',
      on_question: 'long',
    },
    next: {
      action: 'dispatch_or_guide',
      detail:
        'Bridge ready. Start workers with action=dispatch. Call action=guide once if you need waves/brief/devices discipline. health is optional diagnostics — not required before each wave.',
    },
  };

  it('keeps DoD fields and stays under 500 bytes', () => {
    const c = compactHealthPayload(full);
    assert.equal(c.ok, true);
    assert.equal(c.version, '0.3.0');
    assert.equal(c.versionOk, true);
    assert.equal(c.statusProbe.ok, true);
    assert.equal(c.defaultRepo, '/home/orca/src/foo');
    assert.equal(c.verbose, false);
    assert.equal(c.next.action, 'dispatch_or_guide');
    assert.ok(String(c.next.detail).length <= 120);

    // Giant / verbose-only fields must not appear.
    assert.equal('actionAnnotations' in c, false);
    assert.equal('coordinator' in c, false);
    assert.equal('isolation' in c, false);
    assert.equal('audit' in c, false);
    assert.equal('resources' in c, false);
    assert.equal('bridge' in c, false);
    assert.equal('senderTerminal' in c, false);
    assert.equal('toolsets' in c, false);
    assert.equal('actions' in c, false);
    assert.equal(c.statusProbe.envelope, undefined);
    assert.equal(c.statusProbe.stdout, undefined);
    assert.equal(c.statusProbe.exitCode, undefined);

    const bytes = Buffer.byteLength(JSON.stringify(c), 'utf8');
    assert.ok(bytes < 500, `compact health must be <500 bytes, got ${bytes}`);
  });

  it('reports ok=false when versionOk false', () => {
    const c = compactHealthPayload({
      ...full,
      bridge: { ...full.bridge, versionOk: false },
    });
    assert.equal(c.ok, false);
    assert.equal(c.versionOk, false);
  });

  it('reports statusProbe.ok false on failed probe', () => {
    const c = compactHealthPayload({
      ...full,
      statusProbe: { ok: false, exitCode: 127, spawnError: 'ENOENT' },
    });
    assert.equal(c.statusProbe.ok, false);
    assert.equal(c.ok, false);
  });
});

// ---------------------------------------------------------------------------
// Dead-runtime codes (dispatch/await self-diagnose)
// ---------------------------------------------------------------------------

describe('isDeadRuntimeSignal / deadRuntimeFailure', () => {
  it('detects spawnError ENOENT', () => {
    assert.equal(isDeadRuntimeSignal({ ok: false, spawnError: 'ENOENT' }), true);
  });

  it('detects timedOut', () => {
    assert.equal(isDeadRuntimeSignal({ ok: false, timedOut: true }), true);
  });

  it('ignores ordinary orchestration failures', () => {
    assert.equal(
      isDeadRuntimeSignal({
        ok: false,
        envelope: { ok: false, error: { code: 'already_bound' } },
        exitCode: 1,
      }),
      false,
    );
  });

  it('returns stable runtime_unavailable with health hint', () => {
    const fail = deadRuntimeFailure(
      { ok: false, spawnError: 'ENOENT', error: 'orca CLI not found' },
      { stage: 'run-create' },
    );
    assert.equal(fail.ok, false);
    assert.equal(fail.error.code, 'runtime_unavailable');
    assert.equal(fail.stage, 'run-create');
    assert.match(fail.error.recovery, /action=health/i);
    assert.match(fail.next.detail, /action=health/i);
    assert.equal(HEALTH_DIAGNOSTICS_HINT.includes('health'), true);
  });
});

// ---------------------------------------------------------------------------
// Liveness
// ---------------------------------------------------------------------------

describe('computeLiveness', () => {
  const now = Date.parse('2026-08-11T12:00:00.000Z');

  it('unknown without signals', () => {
    const r = computeLiveness({ now, emptyWindowsConsecutive: 0 });
    assert.equal(r.liveness, 'unknown');
  });

  it('active on recent terminal activity', () => {
    const r = computeLiveness({
      now,
      hasDispatch: true,
      dispatchedAt: now - 600_000,
      lastActivityAt: now - 10_000,
      emptyWindowsConsecutive: 3,
    });
    assert.equal(r.liveness, 'active');
    assert.equal(r.msSinceActivity, 10_000);
  });

  it('active on first empty window', () => {
    const r = computeLiveness({
      now,
      hasDispatch: true,
      dispatchedAt: now - 50_000,
      emptyWindowsConsecutive: 1,
    });
    assert.equal(r.liveness, 'active');
  });

  it('idle in the middle band', () => {
    const r = computeLiveness({
      now,
      hasDispatch: true,
      dispatchedAt: now - 5 * 60_000,
      lastActivityAt: now - 3 * 60_000,
      emptyWindowsConsecutive: 4,
    });
    assert.equal(r.liveness, 'idle');
  });

  it('stalled after many empty windows', () => {
    const r = computeLiveness({
      now,
      hasDispatch: true,
      dispatchedAt: now - 20 * 60_000,
      emptyWindowsConsecutive: LIVENESS_THRESHOLDS.stalledEmptyMin,
    });
    assert.equal(r.liveness, 'stalled');
    assert.ok(r.emptyWindowsConsecutive >= AWAIT_EMPTY_ESCALATE_AFTER);
  });

  it('stalled on long quiet + enough empties', () => {
    const r = computeLiveness({
      now,
      hasDispatch: true,
      dispatchedAt: now - 30 * 60_000,
      lastActivityAt: now - LIVENESS_THRESHOLDS.stalledMs - 1,
      emptyWindowsConsecutive: LIVENESS_THRESHOLDS.stalledEmptyWithQuiet,
    });
    assert.equal(r.liveness, 'stalled');
  });

  it('exposes msSinceDispatch', () => {
    const r = computeLiveness({
      now,
      dispatchedAt: '2026-08-11T11:50:00.000Z',
      emptyWindowsConsecutive: 2,
      hasDispatch: true,
    });
    assert.equal(r.msSinceDispatch, 10 * 60_000);
  });
});

describe('nextStepForLiveness', () => {
  it('stalled → diagnose, not blind re-await', () => {
    const n = nextStepForLiveness({ liveness: 'stalled', emptyWindowsConsecutive: 9 });
    assert.equal(n.action, 'diagnose');
    assert.equal(n.liveness, 'stalled');
    assert.match(n.detail, /peek|diagnose|release/i);
    assert.doesNotMatch(n.detail, /NORMAL for 15–60 min/);
  });

  it('active → re-call await', () => {
    const n = nextStepForLiveness({ liveness: 'active', emptyWindowsConsecutive: 0 });
    assert.equal(n.action, 'await');
    assert.match(n.detail, /NORMAL|active/i);
  });

  it('idle → re-call with stall watch', () => {
    const n = nextStepForLiveness({ liveness: 'idle', emptyWindowsConsecutive: 4 });
    assert.equal(n.action, 'await');
    assert.match(n.detail, /idle|emptyWindows/i);
  });
});

describe('pickLastActivityAt', () => {
  it('picks max timestamp', () => {
    const iso = pickLastActivityAt({
      registryUpdatedAt: '2026-08-11T10:00:00.000Z',
      terminalLastOutputAt: '2026-08-11T11:00:00.000Z',
      lastMessageAt: '2026-08-11T10:30:00.000Z',
    });
    assert.equal(iso, '2026-08-11T11:00:00.000Z');
  });

  it('returns null when empty', () => {
    assert.equal(pickLastActivityAt({}), null);
  });
});

// ---------------------------------------------------------------------------
// Doctrine SSOT no longer requires health-first ritual
// ---------------------------------------------------------------------------

describe('doctrine NAS-246/240', () => {
  it('tool description does not require health before work', () => {
    const d = buildToolDescription({ minVersion: '0.2.0' });
    assert.equal(/require statusProbe\.ok/i.test(d), false);
    assert.equal(/health — require/i.test(d), false);
    assert.match(d, /liveness/);
    assert.match(d, /stalled/);
    assert.match(d, /optional compact diagnostics|not required before each wave/i);
  });

  it('flow starts at dispatch, not health ritual', () => {
    assert.match(DOCTRINE.flow[0], /dispatch/i);
    assert.equal(/^1\.\s*orca\{action:"health"\}/.test(DOCTRINE.flow[0]), false);
  });

  it('guide exposes liveness ceilings', () => {
    const g = buildCoordinatorGuide({ version: '0.3.0', minVersion: '0.2.0' });
    assert.equal(g.liveness.empty_escalate_after, AWAIT_EMPTY_ESCALATE_AFTER);
    assert.ok(g.await_statuses.empty_stalled);
    assert.match(g.health, /optional|verbose/i);
  });
});
