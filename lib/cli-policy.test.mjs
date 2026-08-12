import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  RAW_CLI_OK_PREFIXES,
  RAW_CLI_ADMIN_PREFIXES,
  resolveCliPolicyConfig,
  commandTokens,
  matchesPrefix,
  matchAllowlist,
  createCliPolicy,
  evaluateCliArgv,
  allowedSurfaceLabels,
  formatPrefix,
  extractTerminalHandleFromArgv,
  isOwnershipGatedArgv,
  OWNERSHIP_GATED_PREFIXES,
} from './cli-policy.mjs';

// ---------------------------------------------------------------------------
// config defaults — owner requirement: permissive unless explicitly enabled
// ---------------------------------------------------------------------------

describe('resolveCliPolicyConfig', () => {
  it('defaults hardening and admin to false with empty env', () => {
    assert.deepEqual(resolveCliPolicyConfig({}), { hardening: false, admin: false });
  });

  it('enables hardening only when ORCA_BRIDGE_CLI_HARDENING=1', () => {
    assert.deepEqual(
      resolveCliPolicyConfig({ ORCA_BRIDGE_CLI_HARDENING: '1' }),
      { hardening: true, admin: false },
    );
    assert.deepEqual(
      resolveCliPolicyConfig({ ORCA_BRIDGE_CLI_HARDENING: 'true' }),
      { hardening: false, admin: false },
    );
    assert.deepEqual(
      resolveCliPolicyConfig({ ORCA_BRIDGE_CLI_HARDENING: '0' }),
      { hardening: false, admin: false },
    );
  });

  it('enables admin only when ORCA_BRIDGE_CLI_ADMIN=1', () => {
    assert.deepEqual(
      resolveCliPolicyConfig({ ORCA_BRIDGE_CLI_ADMIN: '1' }),
      { hardening: false, admin: true },
    );
    assert.deepEqual(
      resolveCliPolicyConfig({
        ORCA_BRIDGE_CLI_HARDENING: '1',
        ORCA_BRIDGE_CLI_ADMIN: '1',
      }),
      { hardening: true, admin: true },
    );
  });
});

// ---------------------------------------------------------------------------
// token / prefix matching
// ---------------------------------------------------------------------------

describe('commandTokens + prefix match', () => {
  it('collects leading non-flag tokens lowercased', () => {
    assert.deepEqual(
      commandTokens(['Orchestration', 'Reply', '--id', 'msg_1']),
      ['orchestration', 'reply'],
    );
    assert.deepEqual(commandTokens(['status', '--json']), ['status']);
    assert.deepEqual(commandTokens(['--json']), []);
  });

  it('stops at -- end-of-options', () => {
    assert.deepEqual(
      commandTokens(['worktree', 'create', '--', 'nope']),
      ['worktree', 'create'],
    );
  });

  it('matches prefixes case-insensitively via lowercased tokens', () => {
    assert.equal(matchesPrefix(['terminal', 'send'], ['terminal', 'send']), true);
    assert.equal(matchesPrefix(['terminal', 'read'], ['terminal', 'send']), false);
    assert.equal(matchesPrefix(['terminal'], ['terminal', 'read']), false);
  });

  it('matchAllowlist returns the first hit', () => {
    const hit = matchAllowlist(['orchestration', 'reply', 'extra'], RAW_CLI_OK_PREFIXES);
    assert.deepEqual(hit, ['orchestration', 'reply']);
    assert.equal(matchAllowlist(['terminal', 'send'], RAW_CLI_OK_PREFIXES), null);
  });
});

// ---------------------------------------------------------------------------
// always-on forbidden handoff
// ---------------------------------------------------------------------------

describe('evaluateCliArgv: forbidden handoff always denies', () => {
  for (const mode of [
    { hardening: false, admin: false },
    { hardening: true, admin: false },
    { hardening: true, admin: true },
  ]) {
    it(`denies handoff when ${JSON.stringify(mode)}`, () => {
      const r = evaluateCliArgv(
        ['worktree', 'create', '--agent', 'omp', '--prompt', 'x'],
        mode,
      );
      assert.equal(r.ok, false);
      assert.equal(r.decision, 'deny');
      assert.equal(r.rejection.error, 'forbidden_handoff');
      assert.equal(r.rejection.rejected_subcommand, 'worktree create');
      assert.ok(Array.isArray(r.rejection.allowed_surface));
      assert.ok(r.rejection.allowed_surface.includes('orchestration reply'));
    });
  }

  it('denies case/alias handoff variants under default config', () => {
    const r = evaluateCliArgv(
      ['Worktree', 'CREATE', '-a', 'omp', '-p', 'hi'],
      resolveCliPolicyConfig({}),
    );
    assert.equal(r.ok, false);
    assert.equal(r.rejection.error, 'forbidden_handoff');
  });
});

// ---------------------------------------------------------------------------
// default-config: legitimate argv unchanged (owner requirement)
// ---------------------------------------------------------------------------

describe('evaluateCliArgv: default config preserves legitimate argv', () => {
  const defaults = resolveCliPolicyConfig({});

  const legitimate = [
    ['orchestration', 'reply', '--id', 'msg_1', '--body', 'yes', '--json'],
    ['orchestration', 'check', '--run', 'run_1', '--json'],
    ['skills', 'get', 'foo'],
    ['status', '--json'],
    ['worktree', 'show', '--json'],
    ['worktree', 'list', '--limit', '20', '--json'],
    ['terminal', 'list', '--json'],
    ['terminal', 'read', '--terminal', 'term_1', '--limit', '50'],
    ['terminal', 'close', '--terminal', 'term_1', '--tab', '--json'],
    ['orchestration', 'worker-show', '--dispatch', 'ctx_1', '--json'],
    ['orchestration', 'worker-read', '--dispatch', 'ctx_1', '--json'],
    ['orchestration', 'dispatch-show', '--task', 'task_1', '--json'],
  ];

  for (const argv of legitimate) {
    it(`allows ${argv.slice(0, 2).join(' ')} with decision=allow and no warning`, () => {
      const r = evaluateCliArgv(argv, defaults);
      assert.equal(r.ok, true);
      assert.equal(r.decision, 'allow');
      assert.equal(r.warning, null);
      assert.equal(r.rejection, null);
      assert.ok(r.matched_prefix);
    });
  }

  it('explicit owner invariant: no-config policy is non-blocking for allowlisted work', () => {
    const policy = createCliPolicy(resolveCliPolicyConfig({}));
    assert.equal(policy.hardening, false);
    assert.equal(policy.admin, false);
    for (const argv of legitimate) {
      const r = policy.evaluate(argv);
      assert.equal(r.ok, true, `expected allow for ${argv.join(' ')}`);
      assert.equal(r.decision, 'allow');
    }
  });
});

// ---------------------------------------------------------------------------
// permissive default: out-of-allowlist warns, does not block
// ---------------------------------------------------------------------------

describe('evaluateCliArgv: permissive default warns instead of blocking', () => {
  const defaults = resolveCliPolicyConfig({});

  const previouslyWorkingRisky = [
    ['terminal', 'send', '--terminal', 'term_x', '--text', 'hi'],
    ['orchestration', 'send', '--from', 't', '--type', 'x', '--body', 'b'],
    ['worktree', 'create', '--name', 'n', '--agent', 'omp', '--repo', 'path:/r', '--json'],
    ['terminal', 'create', '--title', 'x', '--json'],
    ['git', 'status'],
  ];

  for (const argv of previouslyWorkingRisky) {
    it(`warns but allows ${argv.slice(0, 2).join(' ')} when hardening off`, () => {
      const warnings = [];
      const r = evaluateCliArgv(argv, {
        ...defaults,
        onWarning: (w) => warnings.push(w),
      });
      assert.equal(r.ok, true);
      assert.equal(r.decision, 'allow_with_warning');
      assert.equal(r.rejection, null);
      assert.ok(r.warning);
      assert.equal(r.warning.code, 'cli_policy_would_deny');
      assert.equal(r.warning.hardening, false);
      assert.equal(typeof r.warning.rejected_subcommand, 'string');
      assert.ok(Array.isArray(r.warning.allowed_surface));
      assert.equal(warnings.length, 1);
      assert.equal(warnings[0].code, 'cli_policy_would_deny');
    });
  }

  it('marks admin_required for terminal send under warn path', () => {
    const r = evaluateCliArgv(
      ['terminal', 'send', '--terminal', 't', '--text', 'x'],
      defaults,
    );
    assert.equal(r.ok, true);
    assert.equal(r.admin_required, true);
    assert.equal(r.warning.admin_required, true);
  });

  it('does not mark admin_required for unknown commands', () => {
    const r = evaluateCliArgv(['git', 'status'], defaults);
    assert.equal(r.ok, true);
    assert.equal(r.admin_required, false);
  });
});

// ---------------------------------------------------------------------------
// hardened mode: deny by default allowlist
// ---------------------------------------------------------------------------

describe('evaluateCliArgv: hardened mode enforces allowlist', () => {
  const hardened = { hardening: true, admin: false };

  it('still allows default surface', () => {
    const r = evaluateCliArgv(
      ['orchestration', 'reply', '--id', 'm', '--body', 'ok', '--json'],
      hardened,
    );
    assert.equal(r.ok, true);
    assert.equal(r.decision, 'allow');
  });

  it('denies terminal send with structured error', () => {
    const r = evaluateCliArgv(
      ['terminal', 'send', '--terminal', 't', '--text', 'hi'],
      hardened,
    );
    assert.equal(r.ok, false);
    assert.equal(r.decision, 'deny');
    assert.equal(r.rejection.error, 'cli_policy_denied');
    assert.equal(r.rejection.rejected_subcommand, 'terminal send');
    assert.equal(r.rejection.admin_required, true);
    assert.ok(Array.isArray(r.rejection.allowed_surface));
    assert.ok(r.rejection.allowed_surface.includes('orchestration reply'));
    assert.ok(Array.isArray(r.rejection.admin_surface));
    assert.ok(r.rejection.admin_surface.includes('terminal send'));
    assert.equal(r.rejection.next.action, 'guide');
  });

  it('denies unknown commands with structured error (not bare string)', () => {
    const r = evaluateCliArgv(['rm', '-rf', '/'], hardened);
    assert.equal(r.ok, false);
    assert.equal(r.rejection.error, 'cli_policy_denied');
    assert.equal(r.rejection.rejected_subcommand, 'rm');
    assert.equal(r.rejection.admin_required, false);
    assert.equal(typeof r.rejection.detail, 'string');
    assert.ok(Array.isArray(r.rejection.allowed_surface));
  });

  it('case-insensitive allow match under hardening', () => {
    const r = evaluateCliArgv(['Skills', 'Get', 'x'], hardened);
    assert.equal(r.ok, true);
    assert.deepEqual(r.matched_prefix, ['skills', 'get']);
  });
});

// ---------------------------------------------------------------------------
// admin unlock
// ---------------------------------------------------------------------------

describe('evaluateCliArgv: admin unlock', () => {
  it('allows terminal send when admin=true even with hardening', () => {
    const r = evaluateCliArgv(
      ['terminal', 'send', '--terminal', 't', '--text', 'hi'],
      { hardening: true, admin: true },
    );
    assert.equal(r.ok, true);
    assert.equal(r.decision, 'allow');
    assert.equal(r.admin_required, true);
    assert.deepEqual(r.matched_prefix, ['terminal', 'send']);
  });

  it('admin without hardening still allows everything (permissive)', () => {
    const r = evaluateCliArgv(['git', 'status'], { hardening: false, admin: true });
    assert.equal(r.ok, true);
    assert.equal(r.decision, 'allow_with_warning');
  });

  it('admin unlock covers worktree create --agent without --prompt', () => {
    const r = evaluateCliArgv(
      ['worktree', 'create', '--name', 'n', '--agent', 'omp', '--repo', 'path:/r', '--json'],
      { hardening: true, admin: true },
    );
    assert.equal(r.ok, true);
    assert.equal(r.decision, 'allow');
  });

  it('admin unlock does NOT bypass forbidden handoff', () => {
    const r = evaluateCliArgv(
      ['worktree', 'create', '--agent', 'omp', '--prompt', 'x'],
      { hardening: true, admin: true },
    );
    assert.equal(r.ok, false);
    assert.equal(r.rejection.error, 'forbidden_handoff');
  });
});

// ---------------------------------------------------------------------------
// createCliPolicy surface for toolset integration
// ---------------------------------------------------------------------------

describe('createCliPolicy', () => {
  it('exposes evaluate bound to config', () => {
    const policy = createCliPolicy({ hardening: true, admin: false });
    const ok = policy.evaluate(['status', '--json']);
    const deny = policy.evaluate(['terminal', 'send', '--terminal', 't', '--text', 'x']);
    assert.equal(ok.ok, true);
    assert.equal(deny.ok, false);
    assert.equal(deny.rejection.error, 'cli_policy_denied');
  });

  it('onWarning is invoked on warn path only', () => {
    const seen = [];
    const policy = createCliPolicy({
      hardening: false,
      onWarning: (w) => seen.push(w.code),
    });
    policy.evaluate(['status']);
    policy.evaluate(['terminal', 'send', '--terminal', 't', '--text', 'x']);
    assert.deepEqual(seen, ['cli_policy_would_deny']);
  });

  it('warning hook errors do not fail the allow path', () => {
    const policy = createCliPolicy({
      hardening: false,
      onWarning: () => {
        throw new Error('hook boom');
      },
    });
    const r = policy.evaluate(['terminal', 'send', '--terminal', 't', '--text', 'x']);
    assert.equal(r.ok, true);
    assert.equal(r.decision, 'allow_with_warning');
  });
});

// ---------------------------------------------------------------------------
// surface labels / guide alignment
// ---------------------------------------------------------------------------

describe('allowed surface labels', () => {
  it('formatPrefix joins tokens', () => {
    assert.equal(formatPrefix(['orchestration', 'reply']), 'orchestration reply');
  });

  it('default OK prefixes cover guide raw_cli_ok themes', () => {
    const labels = allowedSurfaceLabels(RAW_CLI_OK_PREFIXES);
    for (const need of [
      'orchestration reply',
      'orchestration check',
      'skills get',
      'status',
      'worktree show',
      'worktree list',
      'terminal list',
      'terminal read',
      'terminal close',
      'orchestration worker-show',
      'orchestration worker-read',
    ]) {
      assert.ok(labels.includes(need), `missing ${need}`);
    }
  });

  it('admin prefixes include terminal send', () => {
    assert.ok(allowedSurfaceLabels(RAW_CLI_ADMIN_PREFIXES).includes('terminal send'));
  });
});


// ---------------------------------------------------------------------------
// NAS-247 handle ownership funnel
// ---------------------------------------------------------------------------

describe('extractTerminalHandleFromArgv / isOwnershipGatedArgv', () => {
  it('parses --terminal forms', () => {
    assert.equal(
      extractTerminalHandleFromArgv(['terminal', 'read', '--terminal', 'term_1']),
      'term_1',
    );
    assert.equal(
      extractTerminalHandleFromArgv(['terminal', 'close', '--terminal=term_2']),
      'term_2',
    );
    assert.equal(extractTerminalHandleFromArgv(['terminal', 'list']), null);
  });

  it('gates only read/close/send', () => {
    assert.equal(isOwnershipGatedArgv(['terminal', 'read']), true);
    assert.equal(isOwnershipGatedArgv(['terminal', 'close']), true);
    assert.equal(isOwnershipGatedArgv(['terminal', 'send']), true);
    assert.equal(isOwnershipGatedArgv(['terminal', 'list']), false);
    assert.equal(isOwnershipGatedArgv(['status']), false);
    assert.equal(OWNERSHIP_GATED_PREFIXES.length, 3);
  });
});

describe('evaluateCliArgv: handle ownership', () => {
  const ownedCheck = () => ({
    status: 'owned',
    handle: 'term_own',
    owned_handles: ['term_own', 'term_worker'],
  });
  const foreignCheck = () => ({
    status: 'not-owned',
    handle: 'term_foreign',
    owned_handles: ['term_own'],
    reason: 'foreign_handle',
  });
  const unknownCheck = () => ({
    status: 'unknown',
    handle: 'term_ghost',
    owned_handles: ['term_own'],
    reason: 'handle_not_in_registry',
  });

  const gated = {
    read: ['terminal', 'read', '--terminal', 'term_foreign', '--limit', '20'],
    close: ['terminal', 'close', '--terminal', 'term_foreign', '--tab', '--json'],
    send: ['terminal', 'send', '--terminal', 'term_foreign', '--text', 'x'],
  };
  const ownedArgv = {
    read: ['terminal', 'read', '--terminal', 'term_own', '--limit', '20'],
    close: ['terminal', 'close', '--terminal', 'term_own', '--tab', '--json'],
    send: ['terminal', 'send', '--terminal', 'term_own', '--text', 'x'],
  };

  for (const [name, argv] of Object.entries(gated)) {
    it(`hardening on denies ${name} with handle_not_owned`, () => {
      const admin = name === 'send'; // send needs admin unlock to reach ownership
      const r = evaluateCliArgv(argv, {
        hardening: true,
        admin,
        ownershipCheck: foreignCheck,
      });
      assert.equal(r.ok, false);
      assert.equal(r.decision, 'deny');
      assert.ok(r.rejection);
      assert.equal(r.rejection.error, 'cli_policy_denied');
      assert.equal(r.rejection.code, 'handle_not_owned');
      assert.equal(r.rejection.handle, 'term_foreign');
      assert.deepEqual(r.rejection.owned_handles, ['term_own']);
      assert.equal(r.rejection.ownership_status, 'not-owned');
      assert.match(r.rejection.detail, /term_foreign/);
      assert.match(r.rejection.detail, /term_own/);
      assert.equal(r.rejection.next.action, 'guide');
      assert.ok(Array.isArray(r.rejection.allowed_surface));
    });

    it(`hardening off warns on ${name} ownership miss (allow_with_warning)`, () => {
      const warnings = [];
      const r = evaluateCliArgv(argv, {
        hardening: false,
        admin: true,
        ownershipCheck: foreignCheck,
        onWarning: (w) => warnings.push(w),
      });
      assert.equal(r.ok, true);
      assert.equal(r.decision, 'allow_with_warning');
      assert.equal(r.rejection, null);
      assert.ok(r.warning);
      assert.equal(r.warning.code, 'handle_not_owned');
      assert.equal(r.warning.handle, 'term_foreign');
      assert.deepEqual(r.warning.owned_handles, ['term_own']);
      assert.equal(warnings.length, 1);
      assert.equal(warnings[0].code, 'handle_not_owned');
    });
  }

  for (const [name, argv] of Object.entries(ownedArgv)) {
    it(`allows ${name} when caller owns the handle`, () => {
      const r = evaluateCliArgv(argv, {
        hardening: true,
        admin: true,
        ownershipCheck: ownedCheck,
      });
      assert.equal(r.ok, true);
      assert.equal(r.decision, 'allow');
      assert.equal(r.warning, null);
      assert.equal(r.rejection, null);
    });
  }

  it('unknown handle fails closed under hardening', () => {
    const r = evaluateCliArgv(gated.read, {
      hardening: true,
      ownershipCheck: unknownCheck,
    });
    assert.equal(r.ok, false);
    assert.equal(r.rejection.code, 'handle_not_owned');
    assert.equal(r.rejection.ownership_status, 'unknown');
  });

  it('missing ownershipCheck leaves prefix-only policy unchanged', () => {
    const r = evaluateCliArgv(gated.read, { hardening: true });
    assert.equal(r.ok, true);
    assert.equal(r.decision, 'allow');
  });

  it('createCliPolicy threads ownershipCheck; evaluate overrides work', () => {
    const policy = createCliPolicy({
      hardening: true,
      admin: true,
      ownershipCheck: foreignCheck,
    });
    const deny = policy.evaluate(ownedArgv.read); // foreignCheck ignores argv handle status
    assert.equal(deny.ok, false);
    assert.equal(deny.rejection.code, 'handle_not_owned');

    const allow = policy.evaluate(ownedArgv.read, { ownershipCheck: ownedCheck });
    assert.equal(allow.ok, true);
    assert.equal(allow.decision, 'allow');
  });

  it('accepts verdict field from resolver', () => {
    const r = evaluateCliArgv(gated.close, {
      hardening: true,
      ownershipCheck: () => ({
        verdict: 'not-owned',
        handle: 'term_foreign',
        ownedHandles: ['term_own'],
      }),
    });
    assert.equal(r.ok, false);
    assert.equal(r.rejection.code, 'handle_not_owned');
    assert.deepEqual(r.rejection.owned_handles, ['term_own']);
  });
});
