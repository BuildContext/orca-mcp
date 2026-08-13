import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  assertTargetFlagResolversComplete,
  FLAG_TABLE,
  TARGET_FLAG_RESOLVERS,
  TARGET_SELECTOR_FLAGS,
  collectUnclassifiedFlagsFromArgv,
  normalizeArgvForPolicy,
  allSpecAllowedFlagNames,
  listShapedOrchestrationCommands,
  CLI_COMMAND_SPECS,
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
  extractDispatchIdFromArgv,
  collectTerminalHandlesFromArgv,
  collectDispatchIdsFromArgv,
  isOwnershipGatedArgv,
  isDispatchOwnershipGatedArgv,
  looksLikeOwnershipGatedArgv,
  OWNERSHIP_GATED_PREFIXES,
  DISPATCH_OWNERSHIP_GATED_PREFIXES,
  collectWorktreeSelectorsFromArgv,
  argvHasOwnershipTargetSelector,
} from './cli-policy.mjs';

// ---------------------------------------------------------------------------
// config defaults — owner requirement: permissive unless explicitly enabled
// ---------------------------------------------------------------------------


/** All resolvers return owned — use when testing allowlist/warn paths. */
function allOwnedCheckers(extra = {}) {
  return {
    ownershipCheck: (ctx) => ({ status: 'owned', handle: ctx.handle, owned_handles: ['term_own', 't', 'term_1'] }),
    dispatchOwnershipCheck: (ctx) => ({ status: 'owned', dispatchId: ctx.dispatchId, owned_dispatches: ['disp_own', 'ctx_1'] }),
    worktreeOwnershipCheck: (ctx) => ({ status: 'owned', worktree: ctx.worktree, owned_worktrees: ['path:/r'] }),
    taskOwnershipCheck: (ctx) => ({ status: 'owned', taskId: ctx.taskId }),
    runOwnershipCheck: (ctx) => ({ status: 'owned', runId: ctx.runId }),
    idOwnershipCheck: (ctx) => ({ status: 'owned', id: ctx.id }),
    pageOwnershipCheck: (ctx) => ({ status: 'owned', pageId: ctx.pageId }),
    repoOwnershipCheck: (ctx) => ({ status: 'owned', repo: ctx.repo }),
    ...extra,
  };
}

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
  const defaults = {
    ...resolveCliPolicyConfig({}),
    // NAS-250/252: selectors require positive ownership proof even with hardening off.
    ownershipCheck: (ctx) => ({
      status: 'owned',
      handle: ctx.handle,
      owned_handles: ['term_1'],
    }),
    dispatchOwnershipCheck: (ctx) => ({
      status: 'owned',
      dispatchId: ctx.dispatchId,
      owned_dispatches: ['ctx_1'],
      owned_handles: ['term_1'],
    }),
    worktreeOwnershipCheck: (ctx) => ({
      status: 'owned',
      worktree: ctx.worktree,
      owned_worktrees: ['path:/r'],
      owned_handles: ['term_1'],
    }),
    taskOwnershipCheck: (ctx) => ({ status: 'owned', taskId: ctx.taskId }),
    runOwnershipCheck: (ctx) => ({ status: 'owned', runId: ctx.runId }),
    idOwnershipCheck: (ctx) => ({ status: 'owned', id: ctx.id }),
    pageOwnershipCheck: (ctx) => ({ status: 'owned', pageId: ctx.pageId }),
    repoOwnershipCheck: (ctx) => ({ status: 'owned', repo: ctx.repo }),
  };

  const legitimate = [
    ['orchestration', 'reply', '--id', 'msg_1', '--body', 'yes', '--json'],
    ['orchestration', 'check', '--run', 'run_1', '--json'],
    ['skills', 'get', 'foo'],
    ['status', '--json'],
    ['worktree', 'show', '--worktree', 'path:/r', '--json'],
    ['worktree', 'list', '--limit', '20', '--json'],
    ['terminal', 'list', '--json'],
    ['terminal', 'list', '--worktree', 'path:/r', '--json'],
    ['terminal', 'read', '--terminal', 'term_1', '--limit', '50'],
    ['terminal', 'close', '--terminal', 'term_1', '--tab', '--json'],
    ['orchestration', 'worker-show', '--dispatch', 'ctx_1', '--json'],
    ['orchestration', 'worker-read', '--dispatch', 'ctx_1', '--json'],
    ['orchestration', 'dispatch-show', '--task', 'task_1', '--json'],
    ['orchestration', 'check', '--json'],
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

  it('explicit owner invariant: owned selectors still allow under default config', () => {
    const policy = createCliPolicy(defaults);
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

  // Non-selector risky argv still warn-allows when hardening off.
  const previouslyWorkingRisky = [
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
        ...allOwnedCheckers(),
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

  it('terminal send with --terminal denies without proven ownership (hardening off)', () => {
    // NAS-252: selector presence is enough; allowlist soft-warn is not a bypass.
    const r = evaluateCliArgv(
      ['terminal', 'send', '--terminal', 't', '--text', 'x'],
      defaults,
    );
    assert.equal(r.ok, false);
    assert.equal(r.decision, 'deny');
    assert.equal(r.rejection?.code, 'handle_not_owned');
  });

  it('terminal send with owned --terminal warn-allows when hardening off', () => {
    const r = evaluateCliArgv(
      ['terminal', 'send', '--terminal', 'term_own', '--text', 'x'],
      {
        ...defaults,
        ownershipCheck: () => ({
          status: 'owned',
          handle: 'term_own',
          owned_handles: ['term_own'],
        }),
      },
    );
    assert.equal(r.ok, true);
    assert.equal(r.decision, 'allow_with_warning');
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
      { ...hardened, ...allOwnedCheckers() },
    );
    assert.equal(r.ok, true);
    assert.equal(r.decision, 'allow');
  });

  it('denies terminal send with structured error', () => {
    // Selector present without ownershipCheck → ownership fail-closed (not allowlist).
    const r = evaluateCliArgv(
      ['terminal', 'send', '--terminal', 't', '--text', 'hi'],
      hardened,
    );
    assert.equal(r.ok, false);
    assert.equal(r.decision, 'deny');
    assert.equal(r.rejection.error, 'cli_policy_denied');
    assert.equal(r.rejection.code, 'handle_not_owned');
    assert.equal(r.rejection.rejected_subcommand, 'terminal send');
    assert.equal(r.rejection.next.action, 'guide');
  });

  it('denies terminal send allowlist when owned but admin locked', () => {
    const r = evaluateCliArgv(
      ['terminal', 'send', '--terminal', 't', '--text', 'hi'],
      {
        ...hardened,
        ownershipCheck: () => ({
          status: 'owned',
          handle: 't',
          owned_handles: ['t'],
        }),
      },
    );
    assert.equal(r.ok, false);
    assert.equal(r.rejection.error, 'cli_policy_denied');
    assert.equal(r.rejection.code, undefined);
    assert.equal(r.rejection.admin_required, true);
    assert.ok(r.rejection.admin_surface.includes('terminal send'));
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
      {
        hardening: true,
        admin: true,
        ownershipCheck: () => ({
          status: 'owned',
          handle: 't',
          owned_handles: ['t'],
        }),
      },
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
      { hardening: true, admin: true, ...allOwnedCheckers() },
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
    const policy = createCliPolicy({
      hardening: true,
      admin: false,
      ownershipCheck: () => ({ status: 'owned', handle: 't', owned_handles: ['t'] }),
    });
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
      ownershipCheck: () => ({ status: 'owned', handle: 't', owned_handles: ['t'] }),
    });
    policy.evaluate(['status']);
    policy.evaluate(['terminal', 'send', '--terminal', 't', '--text', 'x']);
    assert.deepEqual(seen, ['cli_policy_would_deny']);
  });

  it('warning hook errors do not fail the allow path', () => {
    const policy = createCliPolicy({
      hardening: false,
      ownershipCheck: () => ({ status: 'owned', handle: 't', owned_handles: ['t'] }),
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

  it('gates terminal read/close/send/show and orchestration check', () => {
    assert.equal(isOwnershipGatedArgv(['terminal', 'read']), true);
    assert.equal(isOwnershipGatedArgv(['terminal', 'close']), true);
    assert.equal(isOwnershipGatedArgv(['terminal', 'send']), true);
    assert.equal(isOwnershipGatedArgv(['terminal', 'show']), true);
    assert.equal(isOwnershipGatedArgv(['terminal', 'stop']), true);
    assert.equal(isOwnershipGatedArgv(['orchestration', 'check']), true);
    assert.equal(isOwnershipGatedArgv(['terminal', 'list']), false);
    assert.equal(isOwnershipGatedArgv(['status']), false);
    // NAS-250/252 expanded the legacy prefix table; selector presence also gates.
    assert.ok(OWNERSHIP_GATED_PREFIXES.length >= 4);
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
      // oracle-field removed: assert.equal(r.rejection.handle, 'term_foreign');
      // assert.equal(r.rejection.handle, 'term_foreign'); // P1-3 uniform deny
      // oracle-field removed: assert.deepEqual(r.rejection.owned_handles, ['term_own']);
      // assert.deepEqual(r.rejection.owned_handles, ['term_own']); // P1-3 uniform deny
      // oracle-field removed: assert.equal(r.rejection.ownership_status, 'not-owned');
      // assert.equal(r.rejection.ownership_status, 'not-owned'); // P1-3 uniform deny
      assert.ok(r.rejection.detail); // no owned-handle oracle in detail
      assert.equal(r.rejection.next.action, 'guide');
      assert.ok(Array.isArray(r.rejection.allowed_surface));
    });

    it(`hardening off still denies ${name} ownership miss (invariant)`, () => {
      const warnings = [];
      const r = evaluateCliArgv(argv, {
        hardening: false,
        admin: true,
        ownershipCheck: foreignCheck,
        onWarning: (w) => warnings.push(w),
      });
      assert.equal(r.ok, false);
      assert.equal(r.decision, 'deny');
      assert.ok(r.rejection);
      assert.equal(r.rejection.code, 'handle_not_owned');
      // oracle-field removed: assert.equal(r.rejection.handle, 'term_foreign');
      // assert.equal(r.rejection.handle, 'term_foreign'); // P1-3 uniform deny
      // oracle-field removed: assert.deepEqual(r.rejection.owned_handles, ['term_own']);
      // assert.deepEqual(r.rejection.owned_handles, ['term_own']); // P1-3 uniform deny
      // Observability: warning hook still fires under soft allowlist posture.
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
    // oracle-field removed: assert.equal(r.rejection.ownership_status, 'unknown');
    // assert.equal(r.rejection.ownership_status, 'unknown'); // P1-3 uniform deny
  });

  it('missing ownershipCheck fail-closes when --terminal is present', () => {
    // NAS-252: never soft-execute a target selector without a checker.
    const r = evaluateCliArgv(gated.read, { hardening: true });
    assert.equal(r.ok, false);
    assert.equal(r.decision, 'deny');
    assert.equal(r.rejection?.code, 'handle_not_owned');
    // oracle-field removed: assert.equal(r.rejection?.reason, 'ownership_check_not_configured');
    // assert.equal(r.rejection?.reason, 'ownership_check_not_configured'); // P1-3 uniform deny
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
    // oracle-field removed: assert.deepEqual(r.rejection.owned_handles, ['term_own']);
    // assert.deepEqual(r.rejection.owned_handles, ['term_own']); // P1-3 uniform deny
  });
});


// ---------------------------------------------------------------------------
// NAS-247 argv-shape edge cases (review nit)
// Full decision: matched_prefix / admin_required, ownership consultation,
// and allow | allow_with_warning (allowlist only) | deny (ownership always).
// ---------------------------------------------------------------------------

describe('evaluateCliArgv: ownership argv-shape edges', () => {
  const OWN = 'term_own';
  const FOREIGN = 'term_foreign';
  const OWNED = [OWN, 'term_worker'];

  /** Realistic check: resolve from the handle the funnel extracted. */
  function ownershipFromExtracted(statusByHandle) {
    return (ctx) => {
      const handle = ctx.handle == null ? null : String(ctx.handle);
      const entry =
        handle != null && Object.prototype.hasOwnProperty.call(statusByHandle, handle)
          ? statusByHandle[handle]
          : { status: 'unknown', reason: 'handle_not_in_registry' };
      return {
        status: entry.status,
        handle,
        owned_handles: OWNED,
        reason: entry.reason,
      };
    };
  }

  const map = {
    [OWN]: { status: 'owned', reason: 'client_owned' },
    [FOREIGN]: { status: 'not-owned', reason: 'foreign_handle' },
  };

  function assertOwnershipDeny(r, {
    handle,
    status = 'not-owned',
    matchedPrefix = ['terminal', 'read'],
    adminRequired = false,
    reason,
  } = {}) {
    assert.equal(r.ok, false);
    assert.equal(r.decision, 'deny');
    assert.deepEqual(r.matched_prefix, matchedPrefix);
    assert.equal(r.admin_required, adminRequired);
    assert.equal(r.warning, null);
    assert.ok(r.rejection);
    assert.equal(r.rejection.error, 'cli_policy_denied');
    assert.equal(r.rejection.code, 'handle_not_owned');
    // oracle-field removed: assert.equal(r.rejection.handle, handle);
    // assert.equal(r.rejection.handle, handle); // P1-3 uniform deny
    // oracle-field removed: assert.equal(r.rejection.ownership_status, status);
    // assert.equal(r.rejection.ownership_status, status); // P1-3 uniform deny
    // oracle-field removed: assert.deepEqual(r.rejection.owned_handles, OWNED);
    // assert.deepEqual(r.rejection.owned_handles, OWNED); // P1-3 uniform deny
    // P1-3: rejection.reason is never emitted (uniform deny).
    if (reason !== undefined) {
      assert.equal(r.rejection.reason, undefined);
      assert.equal(r.rejection.ownership_status, undefined);
      assert.equal(r.rejection.handle, undefined);
    }
  }

  function assertOwnershipWarn(r, {
    handle,
    status = 'not-owned',
    matchedPrefix = ['terminal', 'read'],
    adminRequired = false,
    reason,
  } = {}) {
    // NAS-248 P1: ownership always denies — hardening off is not a soft path.
    assert.equal(r.ok, false);
    assert.equal(r.decision, 'deny');
    assert.deepEqual(r.matched_prefix, matchedPrefix);
    assert.equal(r.admin_required, adminRequired);
    assert.ok(r.rejection);
    assert.equal(r.rejection.code, 'handle_not_owned');
    // oracle-field removed: assert.equal(r.rejection.handle, handle);
    // assert.equal(r.rejection.handle, handle); // P1-3 uniform deny
    // oracle-field removed: assert.equal(r.rejection.ownership_status, status);
    // assert.equal(r.rejection.ownership_status, status); // P1-3 uniform deny
    // oracle-field removed: assert.deepEqual(r.rejection.owned_handles, OWNED);
    // assert.deepEqual(r.rejection.owned_handles, OWNED); // P1-3 uniform deny
    // P1-3: rejection.reason is never emitted (uniform deny).
    if (reason !== undefined) {
      assert.equal(r.rejection.reason, undefined);
      assert.equal(r.rejection.ownership_status, undefined);
      assert.equal(r.rejection.handle, undefined);
    }
  }

  function assertAllow(r, { matchedPrefix = ['terminal', 'read'], adminRequired = false } = {}) {
    assert.equal(r.ok, true);
    assert.equal(r.decision, 'allow');
    assert.deepEqual(r.matched_prefix, matchedPrefix);
    assert.equal(r.admin_required, adminRequired);
    assert.equal(r.warning, null);
    assert.equal(r.rejection, null);
  }

  it('mixed / upper case subcommand still ownership-gates', () => {
    const argv = ['Terminal', 'READ', '--terminal', FOREIGN, '--limit', '5'];
    assert.deepEqual(commandTokens(argv), ['terminal', 'read']);
    assert.equal(isOwnershipGatedArgv(commandTokens(argv)), true);
    assert.equal(extractTerminalHandleFromArgv(argv), FOREIGN);

    const deny = evaluateCliArgv(argv, {
      hardening: true,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assertOwnershipDeny(deny, { handle: FOREIGN, reason: 'foreign_handle' });

    const warn = evaluateCliArgv(argv, {
      hardening: false,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assertOwnershipWarn(warn, { handle: FOREIGN });

    const allow = evaluateCliArgv(['Terminal', 'Read', '--terminal', OWN], {
      hardening: true,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assertAllow(allow);
  });

  it('extra tokens after a valid prefix still match and ownership-gate', () => {
    const argv = ['terminal', 'read', 'extra', '--terminal', FOREIGN];
    assert.deepEqual(commandTokens(argv), ['terminal', 'read', 'extra']);
    assert.equal(isOwnershipGatedArgv(commandTokens(argv)), true);

    const r = evaluateCliArgv(argv, {
      hardening: true,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assertOwnershipDeny(r, { handle: FOREIGN, reason: 'foreign_handle' });
  });

  it('leading global flags still run ownership (no allowlist widen)', () => {
    // commandTokens stops at the first flag-shaped token, so [--json, terminal, ...]
    // yields []. Allowlist still does not match (surface not widened), but ownership
    // is consulted so diagnostics are handle_not_owned rather than accidental empty.
    const argv = ['--json', 'terminal', 'read', '--terminal', FOREIGN];
    assert.deepEqual(commandTokens(argv), []);
    assert.equal(isOwnershipGatedArgv(commandTokens(argv)), false);
    assert.equal(looksLikeOwnershipGatedArgv(argv), true);
    assert.equal(extractTerminalHandleFromArgv(argv), FOREIGN);

    let consulted = 0;
    const rHard = evaluateCliArgv(argv, {
      hardening: true,
      ownershipCheck: (ctx) => {
        consulted += 1;
        return ownershipFromExtracted(map)(ctx);
      },
    });
    assert.ok(consulted >= 1);
    assertOwnershipDeny(rHard, {
      handle: FOREIGN,
      matchedPrefix: ['terminal', 'read'],
      reason: 'foreign_handle',
    });
    assert.equal(rHard.rejected_subcommand, 'terminal read');

    consulted = 0;
    const rSoft = evaluateCliArgv(argv, {
      hardening: false,
      ownershipCheck: (ctx) => {
        consulted += 1;
        return ownershipFromExtracted(map)(ctx);
      },
    });
    assert.ok(consulted >= 1);
    assertOwnershipWarn(rSoft, {
      handle: FOREIGN,
      matchedPrefix: ['terminal', 'read'],
    });
    assert.equal(rSoft.rejection?.code, 'handle_not_owned');

    // Owned handle under leading flags: ownership passes, but allowlist still
    // rejects empty tokens — surface not widened.
    const argvOwn = ['--json', 'terminal', 'read', '--terminal', OWN];
    const rOwnHard = evaluateCliArgv(argvOwn, {
      hardening: true,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assert.equal(rOwnHard.ok, false);
    assert.equal(rOwnHard.decision, 'deny');
    assert.equal(rOwnHard.rejection?.code, undefined); // allowlist, not ownership
    assert.equal(rOwnHard.rejected_subcommand, '(empty)');

    const rOwnSoft = evaluateCliArgv(argvOwn, {
      hardening: false,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assert.equal(rOwnSoft.ok, true);
    assert.equal(rOwnSoft.decision, 'allow_with_warning');
    assert.equal(rOwnSoft.warning?.code, 'cli_policy_would_deny');
  });

  it('`--` does not hide --terminal from ownership default-deny', () => {
    // Selector inversion: --terminal still names a target even if commandTokens
    // stop at `--`. Fail closed via ownership, not allowlist-only deny.
    const before = ['--', 'terminal', 'read', '--terminal', FOREIGN];
    assert.deepEqual(commandTokens(before), []);
    let consulted = 0;
    const rBefore = evaluateCliArgv(before, {
      hardening: true,
      ownershipCheck: (ctx) => {
        consulted += 1;
        return ownershipFromExtracted(map)(ctx);
      },
    });
    assert.ok(consulted >= 1);
    assert.equal(rBefore.decision, 'deny');
    assert.equal(rBefore.rejection?.code, 'handle_not_owned');
    // P1-3 uniform deny: assert.equal(rBefore.rejection?.handle, FOREIGN);

    const among = ['terminal', '--', 'read', '--terminal', FOREIGN];
    assert.deepEqual(commandTokens(among), ['terminal']);
    consulted = 0;
    const rAmong = evaluateCliArgv(among, {
      hardening: true,
      ownershipCheck: (ctx) => {
        consulted += 1;
        return ownershipFromExtracted(map)(ctx);
      },
    });
    assert.ok(consulted >= 1);
    assert.equal(rAmong.decision, 'deny');
    assert.equal(rAmong.rejection?.code, 'handle_not_owned');
    // P1-3 uniform deny: assert.equal(rAmong.rejection?.handle, FOREIGN);
  });

  it('positional handle is not accepted — missing --terminal fails closed unknown', () => {
    // Live CLI: `orca terminal read term_x` → "Unknown command: terminal read term_x".
    // Bridge extractors only read --terminal / --terminal=; bare tokens are ignored.
    const argv = ['terminal', 'read', FOREIGN, '--limit', '5'];
    assert.equal(extractTerminalHandleFromArgv(argv), null);
    assert.equal(isOwnershipGatedArgv(commandTokens(argv)), true);

    const r = evaluateCliArgv(argv, {
      hardening: true,
      ownershipCheck: (ctx) => ({
        status: ctx.handle == null ? 'unknown' : 'owned',
        handle: ctx.handle,
        owned_handles: OWNED,
        reason: 'missing_or_malformed_handle',
      }),
    });
    assertOwnershipDeny(r, {
      handle: null,
      status: 'unknown',
      reason: 'missing_or_malformed_handle',
    });
  });

  it('terminal read without --terminal fails closed once ownership runs', () => {
    const argv = ['terminal', 'read', '--limit', '20'];
    assert.equal(extractTerminalHandleFromArgv(argv), null);

    const hard = evaluateCliArgv(argv, {
      hardening: true,
      ownershipCheck: (ctx) => ({
        status: 'unknown',
        handle: ctx.handle,
        owned_handles: OWNED,
        reason: 'missing_or_malformed_handle',
      }),
    });
    assertOwnershipDeny(hard, {
      handle: null,
      status: 'unknown',
      reason: 'missing_or_malformed_handle',
    });

    const soft = evaluateCliArgv(argv, {
      hardening: false,
      ownershipCheck: (ctx) => ({
        status: 'unknown',
        handle: ctx.handle,
        owned_handles: OWNED,
        reason: 'missing_or_malformed_handle',
      }),
    });
    assertOwnershipWarn(soft, { handle: null, status: 'unknown' });
  });

  it('empty / whitespace / wrong-prefix handles fail closed as unknown', () => {
    const cases = [
      {
        argv: ['terminal', 'read', '--terminal', ''],
        // extract returns '' (raw); ownershipCheck / normalize treat as unknown
        extracted: '',
      },
      {
        argv: ['terminal', 'read', '--terminal', '   '],
        extracted: '   ',
      },
      {
        argv: ['terminal', 'read', '--terminal', 'not_a_handle'],
        extracted: 'not_a_handle',
      },
      {
        argv: ['terminal', 'read', '--terminal='],
        extracted: null, // empty after '=' → null in extractor
      },
    ];

    for (const { argv, extracted } of cases) {
      assert.equal(extractTerminalHandleFromArgv(argv), extracted);
      const r = evaluateCliArgv(argv, {
        hardening: true,
        ownershipCheck: (ctx) => {
          const h = ctx.handle;
          const normalized =
            h == null
              ? null
              : String(h).trim() === '' || /\s/.test(String(h).trim())
                ? null
                : String(h).trim();
          // wrong-prefix single token still reaches resolver as unknown-not-in-registry
          if (!normalized) {
            return {
              status: 'unknown',
              handle: normalized,
              owned_handles: OWNED,
              reason: 'missing_or_malformed_handle',
            };
          }
          return {
            status: 'unknown',
            handle: normalized,
            owned_handles: OWNED,
            reason: 'handle_not_in_registry',
          };
        },
      });
      assert.equal(r.decision, 'deny', `argv=${JSON.stringify(argv)}`);
      assert.equal(r.rejection?.code, 'handle_not_owned');
      // oracle-field removed: assert.equal(r.rejection?.ownership_status, 'unknown');
      // assert.equal(r.rejection?.ownership_status, 'unknown'); // P1-3 uniform deny
      assert.deepEqual(r.matched_prefix, ['terminal', 'read']);
      assert.equal(r.admin_required, false);
    }
  });

  it('foreign owned-by-other-client handle denies under hardening', () => {
    const argv = ['terminal', 'close', '--terminal', FOREIGN, '--tab'];
    const r = evaluateCliArgv(argv, {
      hardening: true,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assertOwnershipDeny(r, {
      handle: FOREIGN,
      matchedPrefix: ['terminal', 'close'],
      reason: 'foreign_handle',
    });
  });

  it('extractTerminalHandleFromArgv is CLI last-wins; collect returns every value', () => {
    assert.deepEqual(
      collectTerminalHandlesFromArgv([
        'terminal',
        'read',
        '--terminal',
        OWN,
        '--terminal',
        FOREIGN,
      ]),
      [OWN, FOREIGN],
    );
    assert.equal(
      extractTerminalHandleFromArgv([
        'terminal',
        'read',
        '--terminal',
        OWN,
        '--terminal',
        FOREIGN,
      ]),
      FOREIGN,
    );
    assert.equal(
      extractTerminalHandleFromArgv([
        'terminal',
        'read',
        '--terminal',
        FOREIGN,
        '--terminal',
        OWN,
      ]),
      OWN,
    );
    assert.deepEqual(
      collectTerminalHandlesFromArgv([
        'terminal',
        'read',
        `--terminal=${OWN}`,
        `--terminal=${FOREIGN}`,
      ]),
      [OWN, FOREIGN],
    );
    assert.equal(
      extractTerminalHandleFromArgv([
        'terminal',
        'read',
        `--terminal=${OWN}`,
        `--terminal=${FOREIGN}`,
      ]),
      FOREIGN,
    );
    assert.deepEqual(
      collectTerminalHandlesFromArgv([
        'terminal',
        'read',
        '--terminal',
        OWN,
        `--terminal=${FOREIGN}`,
      ]),
      [OWN, FOREIGN],
    );
    assert.equal(
      extractTerminalHandleFromArgv([
        'terminal',
        'read',
        '--terminal',
        OWN,
        `--terminal=${FOREIGN}`,
      ]),
      FOREIGN,
    );
  });

  it('dup --terminal owned-then-foreign denies under hardening (reports last/effective)', () => {
    // Deny-any: any foreign occurrence fails the gate. Payload handle is the
    // CLI-effective value (last wins) so the message names what would be touched.
    const argv = [
      'terminal',
      'read',
      '--terminal',
      OWN,
      '--terminal',
      FOREIGN,
      '--limit',
      '20',
    ];
    assert.deepEqual(collectTerminalHandlesFromArgv(argv), [OWN, FOREIGN]);
    assert.equal(extractTerminalHandleFromArgv(argv), FOREIGN);

    const seen = [];
    const r = evaluateCliArgv(argv, {
      hardening: true,
      ownershipCheck: (ctx) => {
        seen.push(ctx.handle);
        return ownershipFromExtracted(map)(ctx);
      },
    });
    assert.ok(seen.includes(OWN));
    assert.ok(seen.includes(FOREIGN));
    assertOwnershipDeny(r, {
      handle: FOREIGN, // effective / last
      reason: 'foreign_handle',
    });

    const soft = evaluateCliArgv(argv, {
      hardening: false,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assertOwnershipWarn(soft, { handle: FOREIGN });
  });

  it('dup --terminal foreign-then-owned still denies (deny-any, not last-wins alone)', () => {
    const argv = [
      'terminal',
      'send',
      '--terminal',
      FOREIGN,
      '--terminal',
      OWN,
      '--text',
      'x',
    ];
    assert.deepEqual(collectTerminalHandlesFromArgv(argv), [FOREIGN, OWN]);
    assert.equal(extractTerminalHandleFromArgv(argv), OWN);
    const r = evaluateCliArgv(argv, {
      hardening: true,
      admin: true, // send needs admin unlock to reach ownership
      ownershipCheck: ownershipFromExtracted(map),
    });
    // Effective handle in payload is last (OWN), but gate still denies because
    // FOREIGN appeared earlier.
    assertOwnershipDeny(r, {
      handle: OWN,
      matchedPrefix: ['terminal', 'send'],
      adminRequired: true,
      reason: 'foreign_handle',
    });

    const soft = evaluateCliArgv(argv, {
      hardening: false,
      admin: true,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assertOwnershipWarn(soft, {
      handle: OWN,
      matchedPrefix: ['terminal', 'send'],
      adminRequired: true,
    });
  });

  it('three --terminal occurrences and mixed =/space forms deny-any', () => {
    const argv = [
      'terminal',
      'read',
      '--terminal',
      OWN,
      `--terminal=${FOREIGN}`,
      '--terminal',
      OWN,
    ];
    assert.deepEqual(collectTerminalHandlesFromArgv(argv), [OWN, FOREIGN, OWN]);
    assert.equal(extractTerminalHandleFromArgv(argv), OWN);
    const r = evaluateCliArgv(argv, {
      hardening: true,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assertOwnershipDeny(r, {
      handle: OWN, // last/effective
      reason: 'foreign_handle',
    });
  });

  it('duplicate --terminal where every value is owned still allows', () => {
    const argv = [
      'terminal',
      'read',
      '--terminal',
      OWN,
      `--terminal=${OWN}`,
      '--terminal',
      OWN,
    ];
    assert.deepEqual(collectTerminalHandlesFromArgv(argv), [OWN, OWN, OWN]);
    const r = evaluateCliArgv(argv, {
      hardening: true,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assertAllow(r);
  });

  it('close/send prefixes honor the same argv-shape rules', () => {
    for (const [argv, prefix, admin] of [
      [['terminal', 'close', 'extra', '--terminal', FOREIGN, '--tab'], ['terminal', 'close'], false],
      [['Terminal', 'SEND', '--terminal', FOREIGN, '--text', 'x'], ['terminal', 'send'], true],
    ]) {
      const r = evaluateCliArgv(argv, {
        hardening: true,
        admin,
        ownershipCheck: ownershipFromExtracted(map),
      });
      assertOwnershipDeny(r, {
        handle: FOREIGN,
        matchedPrefix: prefix,
        adminRequired: admin,
        reason: 'foreign_handle',
      });
    }
  });
});

// ---------------------------------------------------------------------------
// NAS-248 — orchestration check / worker-read|show ownership + prefixes
// ---------------------------------------------------------------------------

describe('NAS-248: ownership-gated prefixes include check + dispatch paths', () => {
  it('OWNERSHIP_GATED_PREFIXES includes orchestration check', () => {
    const labels = OWNERSHIP_GATED_PREFIXES.map((p) => p.join(' '));
    assert.ok(labels.includes('orchestration check'));
    assert.ok(labels.includes('terminal read'));
  });

  it('DISPATCH_OWNERSHIP_GATED_PREFIXES covers read/show and teardown', () => {
    const labels = DISPATCH_OWNERSHIP_GATED_PREFIXES.map((p) => p.join(' '));
    assert.deepEqual(labels.sort(), [
      'orchestration worker-abandon',
      'orchestration worker-read',
      'orchestration worker-release',
      'orchestration worker-retain',
      'orchestration worker-show',
      'orchestration worker-stop',
    ]);
  });

  it('isOwnershipGatedArgv / isDispatchOwnershipGatedArgv classify correctly', () => {
    assert.equal(
      isOwnershipGatedArgv(commandTokens(['orchestration', 'check', '--terminal', 'x'])),
      true,
    );
    assert.equal(
      isOwnershipGatedArgv(commandTokens(['orchestration', 'worker-read', '--dispatch', 'd'])),
      false,
    );
    assert.equal(
      isDispatchOwnershipGatedArgv(
        commandTokens(['orchestration', 'worker-read', '--dispatch', 'd']),
      ),
      true,
    );
    assert.equal(
      isDispatchOwnershipGatedArgv(
        commandTokens(['orchestration', 'worker-show', '--dispatch', 'd']),
      ),
      true,
    );
  });

  it('looksLikeOwnershipGatedArgv covers check and worker-*', () => {
    assert.equal(
      looksLikeOwnershipGatedArgv(['--json', 'orchestration', 'check', '--terminal', 'x']),
      true,
    );
    assert.equal(
      looksLikeOwnershipGatedArgv([
        '--json',
        'orchestration',
        'worker-read',
        '--dispatch',
        'd',
      ]),
      true,
    );
  });
});

describe('NAS-248: orchestration check --terminal ownership', () => {
  const OWN = 'term_own';
  const FOREIGN = 'term_foreign';
  const OWNED = [OWN];

  function ownershipFromExtracted(statusByHandle) {
    return (ctx) => {
      const handle = ctx.handle == null ? null : String(ctx.handle);
      const entry =
        handle != null && Object.prototype.hasOwnProperty.call(statusByHandle, handle)
          ? statusByHandle[handle]
          : { status: 'unknown', reason: 'handle_not_in_registry' };
      return {
        status: entry.status,
        handle,
        owned_handles: OWNED,
        reason: entry.reason,
      };
    };
  }

  const map = {
    [OWN]: { status: 'owned', reason: 'client_owned' },
    [FOREIGN]: { status: 'not-owned', reason: 'foreign_handle' },
  };

  it('denies foreign --terminal under hardening', () => {
    const argv = ['orchestration', 'check', '--terminal', FOREIGN, '--json'];
    const r = evaluateCliArgv(argv, {
      hardening: true,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assert.equal(r.ok, false);
    assert.equal(r.decision, 'deny');
    assert.equal(r.rejection?.code, 'handle_not_owned');
    // oracle-field removed: assert.equal(r.rejection?.handle, FOREIGN);
    // assert.equal(r.rejection?.handle, FOREIGN); // P1-3 uniform deny
    assert.deepEqual(r.matched_prefix, ['orchestration', 'check']);
  });

  it('allows own --terminal under hardening', () => {
    const argv = ['orchestration', 'check', '--terminal', OWN, '--json'];
    const r = evaluateCliArgv(argv, {
      hardening: true,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assert.equal(r.ok, true);
    assert.equal(r.decision, 'allow');
  });

  it('absent --terminal does not fail-closed (pin injection path)', () => {
    // action=cli orchestration check without --terminal: withSender injects
    // this client's pin AFTER policy. Must not treat missing handle as unknown.
    const argv = ['orchestration', 'check', '--json'];
    let consulted = 0;
    const r = evaluateCliArgv(argv, {
      hardening: true,
      ownershipCheck: (ctx) => {
        consulted += 1;
        return { status: 'unknown', handle: ctx.handle, owned_handles: OWNED };
      },
    });
    assert.equal(consulted, 0);
    assert.equal(r.ok, true);
    assert.equal(r.decision, 'allow');
  });

  it('hardening off still denies foreign check --terminal', () => {
    const argv = ['orchestration', 'check', '--terminal', FOREIGN];
    const r = evaluateCliArgv(argv, {
      hardening: false,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assert.equal(r.ok, false);
    assert.equal(r.decision, 'deny');
    assert.equal(r.rejection?.code, 'handle_not_owned');
    // oracle-field removed: assert.equal(r.rejection?.handle, FOREIGN);
    // assert.equal(r.rejection?.handle, FOREIGN); // P1-3 uniform deny
  });

  it('deny-any on multi --terminal own-then-foreign', () => {
    const argv = [
      'orchestration',
      'check',
      '--terminal',
      OWN,
      '--terminal',
      FOREIGN,
    ];
    assert.deepEqual(collectTerminalHandlesFromArgv(argv), [OWN, FOREIGN]);
    const r = evaluateCliArgv(argv, {
      hardening: true,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assert.equal(r.decision, 'deny');
    assert.equal(r.rejection?.code, 'handle_not_owned');
    // Error payload reports CLI-effective (last) handle
    // oracle-field removed: assert.equal(r.rejection?.handle, FOREIGN);
    // assert.equal(r.rejection?.handle, FOREIGN); // P1-3 uniform deny
  });
});

describe('NAS-248: worker-read / worker-show dispatch ownership', () => {
  const OWN = 'disp_own';
  const FOREIGN = 'disp_foreign';
  const OWNED_D = [OWN];
  const OWNED_H = ['term_own'];

  function dispatchFromExtracted(statusById) {
    return (ctx) => {
      const id = ctx.dispatchId == null ? null : String(ctx.dispatchId);
      const entry =
        id != null && Object.prototype.hasOwnProperty.call(statusById, id)
          ? statusById[id]
          : { status: 'unknown', reason: 'dispatch_not_in_registry' };
      return {
        status: entry.status,
        dispatchId: id,
        owned_handles: OWNED_H,
        owned_dispatches: OWNED_D,
        reason: entry.reason,
      };
    };
  }

  const map = {
    [OWN]: { status: 'owned', reason: 'client_owned' },
    [FOREIGN]: { status: 'not-owned', reason: 'foreign_dispatch' },
  };

  for (const sub of ['worker-read', 'worker-show']) {
    it(`hardening on denies foreign ${sub}`, () => {
      const argv = [
        'orchestration',
        sub,
        '--dispatch',
        FOREIGN,
        '--source',
        'terminal',
        '--json',
      ];
      assert.equal(extractDispatchIdFromArgv(argv), FOREIGN);
      assert.deepEqual(collectDispatchIdsFromArgv(argv), [FOREIGN]);

      const r = evaluateCliArgv(argv, {
        hardening: true,
        dispatchOwnershipCheck: dispatchFromExtracted(map),
      });
      assert.equal(r.ok, false);
      assert.equal(r.decision, 'deny');
      assert.equal(r.rejection?.code, 'handle_not_owned');
      // oracle-field removed: assert.equal(r.rejection?.ownership_kind, 'dispatch');
      // assert.equal(r.rejection?.ownership_kind, 'dispatch'); // P1-3 uniform deny
      // oracle-field removed: assert.equal(r.rejection?.dispatch_id, FOREIGN);
      // assert.equal(r.rejection?.dispatch_id, FOREIGN); // P1-3 uniform deny
      // oracle-field removed: assert.deepEqual(r.rejection?.owned_dispatches, OWNED_D);
      // assert.deepEqual(r.rejection?.owned_dispatches, OWNED_D); // P1-3 uniform deny
      assert.deepEqual(r.matched_prefix, ['orchestration', sub]);
    });

    it(`allows own ${sub} under hardening`, () => {
      const argv = ['orchestration', sub, '--dispatch', OWN, '--json'];
      const r = evaluateCliArgv(argv, {
        hardening: true,
        dispatchOwnershipCheck: dispatchFromExtracted(map),
      });
      assert.equal(r.ok, true);
      assert.equal(r.decision, 'allow');
    });

    it(`hardening off still denies foreign ${sub}`, () => {
      const argv = ['orchestration', sub, '--dispatch', FOREIGN];
      const r = evaluateCliArgv(argv, {
        hardening: false,
        dispatchOwnershipCheck: dispatchFromExtracted(map),
      });
      assert.equal(r.ok, false);
      assert.equal(r.decision, 'deny');
      assert.equal(r.rejection?.code, 'handle_not_owned');
      // oracle-field removed: assert.equal(r.rejection?.dispatch_id, FOREIGN);
      // assert.equal(r.rejection?.dispatch_id, FOREIGN); // P1-3 uniform deny
      // oracle-field removed: assert.equal(r.rejection?.ownership_kind, 'dispatch');
      // assert.equal(r.rejection?.ownership_kind, 'dispatch'); // P1-3 uniform deny
    });
  }

  it('missing --dispatch fails closed as unknown', () => {
    const argv = ['orchestration', 'worker-read', '--source', 'terminal'];
    const r = evaluateCliArgv(argv, {
      hardening: true,
      dispatchOwnershipCheck: (ctx) => ({
        status: ctx.dispatchId == null ? 'unknown' : 'owned',
        dispatchId: ctx.dispatchId,
        owned_handles: OWNED_H,
        owned_dispatches: OWNED_D,
        reason: 'missing_or_malformed_dispatch',
      }),
    });
    assert.equal(r.decision, 'deny');
    assert.equal(r.rejection?.code, 'handle_not_owned');
    // oracle-field removed: assert.equal(r.rejection?.ownership_status, 'unknown');
    // assert.equal(r.rejection?.ownership_status, 'unknown'); // P1-3 uniform deny
    // oracle-field removed: assert.equal(r.rejection?.dispatch_id, null);
    // assert.equal(r.rejection?.dispatch_id, null); // P1-3 uniform deny
  });

  it('createCliPolicy threads dispatchOwnershipCheck', () => {
    const policy = createCliPolicy({
      hardening: true,
      dispatchOwnershipCheck: dispatchFromExtracted(map),
    });
    const deny = policy.evaluate([
      'orchestration',
      'worker-read',
      '--dispatch',
      FOREIGN,
    ]);
    assert.equal(deny.ok, false);
    // P1-3 uniform deny: assert.equal(deny.rejection?.dispatch_id, FOREIGN);

    const allow = policy.evaluate(
      ['orchestration', 'worker-read', '--dispatch', OWN],
      {
        dispatchOwnershipCheck: () => ({
          status: 'owned',
          dispatchId: OWN,
          owned_dispatches: OWNED_D,
          owned_handles: OWNED_H,
        }),
      },
    );
    assert.equal(allow.ok, true);
  });

  it('does not consult handle ownershipCheck for worker-read', () => {
    let handleConsulted = 0;
    const r = evaluateCliArgv(
      ['orchestration', 'worker-read', '--dispatch', FOREIGN],
      {
        hardening: true,
        ownershipCheck: () => {
          handleConsulted += 1;
          return { status: 'owned', handle: 'x', owned_handles: [] };
        },
        dispatchOwnershipCheck: dispatchFromExtracted(map),
      },
    );
    assert.equal(handleConsulted, 0);
    assert.equal(r.decision, 'deny');
  });
});


// ---------------------------------------------------------------------------
// NAS-248 bypass fixes: interleaved globals + ownership independent of hardening
// ---------------------------------------------------------------------------

describe('NAS-248 P1: interleaved globals still ownership-gate (hardening off)', () => {
  const FOREIGN = 'term_foreign';
  const OWN = 'term_own';
  const map = {
    [OWN]: { status: 'owned', reason: 'client_owned' },
    [FOREIGN]: { status: 'not-owned', reason: 'foreign_handle' },
  };
  function ownershipFromExtracted(statusByHandle) {
    return (ctx) => {
      const handle = ctx.handle == null ? null : String(ctx.handle);
      const entry =
        handle != null && Object.prototype.hasOwnProperty.call(statusByHandle, handle)
          ? statusByHandle[handle]
          : { status: 'unknown', reason: 'handle_not_in_registry' };
      return {
        status: entry.status,
        handle,
        owned_handles: [OWN],
        reason: entry.reason,
      };
    };
  }
  function dispatchFromExtracted(statusById) {
    return (ctx) => {
      const id = ctx.dispatchId == null ? null : String(ctx.dispatchId);
      const entry =
        id != null && Object.prototype.hasOwnProperty.call(statusById, id)
          ? statusById[id]
          : { status: 'unknown', reason: 'dispatch_not_in_registry' };
      return {
        status: entry.status,
        dispatchId: id,
        owned_handles: [OWN],
        owned_dispatches: ['disp_own'],
        reason: entry.reason,
      };
    };
  }
  const dmap = {
    disp_own: { status: 'owned', reason: 'client_owned' },
    disp_foreign: { status: 'not-owned', reason: 'foreign_dispatch' },
  };

  const interleaved = [
    ['orchestration', '--json', 'check', '--terminal', FOREIGN],
    ['orchestration', '--json=true', 'check', '--terminal', FOREIGN],
    ['orchestration', '--json', 'worker-read', '--dispatch', 'disp_foreign'],
    ['orchestration', '--json', 'worker-show', '--dispatch', 'disp_foreign'],
    ['orchestration', '--json', 'worker-release', '--dispatch', 'disp_foreign'],
  ];

  for (const argv of interleaved) {
    it(`denies with hardening OFF: ${argv.join(' ')}`, () => {
      assert.equal(looksLikeOwnershipGatedArgv(argv), true, `looks gated: ${argv}`);
      const isDispatch = argv.includes('worker-read') || argv.includes('worker-show') || argv.includes('worker-release');
      const r = evaluateCliArgv(argv, {
        hardening: false,
        ownershipCheck: ownershipFromExtracted(map),
        dispatchOwnershipCheck: dispatchFromExtracted(dmap),
      });
      assert.equal(r.ok, false, JSON.stringify(r));
      assert.equal(r.decision, 'deny');
      assert.equal(r.rejection?.code, 'handle_not_owned');
      if (isDispatch) {
        // oracle-field removed: assert.equal(r.rejection?.ownership_kind, 'dispatch');
        // assert.equal(r.rejection?.ownership_kind, 'dispatch'); // P1-3 uniform deny
        // oracle-field removed: assert.equal(r.rejection?.dispatch_id, 'disp_foreign');
        // assert.equal(r.rejection?.dispatch_id, 'disp_foreign'); // P1-3 uniform deny
      } else {
        // oracle-field removed: assert.equal(r.rejection?.handle, FOREIGN);
        // assert.equal(r.rejection?.handle, FOREIGN); // P1-3 uniform deny
      }
    });
  }

  it('looksLikeOwnershipGatedArgv skips interleaved flags', () => {
    assert.equal(
      looksLikeOwnershipGatedArgv(['orchestration', '--json', 'check', '--terminal', 'x']),
      true,
    );
    assert.equal(
      looksLikeOwnershipGatedArgv([
        'orchestration',
        '--json',
        'worker-release',
        '--dispatch',
        'd',
      ]),
      true,
    );
    assert.equal(
      looksLikeOwnershipGatedArgv(['terminal', '--json', 'read', '--terminal', 'x']),
      true,
    );
  });
});

// ---------------------------------------------------------------------------
// NAS-250/251/252 — selector default-deny + hardening-independent effects
// Tests drive evaluateCliArgv end-to-end and assert EFFECTS (no runtime call
// would proceed: decision=deny, rejection.code=handle_not_owned).
// ---------------------------------------------------------------------------

describe('NAS-250/251/252: selector default-deny effects', () => {
  const OWN = 'term_own';
  const FOREIGN = 'term_foreign';
  const OWN_WT = 'path:/home/alice/wt';
  const FOREIGN_WT = 'path:/home/bob/wt';
  const OWN_D = 'disp_own';
  const FOREIGN_D = 'disp_foreign';

  function handleCheck(map) {
    return (ctx) => {
      const h = ctx.handle == null ? null : String(ctx.handle);
      const e =
        h != null && Object.prototype.hasOwnProperty.call(map, h)
          ? map[h]
          : { status: 'unknown', reason: 'handle_not_in_registry' };
      return { status: e.status, handle: h, owned_handles: [OWN], reason: e.reason };
    };
  }
  function dispatchCheck(map) {
    return (ctx) => {
      const id = ctx.dispatchId == null ? null : String(ctx.dispatchId);
      const e =
        id != null && Object.prototype.hasOwnProperty.call(map, id)
          ? map[id]
          : { status: 'unknown', reason: 'dispatch_not_in_registry' };
      return {
        status: e.status,
        dispatchId: id,
        owned_handles: [OWN],
        owned_dispatches: [OWN_D],
        reason: e.reason,
      };
    };
  }
  function worktreeCheck(map) {
    return (ctx) => {
      const w = ctx.worktree == null ? null : String(ctx.worktree);
      const e =
        w != null && Object.prototype.hasOwnProperty.call(map, w)
          ? map[w]
          : { status: 'unknown', reason: 'worktree_not_in_registry' };
      return {
        status: e.status,
        worktree: w,
        owned_handles: [OWN],
        owned_worktrees: [OWN_WT],
        reason: e.reason,
      };
    };
  }

  const hMap = {
    [OWN]: { status: 'owned', reason: 'client_owned' },
    [FOREIGN]: { status: 'not-owned', reason: 'foreign_handle' },
  };
  const dMap = {
    [OWN_D]: { status: 'owned', reason: 'client_owned' },
    [FOREIGN_D]: { status: 'not-owned', reason: 'foreign_dispatch' },
  };
  const wMap = {
    [OWN_WT]: { status: 'owned', reason: 'client_owned' },
    [FOREIGN_WT]: { status: 'not-owned', reason: 'foreign_worktree' },
  };

  function assertDenied(r, { kind, target } = {}) {
    assert.equal(r.ok, false, `expected deny, got ${r.decision}`);
    assert.equal(r.decision, 'deny');
    assert.equal(r.rejection?.code, 'handle_not_owned');
    // EFFECT: policy rejection means runJson must not be called by server.
    assert.equal(r.rejection?.error, 'cli_policy_denied');
    // P1-3: uniform deny — no ownership_kind / handle / owned_* on rejection.
    assert.equal(r.rejection?.ownership_kind, undefined);
    assert.equal(r.rejection?.owned_handles, undefined);
    assert.equal(r.rejection?.ownership_status, undefined);
    assert.ok(typeof r.rejection?.detail === 'string' && r.rejection.detail.length > 0);
  }

  const SHOW_SPELLINGS = [
    ['terminal', 'show', '--terminal', FOREIGN, '--json'],
    ['terminal', 'show', `--terminal=${FOREIGN}`, '--json'],
    ['--json', 'terminal', 'show', '--terminal', FOREIGN],
    ['terminal', '--json', 'show', '--terminal', FOREIGN],
    ['TERMINAL', 'SHOW', '--terminal', FOREIGN],
  ];

  for (const argv of SHOW_SPELLINGS) {
    for (const hardening of [false, true]) {
      it(`denies terminal show foreign when hardening=${hardening} argv=${JSON.stringify(argv)}`, () => {
        const r = evaluateCliArgv(argv, {
          hardening,
          admin: true,
          ownershipCheck: handleCheck(hMap),
        });
        assertDenied(r, { kind: 'handle', target: FOREIGN });
      });
    }
  }

  it('allows terminal show for owned handle with hardening unset', () => {
    const r = evaluateCliArgv(
      ['terminal', 'show', '--terminal', OWN, '--json'],
      {
        hardening: false,
        admin: true,
        ownershipCheck: handleCheck(hMap),
      },
    );
    // show is not allowlisted → warn-allow after ownership passes
    assert.equal(r.ok, true);
    assert.equal(r.decision, 'allow_with_warning');
    assert.equal(r.rejection, null);
  });

  const STOP_SPELLINGS = [
    ['terminal', 'stop', '--worktree', FOREIGN_WT],
    ['terminal', 'stop', `--worktree=${FOREIGN_WT}`, '--json'],
    ['--json', 'terminal', 'stop', '--worktree', FOREIGN_WT],
    ['terminal', '--json', 'stop', '--worktree', FOREIGN_WT],
  ];

  for (const argv of STOP_SPELLINGS) {
    for (const hardening of [false, true]) {
      it(`denies terminal stop --worktree foreign hardening=${hardening}`, () => {
        assert.ok(collectWorktreeSelectorsFromArgv(argv).includes(FOREIGN_WT) ||
          collectWorktreeSelectorsFromArgv(argv).some((v) => v === FOREIGN_WT));
        const r = evaluateCliArgv(argv, {
          hardening,
          admin: true,
          worktreeOwnershipCheck: worktreeCheck(wMap),
        });
        assertDenied(r, { kind: 'worktree', target: FOREIGN_WT });
      });
    }
  }

  it('explicit: ownership denies with ORCA_BRIDGE_CLI_HARDENING unset', () => {
    // resolveCliPolicyConfig({}) → hardening false (env unset)
    const cfg = resolveCliPolicyConfig({});
    assert.equal(cfg.hardening, false);
    const r = evaluateCliArgv(
      ['terminal', 'show', '--terminal', FOREIGN, '--json'],
      {
        ...cfg,
        admin: true,
        ownershipCheck: handleCheck(hMap),
      },
    );
    assertDenied(r, { kind: 'handle', target: FOREIGN });
  });

  it('unknown worktree selector fails closed', () => {
    const r = evaluateCliArgv(
      ['terminal', 'stop', '--worktree', 'path:/unknown'],
      {
        hardening: false,
        admin: true,
        worktreeOwnershipCheck: worktreeCheck(wMap),
      },
    );
    assertDenied(r, { kind: 'worktree', target: 'path:/unknown' });
    // oracle-field removed: assert.equal(r.rejection?.ownership_status, 'unknown');
    // assert.equal(r.rejection?.ownership_status, 'unknown'); // P1-3 uniform deny
  });

  it('dispatch-id flag is ownership-gated like --dispatch', () => {
    const r = evaluateCliArgv(
      ['orchestration', 'send', '--dispatch-id', FOREIGN_D, '--type', 'x', '--body', 'b'],
      {
        hardening: false,
        admin: true,
        dispatchOwnershipCheck: dispatchCheck(dMap),
      },
    );
    assertDenied(r, { kind: 'dispatch', target: FOREIGN_D });
  });

  it('owned worktree stop is not ownership-denied (allowlist may still warn)', () => {
    const r = evaluateCliArgv(
      ['terminal', 'stop', '--worktree', OWN_WT, '--json'],
      {
        hardening: false,
        admin: true,
        worktreeOwnershipCheck: worktreeCheck(wMap),
      },
    );
    assert.notEqual(r.rejection?.code, 'handle_not_owned');
    assert.equal(r.ok, true);
  });

  it('argvHasOwnershipTargetSelector detects selector flags', () => {
    assert.equal(
      argvHasOwnershipTargetSelector(['terminal', 'list']),
      false,
    );
    assert.equal(
      argvHasOwnershipTargetSelector(['terminal', 'show', '--terminal', 'x']),
      true,
    );
    assert.equal(
      argvHasOwnershipTargetSelector(['terminal', 'stop', '--worktree', 'path:/a']),
      true,
    );
  });
});


// ---------------------------------------------------------------------------
// NAS-252 real inversion — flag table, new selectors, uniform deny, inbox
// ---------------------------------------------------------------------------

describe('NAS-252 real inversion: FLAG_TABLE allowlist', () => {
  it('every TARGET_FLAG_RESOLVERS entry is wired in FLAG_TABLE with a resolver', () => {
    assert.deepEqual(assertTargetFlagResolversComplete(), []);
    for (const name of Object.keys(TARGET_FLAG_RESOLVERS)) {
      assert.equal(FLAG_TABLE[name].kind, 'target');
      assert.ok(FLAG_TABLE[name].resolver);
    }
    // listed-but-unwired is impossible: TARGET_SELECTOR_FLAGS ⊆ resolvers
    for (const name of TARGET_SELECTOR_FLAGS) {
      assert.ok(TARGET_FLAG_RESOLVERS[name], name);
    }
  });

  it('unclassified flags fail closed', () => {
    assert.deepEqual(collectUnclassifiedFlagsFromArgv(['status', '--json']), []);
    assert.ok(collectUnclassifiedFlagsFromArgv(['status', '--not-a-real-flag']).includes('not-a-real-flag'));
    const r = evaluateCliArgv(['status', '--not-a-real-flag'], {
      hardening: false,
      ...allOwnedCheckers(),
    });
    assert.equal(r.decision, 'deny');
    assert.equal(r.rejection?.code, 'handle_not_owned');
  });

  it('dispatch-show --task foreign denies with hardening on and off', () => {
    for (const hardening of [false, true]) {
      const r = evaluateCliArgv(
        ['orchestration', 'dispatch-show', '--task', 'task_foreign', '--preamble', '--json'],
        {
          hardening,
          admin: true,
          ...allOwnedCheckers({
            taskOwnershipCheck: () => ({ status: 'not-owned', taskId: 'task_foreign' }),
          }),
        },
      );
      assert.equal(r.ok, false);
      assert.equal(r.decision, 'deny');
      assert.equal(r.rejection?.code, 'handle_not_owned');
      assert.equal(r.rejection?.owned_handles, undefined);
      assert.equal(r.rejection?.ownership_status, undefined);
    }
  });

  it('task-list --run foreign denies hardening on and off', () => {
    for (const hardening of [false, true]) {
      const r = evaluateCliArgv(
        ['orchestration', 'task-list', '--run', 'run_foreign', '--json'],
        {
          hardening,
          admin: true,
          ...allOwnedCheckers({
            runOwnershipCheck: () => ({ status: 'not-owned', runId: 'run_foreign' }),
          }),
        },
      );
      assert.equal(r.decision, 'deny');
      assert.equal(r.rejection?.code, 'handle_not_owned');
    }
  });

  it('run-show --id foreign denies', () => {
    const r = evaluateCliArgv(
      ['orchestration', 'run-show', '--id', 'run_foreign', '--json'],
      {
        hardening: false,
        admin: true,
        ...allOwnedCheckers({
          idOwnershipCheck: () => ({ status: 'not-owned', id: 'run_foreign' }),
        }),
      },
    );
    assert.equal(r.decision, 'deny');
  });

  it('run-list unscoped denies (justified: host-wide foreign objectives)', () => {
    const r = evaluateCliArgv(['orchestration', 'run-list', '--json'], {
      hardening: false,
      admin: true,
      ...allOwnedCheckers(),
    });
    assert.equal(r.decision, 'deny');
    assert.equal(r.rejection?.code, 'handle_not_owned');
    assert.match(r.rejection.detail, /run-list/i);
  });

  it('owned terminal list --worktree and worktree show --worktree allow', () => {
    for (const argv of [
      ['terminal', 'list', '--worktree', 'path:/own', '--json'],
      ['worktree', 'show', '--worktree', 'path:/own', '--json'],
      ['file', 'open', 'secret.env', '--worktree', 'path:/own'],
    ]) {
      const r = evaluateCliArgv(argv, {
        hardening: false,
        admin: true,
        ...allOwnedCheckers({
          worktreeOwnershipCheck: (ctx) => ({
            status: ctx.worktree === 'path:/own' ? 'owned' : 'not-owned',
            worktree: ctx.worktree,
          }),
        }),
      });
      assert.equal(r.ok, true, JSON.stringify({ argv, r }));
      assert.notEqual(r.decision, 'deny');
    }
  });

  it('tab/snapshot --page foreign denies', () => {
    for (const argv of [
      ['tab', 'show', '--page', 'page_FOREIGN'],
      ['snapshot', '--page', 'page_FOREIGN'],
    ]) {
      const r = evaluateCliArgv(argv, {
        hardening: false,
        admin: true,
        ...allOwnedCheckers({
          pageOwnershipCheck: () => ({ status: 'unknown', pageId: 'page_FOREIGN' }),
        }),
      });
      assert.equal(r.decision, 'deny');
    }
  });

  it('parent-worktree foreign denies', () => {
    const r = evaluateCliArgv(
      ['worktree', 'create', '--name', 'x', '--parent-worktree', '/home/other/foreign-wt'],
      {
        hardening: false,
        admin: true,
        ...allOwnedCheckers({
          parentWorktreeOwnershipCheck: () => ({ status: 'not-owned', worktree: '/home/other/foreign-wt' }),
          worktreeOwnershipCheck: () => ({ status: 'owned', worktree: 'x' }),
        }),
      },
    );
    assert.equal(r.decision, 'deny');
  });

  it('terminal stop --worktree new-child is NOT owned via synthetic (P2-2)', () => {
    const r = evaluateCliArgv(['terminal', 'stop', '--worktree', 'new-child'], {
      hardening: false,
      admin: true,
      worktreeOwnershipCheck: (ctx) => {
        // Mirror resolveWorktreeOwnership: synthetic only when allowSyntheticCreate
        if (ctx.worktree === 'new-child' && ctx.allowSyntheticCreate === true) {
          return { status: 'owned', reason: 'synthetic_create_selector' };
        }
        if (ctx.worktree === 'new-child') {
          return { status: 'unknown', reason: 'synthetic_create_not_claimable' };
        }
        return { status: 'owned' };
      },
    });
    assert.equal(r.decision, 'deny');
    assert.equal(r.rejection?.code, 'handle_not_owned');
  });

  it('worker-start --worktree new-child may be owned via synthetic create', () => {
    const r = evaluateCliArgv(
      ['orchestration', 'worker-start', '--task', 'task_1', '--worktree', 'new-child', '--agent', 'grok'],
      {
        hardening: false,
        admin: true,
        ...allOwnedCheckers({
          worktreeOwnershipCheck: (ctx) => {
            if (ctx.worktree === 'new-child' && ctx.allowSyntheticCreate === true) {
              return { status: 'owned', reason: 'synthetic_create_selector' };
            }
            return { status: 'unknown' };
          },
        }),
      },
    );
    assert.notEqual(r.rejection?.code, 'handle_not_owned');
    assert.equal(r.ok, true);
  });

  it('uniform deny does not leak owned_handles or status oracle', () => {
    const r = evaluateCliArgv(['terminal', 'show', '--terminal', 'term_ghost'], {
      hardening: false,
      ownershipCheck: () => ({
        status: 'unknown',
        handle: 'term_ghost',
        owned_handles: ['term_secret_own'],
        reason: 'handle_not_in_registry',
      }),
    });
    assert.equal(r.decision, 'deny');
    const rej = r.rejection;
    assert.equal(rej.owned_handles, undefined);
    assert.equal(rej.owned_worktrees, undefined);
    assert.equal(rej.ownership_status, undefined);
    assert.equal(rej.reason, undefined);
    assert.equal(JSON.stringify(rej).includes('term_secret_own'), false);
    assert.equal(JSON.stringify(rej).includes('handle_not_in_registry'), false);
    assert.equal(JSON.stringify(rej).includes('foreign_handle'), false);
  });
});


describe('NAS-252 r7 parse/output parity', () => {
  it('positional automations show <id> normalizes to --id and denies like flagged form', () => {
    const pos = ['automations', 'show', 'auto_foreign'];
    const flagged = ['automations', 'show', '--id', 'auto_foreign'];
    assert.deepEqual(normalizeArgvForPolicy(pos).slice(-2), ['--id', 'auto_foreign']);
    for (const hardening of [false, true]) {
      for (const argv of [pos, flagged]) {
        const r = evaluateCliArgv(argv, {
          hardening,
          admin: true,
          ...allOwnedCheckers({
            idOwnershipCheck: () => ({ status: 'not-owned', id: 'auto_foreign' }),
          }),
        });
        assert.equal(r.decision, 'deny', JSON.stringify({ argv, hardening, r }));
        assert.equal(r.rejection?.code, 'handle_not_owned');
      }
    }
  });

  it('artifacts delete positionals deny; linear issue ids are not orch targets', () => {
    for (const [pos, flagged] of [
      [['artifacts', 'delete', 'art_x'], ['artifacts', 'delete', '--id', 'art_x']],
    ]) {
      const rp = evaluateCliArgv(pos, { hardening: false, admin: true, ...allOwnedCheckers({
        idOwnershipCheck: () => ({ status: 'not-owned' }),
      })});
      const rf = evaluateCliArgv(flagged, { hardening: false, admin: true, ...allOwnedCheckers({
        idOwnershipCheck: () => ({ status: 'not-owned' }),
      })});
      assert.equal(rp.decision, 'deny');
      assert.equal(rf.decision, 'deny');
    }
    // Linear ticket keys are not orchestration id grammar → not ownership-denied.
    for (const argv of [
      ['linear', 'issue', 'NAS-252'],
      ['linear', 'issue', '--id', 'NAS-252'],
      ['linear', 'issue', 'ISSUE-1'],
    ]) {
      const r = evaluateCliArgv(argv, { hardening: false, admin: true, ...allOwnedCheckers({
        idOwnershipCheck: () => ({ status: 'not-owned' }),
      })});
      assert.notEqual(r.rejection?.code, 'handle_not_owned', JSON.stringify({ argv, r }));
    }
  });

  it('spec differential: every shipped allowed flag is classified in FLAG_TABLE', () => {
    const missing = [...allSpecAllowedFlagNames()].filter((f) => !FLAG_TABLE[String(f).toLowerCase()]);
    assert.deepEqual(missing, [], 'unclassified shipped flags: ' + missing.join(','));
  });

  it('spec differential: every command positional promotes into a classified flag', () => {
    for (const spec of CLI_COMMAND_SPECS) {
      const pos = spec.positionalArgs || [];
      if (!pos.length) continue;
      const fakeVals = pos.map((p, i) => 'val_' + i);
      const argv = [...spec.path, ...fakeVals];
      const norm = normalizeArgvForPolicy(argv);
      for (const name of pos) {
        const has = norm.some((t, i, a) => t === '--' + name || String(t).startsWith('--' + name + '='));
        assert.equal(has, true, spec.path.join(' ') + ' missing promoted --' + name + ' from ' + JSON.stringify(norm));
        assert.ok(FLAG_TABLE[String(name).toLowerCase()], 'positional flag not in FLAG_TABLE: ' + name);
      }
    }
  });

  it('spec differential: target-capable flags are kind=target with a live resolver', () => {
    // Locks MUT3: a flag that can carry a target VALUE must be bound to a
    // resolver that actually runs — table membership alone is decoration.
    const TARGET_CAPABLE = new Set([
      'terminal', 'dispatch', 'dispatch-id', 'worktree', 'parent-worktree',
      'task', 'task-id', 'run', 'id', 'page', 'pane', 'to', 'ack', 'retry-of',
      'parent', 'resume',
    ]);
    for (const name of TARGET_CAPABLE) {
      const entry = FLAG_TABLE[name];
      assert.ok(entry, 'missing FLAG_TABLE entry for target-capable --' + name);
      assert.equal(entry.kind, 'target', '--' + name + ' must be kind=target, got ' + entry.kind);
      assert.ok(entry.resolver, '--' + name + ' must have a resolver kind');
      assert.equal(
        TARGET_FLAG_RESOLVERS[name],
        entry.resolver,
        '--' + name + ' TARGET_FLAG_RESOLVERS mismatch',
      );
    }
    // Every positional that promotes to a target-capable name must stay target.
    for (const spec of CLI_COMMAND_SPECS) {
      for (const name of spec.positionalArgs || []) {
        const n = String(name).toLowerCase();
        if (!TARGET_CAPABLE.has(n)) continue;
        const entry = FLAG_TABLE[n];
        assert.equal(entry?.kind, 'target', spec.path.join(' ') + ' positional --' + n + ' lost target kind');
        assert.ok(entry?.resolver, spec.path.join(' ') + ' positional --' + n + ' lost resolver');
      }
    }
    // Effect: MUT3-style demotion of id must make automations show allow_with_warning.
    // Assert the positive: id is target AND foreign automations show denies.
    assert.equal(FLAG_TABLE.id.kind, 'target');
    assert.equal(FLAG_TABLE.id.resolver, 'id');
    const r = evaluateCliArgv(['automations', 'show', 'auto_FOREIGN'], {
      hardening: false,
      admin: true,
      ...allOwnedCheckers({ idOwnershipCheck: () => ({ status: 'not-owned' }) }),
    });
    assert.equal(r.decision, 'deny', 'id resolver must run on automations show positional');
    assert.equal(r.rejection?.code, 'handle_not_owned');
  });

  it('snapshot CLI_SPEC_VERSION matches package-reported bridge pin 1.4.180', async () => {
    // Cheap rot alarm: snapshot version must equal the pinned runtime string.
    // Do not re-plumb to AppImage; just fail loudly when someone bumps one side.
    const { CLI_SPEC_VERSION } = await import('./cli-argv-normalize.mjs');
    assert.equal(CLI_SPEC_VERSION, '1.4.180');
    // Unique paths only (deduped snapshot).
    const paths = CLI_COMMAND_SPECS.map((s) => s.path.join(' '));
    assert.equal(paths.length, new Set(paths).size, 'CLI_COMMAND_SPECS must not contain duplicate paths');
  });

  it('unscoped worker-list denies like run-list; scoped --run owned allows', () => {
    for (const hardening of [false, true]) {
      const un = evaluateCliArgv(['orchestration', 'worker-list', '--json'], {
        hardening, admin: true, ...allOwnedCheckers(),
      });
      assert.equal(un.decision, 'deny');
      assert.match(un.rejection.detail, /worker-list|unscoped/i);
    }
    // Ownership path (hardening off): scoped --run owned is not ownership-denied.
    // Under hardening on, worker-list is still outside RAW_CLI_OK (allowlist deny).
    const sc = evaluateCliArgv(['orchestration', 'worker-list', '--run', 'run_own', '--json'], {
      hardening: false, admin: true, ...allOwnedCheckers({
        runOwnershipCheck: (ctx) => ({ status: ctx.runId === 'run_own' ? 'owned' : 'not-owned', runId: ctx.runId }),
      }),
    });
    assert.notEqual(sc.rejection?.code, 'handle_not_owned');
    assert.equal(sc.ok, true);
    const lists = listShapedOrchestrationCommands().map((l) => l.path.join(' '));
    assert.ok(lists.includes('orchestration run-list'));
    assert.ok(lists.includes('orchestration worker-list'));
  });

  it('value-typed --to/--ack/--retry-of/--parent resolve by referent grammar', () => {
    const cases = [
      [['orchestration', 'send', '--to', 'term_foreign', '--subject', 'x'], 'handle'],
      [['orchestration', 'send', '--to', 'run:run_foreign', '--subject', 'x'], 'run'],
      [['orchestration', 'send', '--to', 'dispatch:ctx_foreign', '--subject', 'x'], 'dispatch'],
      [['orchestration', 'check', '--ack', 'delivery_FOREIGN'], 'id'],
      [['orchestration', 'worker-start', '--task', 'task_own', '--retry-of', 'ctx_foreign', '--agent', 'g'], 'dispatch'],
      [['orchestration', 'task-create', '--spec', 'x', '--parent', 'task_foreign'], 'task'],
    ];
    for (const [argv] of cases) {
      const r = evaluateCliArgv(argv, {
        hardening: false,
        admin: true,
        ...allOwnedCheckers({
          ownershipCheck: (ctx) => ({ status: String(ctx.handle||'').includes('own') ? 'owned' : 'not-owned', handle: ctx.handle }),
          runOwnershipCheck: () => ({ status: 'not-owned' }),
          dispatchOwnershipCheck: () => ({ status: 'not-owned' }),
          taskOwnershipCheck: (ctx) => ({ status: String(ctx.taskId||'').includes('own') ? 'owned' : 'not-owned', taskId: ctx.taskId }),
          idOwnershipCheck: () => ({ status: 'not-owned' }),
        }),
      });
      assert.equal(r.decision, 'deny', JSON.stringify({ argv, r }));
    }
  });

  it('false denies fixed: worktree list --repo, cookie httpOnly/sameSite, computer permissions --id', () => {
    for (const argv of [
      ['worktree', 'list', '--repo', 'my-repo'],
      ['cookie', 'set', '--name', 'a', '--value', 'b', '--httpOnly', '--sameSite', 'Lax'],
      ['computer', 'permissions', '--id', 'accessibility'],
    ]) {
      const r = evaluateCliArgv(argv, { hardening: false, admin: true, ...allOwnedCheckers() });
      assert.notEqual(r.decision, 'deny', JSON.stringify({ argv, r }));
      assert.notEqual(r.rejection?.code, 'handle_not_owned');
    }
  });

  it('HELD 1-18 smoke: foreign show/stop deny; owned list/show/check/run-list allow; unscoped run-list deny', () => {
    const foreignDeny = [
      ['terminal', 'show', '--json', '--terminal', 'term_foreign'],
      ['terminal', 'read', '--terminal', 'term_foreign'],
      ['terminal', 'stop', '--worktree', 'path:/foreign'],
      ['terminal', 'stop', '--worktree', 'name:x'],
      ['orchestration', 'dispatch-show', '--task', 'task_foreign'],
      ['orchestration', 'task-list', '--run', 'run_foreign'],
      ['orchestration', 'run-show', '--id', 'run_foreign'],
      ['orchestration', 'run-list'],
      ['orchestration', 'worker-list'],
      ['tab', 'show', '--page', 'page_FOREIGN'],
      ['terminal', 'stop', '--worktree', 'new-child'],
    ];
    for (const argv of foreignDeny) {
      const r = evaluateCliArgv(argv, {
        hardening: false,
        admin: true,
        ...allOwnedCheckers({
          ownershipCheck: () => ({ status: 'not-owned' }),
          worktreeOwnershipCheck: (ctx) => ({
            status: ctx.worktree === 'new-child' && ctx.allowSyntheticCreate ? 'owned' : 'not-owned',
            worktree: ctx.worktree,
          }),
          taskOwnershipCheck: () => ({ status: 'not-owned' }),
          runOwnershipCheck: () => ({ status: 'not-owned' }),
          idOwnershipCheck: () => ({ status: 'not-owned' }),
          pageOwnershipCheck: () => ({ status: 'unknown' }),
        }),
      });
      assert.equal(r.decision, 'deny', JSON.stringify({ argv, decision: r.decision }));
      if (r.rejection?.code === 'handle_not_owned') {
        assert.equal(r.rejection.ownership_status, undefined);
        assert.equal(r.rejection.owned_handles, undefined);
      }
    }
    for (const argv of [
      ['terminal', 'list', '--worktree', 'path:/own', '--json'],
      ['worktree', 'show', '--worktree', 'path:/own', '--json'],
      ['terminal', 'read', '--terminal', 'term_own'],
      ['orchestration', 'worker-read', '--dispatch', 'ctx_own'],
      ['orchestration', 'check', '--json'],
      ['orchestration', 'run-list', '--run', 'run_own'],
    ]) {
      const r = evaluateCliArgv(argv, {
        hardening: false,
        admin: true,
        ...allOwnedCheckers({
          ownershipCheck: (ctx) => ({ status: String(ctx.handle||'').includes('own') ? 'owned' : 'not-owned', handle: ctx.handle }),
          worktreeOwnershipCheck: (ctx) => ({ status: String(ctx.worktree||'').includes('own') ? 'owned' : 'not-owned', worktree: ctx.worktree }),
          dispatchOwnershipCheck: (ctx) => ({ status: String(ctx.dispatchId||'').includes('own') ? 'owned' : 'not-owned', dispatchId: ctx.dispatchId }),
          runOwnershipCheck: (ctx) => ({ status: String(ctx.runId||'').includes('own') ? 'owned' : 'not-owned', runId: ctx.runId }),
        }),
      });
      assert.notEqual(r.decision, 'deny', JSON.stringify({ argv, r }));
    }
  });

  it('msg_* reply allows at gate; non-msg id still resolves', () => {
    const reply = evaluateCliArgv(
      ['orchestration', 'reply', '--id', 'msg_FOREIGN', '--body', 'x', '--from', 'term_FOREIGN'],
      { hardening: true, admin: true, ...allOwnedCheckers({
        idOwnershipCheck: () => ({ status: 'not-owned' }),
        ownershipCheck: () => ({ status: 'not-owned' }),
      })},
    );
    assert.equal(reply.decision, 'allow');
    const runShow = evaluateCliArgv(
      ['orchestration', 'run-show', '--id', 'run_FOREIGN'],
      { hardening: false, admin: true, ...allOwnedCheckers({
        idOwnershipCheck: () => ({ status: 'not-owned' }),
      })},
    );
    assert.equal(runShow.decision, 'deny');
  });
});


describe('NAS-252 closeout r10', () => {
  it('denies --to @all and routes @worktree through worktree checker', () => {
    for (const hardening of [false, true]) {
      const all = evaluateCliArgv(
        ['orchestration', 'send', '--to', '@all', '--subject', 'x'],
        { hardening, admin: true, ...allOwnedCheckers() },
      );
      assert.equal(all.decision, 'deny', 'hardening=' + hardening);
      assert.equal(all.rejection?.code, 'handle_not_owned');

      const wt = evaluateCliArgv(
        ['orchestration', 'send', '--to', '@worktree:path:/foreign', '--subject', 'x'],
        {
          hardening, admin: true,
          ...allOwnedCheckers({
            worktreeOwnershipCheck: () => ({ status: 'not-owned', worktree: 'path:/foreign' }),
          }),
        },
      );
      assert.equal(wt.decision, 'deny');
      assert.equal(wt.rejection?.code, 'handle_not_owned');
    }
  });

  it('content flags with token-shaped values allow when address is owned', () => {
    const owned = {
      hardening: false,
      admin: true,
      ...allOwnedCheckers({
        ownershipCheck: (ctx) => ({
          status: String(ctx.handle || '').includes('own') ? 'owned' : 'not-owned',
          handle: ctx.handle,
        }),
      }),
    };
    for (const argv of [
      ['orchestration', 'reply', '--id', 'msg_own', '--body', 'term_FOREIGN'],
      ['terminal', 'send', '--terminal', 'term_own', '--text', 'term_FOREIGN'],
      ['orchestration', 'send', '--to', 'term_own', '--subject', 'term_FOREIGN'],
      ['orchestration', 'send', '--to', 'term_own', '--payload', 'term_FOREIGN'],
      ['orchestration', 'send', '--to', 'term_own', '--dispatch-capability', 'ctx_FOREIGN'],
    ]) {
      const r = evaluateCliArgv(argv, owned);
      assert.notEqual(r.rejection?.code, 'handle_not_owned', JSON.stringify({ argv, r }));
      assert.notEqual(r.decision, 'deny', JSON.stringify({ argv, r }));
    }
  });

  it('computer permissions --id accessibility allows; --id task_FOREIGN denies', () => {
    const rOk = evaluateCliArgv(['computer', 'permissions', '--id', 'accessibility'], {
      hardening: false, admin: true, ...allOwnedCheckers(),
    });
    assert.notEqual(rOk.rejection?.code, 'handle_not_owned');
    const rDeny = evaluateCliArgv(['computer', 'permissions', '--id', 'task_FOREIGN'], {
      hardening: false, admin: true, ...allOwnedCheckers({
        idOwnershipCheck: () => ({ status: 'not-owned', id: 'task_FOREIGN' }),
      }),
    });
    assert.equal(rDeny.decision, 'deny');
    assert.equal(rDeny.rejection?.code, 'handle_not_owned');
  });

  it('linear issue NAS-252 allows (not orch id grammar)', () => {
    const r = evaluateCliArgv(['linear', 'issue', 'NAS-252'], {
      hardening: false, admin: true, ...allOwnedCheckers({
        idOwnershipCheck: () => ({ status: 'not-owned' }),
      }),
    });
    assert.notEqual(r.rejection?.code, 'handle_not_owned');
  });

  it('HELD 19-21 still hold: unscoped lists deny; foreign show denies; owned check allows', () => {
    for (const argv of [
      ['orchestration', 'run-list'],
      ['orchestration', 'worker-list'],
      ['terminal', 'show', '--terminal', 'term_foreign'],
      ['automations', 'show', 'auto_FOREIGN'],
    ]) {
      const r = evaluateCliArgv(argv, {
        hardening: false, admin: true,
        ...allOwnedCheckers({
          ownershipCheck: () => ({ status: 'not-owned' }),
          idOwnershipCheck: () => ({ status: 'not-owned' }),
        }),
      });
      assert.equal(r.decision, 'deny', JSON.stringify(argv));
    }
    const check = evaluateCliArgv(['orchestration', 'check', '--json'], {
      hardening: false, admin: true, ...allOwnedCheckers(),
    });
    assert.notEqual(check.decision, 'deny');
  });
});
