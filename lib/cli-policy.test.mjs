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
  extractDispatchIdFromArgv,
  collectTerminalHandlesFromArgv,
  collectDispatchIdsFromArgv,
  isOwnershipGatedArgv,
  isDispatchOwnershipGatedArgv,
  looksLikeOwnershipGatedArgv,
  OWNERSHIP_GATED_PREFIXES,
  DISPATCH_OWNERSHIP_GATED_PREFIXES,
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

  it('gates terminal read/close/send and orchestration check', () => {
    assert.equal(isOwnershipGatedArgv(['terminal', 'read']), true);
    assert.equal(isOwnershipGatedArgv(['terminal', 'close']), true);
    assert.equal(isOwnershipGatedArgv(['terminal', 'send']), true);
    assert.equal(isOwnershipGatedArgv(['orchestration', 'check']), true);
    assert.equal(isOwnershipGatedArgv(['terminal', 'list']), false);
    assert.equal(isOwnershipGatedArgv(['status']), false);
    // NAS-248 added orchestration check to the handle-gated set.
    assert.equal(OWNERSHIP_GATED_PREFIXES.length, 4);
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


// ---------------------------------------------------------------------------
// NAS-247 argv-shape edge cases (review nit)
// Full decision: matched_prefix / admin_required, ownership consultation,
// and allow | allow_with_warning | deny.
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
    assert.equal(r.rejection.handle, handle);
    assert.equal(r.rejection.ownership_status, status);
    assert.deepEqual(r.rejection.owned_handles, OWNED);
    if (reason !== undefined) assert.equal(r.rejection.reason, reason);
  }

  function assertOwnershipWarn(r, {
    handle,
    status = 'not-owned',
    matchedPrefix = ['terminal', 'read'],
    adminRequired = false,
  } = {}) {
    assert.equal(r.ok, true);
    assert.equal(r.decision, 'allow_with_warning');
    assert.deepEqual(r.matched_prefix, matchedPrefix);
    assert.equal(r.admin_required, adminRequired);
    assert.equal(r.rejection, null);
    assert.ok(r.warning);
    assert.equal(r.warning.code, 'handle_not_owned');
    assert.equal(r.warning.handle, handle);
    assert.equal(r.warning.ownership_status, status);
    assert.deepEqual(r.warning.owned_handles, OWNED);
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
    assert.equal(rSoft.warning?.code, 'handle_not_owned');

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

  it('`--` before or among subcommand tokens prevents ownership gating', () => {
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
    assert.equal(consulted, 0);
    assert.equal(rBefore.decision, 'deny');
    assert.equal(rBefore.rejection?.error, 'cli_policy_denied');
    assert.equal(rBefore.rejection?.code, undefined);

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
    assert.equal(consulted, 0);
    // "terminal" alone is not an ownership-gated / allowlisted prefix.
    assert.equal(rAmong.decision, 'deny');
    assert.equal(rAmong.rejection?.code, undefined);
    assert.equal(rAmong.rejected_subcommand, 'terminal');
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
      assert.equal(r.rejection?.ownership_status, 'unknown');
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

  it('DISPATCH_OWNERSHIP_GATED_PREFIXES covers worker-read and worker-show', () => {
    const labels = DISPATCH_OWNERSHIP_GATED_PREFIXES.map((p) => p.join(' '));
    assert.deepEqual(labels.sort(), [
      'orchestration worker-read',
      'orchestration worker-show',
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
    assert.equal(r.rejection?.handle, FOREIGN);
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

  it('soft mode warns on foreign check --terminal', () => {
    const argv = ['orchestration', 'check', '--terminal', FOREIGN];
    const r = evaluateCliArgv(argv, {
      hardening: false,
      ownershipCheck: ownershipFromExtracted(map),
    });
    assert.equal(r.ok, true);
    assert.equal(r.decision, 'allow_with_warning');
    assert.equal(r.warning?.code, 'handle_not_owned');
    assert.equal(r.warning?.handle, FOREIGN);
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
    assert.equal(r.rejection?.handle, FOREIGN);
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
      assert.equal(r.rejection?.ownership_kind, 'dispatch');
      assert.equal(r.rejection?.dispatch_id, FOREIGN);
      assert.deepEqual(r.rejection?.owned_dispatches, OWNED_D);
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

    it(`soft mode warns on foreign ${sub}`, () => {
      const argv = ['orchestration', sub, '--dispatch', FOREIGN];
      const r = evaluateCliArgv(argv, {
        hardening: false,
        dispatchOwnershipCheck: dispatchFromExtracted(map),
      });
      assert.equal(r.ok, true);
      assert.equal(r.decision, 'allow_with_warning');
      assert.equal(r.warning?.code, 'handle_not_owned');
      assert.equal(r.warning?.dispatch_id, FOREIGN);
      assert.equal(r.warning?.ownership_kind, 'dispatch');
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
    assert.equal(r.rejection?.ownership_status, 'unknown');
    assert.equal(r.rejection?.dispatch_id, null);
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
    assert.equal(deny.rejection?.dispatch_id, FOREIGN);

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

