import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  TOOLSET_TIERS,
  ACTION_TIERS,
  CLI_PREFIX_TIERS,
  defaultEnabledToolsets,
  parseToolsetsList,
  resolveToolsetsConfig,
  tierForAction,
  tierForCliArgv,
  requiredTierFor,
  evaluateToolsetAccess,
  createToolsetGate,
  assertTierMappingInvariants,
} from './toolsets.mjs';
import {
  RAW_CLI_OK_PREFIXES,
  RAW_CLI_ADMIN_PREFIXES,
  createCliPolicy,
  resolveCliPolicyConfig,
  formatPrefix,
} from './cli-policy.mjs';

// ---------------------------------------------------------------------------
// mapping completeness — fails if a new action/prefix is added without a tier
// ---------------------------------------------------------------------------

describe('tier mapping completeness', () => {
  it('every ACTION_TIERS value is a known TOOLSET_TIERS entry', () => {
    for (const [action, tier] of Object.entries(ACTION_TIERS)) {
      assert.ok(TOOLSET_TIERS.includes(tier), `${action} → ${tier}`);
    }
  });

  it('covers the canonical multiplexed actions', () => {
    for (const action of ['health', 'guide', 'check', 'dispatch', 'await', 'release', 'cli']) {
      assert.ok(action in ACTION_TIERS, `missing ACTION_TIERS.${action}`);
    }
  });

  it('assertTierMappingInvariants reports no errors', () => {
    assert.deepEqual(assertTierMappingInvariants(), []);
  });

  it('every OK + ADMIN cli-policy prefix has exactly one CLI_PREFIX_TIERS row', () => {
    const labels = CLI_PREFIX_TIERS.map((r) => formatPrefix(r.prefix));
    for (const p of RAW_CLI_OK_PREFIXES) {
      assert.ok(labels.includes(formatPrefix(p)), `missing OK ${formatPrefix(p)}`);
    }
    for (const p of RAW_CLI_ADMIN_PREFIXES) {
      assert.ok(labels.includes(formatPrefix(p)), `missing ADMIN ${formatPrefix(p)}`);
    }
    assert.equal(labels.length, new Set(labels).size);
  });

  it('reply is dispatch; status reads are status; admin prefixes are admin', () => {
    assert.equal(tierForCliArgv(['orchestration', 'reply', '--id', 'x']), 'dispatch');
    assert.equal(tierForCliArgv(['status', '--json']), 'status');
    assert.equal(tierForCliArgv(['worktree', 'list', '--json']), 'status');
    assert.equal(tierForCliArgv(['terminal', 'read', '--terminal', 't']), 'status');
    assert.equal(tierForCliArgv(['terminal', 'close', '--terminal', 't', '--tab']), 'dispatch');
    assert.equal(tierForCliArgv(['terminal', 'send', '--terminal', 't', '--text', 'x']), 'admin');
    assert.equal(tierForCliArgv(['worktree', 'create', '--name', 'n']), 'admin');
    assert.equal(tierForCliArgv(['git', 'status']), 'admin'); // unknown → admin
  });

  it('requiredTierFor routes actions and cli argv', () => {
    assert.equal(requiredTierFor('health'), 'status');
    assert.equal(requiredTierFor('dispatch'), 'dispatch');
    assert.equal(requiredTierFor('cli', ['orchestration', 'reply', '--id', '1']), 'dispatch');
    assert.equal(requiredTierFor('cli', ['terminal', 'send', '--terminal', 't', '--text', 'x']), 'admin');
  });
});

// ---------------------------------------------------------------------------
// config defaults — owner hard requirement: all tiers on with no config
// ---------------------------------------------------------------------------

describe('resolveToolsetsConfig defaults (owner invariant)', () => {
  it('with empty env and no flag enables all tiers', () => {
    const r = resolveToolsetsConfig({}, []);
    assert.equal(r.source, 'default');
    assert.deepEqual(r.enabledList, ['status', 'dispatch', 'admin']);
    assert.equal(r.admin, true);
    assert.equal(r.readOnly, false);
    assert.equal(r.adminFromCliEnv, false);
  });

  it('defaultEnabledToolsets matches TOOLSET_TIERS', () => {
    assert.deepEqual([...defaultEnabledToolsets()], [...TOOLSET_TIERS]);
  });

  it('owner invariant: no-config gate allows every action tier', () => {
    const gate = createToolsetGate({ env: {}, argv: [] });
    for (const action of Object.keys(ACTION_TIERS)) {
      const r = gate.evaluate(action, action === 'cli' ? ['status', '--json'] : undefined);
      assert.equal(r.ok, true, `expected allow for ${action}`);
      assert.equal(r.decision, 'allow');
    }
    // high-risk cli still allowed under default-all
    const adminCli = gate.evaluate('cli', ['terminal', 'send', '--terminal', 't', '--text', 'x']);
    assert.equal(adminCli.ok, true);
  });
});

// ---------------------------------------------------------------------------
// parse + env
// ---------------------------------------------------------------------------

describe('parseToolsetsList + ORCA_BRIDGE_TOOLSETS', () => {
  it('parses comma and whitespace lists, lowercases, dedupes', () => {
    assert.deepEqual(parseToolsetsList('status, dispatch'), {
      requested: ['status', 'dispatch'],
      unknown: [],
    });
    assert.deepEqual(parseToolsetsList('ADMIN Status admin'), {
      requested: ['admin', 'status'],
      unknown: [],
    });
  });

  it('returns null for empty / missing', () => {
    assert.equal(parseToolsetsList(undefined), null);
    assert.equal(parseToolsetsList(''), null);
    assert.equal(parseToolsetsList('   '), null);
  });

  it('collects unknown tokens', () => {
    const p = parseToolsetsList('status,foo,dispatch,bar');
    assert.deepEqual(p.requested, ['status', 'dispatch']);
    assert.deepEqual(p.unknown, ['foo', 'bar']);
  });

  it('env ORCA_BRIDGE_TOOLSETS=status,dispatch restricts admin', () => {
    const r = resolveToolsetsConfig({ ORCA_BRIDGE_TOOLSETS: 'status,dispatch' }, []);
    assert.equal(r.source, 'env:ORCA_BRIDGE_TOOLSETS');
    assert.deepEqual(r.enabledList, ['status', 'dispatch']);
    assert.equal(r.admin, false);
  });

  it('env status-only is readOnly', () => {
    const r = resolveToolsetsConfig({ ORCA_BRIDGE_TOOLSETS: 'status' }, []);
    assert.deepEqual(r.enabledList, ['status']);
    assert.equal(r.readOnly, true);
  });

  it('garbage-only env fails closed to status', () => {
    const r = resolveToolsetsConfig({ ORCA_BRIDGE_TOOLSETS: 'nope,also-no' }, []);
    assert.equal(r.source, 'env:ORCA_BRIDGE_TOOLSETS');
    assert.deepEqual(r.enabledList, ['status']);
    assert.ok(r.unknown.includes('nope'));
  });
});

// ---------------------------------------------------------------------------
// --read-only flag precedence
// ---------------------------------------------------------------------------

describe('--read-only flag precedence', () => {
  it('--read-only alone → status only', () => {
    const r = resolveToolsetsConfig({}, ['node', 'server.mjs', '--read-only']);
    assert.equal(r.source, 'flag:--read-only');
    assert.deepEqual(r.enabledList, ['status']);
    assert.equal(r.readOnly, true);
    assert.equal(r.admin, false);
  });

  it('--read-only wins over ORCA_BRIDGE_TOOLSETS=status,dispatch,admin', () => {
    const r = resolveToolsetsConfig(
      { ORCA_BRIDGE_TOOLSETS: 'status,dispatch,admin' },
      ['node', 'server.mjs', '--read-only', '--port', '8787'],
    );
    assert.equal(r.source, 'flag:--read-only');
    assert.deepEqual(r.enabledList, ['status']);
    assert.equal(r.admin, false);
  });

  it('--read-only ignores ORCA_BRIDGE_CLI_ADMIN=1 union', () => {
    const r = resolveToolsetsConfig(
      { ORCA_BRIDGE_CLI_ADMIN: '1', ORCA_BRIDGE_TOOLSETS: 'status,dispatch' },
      ['node', 'server.mjs', '--read-only'],
    );
    assert.deepEqual(r.enabledList, ['status']);
    assert.equal(r.adminFromCliEnv, false);
    assert.equal(r.admin, false);
  });
});

// ---------------------------------------------------------------------------
// ORCA_BRIDGE_CLI_ADMIN union (admin collapse into toolsets)
// ---------------------------------------------------------------------------

describe('ORCA_BRIDGE_CLI_ADMIN union into toolsets', () => {
  it('adds admin when toolsets omit it', () => {
    const r = resolveToolsetsConfig(
      { ORCA_BRIDGE_TOOLSETS: 'status,dispatch', ORCA_BRIDGE_CLI_ADMIN: '1' },
      [],
    );
    assert.deepEqual(r.enabledList, ['status', 'dispatch', 'admin']);
    assert.equal(r.admin, true);
    assert.equal(r.adminFromCliEnv, true);
  });

  it('does nothing when admin already present', () => {
    const r = resolveToolsetsConfig(
      { ORCA_BRIDGE_TOOLSETS: 'status,admin', ORCA_BRIDGE_CLI_ADMIN: '1' },
      [],
    );
    assert.deepEqual(r.enabledList, ['status', 'admin']);
    assert.equal(r.adminFromCliEnv, false);
  });

  it('createCliPolicy admin tracks toolset admin', () => {
    const ts = resolveToolsetsConfig({ ORCA_BRIDGE_TOOLSETS: 'status,dispatch,admin' }, []);
    const cliCfg = resolveCliPolicyConfig({ ORCA_BRIDGE_CLI_HARDENING: '1' });
    const policy = createCliPolicy({ ...cliCfg, admin: ts.admin });
    assert.equal(policy.admin, true);
    const r = policy.evaluate(['terminal', 'send', '--terminal', 't', '--text', 'x']);
    assert.equal(r.ok, true);
  });

  it('without admin toolset, hardened cli policy still denies admin argv', () => {
    const ts = resolveToolsetsConfig({ ORCA_BRIDGE_TOOLSETS: 'status,dispatch' }, []);
    const policy = createCliPolicy({ hardening: true, admin: ts.admin });
    assert.equal(policy.admin, false);
    const r = policy.evaluate(['terminal', 'send', '--terminal', 't', '--text', 'x']);
    assert.equal(r.ok, false);
    assert.equal(r.rejection.error, 'cli_policy_denied');
  });
});

// ---------------------------------------------------------------------------
// evaluateToolsetAccess — allow / structured deny
// ---------------------------------------------------------------------------

describe('evaluateToolsetAccess', () => {
  const statusOnly = new Set(['status']);
  const statusDispatch = new Set(['status', 'dispatch']);
  const all = defaultEnabledToolsets();

  it('allows status actions under status-only', () => {
    for (const op of ['health', 'guide', 'check']) {
      const r = evaluateToolsetAccess({ op, enabled: statusOnly });
      assert.equal(r.ok, true, op);
    }
  });

  it('denies dispatch/await/release under status-only with structured shape', () => {
    for (const op of ['dispatch', 'await', 'release']) {
      const r = evaluateToolsetAccess({ op, enabled: statusOnly });
      assert.equal(r.ok, false, op);
      assert.equal(r.decision, 'deny');
      assert.equal(r.rejection.error, 'toolset_denied');
      assert.equal(r.rejection.required_tier, 'dispatch');
      assert.equal(r.rejection.action, op);
      assert.deepEqual(r.rejection.enabled_toolsets, ['status']);
      assert.equal(r.rejection.enable_via.env, 'ORCA_BRIDGE_TOOLSETS');
      assert.ok(String(r.rejection.detail).includes('ORCA_BRIDGE_TOOLSETS'));
      assert.ok(String(r.rejection.detail).includes('dispatch'));
      assert.equal(r.rejection.next.action, 'health');
    }
  });

  it('allows dispatch tier under status+dispatch but denies admin cli', () => {
    assert.equal(evaluateToolsetAccess({ op: 'dispatch', enabled: statusDispatch }).ok, true);
    assert.equal(evaluateToolsetAccess({ op: 'await', enabled: statusDispatch }).ok, true);
    assert.equal(evaluateToolsetAccess({ op: 'release', enabled: statusDispatch }).ok, true);

    const reply = evaluateToolsetAccess({
      op: 'cli',
      args: ['orchestration', 'reply', '--id', 'm', '--body', 'ok', '--json'],
      enabled: statusDispatch,
    });
    assert.equal(reply.ok, true);
    assert.equal(reply.required_tier, 'dispatch');

    const send = evaluateToolsetAccess({
      op: 'cli',
      args: ['terminal', 'send', '--terminal', 't', '--text', 'x'],
      enabled: statusDispatch,
    });
    assert.equal(send.ok, false);
    assert.equal(send.rejection.error, 'toolset_denied');
    assert.equal(send.rejection.required_tier, 'admin');
    assert.equal(send.rejection.rejected_subcommand, 'terminal send');
    assert.ok(send.rejection.enable_via.example.includes('admin'));
  });

  it('status-only allows read cli, denies reply and admin', () => {
    const list = evaluateToolsetAccess({
      op: 'cli',
      args: ['worktree', 'list', '--json'],
      enabled: statusOnly,
    });
    assert.equal(list.ok, true);
    assert.equal(list.required_tier, 'status');

    const reply = evaluateToolsetAccess({
      op: 'cli',
      args: ['orchestration', 'reply', '--id', 'm', '--body', 'x', '--json'],
      enabled: statusOnly,
    });
    assert.equal(reply.ok, false);
    assert.equal(reply.rejection.required_tier, 'dispatch');
  });

  it('default-all allows every mapped action (owner: identical to today)', () => {
    for (const op of Object.keys(ACTION_TIERS)) {
      const args = op === 'cli' ? ['terminal', 'send', '--terminal', 't', '--text', 'hi'] : undefined;
      const r = evaluateToolsetAccess({ op, args, enabled: all });
      assert.equal(r.ok, true, op);
    }
  });
});

// ---------------------------------------------------------------------------
// createToolsetGate
// ---------------------------------------------------------------------------

describe('createToolsetGate', () => {
  it('snapshot exposes diagnostics for health', () => {
    const gate = createToolsetGate({
      env: { ORCA_BRIDGE_TOOLSETS: 'status' },
      argv: [],
    });
    const snap = gate.snapshot();
    assert.deepEqual(snap.enabled, ['status']);
    assert.equal(snap.source, 'env:ORCA_BRIDGE_TOOLSETS');
    assert.equal(snap.readOnly, true);
    assert.equal(snap.env, 'ORCA_BRIDGE_TOOLSETS');
    assert.equal(snap.flag, '--read-only');
    assert.ok(snap.action_tiers.health === 'status');
  });

  it('explicit enabled config works without env', () => {
    const gate = createToolsetGate({ enabled: ['status', 'dispatch'], source: 'test' });
    assert.equal(gate.evaluate('dispatch').ok, true);
    assert.equal(gate.evaluate('cli', ['terminal', 'send', '--terminal', 't', '--text', 'x']).ok, false);
    assert.equal(gate.admin, false);
  });
});

// ---------------------------------------------------------------------------
// tierForAction edge
// ---------------------------------------------------------------------------

describe('tierForAction', () => {
  it('returns null for unknown ops', () => {
    assert.equal(tierForAction('nope'), null);
    assert.equal(tierForAction(''), null);
  });
});
