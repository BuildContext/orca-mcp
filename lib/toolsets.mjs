/**
 * Capability toolsets for the multiplexed `orca` tool.
 *
 * Tiers:
 *   status   — health, guide, check, read-only cli prefixes
 *   dispatch — dispatch, await, release, orchestration reply
 *   admin    — raw cli high-risk surface (admin prefixes)
 *
 * Owner decision: ALL tiers ENABLED BY DEFAULT. Hardening is opt-in via
 * ORCA_BRIDGE_TOOLSETS and/or --read-only. Existing coordinators need zero
 * config changes.
 *
 * CLI-policy admin unlock is driven by the effective admin toolset
 * (ORCA_BRIDGE_CLI_ADMIN=1 unions admin into the enabled set).
 */

import {
  RAW_CLI_OK_PREFIXES,
  RAW_CLI_ADMIN_PREFIXES,
  commandTokens,
  matchAllowlist,
  formatPrefix,
} from './cli-policy.mjs';

/** Canonical tier names in least→most privilege order. */
export const TOOLSET_TIERS = Object.freeze(['status', 'dispatch', 'admin']);

/** Every resolved tool op → exactly one tier. */
export const ACTION_TIERS = Object.freeze({
  health: 'status',
  guide: 'status',
  check: 'status',
  dispatch: 'dispatch',
  await: 'dispatch',
  release: 'dispatch',
  // action=cli is refined by argv (see CLI_PREFIX_TIERS); bare/unknown → admin.
  cli: 'admin',
});

/**
 * Allowlisted cli argv prefixes → tier.
 * Built from cli-policy surfaces so the two modules stay aligned:
 *   RAW_CLI_OK_PREFIXES   → status or dispatch (reply is dispatch)
 *   RAW_CLI_ADMIN_PREFIXES → admin
 */
export const CLI_PREFIX_TIERS = Object.freeze(buildCliPrefixTiers());

function buildCliPrefixTiers() {
  /** @type {{ prefix: readonly string[], tier: string }[]} */
  const rows = [];

  // Explicit non-default OK mappings (everything else on OK list → status).
  const okOverrides = new Map([
    ['orchestration reply', 'dispatch'],
    // terminal close mutates session state; keep it with supervised cleanup.
    ['terminal close', 'dispatch'],
  ]);

  for (const prefix of RAW_CLI_OK_PREFIXES) {
    const label = formatPrefix(prefix);
    const tier = okOverrides.get(label) || 'status';
    rows.push(Object.freeze({ prefix, tier }));
  }
  for (const prefix of RAW_CLI_ADMIN_PREFIXES) {
    rows.push(Object.freeze({ prefix, tier: 'admin' }));
  }
  return Object.freeze(rows);
}

/** @returns {ReadonlySet<string>} */
export function defaultEnabledToolsets() {
  return new Set(TOOLSET_TIERS);
}

/**
 * Parse a comma/space-separated toolset list.
 * Unknown tokens are ignored (reported in `unknown`).
 * Empty / whitespace-only → null (caller treats as default-all).
 *
 * @param {unknown} raw
 * @returns {{ requested: string[], unknown: string[] } | null}
 */
export function parseToolsetsList(raw) {
  if (raw == null) return null;
  const text = String(raw).trim();
  if (!text) return null;
  const requested = [];
  const unknown = [];
  const seen = new Set();
  for (const part of text.split(/[,\s]+/)) {
    const tok = part.trim().toLowerCase();
    if (!tok) continue;
    if (!TOOLSET_TIERS.includes(tok)) {
      if (!unknown.includes(tok)) unknown.push(tok);
      continue;
    }
    if (!seen.has(tok)) {
      seen.add(tok);
      requested.push(tok);
    }
  }
  // Explicit empty after filtering unknowns still counts as "set" if raw had tokens.
  if (requested.length === 0 && unknown.length === 0) return null;
  return { requested, unknown };
}

/**
 * Resolve enabled toolsets from env + argv.
 *
 * Precedence (highest wins):
 *   1. `--read-only` CLI flag  →  { status } only
 *   2. `ORCA_BRIDGE_TOOLSETS`  →  exact set (if non-empty after parse)
 *   3. default                 →  { status, dispatch, admin }
 *
 * Compat union (does not override --read-only):
 *   `ORCA_BRIDGE_CLI_ADMIN=1` adds `admin` to the enabled set.
 *   This collapses the CLI admin knob into the toolset surface so
 *   operators are not managing two near-identical switches.
 *
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 * @param {readonly string[]} [argv]
 */
export function resolveToolsetsConfig(env = process.env, argv = process.argv) {
  const e = env || {};
  const args = Array.isArray(argv) ? argv : [];
  const readOnlyFlag = args.includes('--read-only');
  const cliAdmin = e.ORCA_BRIDGE_CLI_ADMIN === '1';

  /** @type {'flag:--read-only' | 'env:ORCA_BRIDGE_TOOLSETS' | 'default'} */
  let source = 'default';
  /** @type {Set<string>} */
  let enabled;
  /** @type {string[]} */
  let unknown = [];
  /** @type {string[] | null} */
  let requested = null;

  if (readOnlyFlag) {
    source = 'flag:--read-only';
    enabled = new Set(['status']);
    requested = ['status'];
  } else {
    const parsed = parseToolsetsList(e.ORCA_BRIDGE_TOOLSETS);
    if (parsed && parsed.requested.length > 0) {
      source = 'env:ORCA_BRIDGE_TOOLSETS';
      enabled = new Set(parsed.requested);
      requested = [...parsed.requested];
      unknown = [...parsed.unknown];
    } else if (parsed && parsed.requested.length === 0) {
      // Explicit garbage-only value → fail closed to status rather than all-on.
      source = 'env:ORCA_BRIDGE_TOOLSETS';
      enabled = new Set(['status']);
      requested = [];
      unknown = [...parsed.unknown];
    } else {
      source = 'default';
      enabled = defaultEnabledToolsets();
      requested = null;
    }
  }

  let adminFromCliEnv = false;
  if (cliAdmin && !readOnlyFlag && !enabled.has('admin')) {
    enabled.add('admin');
    adminFromCliEnv = true;
  }

  const enabledList = TOOLSET_TIERS.filter((t) => enabled.has(t));

  return {
    enabled: new Set(enabledList),
    enabledList,
    source,
    readOnly: readOnlyFlag || (enabledList.length === 1 && enabledList[0] === 'status'),
    requested,
    unknown,
    adminFromCliEnv,
    /** Effective admin unlock — single source for createCliPolicy. */
    admin: enabled.has('admin'),
  };
}

/** @param {string} op */
export function tierForAction(op) {
  const key = String(op || '').trim().toLowerCase();
  return ACTION_TIERS[key] || null;
}

/**
 * Tier required by a cli argv. Unknown / empty → admin (fail closed when
 * restricted; permissive default still has admin enabled).
 * @param {unknown} args
 */
export function tierForCliArgv(args) {
  const tokens = commandTokens(args);
  if (!tokens.length) return 'admin';

  // Longest-prefix preference: walk CLI_PREFIX_TIERS in declaration order;
  // lists are disjoint today, first hit wins.
  for (const row of CLI_PREFIX_TIERS) {
    if (matchAllowlist(tokens, [row.prefix])) return row.tier;
  }
  return 'admin';
}

/**
 * Required tier for a resolved tool op (+ cli args when op === 'cli').
 * @param {string} op
 * @param {unknown} [cliArgs]
 */
export function requiredTierFor(op, cliArgs) {
  const key = String(op || '').trim().toLowerCase();
  if (key === 'cli') return tierForCliArgv(cliArgs);
  return tierForAction(key);
}

/**
 * @param {object} params
 * @param {string} params.op
 * @param {unknown} [params.args] cli argv when op === 'cli'
 * @param {ReadonlySet<string> | Iterable<string>} params.enabled
 * @param {object} [params.meta] extra fields merged into rejection
 */
export function evaluateToolsetAccess({ op, args, enabled, meta = {} }) {
  const enabledSet = enabled instanceof Set ? enabled : new Set(enabled || []);
  const enabledList = TOOLSET_TIERS.filter((t) => enabledSet.has(t));
  const required = requiredTierFor(op, args);

  if (!required) {
    const rejection = {
      ok: false,
      error: 'toolset_denied',
      required_tier: null,
      action: String(op || ''),
      enabled_toolsets: enabledList,
      detail: `Unknown action "${op}" has no toolset mapping.`,
      enable_via: enableViaHint(null, enabledList),
      ...meta,
    };
    return {
      ok: false,
      decision: 'deny',
      required_tier: null,
      enabled_toolsets: enabledList,
      rejection,
    };
  }

  if (enabledSet.has(required)) {
    return {
      ok: true,
      decision: 'allow',
      required_tier: required,
      enabled_toolsets: enabledList,
      rejection: null,
    };
  }

  const action = String(op || '');
  const sub =
    action === 'cli' && Array.isArray(args)
      ? commandTokens(args).join(' ') || '(empty)'
      : undefined;

  const rejection = {
    ok: false,
    error: 'toolset_denied',
    required_tier: required,
    action,
    ...(sub != null ? { rejected_subcommand: sub } : {}),
    enabled_toolsets: enabledList,
    detail:
      `Blocked by toolsets: action="${action}"` +
      (sub != null ? ` (cli: "${sub}")` : '') +
      ` requires tier "${required}". ` +
      `Enabled: [${enabledList.join(', ') || '(none)'}]. ` +
      `Set ORCA_BRIDGE_TOOLSETS to include "${required}" ` +
      `(example: status,dispatch,admin). ` +
      `--read-only forces status only.`,
    enable_via: enableViaHint(required, enabledList),
    next: {
      action: 'health',
      detail:
        'Call action=health to inspect bridge.toolsets, or ask the operator to expand ORCA_BRIDGE_TOOLSETS.',
    },
    ...meta,
  };

  return {
    ok: false,
    decision: 'deny',
    required_tier: required,
    enabled_toolsets: enabledList,
    rejection,
  };
}

function enableViaHint(required, enabledList) {
  const base = enabledList.length ? [...enabledList] : [];
  const example = required && !base.includes(required)
    ? TOOLSET_TIERS.filter((t) => base.includes(t) || t === required).join(',')
    : TOOLSET_TIERS.join(',');
  return {
    env: 'ORCA_BRIDGE_TOOLSETS',
    example,
    read_only_flag: '--read-only',
    read_only_means: 'status',
    admin_compat_env: 'ORCA_BRIDGE_CLI_ADMIN',
    admin_compat_note:
      'ORCA_BRIDGE_CLI_ADMIN=1 unions admin into the enabled toolsets (ignored under --read-only).',
  };
}

/**
 * Bound gate object for server startup (mirrors createCliPolicy shape).
 * @param {object} [config]
 * @param {Iterable<string>} [config.enabled]
 * @param {string} [config.source]
 * @param {boolean} [config.readOnly]
 * @param {boolean} [config.admin]
 */
export function createToolsetGate(config = {}) {
  const resolved =
    config.enabled != null
      ? {
          enabled: new Set(
            TOOLSET_TIERS.filter((t) =>
              config.enabled instanceof Set
                ? config.enabled.has(t)
                : [...config.enabled].map(String).includes(t),
            ),
          ),
          enabledList: TOOLSET_TIERS.filter((t) =>
            config.enabled instanceof Set
              ? config.enabled.has(t)
              : [...config.enabled].map(String).includes(t),
          ),
          source: config.source || 'explicit',
          readOnly: config.readOnly === true,
          admin: config.admin != null ? config.admin === true : undefined,
        }
      : resolveToolsetsConfig(config.env || process.env, config.argv || process.argv);

  const enabled = resolved.enabled;
  const enabledList = resolved.enabledList || TOOLSET_TIERS.filter((t) => enabled.has(t));
  const admin = resolved.admin != null ? resolved.admin : enabled.has('admin');

  return {
    enabled,
    enabledList,
    source: resolved.source,
    readOnly: resolved.readOnly === true,
    admin,
    /**
     * @param {string} op
     * @param {unknown} [args]
     */
    evaluate(op, args) {
      return evaluateToolsetAccess({ op, args, enabled });
    },
    /** Snapshot for health / diagnostics. */
    snapshot() {
      return {
        enabled: enabledList,
        source: resolved.source,
        readOnly: resolved.readOnly === true,
        admin,
        action_tiers: { ...ACTION_TIERS },
        default: TOOLSET_TIERS.slice(),
        env: 'ORCA_BRIDGE_TOOLSETS',
        flag: '--read-only',
      };
    },
  };
}

/**
 * Completeness helper for tests: every ACTION_TIERS value is a known tier,
 * every CLI_PREFIX_TIERS row maps to a known tier, and every cli-policy prefix
 * appears exactly once.
 */
export function assertTierMappingInvariants() {
  const errors = [];
  for (const [action, tier] of Object.entries(ACTION_TIERS)) {
    if (!TOOLSET_TIERS.includes(tier)) {
      errors.push(`action ${action} → unknown tier ${tier}`);
    }
  }
  const seen = new Set();
  for (const row of CLI_PREFIX_TIERS) {
    if (!TOOLSET_TIERS.includes(row.tier)) {
      errors.push(`prefix ${formatPrefix(row.prefix)} → unknown tier ${row.tier}`);
    }
    const key = formatPrefix(row.prefix);
    if (seen.has(key)) errors.push(`duplicate cli prefix tier row: ${key}`);
    seen.add(key);
  }
  for (const prefix of RAW_CLI_OK_PREFIXES) {
    const key = formatPrefix(prefix);
    if (!seen.has(key)) errors.push(`OK prefix missing from CLI_PREFIX_TIERS: ${key}`);
  }
  for (const prefix of RAW_CLI_ADMIN_PREFIXES) {
    const key = formatPrefix(prefix);
    if (!seen.has(key)) errors.push(`ADMIN prefix missing from CLI_PREFIX_TIERS: ${key}`);
  }
  return errors;
}
