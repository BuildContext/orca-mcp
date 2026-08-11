/**
 * Opt-in allowlist policy for action=cli.
 *
 * Default posture is PERMISSIVE: without hardening config the only always-on
 * block is isForbiddenHandoffArgv (worktree create --agent --prompt). When a
 * call would fail the allowlist but hardening is off, emit a structured
 * warning instead of rejecting — migration signal for operators.
 *
 * Toolset / admin-tier code should call evaluateCliArgv / createCliPolicy
 * rather than scattering inline checks.
 */

import { isForbiddenHandoffArgv } from './security-core.mjs';

/**
 * Default allow prefixes — mirrors coordinatorGuide().raw_cli_ok prose.
 * Kept as data so the guide single source of truth can reuse the same prefixes
 * without fighting this module's export surface.
 */
export const RAW_CLI_OK_PREFIXES = Object.freeze([
  Object.freeze(['orchestration', 'reply']),
  Object.freeze(['orchestration', 'check']),
  Object.freeze(['orchestration', 'worker-show']),
  Object.freeze(['orchestration', 'worker-read']),
  Object.freeze(['orchestration', 'dispatch-show']),
  Object.freeze(['skills', 'get']),
  Object.freeze(['status']),
  Object.freeze(['worktree', 'show']),
  Object.freeze(['worktree', 'list']),
  Object.freeze(['terminal', 'list']),
  Object.freeze(['terminal', 'read']),
  Object.freeze(['terminal', 'close']),
]);

/**
 * High-risk prefixes unlocked only when policy.admin is true.
 * Maps onto the admin capability tier.
 */
export const RAW_CLI_ADMIN_PREFIXES = Object.freeze([
  Object.freeze(['terminal', 'send']),
  Object.freeze(['orchestration', 'send']),
  Object.freeze(['orchestration', 'task-create']),
  Object.freeze(['orchestration', 'dispatch']),
  Object.freeze(['orchestration', 'run-create']),
  Object.freeze(['orchestration', 'run-use']),
  Object.freeze(['orchestration', 'worker-start']),
  Object.freeze(['worktree', 'create']),
  Object.freeze(['worktree', 'rm']),
  Object.freeze(['terminal', 'create']),
]);

/** Human-readable surface labels for errors / guide alignment. */
export function formatPrefix(prefix) {
  return prefix.join(' ');
}

export function allowedSurfaceLabels(prefixes = RAW_CLI_OK_PREFIXES) {
  return prefixes.map(formatPrefix);
}

/**
 * Resolve policy knobs from env (or an env-like object).
 * Defaults: hardening off, admin off — existing coordinators unchanged.
 *
 *   ORCA_BRIDGE_CLI_HARDENING=1  → enforce allowlist (deny by default)
 *   ORCA_BRIDGE_CLI_ADMIN=1      → unlock admin-tier prefixes
 */
export function resolveCliPolicyConfig(env = process.env) {
  const e = env || {};
  return {
    hardening: e.ORCA_BRIDGE_CLI_HARDENING === '1',
    admin: e.ORCA_BRIDGE_CLI_ADMIN === '1',
  };
}

/**
 * Command tokens = leading non-flag argv entries, lowercased.
 * Stops at the first flag-shaped token or `--`.
 */
export function commandTokens(args) {
  if (!Array.isArray(args)) return [];
  const out = [];
  for (const x of args) {
    const s = String(x);
    if (s === '--' || s.startsWith('-')) break;
    out.push(s.toLowerCase());
  }
  return out;
}

export function matchesPrefix(tokens, prefix) {
  if (!Array.isArray(tokens) || !Array.isArray(prefix)) return false;
  if (tokens.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (tokens[i] !== String(prefix[i]).toLowerCase()) return false;
  }
  return true;
}

export function matchAllowlist(tokens, prefixes) {
  for (const prefix of prefixes) {
    if (matchesPrefix(tokens, prefix)) return prefix;
  }
  return null;
}

/**
 * Build a reusable policy object the toolset gate can hold and call.
 * @param {object} [config]
 * @param {boolean} [config.hardening=false]
 * @param {boolean} [config.admin=false]
 * @param {readonly string[][]} [config.allowPrefixes]
 * @param {readonly string[][]} [config.adminPrefixes]
 * @param {(warning: object) => void} [config.onWarning] stderr/audit hook
 */
export function createCliPolicy(config = {}) {
  const hardening = config.hardening === true;
  const admin = config.admin === true;
  const allowPrefixes = config.allowPrefixes || RAW_CLI_OK_PREFIXES;
  const adminPrefixes = config.adminPrefixes || RAW_CLI_ADMIN_PREFIXES;
  const onWarning = typeof config.onWarning === 'function' ? config.onWarning : null;

  return {
    hardening,
    admin,
    allowPrefixes,
    adminPrefixes,
    /** @param {unknown} args */
    evaluate(args) {
      return evaluateCliArgv(args, {
        hardening,
        admin,
        allowPrefixes,
        adminPrefixes,
        onWarning,
      });
    },
  };
}

/**
 * Evaluate argv against the cli policy.
 *
 * Decision outcomes:
 *   allow              — permitted (default path or on allowlist)
 *   allow_with_warning — would deny under hardening, but hardening is off
 *   deny               — blocked (forbidden handoff always, or hardening allowlist)
 *
 * @returns {{
 *   ok: boolean,
 *   decision: 'allow' | 'allow_with_warning' | 'deny',
 *   rejected_subcommand?: string,
 *   matched_prefix?: string[] | null,
 *   admin_required?: boolean,
 *   allowed_surface?: string[],
 *   admin_surface?: string[],
 *   warning?: object | null,
 *   rejection?: object | null,
 * }}
 */
export function evaluateCliArgv(args, config = {}) {
  const hardening = config.hardening === true;
  const admin = config.admin === true;
  const allowPrefixes = config.allowPrefixes || RAW_CLI_OK_PREFIXES;
  const adminPrefixes = config.adminPrefixes || RAW_CLI_ADMIN_PREFIXES;
  const onWarning = typeof config.onWarning === 'function' ? config.onWarning : null;
  const forbiddenCheck =
    typeof config.isForbiddenHandoff === 'function'
      ? config.isForbiddenHandoff
      : isForbiddenHandoffArgv;

  const surface = allowedSurfaceLabels(allowPrefixes);
  const adminSurface = allowedSurfaceLabels(adminPrefixes);
  const tokens = commandTokens(args);
  const rejectedSubcommand = tokens.length ? tokens.join(' ') : '(empty)';

  // Always-on gate: supervised dispatch is the only start path.
  if (forbiddenCheck(args)) {
    const rejection = {
      ok: false,
      error: 'forbidden_handoff',
      rejected_subcommand: rejectedSubcommand,
      rejected_argv: Array.isArray(args) ? [...args] : args,
      allowed_surface: surface,
      detail:
        'Blocked: worktree create --agent --prompt has no worker_done signal. ' +
        'Use orca{action:"dispatch",spec,agent,worktree,name?,repo?,runId?} then await/release. ' +
        'See action=guide for the full supervised flow.',
      next: {
        action: 'dispatch',
        detail: 'Start the worker with action=dispatch (supervised inject path).',
      },
    };
    return {
      ok: false,
      decision: 'deny',
      rejected_subcommand: rejectedSubcommand,
      matched_prefix: null,
      admin_required: false,
      allowed_surface: surface,
      admin_surface: adminSurface,
      warning: null,
      rejection,
    };
  }

  const allowHit = matchAllowlist(tokens, allowPrefixes);
  if (allowHit) {
    return {
      ok: true,
      decision: 'allow',
      rejected_subcommand: undefined,
      matched_prefix: [...allowHit],
      admin_required: false,
      allowed_surface: surface,
      admin_surface: adminSurface,
      warning: null,
      rejection: null,
    };
  }

  const adminHit = matchAllowlist(tokens, adminPrefixes);
  if (adminHit && admin) {
    return {
      ok: true,
      decision: 'allow',
      rejected_subcommand: undefined,
      matched_prefix: [...adminHit],
      admin_required: true,
      allowed_surface: surface,
      admin_surface: adminSurface,
      warning: null,
      rejection: null,
    };
  }

  // Not on default allowlist (and not unlocked admin).
  const adminRequired = Boolean(adminHit);
  const warning = {
    code: 'cli_policy_would_deny',
    rejected_subcommand: rejectedSubcommand,
    rejected_argv: Array.isArray(args) ? [...args] : args,
    allowed_surface: surface,
    admin_surface: adminSurface,
    admin_required: adminRequired,
    hardening: hardening,
    message: adminRequired
      ? `argv "${rejectedSubcommand}" requires admin unlock (ORCA_BRIDGE_CLI_ADMIN=1); hardening=${hardening ? 'on' : 'off'}`
      : `argv "${rejectedSubcommand}" is outside the default cli allowlist; hardening=${hardening ? 'on' : 'off'}`,
  };

  if (!hardening) {
    if (onWarning) {
      try {
        onWarning(warning);
      } catch {
        // warning hooks must not break the permissive path
      }
    }
    return {
      ok: true,
      decision: 'allow_with_warning',
      rejected_subcommand: rejectedSubcommand,
      matched_prefix: null,
      admin_required: adminRequired,
      allowed_surface: surface,
      admin_surface: adminSurface,
      warning,
      rejection: null,
    };
  }

  const rejection = {
    ok: false,
    error: 'cli_policy_denied',
    rejected_subcommand: rejectedSubcommand,
    rejected_argv: Array.isArray(args) ? [...args] : args,
    allowed_surface: surface,
    admin_surface: adminSurface,
    admin_required: adminRequired,
    detail: adminRequired
      ? `Blocked by cli allowlist: "${rejectedSubcommand}" requires admin unlock ` +
        `(set ORCA_BRIDGE_CLI_ADMIN=1) while ORCA_BRIDGE_CLI_HARDENING=1.`
      : `Blocked by cli allowlist: "${rejectedSubcommand}" is not on the default allowed surface. ` +
        `Enable only what you need, or unset ORCA_BRIDGE_CLI_HARDENING to restore permissive mode.`,
    next: {
      action: 'guide',
      detail: 'See raw_cli_ok / policy.allowed_surface for the permitted prefixes.',
    },
  };

  return {
    ok: false,
    decision: 'deny',
    rejected_subcommand: rejectedSubcommand,
    matched_prefix: null,
    admin_required: adminRequired,
    allowed_surface: surface,
    admin_surface: adminSurface,
    warning: null,
    rejection,
  };
}
