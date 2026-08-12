/**
 * Opt-in allowlist policy for action=cli.
 *
 * Default posture is PERMISSIVE: without hardening config the only always-on
 * block is isForbiddenHandoffArgv (worktree create --agent --prompt). When a
 * call would fail the allowlist but hardening is off, emit a structured
 * warning instead of rejecting — migration signal for operators.
 *
 * NAS-247: optional ownershipCheck runs in this same funnel for
 * terminal read/close/send so handle ownership cannot bypass the allowlist.
 *
 * Toolset / admin-tier code should call evaluateCliArgv / createCliPolicy
 * rather than scattering inline checks.
 */

import { isForbiddenHandoffArgv } from './security-core.mjs';
import { collectTerminalHandlesFromArgv } from './state-ownership.mjs';

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

/** Subcommands that target a terminal handle and require ownership. */
export const OWNERSHIP_GATED_PREFIXES = Object.freeze([
  Object.freeze(['terminal', 'read']),
  Object.freeze(['terminal', 'close']),
  Object.freeze(['terminal', 'send']),
]);

/**
 * Re-export shared collector so policy callers do not reimplement argv scan.
 * @see collectTerminalHandlesFromArgv in state-ownership.mjs
 */
export { collectTerminalHandlesFromArgv };

/**
 * Pull the CLI-effective terminal handle from raw argv (last --terminal wins,
 * matching Orca CLI non-repeatable flag semantics). Ownership checks must still
 * deny if ANY occurrence fails — use collectTerminalHandlesFromArgv.
 *
 * Thin last-of-collect wrapper over the shared helper (no second argv scan).
 * Semantics come entirely from collectTerminalHandlesFromArgv:
 *   --terminal <v>     → raw v (including '' / whitespace)
 *   --terminal (bare)  → null
 *   --terminal -x      → null (flag-shaped value)
 *   --terminal=        → null
 *   --terminal=v       → v
 *
 * @param {unknown} args
 * @returns {string|null}
 */
export function extractTerminalHandleFromArgv(args) {
  const all = collectTerminalHandlesFromArgv(args);
  if (!all.length) return null;
  // last-of-collect only — empty `=` already null in the shared helper;
  // spaced '' remains '' for historical single-flag extract semantics.
  return all[all.length - 1];
}

/**
 * True when argv looks like an ownership-gated terminal command even if
 * commandTokens stopped early on a leading global flag.
 * Does NOT change allowlist tokenization — only used to decide whether to
 * consult ownershipCheck for diagnostics / handle_not_owned.
 *
 * @param {unknown} args
 * @returns {boolean}
 */
export function looksLikeOwnershipGatedArgv(args) {
  if (!Array.isArray(args)) return false;
  const lower = args.map((x) => String(x).toLowerCase());
  // Scan for ['terminal', 'read'|'close'|'send'] as adjacent non-flag tokens,
  // allowing leading flag-shaped tokens before the pair.
  for (let i = 0; i < lower.length; i++) {
    const t = lower[i];
    if (t === '--') break;
    if (t.startsWith('-')) continue;
    if (t !== 'terminal') continue;
    const next = lower[i + 1];
    if (next == null || next === '--' || next.startsWith('-')) continue;
    if (next === 'read' || next === 'close' || next === 'send') return true;
  }
  return false;
}

/**
 * @param {string[]} tokens
 * @returns {boolean}
 */
export function isOwnershipGatedArgv(tokens) {
  return matchAllowlist(tokens, OWNERSHIP_GATED_PREFIXES) != null;
}

/**
 * Build a reusable policy object the toolset gate can hold and call.
 * @param {object} [config]
 * @param {boolean} [config.hardening=false]
 * @param {boolean} [config.admin=false]
 * @param {readonly string[][]} [config.allowPrefixes]
 * @param {readonly string[][]} [config.adminPrefixes]
 * @param {(warning: object) => void} [config.onWarning] stderr/audit hook
 * @param {(ctx: object) => object} [config.ownershipCheck]
 *   Optional. Given { args, handle, tokens, matched_prefix }, return
 *   { status|verdict: 'owned'|'not-owned'|'unknown', owned_handles|ownedHandles?: string[],
 *     handle?: string|null, reason?: string }.
 *   Missing callback → ownership gate skipped (prefix-only policy).
 */
export function createCliPolicy(config = {}) {
  const hardening = config.hardening === true;
  const admin = config.admin === true;
  const allowPrefixes = config.allowPrefixes || RAW_CLI_OK_PREFIXES;
  const adminPrefixes = config.adminPrefixes || RAW_CLI_ADMIN_PREFIXES;
  const onWarning = typeof config.onWarning === 'function' ? config.onWarning : null;
  const ownershipCheck =
    typeof config.ownershipCheck === 'function' ? config.ownershipCheck : null;

  return {
    hardening,
    admin,
    allowPrefixes,
    adminPrefixes,
    /**
     * @param {unknown} args
     * @param {object} [overrides] per-call knobs (e.g. request-scoped ownershipCheck)
     */
    evaluate(args, overrides = {}) {
      return evaluateCliArgv(args, {
        hardening,
        admin,
        allowPrefixes,
        adminPrefixes,
        onWarning,
        ownershipCheck:
          typeof overrides.ownershipCheck === 'function'
            ? overrides.ownershipCheck
            : ownershipCheck,
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
 *   deny               — blocked (forbidden handoff always, or hardening allowlist / ownership)
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
  const ownershipCheck =
    typeof config.ownershipCheck === 'function' ? config.ownershipCheck : null;
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
  const adminHit = matchAllowlist(tokens, adminPrefixes);
  const adminRequired = Boolean(adminHit);
  const prefixAllowed = Boolean(allowHit || (adminHit && admin));
  const matchedPrefix = allowHit ? allowHit : adminHit && admin ? adminHit : null;

  // --- NAS-247 handle ownership (same funnel as prefix allowlist) ---
  // Gated commands: terminal read / close / send. Fail closed on unknown.
  // Hardening off → allow_with_warning (migration); on → deny.
  //
  // Token path: normal commandTokens match (no leading flags).
  // Leading-flag path: commandTokens is empty / non-gated, but argv still
  // looks like terminal read|close|send. We consult ownership for correct
  // handle_not_owned diagnostics WITHOUT widening the allowlist surface —
  // prefixAllowed stays false, so a pass still falls through to allowlist
  // deny / would_deny.
  const ownershipTokensGated = isOwnershipGatedArgv(tokens);
  const ownershipLeadingFlag =
    !ownershipTokensGated && looksLikeOwnershipGatedArgv(args);
  if (ownershipCheck && (ownershipTokensGated || ownershipLeadingFlag)) {
    const rawHandles = collectTerminalHandlesFromArgv(args);
    // CLI-effective handle for error payload (last wins). Empty '=' → null.
    const effectiveHandle = extractTerminalHandleFromArgv(args);
    // Values to check: every occurrence. No occurrences → one unknown (null).
    const toCheck = rawHandles.length ? rawHandles : [null];

    /** @type {object|null} */
    let worst = null;
    /** @type {'owned'|'not-owned'|'unknown'} */
    let worstRank = 'owned'; // owned < not-owned < unknown for reporting? prefer not-owned over unknown when both
    const rank = (s) => (s === 'owned' ? 0 : s === 'not-owned' ? 2 : 1);

    for (const raw of toCheck) {
      // For ownershipCheck: pass raw string when present (policy tests / server
      // resolver normalize). null/empty-equals → null.
      const handleForCheck =
        raw == null || raw === '' ? null : raw;
      let own;
      try {
        own = ownershipCheck({
          args: Array.isArray(args) ? args : [],
          handle: handleForCheck,
          handles: toCheck.map((h) => (h == null || h === '' ? null : h)),
          tokens,
          matched_prefix: matchedPrefix ? [...matchedPrefix] : null,
          effective_handle: effectiveHandle,
        });
      } catch (e) {
        own = {
          status: 'unknown',
          handle: handleForCheck,
          owned_handles: [],
          reason: 'ownership_check_threw',
          detail: e && e.message ? e.message : String(e),
        };
      }
      const statusRaw =
        own && (own.status != null || own.verdict != null)
          ? String(own.status != null ? own.status : own.verdict)
          : 'unknown';
      const status =
        statusRaw === 'owned' ? 'owned' : statusRaw === 'not-owned' ? 'not-owned' : 'unknown';
      if (status === 'owned') continue;
      // Keep the worst miss; prefer reporting the CLI-effective handle below.
      if (!worst || rank(status) >= rank(worstRank)) {
        worst = own;
        worstRank = status;
      }
    }

    if (worst) {
      // Under hardening, if the prefix itself is not allowed AND this is the
      // normal token path, keep the existing allowlist denial (admin_required
      // unlock guidance) — except we still want ownership when the only reason
      // tokens didn't match is leading flags (ownershipLeadingFlag).
      //
      // Leading-flag shapes: prefixAllowed is false. Prefer handle_not_owned
      // over empty-allowlist denial so diagnostics name the real problem.
      // Normal path with admin-locked send (tokens gated, !prefixAllowed,
      // hardening): keep allowlist denial.
      const preferOwnership =
        ownershipLeadingFlag || !hardening || prefixAllowed;
      if (!preferOwnership) {
        // fall through to allowlist deny below
      } else {
        const ownedHandles = Array.isArray(worst?.owned_handles)
          ? worst.owned_handles
          : Array.isArray(worst?.ownedHandles)
            ? worst.ownedHandles
            : [];
        // Error payload handle = CLI effective (last), not the first miss.
        const reportHandle =
          effectiveHandle != null
            ? effectiveHandle
            : worst?.handle != null
              ? worst.handle
              : null;
        // rejected_subcommand: when leading flags emptied tokens, label the
        // gated command we detected so operators aren't stuck with '(empty)'.
        let sub = rejectedSubcommand;
        let matchedForDecision = matchedPrefix;
        if (ownershipLeadingFlag && (!tokens || !tokens.length)) {
          // Best-effort label from argv scan (does not unlock allowlist).
          const lower = (Array.isArray(args) ? args : []).map((x) =>
            String(x).toLowerCase(),
          );
          for (let i = 0; i < lower.length; i++) {
            if (lower[i] === '--') break;
            if (lower[i].startsWith('-')) continue;
            if (lower[i] === 'terminal') {
              const n = lower[i + 1];
              if (n === 'read' || n === 'close' || n === 'send') {
                sub = `terminal ${n}`;
                matchedForDecision = ['terminal', n];
                break;
              }
            }
          }
        }
        return ownershipDecision({
          args,
          hardening,
          onWarning,
          rejectedSubcommand: sub,
          matchedPrefix: matchedForDecision,
          adminRequired,
          surface,
          adminSurface,
          handle: reportHandle,
          status: worstRank,
          ownedHandles,
          reason: worst?.reason,
        });
      }
    }
  }

  if (prefixAllowed) {
    return {
      ok: true,
      decision: 'allow',
      rejected_subcommand: undefined,
      matched_prefix: matchedPrefix ? [...matchedPrefix] : null,
      admin_required: Boolean(adminHit && admin),
      allowed_surface: surface,
      admin_surface: adminSurface,
      warning: null,
      rejection: null,
    };
  }

  // Not on default allowlist (and not unlocked admin).
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

/**
 * Build allow_with_warning or deny for a handle ownership miss.
 * @param {object} p
 */
function ownershipDecision(p) {
  const {
    args,
    hardening,
    onWarning,
    rejectedSubcommand,
    matchedPrefix,
    adminRequired,
    surface,
    adminSurface,
    handle,
    status,
    ownedHandles,
    reason,
  } = p;

  const handleLabel = handle == null || handle === '' ? '(missing)' : String(handle);
  const ownedLabel = ownedHandles.length ? ownedHandles.join(', ') : '(none)';
  const statusLabel = status === 'not-owned' ? 'not-owned' : 'unknown';
  const reasonSuffix = reason ? ` reason=${reason}.` : '';
  const detail =
    `Blocked: terminal handle "${handleLabel}" is ${statusLabel} for this client.` +
    ` Owned handles: ${ownedLabel}.${reasonSuffix} ` +
    `Use a handle from dispatch (worker) or this client's pinned sender.`;

  const warning = {
    code: 'handle_not_owned',
    rejected_subcommand: rejectedSubcommand,
    rejected_argv: Array.isArray(args) ? [...args] : args,
    handle: handle == null ? null : String(handle),
    owned_handles: [...ownedHandles],
    ownership_status: statusLabel,
    reason: reason || undefined,
    allowed_surface: surface,
    admin_surface: adminSurface,
    admin_required: adminRequired,
    hardening,
    message: `argv "${rejectedSubcommand}" handle ownership ${statusLabel}; hardening=${hardening ? 'on' : 'off'}`,
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
      matched_prefix: matchedPrefix ? [...matchedPrefix] : null,
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
    code: 'handle_not_owned',
    rejected_subcommand: rejectedSubcommand,
    rejected_argv: Array.isArray(args) ? [...args] : args,
    handle: handle == null ? null : String(handle),
    owned_handles: [...ownedHandles],
    ownership_status: statusLabel,
    reason: reason || undefined,
    allowed_surface: surface,
    admin_surface: adminSurface,
    admin_required: adminRequired,
    detail,
    next: {
      action: 'guide',
      detail:
        'Pass a terminal handle this client owns (worker handle from dispatch, or the pinned sender).',
    },
  };

  return {
    ok: false,
    decision: 'deny',
    rejected_subcommand: rejectedSubcommand,
    matched_prefix: matchedPrefix ? [...matchedPrefix] : null,
    admin_required: adminRequired,
    allowed_surface: surface,
    admin_surface: adminSurface,
    warning: null,
    rejection,
  };
}
