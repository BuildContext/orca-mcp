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
import {
  collectTerminalHandlesFromArgv,
  collectDispatchIdsFromArgv,
} from './state-ownership.mjs';

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
  // NAS-248: status-tier foreign-handle reads that never entered the NAS-247 funnel
  Object.freeze(['orchestration', 'check']),
]);

/**
 * Subcommands that target a dispatch id (not --terminal) and require ownership.
 * Collector: collectDispatchIdsFromArgv — never reuse the terminal collector here.
 */
export const DISPATCH_OWNERSHIP_GATED_PREFIXES = Object.freeze([
  Object.freeze(['orchestration', 'worker-read']),
  Object.freeze(['orchestration', 'worker-show']),
  // Teardown-by-id: gated even when not allowlisted so soft mode cannot
  // soft-execute foreign release/stop (NAS-248 / NAS-202). Hardening still
  // allowlist-denies these; ownership is independent of that flag.
  Object.freeze(['orchestration', 'worker-release']),
  Object.freeze(['orchestration', 'worker-stop']),
  Object.freeze(['orchestration', 'worker-abandon']),
  Object.freeze(['orchestration', 'worker-retain']),
]);


/**
 * Re-export shared collectors so policy callers do not reimplement argv scan.
 * @see collectTerminalHandlesFromArgv / collectDispatchIdsFromArgv in state-ownership.mjs
 */
export { collectTerminalHandlesFromArgv, collectDispatchIdsFromArgv };

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
 * Last-wins dispatch id from argv (CLI non-repeatable flag semantics).
 * Multi-value ownership must still deny-any via collectDispatchIdsFromArgv.
 * @param {unknown} args
 * @returns {string|null}
 */
export function extractDispatchIdFromArgv(args) {
  const all = collectDispatchIdsFromArgv(args);
  if (!all.length) return null;
  return all[all.length - 1];
}

/**
 * True when argv looks like a handle-ownership-gated command even if
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
  // Scan for gated command pairs. Skip flag tokens anywhere (leading OR
  // interleaved) so `orchestration --json check` matches the same as
  // `orchestration check`. Live parseArgs skips flags via commandPathStartsAt;
  // ownership must not depend on adjacency that the CLI does not require.
  const nextNonFlag = (from) => {
    for (let j = from; j < lower.length; j++) {
      const t = lower[j];
      if (t === '--') return -1;
      if (t.startsWith('-')) continue;
      return j;
    }
    return -1;
  };
  for (let i = 0; i < lower.length; i++) {
    const t = lower[i];
    if (t === '--') break;
    if (t.startsWith('-')) continue;
    if (t === 'terminal') {
      const ni = nextNonFlag(i + 1);
      if (ni < 0) continue;
      const next = lower[ni];
      if (next === 'read' || next === 'close' || next === 'send') return true;
    }
    if (t === 'orchestration') {
      const ni = nextNonFlag(i + 1);
      if (ni < 0) continue;
      const next = lower[ni];
      if (
        next === 'check' ||
        next === 'worker-read' ||
        next === 'worker-show' ||
        next === 'worker-release' ||
        next === 'worker-stop' ||
        next === 'worker-abandon' ||
        next === 'worker-retain'
      ) {
        return true;
      }
    }
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
 * @param {string[]} tokens
 * @returns {boolean}
 */
export function isDispatchOwnershipGatedArgv(tokens) {
  return matchAllowlist(tokens, DISPATCH_OWNERSHIP_GATED_PREFIXES) != null;
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
 *   Missing callback → handle ownership gate skipped (prefix-only policy).
 * @param {(ctx: object) => object} [config.dispatchOwnershipCheck]
 *   Optional. Given { args, dispatchId, tokens, matched_prefix }, same status shape
 *   for dispatch-id gated prefixes (worker-read / worker-show).
 */
export function createCliPolicy(config = {}) {
  const hardening = config.hardening === true;
  const admin = config.admin === true;
  const allowPrefixes = config.allowPrefixes || RAW_CLI_OK_PREFIXES;
  const adminPrefixes = config.adminPrefixes || RAW_CLI_ADMIN_PREFIXES;
  const onWarning = typeof config.onWarning === 'function' ? config.onWarning : null;
  const ownershipCheck =
    typeof config.ownershipCheck === 'function' ? config.ownershipCheck : null;
  const dispatchOwnershipCheck =
    typeof config.dispatchOwnershipCheck === 'function'
      ? config.dispatchOwnershipCheck
      : null;

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
        dispatchOwnershipCheck:
          typeof overrides.dispatchOwnershipCheck === 'function'
            ? overrides.dispatchOwnershipCheck
            : dispatchOwnershipCheck,
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
  const dispatchOwnershipCheck =
    typeof config.dispatchOwnershipCheck === 'function'
      ? config.dispatchOwnershipCheck
      : null;
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

  // --- Handle ownership (NAS-247 + NAS-248) ---
  // Gated: terminal read|close|send, orchestration check.
  // Ownership ALWAYS denies on miss — independent of hardening (NAS-248 P1).
  // Hardening only governs the allowlist; soft-exec of foreign handles is gone.
  //
  // orchestration check without --terminal: withSender injects this client's
  // pin AFTER policy — treat absent handle as "owned by injection" (do not
  // fail-closed null). Explicit --terminal values are always checked deny-any.
  const ownershipTokensGated = isOwnershipGatedArgv(tokens);
  const dispatchTokensGated = isDispatchOwnershipGatedArgv(tokens);
  const ownershipLeadingFlag =
    !ownershipTokensGated &&
    !dispatchTokensGated &&
    looksLikeOwnershipGatedArgv(args);
  // Flag-skipping path (leading OR interleaved globals). Detect kind for funnel.
  const nextCmdAfter = (argsArr, startIdx) => {
    for (let j = startIdx; j < argsArr.length; j++) {
      const t = String(argsArr[j]).toLowerCase();
      if (t === '--') return null;
      if (t.startsWith('-')) continue;
      return t;
    }
    return null;
  };
  const DISPATCH_SUBS = new Set([
    'worker-read',
    'worker-show',
    'worker-release',
    'worker-stop',
    'worker-abandon',
    'worker-retain',
  ]);
  const leadingIsDispatch =
    ownershipLeadingFlag &&
    Array.isArray(args) &&
    args.some((x, i, a) => {
      if (String(x).toLowerCase() !== 'orchestration') return false;
      const n = nextCmdAfter(a, i + 1);
      return n != null && DISPATCH_SUBS.has(n);
    });
  const leadingIsHandle =
    ownershipLeadingFlag && !leadingIsDispatch;

  if (ownershipCheck && (ownershipTokensGated || leadingIsHandle)) {
    const rawHandles = collectTerminalHandlesFromArgv(args);
    const effectiveHandle = extractTerminalHandleFromArgv(args);
    // orchestration check with zero --terminal → pin will be injected; skip.
    const isOrchCheck =
      (matchedPrefix &&
        matchedPrefix[0] === 'orchestration' &&
        matchedPrefix[1] === 'check') ||
      (leadingIsHandle &&
        Array.isArray(args) &&
        args.some((x, i, a) => {
          if (String(x).toLowerCase() !== 'orchestration') return false;
          return nextCmdAfter(a, i + 1) === 'check';
        }));
    const toCheck =
      rawHandles.length > 0
        ? rawHandles
        : isOrchCheck
          ? [] // absent → inject path; no ownership miss
          : [null]; // terminal read/close/send with no handle → fail-closed

    if (toCheck.length) {
      /** @type {object|null} */
      let worst = null;
      /** @type {'owned'|'not-owned'|'unknown'} */
      let worstRank = 'owned';
      const rank = (s) => (s === 'owned' ? 0 : s === 'not-owned' ? 2 : 1);

      for (const raw of toCheck) {
        const handleForCheck = raw == null || raw === '' ? null : raw;
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
        if (!worst || rank(status) >= rank(worstRank)) {
          worst = own;
          worstRank = status;
        }
      }

      if (worst) {
        // Ownership miss always surfaces as ownershipDecision (deny), even when
        // the allowlist would also reject. Hardening no longer soft-execs.
        {
          const ownedHandles = Array.isArray(worst?.owned_handles)
            ? worst.owned_handles
            : Array.isArray(worst?.ownedHandles)
              ? worst.ownedHandles
              : [];
          const reportHandle =
            effectiveHandle != null
              ? effectiveHandle
              : worst?.handle != null
                ? worst.handle
                : null;
          let sub = rejectedSubcommand;
          let matchedForDecision = matchedPrefix;
          if (leadingIsHandle || ownershipLeadingFlag) {
            // Recover command identity even with interleaved flags.
            const lower = (Array.isArray(args) ? args : []).map((x) =>
              String(x).toLowerCase(),
            );
            const nextNonFlag = (from) => {
              for (let j = from; j < lower.length; j++) {
                if (lower[j] === '--') return -1;
                if (lower[j].startsWith('-')) continue;
                return j;
              }
              return -1;
            };
            for (let i = 0; i < lower.length; i++) {
              if (lower[i] === '--') break;
              if (lower[i].startsWith('-')) continue;
              if (lower[i] === 'terminal') {
                const ni = nextNonFlag(i + 1);
                if (ni < 0) continue;
                const n = lower[ni];
                if (n === 'read' || n === 'close' || n === 'send') {
                  sub = `terminal ${n}`;
                  matchedForDecision = ['terminal', n];
                  break;
                }
              }
              if (lower[i] === 'orchestration') {
                const ni = nextNonFlag(i + 1);
                if (ni < 0) continue;
                if (lower[ni] === 'check') {
                  sub = 'orchestration check';
                  matchedForDecision = ['orchestration', 'check'];
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
            kind: 'handle',
          });
        }
      }
    }
  }

  // --- Dispatch-id ownership (NAS-248) ---
  // Gated: worker-read/show + teardown (release/stop/abandon/retain).
  // Keyed by --dispatch via collectDispatchIdsFromArgv. ownershipDecision
  // always denies on miss (hardening independent).
  if (dispatchOwnershipCheck && (dispatchTokensGated || leadingIsDispatch)) {
    const rawIds = collectDispatchIdsFromArgv(args);
    const effectiveId = extractDispatchIdFromArgv(args);
    const toCheck = rawIds.length ? rawIds : [null];

    /** @type {object|null} */
    let worst = null;
    /** @type {'owned'|'not-owned'|'unknown'} */
    let worstRank = 'owned';
    const rank = (s) => (s === 'owned' ? 0 : s === 'not-owned' ? 2 : 1);

    for (const raw of toCheck) {
      const idForCheck = raw == null || raw === '' ? null : raw;
      let own;
      try {
        own = dispatchOwnershipCheck({
          args: Array.isArray(args) ? args : [],
          dispatchId: idForCheck,
          dispatchIds: toCheck.map((d) => (d == null || d === '' ? null : d)),
          tokens,
          matched_prefix: matchedPrefix ? [...matchedPrefix] : null,
          effective_dispatch: effectiveId,
        });
      } catch (e) {
        own = {
          status: 'unknown',
          dispatchId: idForCheck,
          owned_handles: [],
          owned_dispatches: [],
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
      if (!worst || rank(status) >= rank(worstRank)) {
        worst = own;
        worstRank = status;
      }
    }

    if (worst) {
      // Ownership miss always denies; hardening is irrelevant here.
      {
        const ownedHandles = Array.isArray(worst?.owned_handles)
          ? worst.owned_handles
          : Array.isArray(worst?.ownedHandles)
            ? worst.ownedHandles
            : [];
        const ownedDispatches = Array.isArray(worst?.owned_dispatches)
          ? worst.owned_dispatches
          : Array.isArray(worst?.ownedDispatches)
            ? worst.ownedDispatches
            : [];
        const reportId =
          effectiveId != null
            ? effectiveId
            : worst?.dispatchId != null
              ? worst.dispatchId
              : null;
        let sub = rejectedSubcommand;
        let matchedForDecision = matchedPrefix;
        if (leadingIsDispatch || ownershipLeadingFlag || !matchedForDecision) {
          const lower = (Array.isArray(args) ? args : []).map((x) =>
            String(x).toLowerCase(),
          );
          const nextNonFlag = (from) => {
            for (let j = from; j < lower.length; j++) {
              if (lower[j] === '--') return -1;
              if (lower[j].startsWith('-')) continue;
              return j;
            }
            return -1;
          };
          for (let i = 0; i < lower.length; i++) {
            if (lower[i] === '--') break;
            if (lower[i].startsWith('-')) continue;
            if (lower[i] === 'orchestration') {
              const ni = nextNonFlag(i + 1);
              if (ni < 0) continue;
              const n = lower[ni];
              if (
                n === 'worker-read' ||
                n === 'worker-show' ||
                n === 'worker-release' ||
                n === 'worker-stop' ||
                n === 'worker-abandon' ||
                n === 'worker-retain'
              ) {
                sub = `orchestration ${n}`;
                matchedForDecision = ['orchestration', n];
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
          handle: null,
          dispatchId: reportId,
          status: worstRank,
          ownedHandles,
          ownedDispatches,
          reason: worst?.reason,
          kind: 'dispatch',
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
 * Always deny a handle/dispatch ownership miss (NAS-248 invariant).
 * Hardening does not soften this path; onWarning still fires for observability.
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
    dispatchId = null,
    status,
    ownedHandles,
    ownedDispatches = [],
    reason,
    kind = 'handle',
  } = p;

  const statusLabel = status === 'not-owned' ? 'not-owned' : 'unknown';
  const reasonSuffix = reason ? ` reason=${reason}.` : '';
  const isDispatch = kind === 'dispatch';

  let detail;
  if (isDispatch) {
    const idLabel =
      dispatchId == null || dispatchId === '' ? '(missing)' : String(dispatchId);
    const ownedLabel = ownedDispatches.length
      ? ownedDispatches.join(', ')
      : '(none)';
    detail =
      `Blocked: dispatch id "${idLabel}" is ${statusLabel} for this client.` +
      ` Owned dispatches: ${ownedLabel}.${reasonSuffix} ` +
      `Use a dispatch id this client registered via action=dispatch.`;
  } else {
    const handleLabel =
      handle == null || handle === '' ? '(missing)' : String(handle);
    const ownedLabel = ownedHandles.length ? ownedHandles.join(', ') : '(none)';
    detail =
      `Blocked: terminal handle "${handleLabel}" is ${statusLabel} for this client.` +
      ` Owned handles: ${ownedLabel}.${reasonSuffix} ` +
      `Use a handle from dispatch (worker) or this client's pinned sender.`;
  }

  const warning = {
    code: 'handle_not_owned',
    rejected_subcommand: rejectedSubcommand,
    rejected_argv: Array.isArray(args) ? [...args] : args,
    handle: handle == null || handle === '' ? null : String(handle),
    dispatch_id:
      dispatchId == null || dispatchId === '' ? null : String(dispatchId),
    owned_handles: [...ownedHandles],
    owned_dispatches: [...ownedDispatches],
    ownership_status: statusLabel,
    ownership_kind: isDispatch ? 'dispatch' : 'handle',
    reason: reason || undefined,
    allowed_surface: surface,
    admin_surface: adminSurface,
    admin_required: adminRequired,
    hardening,
    message: isDispatch
      ? `argv "${rejectedSubcommand}" dispatch ownership ${statusLabel}; hardening=${hardening ? 'on' : 'off'}`
      : `argv "${rejectedSubcommand}" handle ownership ${statusLabel}; hardening=${hardening ? 'on' : 'off'}`,
  };

  // NAS-248 P1: ownership is an invariant. Always deny on miss.
  // Still emit onWarning for observability when hardening is off so operators
  // see the miss in logs, but never soft-execute foreign/unknown handles.
  if (onWarning) {
    try {
      onWarning(warning);
    } catch {
      // warning hooks must not break the deny path
    }
  }

  const rejection = {
    ok: false,
    error: 'cli_policy_denied',
    code: 'handle_not_owned',
    rejected_subcommand: rejectedSubcommand,
    rejected_argv: Array.isArray(args) ? [...args] : args,
    handle: handle == null || handle === '' ? null : String(handle),
    dispatch_id:
      dispatchId == null || dispatchId === '' ? null : String(dispatchId),
    owned_handles: [...ownedHandles],
    owned_dispatches: [...ownedDispatches],
    ownership_status: statusLabel,
    ownership_kind: isDispatch ? 'dispatch' : 'handle',
    reason: reason || undefined,
    allowed_surface: surface,
    admin_surface: adminSurface,
    admin_required: adminRequired,
    detail,
    next: {
      action: 'guide',
      detail: isDispatch
        ? 'Pass a dispatch id this client owns (from action=dispatch).'
        : 'Pass a terminal handle this client owns (worker handle from dispatch, or the pinned sender).',
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
