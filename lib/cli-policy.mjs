/**
 * Exact-form allowlist policy for action=cli (NAS-254 / NAS-227).
 *
 * A form = exact command path + permitted flags from CLI_COMMAND_SPECS
 * (handler/spec derivation) + value grammar. NO prefix matching on argv.
 *
 * Path membership is filtered by doctrine surfaces (RAW_CLI_OK_PREFIXES /
 * RAW_CLI_ADMIN_PREFIXES), cross-checked against coordinator audit usage.
 * Allowed flags for each form are DERIVED from the matching spec — never
 * hand-written. Same derivation model as HANDLER_ADDRESS_FLAG_RESOLVERS
 * (84c68fd): offline handler/spec census, differential-locked.
 *
 * NAS-227: ORCA_BRIDGE_CLI_HARDENING defaults ON in code. Explicit
 * 0/false/off/no restores the warn-only migration posture. Live host flip
 * remains an operator cutover step — this module only changes the default.
 *
 * NAS-247/248/250-252: ownershipCheck runs in this same funnel and is never
 * softened by the hardening flag.
 *
 * Toolset / admin-tier code should call evaluateCliArgv / createCliPolicy
 * rather than scattering inline checks.
 */

import { isForbiddenHandoffArgv } from './security-core.mjs';
import {
  collectTerminalHandlesFromArgv,
  collectDispatchIdsFromArgv,
  collectDispatchIdFlagFromArgv,
  collectAllDispatchTargetIdsFromArgv,
  collectWorktreeSelectorsFromArgv,
  collectFlagValuesFromArgv,
  collectTaskIdsFromArgv,
  collectRunIdsFromArgv,
  collectGenericIdsFromArgv,
  collectPageIdsFromArgv,
  collectParentWorktreeSelectorsFromArgv,
  collectRepoSelectorsFromArgv,
  classifyValueOwnershipKind,
  stripAddressPrefix,
} from './state-ownership.mjs';
import {
  normalizeArgvForPolicy,
  normalizedFlagRecord,
  listShapedOrchestrationCommands,
  allSpecAllowedFlagNames,
  CLI_COMMAND_SPECS,
} from './cli-argv-normalize.mjs';

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
 *
 * NAS-227: hardening defaults ON when unset/empty. Explicit off:
 *   ORCA_BRIDGE_CLI_HARDENING=0|false|off|no
 * Explicit on (redundant with default):
 *   ORCA_BRIDGE_CLI_HARDENING=1|true|on|yes
 * Unknown non-empty values fail closed to ON.
 *
 *   ORCA_BRIDGE_CLI_ADMIN=1 → unlock admin-tier forms
 */
export function resolveCliPolicyConfig(env = process.env) {
  const e = env || {};
  return {
    hardening: envFlagDefaultOn(e.ORCA_BRIDGE_CLI_HARDENING),
    admin: e.ORCA_BRIDGE_CLI_ADMIN === '1',
  };
}

/**
 * @param {unknown} raw
 * @returns {boolean}
 */
function envFlagDefaultOn(raw) {
  if (raw == null) return true;
  const v = String(raw).trim().toLowerCase();
  if (v === '') return true;
  if (v === '0' || v === 'false' || v === 'off' || v === 'no') return false;
  if (v === '1' || v === 'true' || v === 'on' || v === 'yes') return true;
  return true;
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
 * @typedef {{
 *   path: string[],
 *   aliases: string[][],
 *   allowedFlags: ReadonlySet<string>,
 *   positionalArgs: string[],
 *   tier: 'ok' | 'admin',
 *   label: string,
 * }} CliCommandForm
 */

/**
 * Doctrine path keys (exact) → tier. Built from RAW_CLI_*_PREFIXES only —
 * these lists are the guide/audit surface filter, not the flag allowlist.
 * @param {readonly string[][]} ok
 * @param {readonly string[][]} admin
 * @returns {Map<string, 'ok'|'admin'>}
 */
export function doctrinePathTierMap(
  ok = RAW_CLI_OK_PREFIXES,
  admin = RAW_CLI_ADMIN_PREFIXES,
) {
  /** @type {Map<string, 'ok'|'admin'>} */
  const m = new Map();
  for (const p of ok) m.set(p.map((t) => String(t).toLowerCase()).join('\0'), 'ok');
  for (const p of admin) m.set(p.map((t) => String(t).toLowerCase()).join('\0'), 'admin');
  return m;
}

/**
 * Derive exact command forms from shipped specs filtered by doctrine paths.
 *
 * For each CLI_COMMAND_SPECS entry whose canonical path OR any alias equals a
 * doctrine path EXACTLY (no prefix widening), emit one form:
 *   path            = canonical spec.path
 *   allowedFlags    = Set(spec.allowedFlags)  ← derived, not hand-written
 *   positionalArgs  = spec.positionalArgs
 *   tier            = ok | admin from doctrine
 *
 * MUT-style lock: deleting the filter-to-spec join (hand-writing flags, or
 * accepting any prefix of path) must fail the differential tests.
 *
 * @param {typeof CLI_COMMAND_SPECS} [specs]
 * @param {Map<string, 'ok'|'admin'>} [pathTiers]
 * @returns {readonly CliCommandForm[]}
 */
export function deriveCliCommandForms(
  specs = CLI_COMMAND_SPECS,
  pathTiers = doctrinePathTierMap(),
) {
  /** @type {CliCommandForm[]} */
  const out = [];
  const seen = new Set();
  for (const spec of specs) {
    const canon = (spec.path || []).map((t) => String(t).toLowerCase());
    if (!canon.length) continue;
    /** @type {Array<string[]>} */
    const candidates = [canon];
    for (const a of spec.aliases || []) {
      candidates.push(a.map((t) => String(t).toLowerCase()));
    }
    /** @type {'ok'|'admin'|null} */
    let tier = null;
    for (const cand of candidates) {
      const t = pathTiers.get(cand.join('\0'));
      if (t) {
        tier = t;
        break;
      }
    }
    if (!tier) continue;
    const key = canon.join('\0');
    if (seen.has(key)) continue;
    seen.add(key);
    const allowed = new Set(
      (spec.allowedFlags || []).map((f) => String(f).toLowerCase()),
    );
    // Positionals promote into flags of the same name — ensure they are allowed.
    for (const p of spec.positionalArgs || []) {
      allowed.add(String(p).toLowerCase());
    }
    out.push(
      Object.freeze({
        path: Object.freeze([...canon]),
        aliases: Object.freeze(
          (spec.aliases || []).map((a) =>
            Object.freeze(a.map((t) => String(t).toLowerCase())),
          ),
        ),
        allowedFlags: allowed,
        positionalArgs: Object.freeze(
          (spec.positionalArgs || []).map((p) => String(p).toLowerCase()),
        ),
        tier,
        label: canon.join(' '),
      }),
    );
  }
  return Object.freeze(out);
}

/** Module-load derived forms (doctrine paths × spec flags). */
export const DERIVED_CLI_COMMAND_FORMS = deriveCliCommandForms();

/**
 * Index forms by canonical path and every alias for O(1) exact lookup.
 * @param {readonly CliCommandForm[]} [forms]
 * @returns {Map<string, CliCommandForm>}
 */
export function indexCliCommandForms(forms = DERIVED_CLI_COMMAND_FORMS) {
  /** @type {Map<string, CliCommandForm>} */
  const idx = new Map();
  for (const form of forms) {
    idx.set(form.path.join('\0'), form);
    for (const a of form.aliases) idx.set(a.join('\0'), form);
  }
  return idx;
}

const DERIVED_FORM_INDEX = indexCliCommandForms();

/**
 * Exact form match for argv. NO prefix matching.
 *
 * Steps:
 *  1. parseArgs + normalizeCommandPositionals (same as ownership path)
 *  2. exact lookup of normalized command path in form index
 *  3. every present flag must be in form.allowedFlags
 *  4. command-specific value grammar (check peek⊕all mutex)
 *  5. unparseable short options → fail closed
 *
 * @param {unknown} rawArgs
 * @param {object} [opts]
 * @param {readonly CliCommandForm[]} [opts.forms]
 * @param {Map<string, CliCommandForm>} [opts.index]
 * @returns {{
 *   matched: boolean,
 *   form?: CliCommandForm,
 *   path?: string[],
 *   tier?: 'ok'|'admin',
 *   flags?: string[],
 *   reason?: string,
 *   detail?: string,
 * }}
 */
export function matchExactCliForm(rawArgs, opts = {}) {
  const forms = opts.forms || DERIVED_CLI_COMMAND_FORMS;
  const index = opts.index || (forms === DERIVED_CLI_COMMAND_FORMS
    ? DERIVED_FORM_INDEX
    : indexCliCommandForms(forms));

  if (!Array.isArray(rawArgs)) {
    return {
      matched: false,
      reason: 'unparseable',
      detail: 'argv is not an array',
    };
  }

  // Reject short options early (fail closed).
  for (const raw of rawArgs) {
    const t = String(raw);
    if (t === '--') break;
    if (t.startsWith('--')) continue;
    if (t.startsWith('-') && t.length > 1) {
      return {
        matched: false,
        reason: 'unparseable',
        detail: `short option not permitted: ${t}`,
      };
    }
  }

  // Case-fold non-flag tokens so Skills/Get matches skills get (CLI is
  // case-insensitive on command path). Flag names stay as written; values
  // are untouched. Do this before normalize so positionals promote correctly.
  const folded = rawArgs.map((raw) => {
    const t = String(raw);
    if (t === '--' || t.startsWith('-')) return t;
    return t.toLowerCase();
  });

  let record;
  try {
    record = normalizedFlagRecord(folded);
  } catch (e) {
    return {
      matched: false,
      reason: 'unparseable',
      detail: e && e.message ? e.message : String(e),
    };
  }

  const path = (record.commandPath || []).map((t) => String(t).toLowerCase());
  if (!path.length) {
    return {
      matched: false,
      reason: 'empty_command',
      detail: 'no command path',
    };
  }

  // Exact path lookup only — never a proper-prefix hit.
  const form = index.get(path.join('\0'));
  if (!form) {
    return {
      matched: false,
      reason: 'unknown_command',
      detail: `command not on exact-form allowlist: ${path.join(' ')}`,
      path,
    };
  }

  // Path must equal canonical form path OR an exact alias (index already
  // constrained this). Reject residual longer paths that somehow keyed in.
  const canonHit =
    path.length === form.path.length && path.every((t, i) => t === form.path[i]);
  const aliasHit = form.aliases.some(
    (a) => a.length === path.length && a.every((t, i) => t === path[i]),
  );
  if (!canonHit && !aliasHit) {
    return {
      matched: false,
      reason: 'unknown_command',
      detail: `command path does not exactly match form ${form.label}`,
      path,
    };
  }

  const flagNames = Object.keys(record.flags || {}).map((f) => f.toLowerCase());
  const notPermitted = flagNames.filter((f) => !form.allowedFlags.has(f));
  if (notPermitted.length) {
    return {
      matched: false,
      form,
      path: [...form.path],
      tier: form.tier,
      flags: flagNames,
      reason: 'flag_not_permitted',
      detail:
        `flag(s) not permitted on ${form.label}: ` +
        notPermitted.map((f) => '--' + f).join(', '),
    };
  }

  // Value grammar: orchestration check rejects peek together with all.
  if (form.path[0] === 'orchestration' && form.path[1] === 'check') {
    const hasPeek = Object.prototype.hasOwnProperty.call(record.flags, 'peek');
    const hasAll = Object.prototype.hasOwnProperty.call(record.flags, 'all');
    if (hasPeek && hasAll) {
      return {
        matched: false,
        form,
        path: [...form.path],
        tier: form.tier,
        flags: flagNames,
        reason: 'value_grammar',
        detail:
          'orchestration check rejects --peek together with --all (exactly one read mode)',
      };
    }
  }

  return {
    matched: true,
    form,
    path: [...form.path],
    tier: form.tier,
    flags: flagNames,
  };
}

/**
 * Legacy named prefixes retained for tests/docs. NAS-250/252 inverted the gate:
 * ownership is driven by TARGET SELECTORS present on argv, not by this list.
 * Keeping the list avoids breaking importers; isOwnershipGatedArgv now also
 * returns true when selectors are present.
 */
export const OWNERSHIP_GATED_PREFIXES = Object.freeze([
  Object.freeze(['terminal', 'read']),
  Object.freeze(['terminal', 'close']),
  Object.freeze(['terminal', 'send']),
  Object.freeze(['terminal', 'show']),
  Object.freeze(['terminal', 'wait']),
  Object.freeze(['terminal', 'switch']),
  Object.freeze(['terminal', 'rename']),
  Object.freeze(['terminal', 'split']),
  Object.freeze(['terminal', 'stop']),
  Object.freeze(['orchestration', 'check']),
  Object.freeze(['orchestration', 'inbox']),
]);

/**
 * Legacy dispatch-id prefixes. Selector inversion also gates any argv that
 * carries --dispatch / --dispatch-id regardless of this list.
 */
export const DISPATCH_OWNERSHIP_GATED_PREFIXES = Object.freeze([
  Object.freeze(['orchestration', 'worker-read']),
  Object.freeze(['orchestration', 'worker-show']),
  Object.freeze(['orchestration', 'worker-release']),
  Object.freeze(['orchestration', 'worker-stop']),
  Object.freeze(['orchestration', 'worker-abandon']),
  Object.freeze(['orchestration', 'worker-retain']),
]);

/**
 * CLI flag classification table (NAS-252 real inversion A).
 *
 * Every long-flag the shipped CLI accepts is classified into exactly one of:
 *   - non_target: cannot name a runtime object (formatting, booleans, bodies…)
 *   - target:     names a runtime object; MUST bind a resolver kind
 *   - admin:      address selectors (--from/--to) — admin-tier, not ownership
 *
 * evaluateCliArgv walks argv flags against this table:
 *   - unclassified flag name → DENY (fail closed)
 *   - target flag without positive ownership proof → DENY
 *   - listed-but-unwired target (resolver:null) is impossible by construction:
 *     every target entry has a non-null kind consumed by the evaluator.
 *
 * Source: AppImage v1.4.180 specs under out/cli/specs/ + args.js GLOBAL/BOOLEAN.
 */
export const FLAG_KIND = Object.freeze({
  NON_TARGET: 'non_target',
  TARGET: 'target',
  ADMIN: 'admin',
});

/** @typedef {'handle'|'dispatch'|'worktree'|'task'|'run'|'id'|'page'|'repo'|'parent_worktree'} OwnershipResolverKind */

/**
 * Handler-usage derivation of address/selector flags (v1.4.180).
 *
 * A flag is ADDRESS if its value is passed through to the runtime as a target
 * selector (terminal handle, dispatch id, worktree selector via
 * getOptionalWorktreeSelector / --worktree grammar, task/run/page/id, or a
 * value-typed address such as --to), regardless of what the flag is called.
 * Everything else is content.
 *
 * Built offline from shipped specs + handlers. Not a name heuristic and not
 * read from the AppImage at runtime. Coverage limits are documented in
 * docs/research/NAS-250-252-inversions.md (r11 closeout).
 *
 * @type {Readonly<Record<string, OwnershipResolverKind>>}
 */
export const HANDLER_ADDRESS_FLAG_RESOLVERS = Object.freeze({
  terminal: 'handle',
  dispatch: 'dispatch',
  'dispatch-id': 'dispatch',
  worktree: 'worktree',
  'parent-worktree': 'parent_worktree',
  // automations create/edit: getOptionalWorktreeSelector(flags, 'workspace').
  // Linear --workspace is a UUID; value grammar filters non-worktree forms.
  workspace: 'worktree',
  task: 'task',
  run: 'run',
  id: 'id',
  page: 'page',
  // --pane reserved handle-class; not a value flag in v1.4.180 specs.
  pane: 'handle',
  // --task-id appears on orchestration send worker_done payloads
  'task-id': 'task',
  // Object-naming flags classified by VALUE grammar (also listed here so
  // FLAG_TABLE marks them TARGET — values still go through value-typed resolution).
  to: 'handle', // may also be run:/dispatch:; value grammar decides
  ack: 'id',
  'retry-of': 'dispatch',
  parent: 'task',
  resume: 'id',
});

/**
 * Spec positionals whose handlers treat the value as content (not a runtime
 * ownership selector). Used by {@link deriveRequiredAddressFlags} so a new
 * content-named address positional cannot slip through as NON_TARGET.
 */
export const SPEC_CONTENT_POSITIONAL_FLAGS = Object.freeze([
  'device',
  'file',
  'name',
  'op',
  'orientation',
  'package',
  'path',
  'permission',
  'points',
  'query',
  'recipe-id',
  'text',
  'topic',
  'x',
  'y',
]);

/**
 * Known content flag names (not runtime ownership selectors).
 * SEPARATE from {@link NON_TARGET_FLAGS}: residual-(a) mutations that only
 * demote a name into NON_TARGET without updating this list still fail the
 * derivation lock. Expanding content is a deliberate dual edit.
 *
 * Seeded from the v1.4.180 non-target census; keep in sync when adding a
 * genuine content flag.
 */
export const SPEC_CONTENT_FLAGS = Object.freeze([
  'accuracy',
  'action',
  'activate',
  'activity',
  'agent',
  'all',
  'amount',
  'api-url',
  'app',
  'assignee',
  'attachments',
  'base-branch',
  'body',
  'body-file',
  'brief',
  'button',
  'children',
  'click-count',
  'color-scheme',
  'command',
  'comment',
  'comments',
  'connect',
  'created-at',
  'current',
  'cursor',
  'cycle',
  'delegate',
  'deps',
  'depth',
  'description',
  'destination',
  'device',
  'direction',
  'disabled',
  'dispatch-capability',
  'display-name',
  'domain',
  'dry-run',
  'due-date',
  'dx',
  'dy',
  'effort',
  'element',
  'element-index',
  'emulator',
  'enter',
  'environment',
  'estimate',
  'expires',
  'expression',
  'file',
  'files',
  'files-modified',
  'filter',
  'fn',
  'focus',
  'for',
  'force',
  'format',
  'fresh-session',
  'from-element-index',
  'from-x',
  'from-y',
  'full',
  'git-username',
  'global',
  'headers',
  'height',
  'help',
  'host',
  'http',
  'include-archived',
  'include-visual-layouts',
  'index',
  'inject',
  'input',
  'interrupt',
  'issue',
  'json',
  'key',
  'kind',
  'label',
  'latitude',
  'limit',
  'linear-issue',
  'lines',
  'load',
  'local',
  'locator',
  'longitude',
  'max-concurrent',
  'me',
  'messages',
  'method',
  'mobile',
  'mobile-pairing',
  'mode',
  'model',
  'modifiers',
  'mouse-button',
  'name',
  'no-pairing',
  'no-parent',
  'no-screenshot',
  'no-ua-spoof',
  'objective',
  'on',
  'op',
  'options',
  'order-by',
  'orientation',
  'outcome',
  'package',
  'pages',
  'pairing-address',
  'pairing-code',
  'parent-current',
  'parent-id',
  'pass',
  'path',
  'patterns',
  'payload',
  'peek',
  'permission',
  'phase',
  'points',
  'poll-interval-ms',
  'port',
  'preamble',
  'precheck',
  'priority',
  'profile',
  'project',
  'project-host-setup',
  'project-root',
  'prompt',
  'provider',
  'provision',
  'query',
  'question',
  'ready',
  'recipe-id',
  'recipe-json',
  'reduced-motion',
  'ref',
  'reinstall',
  'related',
  'relations',
  'release',
  'reply-to',
  'repo-path',
  'report-path',
  'resolution',
  'restore-window',
  'result',
  'retry-request',
  'return-preamble',
  'reuse-session',
  'run-hooks',
  'same',
  'scale',
  'scope',
  'secure',
  'selector',
  'session',
  'setup',
  'setup-id',
  'show-profile',
  'skill',
  'source',
  'source-context',
  'spec',
  'staged',
  'state',
  'status',
  'subject',
  'tab',
  'takeover-legacy',
  'task-title',
  'tasks',
  'team',
  'terminal-state',
  'text',
  'text-stdin',
  'thread-id',
  'timeout',
  'timeout-ms',
  'title',
  'to-element-index',
  'to-id',
  'to-x',
  'to-y',
  'topic',
  'trigger',
  'type',
  'types',
  'unread',
  'updated-at',
  'url',
  'user',
  'value',
  'value-stdin',
  'wait',
  'what',
  'width',
  'window-id',
  'window-index',
  'workspace-status',
  'worktree-base-path',
  'write-id',
  'x',
  'y',
  'yes',
  'httpOnly',
  'httponly',
  'sameSite',
  'samesite',
  'day',
  'enabled',
  'schedule',
  'time',
  'timezone',
  'workspace-mode',
  'missed-run-grace-minutes',
  'precheck-timeout',
  'repo',
]);

/**
 * Target selector entries: name → ownership resolver kind.
 * ONE table that evaluateCliArgv actually consumes.
 * Must match HANDLER_ADDRESS_FLAG_RESOLVERS (enforced by differential test).
 * Kept as its own object so demoting a runtime entry without updating the
 * handler derivation is a detectable mutation (MUT3/MUT4a).
 */
export const TARGET_FLAG_RESOLVERS = Object.freeze({
  terminal: 'handle',
  dispatch: 'dispatch',
  'dispatch-id': 'dispatch',
  worktree: 'worktree',
  'parent-worktree': 'parent_worktree',
  workspace: 'worktree',
  task: 'task',
  run: 'run',
  id: 'id',
  page: 'page',
  pane: 'handle',
  'task-id': 'task',
  to: 'handle', // may also be run:/dispatch:; value grammar decides
  ack: 'id',
  'retry-of': 'dispatch',
  parent: 'task',
  resume: 'id',
});

/**
 * Derive the address/selector flag set the differential lock asserts.
 *
 * Base = handler-usage map (offline audit of v1.4.180 handlers).
 * Extension = every shipped (or synthetic) positional that is not a known
 * content positional: those values are treated as address candidates and MUST
 * be kind=target with a live resolver. This is what makes MUT4b fail when a
 * content-named address flag is added only as NON_TARGET + spec.
 *
 * @param {typeof CLI_COMMAND_SPECS} [specs]
 * @returns {Map<string, OwnershipResolverKind|null>}
 */
export function deriveRequiredAddressFlags(specs = CLI_COMMAND_SPECS) {
  /** @type {Map<string, OwnershipResolverKind|null>} */
  const out = new Map();
  for (const [name, resolver] of Object.entries(HANDLER_ADDRESS_FLAG_RESOLVERS)) {
    out.set(String(name).toLowerCase(), resolver);
  }
  const contentFlags = new Set(SPEC_CONTENT_FLAGS.map((f) => String(f).toLowerCase()));
  const contentPos = new Set(SPEC_CONTENT_POSITIONAL_FLAGS.map((f) => String(f).toLowerCase()));
  const admin = new Set(['from']); // ADMIN_SELECTOR_FLAGS (declared later)
  // GLOBAL_FLAGS are imported via normalize; treat help/json/pairing-code/environment as content.
  const globals = new Set(['help', 'json', 'pairing-code', 'environment']);
  for (const s of specs) {
    for (const p of s.positionalArgs || []) {
      const n = String(p).toLowerCase();
      if (!n || contentPos.has(n) || contentFlags.has(n)) continue;
      if (!out.has(n)) out.set(n, null);
    }
    // Residual (a): flag-only address shapes. Any allowedFlags entry that is
    // not known content / admin / global / already-handler-mapped is an address
    // candidate and MUST be kind=target. Demoting only into NON_TARGET without
    // updating SPEC_CONTENT_FLAGS fails the differential.
    for (const f of s.allowedFlags || []) {
      const n = String(f).toLowerCase();
      if (!n || contentFlags.has(n) || contentPos.has(n) || admin.has(n) || globals.has(n)) continue;
      if (!out.has(n)) out.set(n, null);
    }
  }
  return out;
}

/**
 * Worktree-class address flag names derived from the handler-usage map.
 * Collection and differential locks use this set — never a hand-written
 * spelling list like ['worktree','workspace'].
 * @param {Readonly<Record<string, OwnershipResolverKind>>} [resolvers]
 * @returns {readonly string[]}
 */
export function deriveWorktreeClassAddressFlags(
  resolvers = HANDLER_ADDRESS_FLAG_RESOLVERS,
) {
  return Object.freeze(
    Object.entries(resolvers)
      .filter(([, resolver]) => resolver === 'worktree')
      .map(([name]) => String(name).toLowerCase())
      .sort(),
  );
}

/**
 * Item-5 filter: keep worktree-grammar values; drop Linear UUID / non-orch.
 * @param {Array<string|null|undefined>} vals
 * @returns {Array<string|null>}
 */
export function filterWorktreeGrammarValues(vals) {
  const filtered = [];
  for (const raw of vals || []) {
    if (raw == null || raw === '') {
      filtered.push(raw == null ? null : raw);
      continue;
    }
    const vk = classifyValueOwnershipKind(raw);
    if (vk === 'worktree') {
      filtered.push(stripAddressPrefix(raw));
    } else if (vk == null) {
      continue;
    } else {
      filtered.push(String(raw));
    }
  }
  return filtered;
}

/**
 * Collect worktree-class targets for EVERY derived worktree-class flag present
 * on argv. Single collection path used by evaluateCliArgv — MUT6-shaped
 * deletion of an alias-only branch cannot leave tables green while evaluate
 * drops --workspace.
 *
 * Primary spelling `--worktree` accepts all collector values (incl. synthetic).
 * Aliases (today: `--workspace`) use Item-5 grammar filtering.
 *
 * @param {unknown} args
 * @param {readonly string[]} [classFlags]
 * @returns {Array<string|null>}
 */
export function collectWorktreeClassTargetsFromArgv(
  args,
  classFlags = deriveWorktreeClassAddressFlags(),
) {
  if (!Array.isArray(args)) return [];
  const present = new Set(collectFlagNamesFromArgv(args));
  /** @type {Array<string|null>} */
  const out = [];
  for (const name of classFlags) {
    if (!present.has(name)) continue;
    if (name === 'worktree') {
      out.push(...collectWorktreeSelectorsFromArgv(args));
      continue;
    }
    out.push(...filterWorktreeGrammarValues(collectFlagValuesFromArgv(args, name)));
  }
  return out;
}

/**
 * file open / file diff path selectors (NAS-251 family on --path / positional).
 * --path remains NON_TARGET globally (repo add, emulator install, …); only
 * these commands treat worktree-grammar path values as ownership targets.
 * @param {unknown} args
 * @returns {Array<string|null>}
 */
export function collectFileOpenPathTargetsFromArgv(args) {
  if (!Array.isArray(args)) return [];
  // Promote positionals so `file open path:/x` and `file open --path path:/x`
  // share one collection path (same as evaluateCliArgv).
  const argv = normalizeArgvForPolicy(args);
  let hit = false;
  for (let i = 0; i < argv.length; i++) {
    if (String(argv[i]).toLowerCase() !== 'file') continue;
    for (let j = i + 1; j < argv.length; j++) {
      const tok = String(argv[j]).toLowerCase();
      if (tok === '--') break;
      if (tok.startsWith('-')) continue;
      if (tok === 'open' || tok === 'diff') {
        hit = true;
      }
      break;
    }
    if (hit) break;
  }
  if (!hit) return [];
  return filterWorktreeGrammarValues(collectFlagValuesFromArgv(argv, 'path'));
}

/**
 * Non-target flags (cannot name a runtime ownership object).
 * Enumerated from v1.4.180 specs allowedFlags + usage --flags, minus targets.
 */
export const NON_TARGET_FLAGS = Object.freeze([
  'accuracy',
  'action',
  'activate',
  'activity',
  'agent',
  'all',
  'amount',
  'api-url',
  'app',
  'assignee',
  'attachments',
  'base-branch',
  'body',
  'body-file',
  'brief',
  'button',
  'children',
  'click-count',
  'color-scheme',
  'command',
  'comment',
  'comments',
  'connect',
  'created-at',
  'current',
  'cursor',
  'cycle',
  'delegate',
  'deps',
  'depth',
  'description',
  'destination',
  'device',
  'direction',
  'disabled',
  'dispatch-capability',
  'display-name',
  'domain',
  'dry-run',
  'due-date',
  'dx',
  'dy',
  'effort',
  'element',
  'element-index',
  'emulator',
  'enter',
  'environment',
  'estimate',
  'expires',
  'expression',
  'file',
  'files',
  'files-modified',
  'filter',
  'fn',
  'focus',
  'for',
  'force',
  'format',
  'fresh-session',
  'from-element-index',
  'from-x',
  'from-y',
  'full',
  'git-username',
  'global',
  'headers',
  'height',
  'help',
  'host',
  'http',
  'include-archived',
  'include-visual-layouts',
  'index',
  'inject',
  'input',
  'interrupt',
  'issue',
  'json',
  'key',
  'kind',
  'label',
  'latitude',
  'limit',
  'linear-issue',
  'lines',
  'load',
  'local',
  'locator',
  'longitude',
  'max-concurrent',
  'me',
  'messages',
  'method',
  'mobile',
  'mobile-pairing',
  'mode',
  'model',
  'modifiers',
  'mouse-button',
  'name',
  'no-pairing',
  'no-parent',
  'no-screenshot',
  'no-ua-spoof',
  'objective',
  'on',
  'op',
  'options',
  'order-by',
  'orientation',
  'outcome',
  'package',
  'pages',
  'pairing-address',
  'pairing-code',
  'parent-current',
  'parent-id',
  'pass',
  'path',
  'patterns',
  'payload',
  'peek',
  'permission',
  'phase',
  'points',
  'poll-interval-ms',
  'port',
  'preamble',
  'precheck',
  'priority',
  'profile',
  'project',
  'project-host-setup',
  'project-root',
  'prompt',
  'provider',
  'provision',
  'query',
  'question',
  'ready',
  'recipe-id',
  'recipe-json',
  'reduced-motion',
  'ref',
  'reinstall',
  'related',
  'relations',
  'release',
  'reply-to',
  'repo-path',
  'report-path',
  'resolution',
  'restore-window',
  'result',
  'retry-request',
  'return-preamble',
  'reuse-session',
  'run-hooks',
  'same',
  'scale',
  'scope',
  'secure',
  'selector',
  'session',
  'setup',
  'setup-id',
  'show-profile',
  'skill',
  'source',
  'source-context',
  'spec',
  'staged',
  'state',
  'status',
  'subject',
  'tab',
  'takeover-legacy',
  'task-title',
  'tasks',
  'team',
  'terminal-state',
  'text',
  'text-stdin',
  'thread-id',
  'timeout',
  'timeout-ms',
  'title',
  'to-element-index',
  'to-id',
  'to-x',
  'to-y',
  'topic',
  'trigger',
  'type',
  'types',
  'unread',
  'updated-at',
  'url',
  'user',
  'value',
  'value-stdin',
  'wait',
  'what',
  'width',
  'window-id',
  'window-index',
  'workspace-status',
  'worktree-base-path',
  'write-id',
  'x',
  'y',
  'yes',
  // v1.4.180 cookie / automations flags previously missing (false deny)
  'httpOnly',
  'httponly',
  'sameSite',
  'samesite',
  'day',
  'enabled',
  'schedule',
  'time',
  'timezone',
  'workspace-mode',
  'missed-run-grace-minutes',
  'precheck-timeout',
  // repo: git/path filter, not a bridge-owned runtime object. Documented
  // `worktree list --repo` must not false-deny; foreign teardown uses --worktree.
  'repo',
]);

/**
 * Admin-tier address selectors — not ownership-gated as foreign teardown.
 * Classified explicitly so they are not "unclassified → deny".
 */
// --from is bridge-controlled (always overwritten by inject). Classified admin so bare
// presence is not an ownership target; value is never trusted from the caller.
// --to is a TARGET (value-typed) — see TARGET_FLAG_RESOLVERS.
export const ADMIN_SELECTOR_FLAGS = Object.freeze(['from']);

/**
 * Unified flag → classification map consumed by evaluateCliArgv.
 * @type {Readonly<Record<string, { kind: string, resolver: OwnershipResolverKind|null }>>}
 */
export const FLAG_TABLE = Object.freeze((() => {
  /** @type {Record<string, { kind: string, resolver: string|null }>} */
  const t = Object.create(null);
  for (const name of NON_TARGET_FLAGS) {
    t[String(name).toLowerCase()] = Object.freeze({ kind: FLAG_KIND.NON_TARGET, resolver: null });
  }
  for (const name of ADMIN_SELECTOR_FLAGS) {
    t[String(name).toLowerCase()] = Object.freeze({ kind: FLAG_KIND.ADMIN, resolver: null });
  }
  for (const [name, resolver] of Object.entries(TARGET_FLAG_RESOLVERS)) {
    t[String(name).toLowerCase()] = Object.freeze({ kind: FLAG_KIND.TARGET, resolver });
  }
  return t;
})());

/**
 * Legacy export — flag names only. Prefer FLAG_TABLE / TARGET_FLAG_RESOLVERS.
 * Kept so older importers do not break; every entry is wired in FLAG_TABLE.
 */
export const TARGET_SELECTOR_FLAGS = Object.freeze(Object.keys(TARGET_FLAG_RESOLVERS));

/**
 * Collect every long-flag name present on argv (without dashes), stopping at `--`.
 * @param {unknown} args
 * @returns {string[]}
 */
export function collectFlagNamesFromArgv(args) {
  if (!Array.isArray(args)) return [];
  const out = [];
  for (const raw of args) {
    const t = String(raw);
    // Do NOT stop at `--`: ownership must still see `--terminal FOREIGN` after
    // end-of-options (HELD: `--` does not hide selectors).
    if (!t.startsWith('--') || t === '--') continue;
    const body = t.slice(2);
    if (!body) continue;
    const eq = body.indexOf('=');
    const name = (eq === -1 ? body : body.slice(0, eq)).toLowerCase();
    if (name) out.push(name);
  }
  return out;
}

/**
 * Return unclassified flag names (not in FLAG_TABLE). Fail-closed input.
 * @param {unknown} args
 * @returns {string[]}
 */
export function collectUnclassifiedFlagsFromArgv(args) {
  const names = collectFlagNamesFromArgv(args);
  const bad = [];
  for (const n of names) {
    if (!Object.prototype.hasOwnProperty.call(FLAG_TABLE, n)) bad.push(n);
  }
  return bad;
}

/**
 * True when every TARGET_FLAG_RESOLVERS entry has a non-null resolver kind.
 * Used by tests so a listed-but-unwired selector is impossible.
 */
export function assertTargetFlagResolversComplete() {
  const missing = [];
  for (const [name, resolver] of Object.entries(TARGET_FLAG_RESOLVERS)) {
    if (resolver == null || resolver === '') missing.push(name);
    const entry = FLAG_TABLE[name];
    if (!entry || entry.kind !== FLAG_KIND.TARGET || entry.resolver !== resolver) {
      missing.push(name + '(table-mismatch)');
    }
  }
  return missing;
}

/**
 * Re-export shared collectors so policy callers do not reimplement argv scan.
 */
export {
  collectTerminalHandlesFromArgv,
  collectDispatchIdsFromArgv,
  collectDispatchIdFlagFromArgv,
  collectAllDispatchTargetIdsFromArgv,
  collectWorktreeSelectorsFromArgv,
  collectFlagValuesFromArgv,
  collectTaskIdsFromArgv,
  collectRunIdsFromArgv,
  collectGenericIdsFromArgv,
  collectPageIdsFromArgv,
  collectParentWorktreeSelectorsFromArgv,
  collectRepoSelectorsFromArgv,
};

export {
  normalizeArgvForPolicy,
  normalizedFlagRecord,
  listShapedOrchestrationCommands,
  allSpecAllowedFlagNames,
  CLI_COMMAND_SPECS,
} from './cli-argv-normalize.mjs';

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
 * True when argv carries any ownership-relevant target selector, or matches a
 * legacy gated command path (including leading/interleaved globals).
 *
 * Inversion (NAS-250/252): selector presence is sufficient. Unknown selector
 * spellings that name a target still fail closed via collect* helpers.
 *
 * @param {unknown} args
 * @returns {boolean}
 */
export function looksLikeOwnershipGatedArgv(args) {
  if (!Array.isArray(args)) return false;
  // Any target-class flag from FLAG_TABLE is enough.
  for (const name of collectFlagNamesFromArgv(args)) {
    const entry = FLAG_TABLE[name];
    if (entry && entry.kind === FLAG_KIND.TARGET) return true;
  }

  const lower = args.map((x) => String(x).toLowerCase());
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
      if (
        next === 'read' ||
        next === 'close' ||
        next === 'send' ||
        next === 'show' ||
        next === 'wait' ||
        next === 'switch' ||
        next === 'rename' ||
        next === 'split' ||
        next === 'stop' ||
        next === 'focus'
      ) {
        return true;
      }
    }
    if (t === 'orchestration') {
      const ni = nextNonFlag(i + 1);
      if (ni < 0) continue;
      const next = lower[ni];
      if (
        next === 'check' ||
        next === 'inbox' ||
        next === 'worker-read' ||
        next === 'worker-show' ||
        next === 'worker-release' ||
        next === 'worker-stop' ||
        next === 'worker-abandon' ||
        next === 'worker-retain' ||
        next === 'dispatch-show' ||
        next === 'task-list' ||
        next === 'run-show' ||
        next === 'run-list' ||
        next === 'worker-list' ||
        next === 'worker-start' ||
        next === 'reply'
      ) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Detect whether argv contains a given long-flag name (--name / --name=).
 * @param {unknown} args
 * @param {string} name without dashes
 */
export function argvHasFlag(args, name) {
  if (!Array.isArray(args)) return false;
  const spaced = `--${name}`;
  const eq = `--${name}=`;
  for (const raw of args) {
    const t = String(raw);
    if (t === spaced || t.startsWith(eq)) return true;
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
 * True when argv has any target selector that must be ownership-proven.
 * @param {unknown} args
 */
export function argvHasOwnershipTargetSelector(args) {
  if (!Array.isArray(args)) return false;
  for (const name of collectFlagNamesFromArgv(args)) {
    const entry = FLAG_TABLE[name];
    if (entry && entry.kind === FLAG_KIND.TARGET) return true;
  }
  return false;
}

/**
 * Build a reusable policy object the toolset gate can hold and call.
 * @param {object} [config]
 * @param {boolean} [config.hardening] default ON (NAS-227); pass false for warn-only
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
 *   for dispatch-id selectors.
 * @param {(ctx: object) => object} [config.worktreeOwnershipCheck]
 *   Optional. Given { args, worktree, tokens, matched_prefix } for --worktree.
 */
export function createCliPolicy(config = {}) {
  // NAS-227: hardening defaults ON when omitted; explicit false keeps migration path.
  const hardening = Object.prototype.hasOwnProperty.call(config, 'hardening')
    ? config.hardening === true
    : true;
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
  const worktreeOwnershipCheck =
    typeof config.worktreeOwnershipCheck === 'function'
      ? config.worktreeOwnershipCheck
      : null;
  const taskOwnershipCheck =
    typeof config.taskOwnershipCheck === 'function' ? config.taskOwnershipCheck : null;
  const runOwnershipCheck =
    typeof config.runOwnershipCheck === 'function' ? config.runOwnershipCheck : null;
  const idOwnershipCheck =
    typeof config.idOwnershipCheck === 'function' ? config.idOwnershipCheck : null;
  const pageOwnershipCheck =
    typeof config.pageOwnershipCheck === 'function' ? config.pageOwnershipCheck : null;
  const repoOwnershipCheck =
    typeof config.repoOwnershipCheck === 'function' ? config.repoOwnershipCheck : null;
  const parentWorktreeOwnershipCheck =
    typeof config.parentWorktreeOwnershipCheck === 'function'
      ? config.parentWorktreeOwnershipCheck
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
        worktreeOwnershipCheck:
          typeof overrides.worktreeOwnershipCheck === 'function'
            ? overrides.worktreeOwnershipCheck
            : worktreeOwnershipCheck,
        taskOwnershipCheck:
          typeof overrides.taskOwnershipCheck === 'function'
            ? overrides.taskOwnershipCheck
            : taskOwnershipCheck,
        runOwnershipCheck:
          typeof overrides.runOwnershipCheck === 'function'
            ? overrides.runOwnershipCheck
            : runOwnershipCheck,
        idOwnershipCheck:
          typeof overrides.idOwnershipCheck === 'function'
            ? overrides.idOwnershipCheck
            : idOwnershipCheck,
        pageOwnershipCheck:
          typeof overrides.pageOwnershipCheck === 'function'
            ? overrides.pageOwnershipCheck
            : pageOwnershipCheck,
        repoOwnershipCheck:
          typeof overrides.repoOwnershipCheck === 'function'
            ? overrides.repoOwnershipCheck
            : repoOwnershipCheck,
        parentWorktreeOwnershipCheck:
          typeof overrides.parentWorktreeOwnershipCheck === 'function'
            ? overrides.parentWorktreeOwnershipCheck
            : parentWorktreeOwnershipCheck,
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
export function evaluateCliArgv(rawArgs, config = {}) {
  // NAS-227: hardening defaults ON when the key is omitted.
  const hardening = Object.prototype.hasOwnProperty.call(config, 'hardening')
    ? config.hardening === true
    : true;
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
  const worktreeOwnershipCheck =
    typeof config.worktreeOwnershipCheck === 'function'
      ? config.worktreeOwnershipCheck
      : null;
  const taskOwnershipCheck =
    typeof config.taskOwnershipCheck === 'function' ? config.taskOwnershipCheck : null;
  const runOwnershipCheck =
    typeof config.runOwnershipCheck === 'function' ? config.runOwnershipCheck : null;
  const idOwnershipCheck =
    typeof config.idOwnershipCheck === 'function' ? config.idOwnershipCheck : null;
  const pageOwnershipCheck =
    typeof config.pageOwnershipCheck === 'function' ? config.pageOwnershipCheck : null;
  const repoOwnershipCheck =
    typeof config.repoOwnershipCheck === 'function' ? config.repoOwnershipCheck : null;
  const parentWorktreeOwnershipCheck =
    typeof config.parentWorktreeOwnershipCheck === 'function'
      ? config.parentWorktreeOwnershipCheck
      : worktreeOwnershipCheck; // parent-worktree uses worktree resolver by default
  const forbiddenCheck =
    typeof config.isForbiddenHandoff === 'function'
      ? config.isForbiddenHandoff
      : isForbiddenHandoffArgv;

  // PARSE PARITY: evaluate the argv the CLI will see after positional promotion.
  const args = Array.isArray(rawArgs)
    ? normalizeArgvForPolicy(rawArgs)
    : rawArgs;
  const originalArgs = rawArgs;

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

  // NAS-254: exact command-form allowlist (path + derived flags + value grammar).
  // Path filter = doctrine prefixes; flags come from CLI_COMMAND_SPECS for that path.
  // NO token-prefix matching — a longer/unknown path is a miss.
  const formSourceCustom =
    allowPrefixes !== RAW_CLI_OK_PREFIXES || adminPrefixes !== RAW_CLI_ADMIN_PREFIXES;
  const forms = formSourceCustom
    ? deriveCliCommandForms(
        CLI_COMMAND_SPECS,
        doctrinePathTierMap(allowPrefixes, adminPrefixes),
      )
    : DERIVED_CLI_COMMAND_FORMS;
  const formMatch = matchExactCliForm(originalArgs, { forms });
  const formTier = formMatch.matched ? formMatch.tier : null;
  const allowHit = formMatch.matched && formTier === 'ok' ? formMatch.path : null;
  const adminHit = formMatch.matched && formTier === 'admin' ? formMatch.path : null;
  // Admin required when the matched form is admin-tier, OR when the path alone
  // is an admin doctrine path but flags/grammar rejected the form (so the deny
  // message still points at admin unlock rather than "unknown command").
  const doctrineAdminPath =
    !formMatch.matched &&
    matchAllowlist(tokens, adminPrefixes) != null &&
    matchAllowlist(tokens, allowPrefixes) == null;
  const adminRequired = Boolean(adminHit) || doctrineAdminPath;
  const formAllowed = Boolean(allowHit || (adminHit && admin));
  const matchedPrefix = allowHit ? allowHit : adminHit && admin ? adminHit : null;

  // ---------- helpers ----------
  const nextCmdAfter = (argsArr, startIdx) => {
    for (let j = startIdx; j < argsArr.length; j++) {
      const t = String(argsArr[j]).toLowerCase();
      if (t === '--') return null;
      if (t.startsWith('-')) continue;
      return t;
    }
    return null;
  };

  const isCmd = (group, sub) =>
    Array.isArray(args) &&
    args.some((x, i, a) => {
      if (String(x).toLowerCase() !== group) return false;
      return nextCmdAfter(a, i + 1) === sub;
    });

  const recoverCommandLabel = () => {
    let sub = rejectedSubcommand;
    let matchedForDecision = matchedPrefix;
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
        sub = `terminal ${lower[ni]}`;
        matchedForDecision = ['terminal', lower[ni]];
        return { sub, matchedForDecision };
      }
      if (lower[i] === 'orchestration') {
        const ni = nextNonFlag(i + 1);
        if (ni < 0) continue;
        sub = `orchestration ${lower[ni]}`;
        matchedForDecision = ['orchestration', lower[ni]];
        return { sub, matchedForDecision };
      }
      if (lower[i] === 'worktree') {
        const ni = nextNonFlag(i + 1);
        if (ni < 0) continue;
        sub = `worktree ${lower[ni]}`;
        matchedForDecision = ['worktree', lower[ni]];
        return { sub, matchedForDecision };
      }
    }
    return { sub, matchedForDecision };
  };

  const denyOwnership = (fields) => {
    const { sub, matchedForDecision } = recoverCommandLabel();
    return ownershipDecision({
      args: Array.isArray(originalArgs) ? originalArgs : args,
      hardening,
      onWarning,
      rejectedSubcommand: sub,
      matchedPrefix: matchedForDecision,
      adminRequired,
      surface,
      adminSurface,
      ...fields,
    });
  };

  // ---------- A0. Unclassified flags fail closed ----------
  const unclassified = collectUnclassifiedFlagsFromArgv(args);
  if (unclassified.length) {
    return denyOwnership({
      handle: null,
      status: 'unknown',
      ownedHandles: [],
      reason: 'unclassified_flag',
      kind: 'handle',
      detailOverride:
        `Blocked: argv carries unclassified flag(s): ${unclassified.map((f) => '--' + f).join(', ')}. ` +
        `Unknown flags fail closed under the ownership allowlist.`,
    });
  }

  // ---------- Collect target flags present (from FLAG_TABLE) ----------
  const flagNames = collectFlagNamesFromArgv(args);
  /** @type {Map<string, string[]|Array<string|null>>} */
  const targetsByKind = new Map();
  const note = (kind, values) => {
    if (!values || !values.length) return;
    const cur = targetsByKind.get(kind) || [];
    targetsByKind.set(kind, cur.concat(values));
  };

  // Flags whose referent is decided solely by value grammar (not flag name).
  const VALUE_TYPED_ONLY = new Set(['to', 'ack', 'retry-of', 'parent', 'resume']);

  for (const name of flagNames) {
    const entry = FLAG_TABLE[name];
    if (!entry || entry.kind !== FLAG_KIND.TARGET) continue;
    if (VALUE_TYPED_ONLY.has(name)) continue; // value-typed block below
    const kind = entry.resolver;
    if (kind === 'handle' && name === 'terminal') {
      note('handle', collectTerminalHandlesFromArgv(args));
    } else if (kind === 'dispatch') {
      note('dispatch', collectAllDispatchTargetIdsFromArgv(args));
    } else if (kind === 'worktree') {
      // Worktree-class collection is NOT done per spelling here.
      // See collectWorktreeClassTargetsFromArgv after the flag loop — derived
      // from HANDLER_ADDRESS_FLAG_RESOLVERS so alias/collection drift (MUT6)
      // cannot leave FLAG_TABLE green while evaluate drops --workspace.
    } else if (kind === 'parent_worktree') {
      note('parent_worktree', collectParentWorktreeSelectorsFromArgv(args));
    } else if (kind === 'task') {
      note('task', name === 'task-id'
        ? collectFlagValuesFromArgv(args, 'task-id')
        : collectTaskIdsFromArgv(args));
    } else if (kind === 'run') {
      note('run', collectRunIdsFromArgv(args));
    } else if (kind === 'id') {
      // Value rule (Item 5): only orch-id grammar is ownership-relevant.
      // computer permissions --id accessibility → not a target.
      // computer permissions --id task_FOREIGN → id target.
      // linear issue NAS-252 → not a target.
      const rawIds = collectGenericIdsFromArgv(args);
      const orchIds = [];
      for (const raw of rawIds) {
        if (raw == null || raw === '') {
          orchIds.push(raw);
          continue;
        }
        const vk = classifyValueOwnershipKind(raw);
        if (vk == null) {
          // Not an orchestration referent — ignore (permission name, Linear key, …).
          continue;
        }
        if (vk === 'id' || vk === 'task' || vk === 'run' || vk === 'dispatch' || vk === 'handle' || vk === 'page') {
          // Keep as id-kind for the generic id checker (msg_/delivery_/task_/…).
          // task_/run_/ctx_ still go through idOwnershipCheck which branches on prefix.
          orchIds.push(String(raw));
        } else if (vk === 'worktree') {
          note('worktree', [stripAddressPrefix(raw)]);
        } else {
          orchIds.push(String(raw));
        }
      }
      if (orchIds.length) note('id', orchIds);
    } else if (kind === 'page') {
      note('page', collectPageIdsFromArgv(args));
    } else if (kind === 'repo') {
      note('repo', collectRepoSelectorsFromArgv(args));
    } else if (kind === 'handle') {
      // pane or other handle-class: presence with no value still notes null
      note('handle', collectFlagValuesFromArgv(args, name));
    }
  }

  // Worktree-class targets: one collector derived from handler resolver kind.
  note('worktree', collectWorktreeClassTargetsFromArgv(args));

  // file open|diff path selectors (residual b / NAS-251 family). --path is
  // still NON_TARGET for other commands; only these handlers treat path
  // grammar as a worktree ownership target.
  note('worktree', collectFileOpenPathTargetsFromArgv(args));

  // VALUE-TYPED RESOLUTION: only flags whose referent is decided by value
  // grammar (--to/--ack/--retry-of/--parent/--resume). Name-based TARGET flags
  // (terminal/worktree/id/…) already collected above; do NOT re-scan them or
  // bare tokens like --terminal t / --worktree new-child false-deny.
  // Content flags are never scanned (Item 4).
  {
    for (const name of collectFlagNamesFromArgv(args)) {
      if (!VALUE_TYPED_ONLY.has(name)) continue;
      const values = collectFlagValuesFromArgv(args, name);
      for (const raw of values) {
        if (raw == null || raw === '') continue;
        const s = String(raw);

        // Item 1 — group addresses (documented on --to; any @ form on these flags).
        if (s.startsWith('@')) {
          if (/^@worktree:/i.test(s)) {
            note('worktree', [stripAddressPrefix(s)]);
            continue;
          }
          return denyOwnership({
            handle: null,
            status: 'unknown',
            ownedHandles: [],
            reason: 'unowned_group_address',
            kind: 'handle',
            detailOverride:
              'Blocked: group address ' + JSON.stringify(s) + ' on --' + name +
              ' is not an owned selector. Use a concrete owned handle/run/dispatch/worktree.',
          });
        }

        const vk = classifyValueOwnershipKind(raw);
        if (!vk) {
          // --ack outside delivery_/msg_/orch-id grammar: not an ownership target
          // (Item 5). Documented tokens classify; unknown forms are ignored.
          if (name === 'ack') continue;
          // Other value-typed address flags: unrecognised form denies (class bug).
          return denyOwnership({
            handle: null,
            status: 'unknown',
            ownedHandles: [],
            reason: 'unrecognized_address_value',
            kind: 'handle',
            detailOverride:
              'Blocked: --' + name + ' value ' + JSON.stringify(s) +
              ' is not a recognised ownership address form.',
          });
        }
        let v = s;
        if (vk === 'run' || vk === 'dispatch' || vk === 'task' || vk === 'worktree') {
          v = stripAddressPrefix(v);
        }
        note(vk, [v]);
      }
    }
  }

  // Legacy command-path gates (no selector flag): terminal read/show/... without
  // --terminal, worker-read without --dispatch, etc.
  const ownershipTokensGated = isOwnershipGatedArgv(tokens);
  const dispatchTokensGated = isDispatchOwnershipGatedArgv(tokens);
  const isOrchCheck =
    (matchedPrefix && matchedPrefix[0] === 'orchestration' && matchedPrefix[1] === 'check') ||
    isCmd('orchestration', 'check');
  const isOrchInbox =
    (matchedPrefix && matchedPrefix[0] === 'orchestration' && matchedPrefix[1] === 'inbox') ||
    isCmd('orchestration', 'inbox');
  const isTerminalStop =
    (matchedPrefix && matchedPrefix[0] === 'terminal' && matchedPrefix[1] === 'stop') ||
    isCmd('terminal', 'stop');
  const isWorktreeCreate =
    (matchedPrefix && matchedPrefix[0] === 'worktree' && matchedPrefix[1] === 'create') ||
    isCmd('worktree', 'create');
  const isWorkerStart =
    (matchedPrefix && matchedPrefix[0] === 'orchestration' && matchedPrefix[1] === 'worker-start') ||
    isCmd('orchestration', 'worker-start');
  const isRunList =
    (matchedPrefix && matchedPrefix[0] === 'orchestration' && matchedPrefix[1] === 'run-list') ||
    isCmd('orchestration', 'run-list');

  // Spec-derived unscoped list-shaped orch commands: host-wide inventory without
  // a scope selector is denied (run-list, worker-list, …). task-list/gate-list
  // accept --run/--task scope; when those flags are absent and the command is
  // list-shaped with empty scopeFlags OR scope flags not present → deny.
  {
    const listCmds = listShapedOrchestrationCommands();
    for (const lc of listCmds) {
      const isThis =
        tokens.length >= lc.path.length &&
        lc.path.every((p, i) => tokens[i] === p);
      if (!isThis && !(lc.path[1] && isCmd(lc.path[0], lc.path[1]))) continue;
      // Scope = any ownership target already collected (run/id/task/handle/…).
      // Spec scopeFlags are advisory for the error text; presence of ANY target
      // selector counts (run-list accepts --run even if older specs omit it).
      const scoped =
        targetsByKind.has('run') ||
        targetsByKind.has('id') ||
        targetsByKind.has('task') ||
        targetsByKind.has('handle') ||
        targetsByKind.has('dispatch') ||
        targetsByKind.has('worktree');
      // task-list / gate-list without selector: CLI pin-scopes via --from.
      const pinScopedOk =
        lc.path[1] === 'task-list' || lc.path[1] === 'gate-list';
      if (!scoped && !pinScopedOk) {
        const hint = lc.scopeFlags.length
          ? lc.scopeFlags.map((f) => '--' + f).join(', ')
          : '--run, --id';
        return denyOwnership({
          handle: null,
          status: 'unknown',
          ownedHandles: [],
          reason: 'unscoped_list',
          kind: 'run',
          detailOverride:
            'Blocked: ' + lc.path.join(' ') + ' is unscoped and would return foreign inventory. ' +
            'Pass an owned scope selector (' + hint + ').',
        });
      }
    }
  }

  // Handle-gated commands without --terminal: fail closed (null handle),
  // except check/inbox (pin injection) and terminal stop (worktree-keyed).
  if (
    (ownershipTokensGated || looksLikeHandleCommand(args)) &&
    !targetsByKind.has('handle') &&
    !isOrchCheck &&
    !isOrchInbox &&
    !(isTerminalStop && targetsByKind.has('worktree'))
  ) {
    // Only inject null handle check for true handle-targeted commands
    if (ownershipTokensGated || looksLikeHandleCommand(args)) {
      const skipNull =
        isOrchCheck ||
        isOrchInbox ||
        (isTerminalStop && !targetsByKind.has('handle'));
      if (!skipNull && !targetsByKind.has('handle')) {
        // For terminal list etc. that are only gated via worktree, don't null-handle.
        if (looksLikeHandleCommand(args) || ownershipTokensGated) {
          if (!isTerminalStop) {
            note('handle', [null]);
          }
        }
      }
    }
  }

  // Dispatch-gated commands without --dispatch: fail closed
  if (dispatchTokensGated && !targetsByKind.has('dispatch')) {
    note('dispatch', [null]);
  }

  // Helper: does argv look like a handle-targeted terminal command?
  function looksLikeHandleCommand(a) {
    if (!Array.isArray(a)) return false;
    return a.some((x, i, arr) => {
      if (String(x).toLowerCase() !== 'terminal') return false;
      const n = nextCmdAfter(arr, i + 1);
      return (
        n === 'read' ||
        n === 'close' ||
        n === 'send' ||
        n === 'show' ||
        n === 'wait' ||
        n === 'switch' ||
        n === 'rename' ||
        n === 'split' ||
        n === 'focus'
      );
    });
  }

  // Resolver map — every TARGET_FLAG_RESOLVERS kind must appear here.
  const resolvers = {
    handle: ownershipCheck,
    dispatch: dispatchOwnershipCheck,
    worktree: worktreeOwnershipCheck,
    parent_worktree: parentWorktreeOwnershipCheck || worktreeOwnershipCheck,
    task: taskOwnershipCheck,
    run: runOwnershipCheck,
    id: idOwnershipCheck,
    page: pageOwnershipCheck,
    repo: repoOwnershipCheck,
  };

  // Ensure table completeness at runtime (dev/test safety).
  for (const kind of new Set(Object.values(TARGET_FLAG_RESOLVERS))) {
    if (!Object.prototype.hasOwnProperty.call(resolvers, kind)) {
      return denyOwnership({
        handle: null,
        status: 'unknown',
        ownedHandles: [],
        reason: 'ownership_check_not_configured',
        kind: 'handle',
      });
    }
  }

  const rank = (st) => (st === 'owned' ? 0 : st === 'not-owned' ? 2 : 1);

  /**
   * Run a checker over values; return deny result or null if all owned.
   */
  const runChecker = (kind, values, checker, buildCtx, reportField) => {
    if (!values || !values.length) return null;
    if (!checker) {
      return denyOwnership({
        handle: null,
        status: 'unknown',
        ownedHandles: [],
        reason: 'ownership_check_not_configured',
        kind,
        [reportField]: values[values.length - 1],
      });
    }
    let worst = null;
    let worstRank = 'owned';
    for (const raw of values) {
      const v = raw == null || raw === '' ? null : raw;
      let own;
      try {
        own = checker(buildCtx(v, values));
      } catch (e) {
        own = {
          status: 'unknown',
          reason: 'ownership_check_threw',
          detail: e && e.message ? e.message : String(e),
        };
      }
      const statusRaw =
        own && (own.status != null || own.verdict != null)
          ? String(own.status != null ? own.status : own.verdict)
          : 'unknown';
      const status =
        statusRaw === 'owned'
          ? 'owned'
          : statusRaw === 'not-owned'
            ? 'not-owned'
            : 'unknown';
      if (status === 'owned') continue;
      if (!worst || rank(status) >= rank(worstRank)) {
        worst = own;
        worstRank = status;
      }
    }
    if (!worst) return null;
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
    const ownedWorktrees = Array.isArray(worst?.owned_worktrees)
      ? worst.owned_worktrees
      : Array.isArray(worst?.ownedWorktrees)
        ? worst.ownedWorktrees
        : [];
    return denyOwnership({
      handle: kind === 'handle'
        ? (worst?.handle != null ? worst.handle : values[values.length - 1])
        : null,
      dispatchId: kind === 'dispatch'
        ? (worst?.dispatchId != null ? worst.dispatchId : values[values.length - 1])
        : null,
      worktree: kind === 'worktree' || kind === 'parent_worktree'
        ? (worst?.worktree != null ? worst.worktree : values[values.length - 1])
        : null,
      taskId: kind === 'task'
        ? (worst?.taskId != null ? worst.taskId : values[values.length - 1])
        : null,
      runId: kind === 'run'
        ? (worst?.runId != null ? worst.runId : values[values.length - 1])
        : null,
      genericId: kind === 'id' || kind === 'page' || kind === 'repo'
        ? values[values.length - 1]
        : null,
      status: worstRank,
      ownedHandles,
      ownedDispatches,
      ownedWorktrees,
      reason: worst?.reason,
      kind,
    });
  };

  // Evaluate each target kind present. Order: handle, dispatch, worktree,
  // parent_worktree, task, run, id, page, repo. Never run handle check solely
  // because a worktree selector is present (P1-2 false deny).
  if (targetsByKind.has('handle')) {
    const values = targetsByKind.get('handle');
    // check/inbox without --terminal already skipped (no handle entry)
    const denied = runChecker(
      'handle',
      values,
      ownershipCheck,
      (v, all) => ({
        args: Array.isArray(args) ? args : [],
        handle: v,
        handles: all.map((h) => (h == null || h === '' ? null : h)),
        tokens,
        matched_prefix: matchedPrefix ? [...matchedPrefix] : null,
        effective_handle: extractTerminalHandleFromArgv(args),
      }),
      'handle',
    );
    if (denied) return denied;
  }

  if (targetsByKind.has('dispatch')) {
    const values = targetsByKind.get('dispatch');
    const denied = runChecker(
      'dispatch',
      values,
      dispatchOwnershipCheck,
      (v, all) => ({
        args: Array.isArray(args) ? args : [],
        dispatchId: v,
        dispatchIds: all.map((d) => (d == null || d === '' ? null : d)),
        tokens,
        matched_prefix: matchedPrefix ? [...matchedPrefix] : null,
        effective_dispatch: extractDispatchIdFromArgv(args),
      }),
      'dispatchId',
    );
    if (denied) return denied;
  }

  if (targetsByKind.has('worktree')) {
    const values = targetsByKind.get('worktree');
    // Synthetic create tokens only owned on create/start paths (P2-2).
    const allowSynthetic = isWorktreeCreate || isWorkerStart;
    const denied = runChecker(
      'worktree',
      values,
      worktreeOwnershipCheck
        ? (ctx) =>
            worktreeOwnershipCheck({
              ...ctx,
              allowSyntheticCreate: allowSynthetic,
            })
        : null,
      (v, all) => ({
        args: Array.isArray(args) ? args : [],
        worktree: v,
        worktrees: all.map((w) => (w == null || w === '' ? null : w)),
        tokens,
        matched_prefix: matchedPrefix ? [...matchedPrefix] : null,
        effective_worktree: values[values.length - 1],
        allowSyntheticCreate: allowSynthetic,
      }),
      'worktree',
    );
    if (denied) return denied;
  }

  if (targetsByKind.has('parent_worktree')) {
    const values = targetsByKind.get('parent_worktree');
    const checker = parentWorktreeOwnershipCheck || worktreeOwnershipCheck;
    const denied = runChecker(
      'parent_worktree',
      values,
      checker,
      (v, all) => ({
        args: Array.isArray(args) ? args : [],
        worktree: v,
        worktrees: all.map((w) => (w == null || w === '' ? null : w)),
        tokens,
        matched_prefix: matchedPrefix ? [...matchedPrefix] : null,
        effective_worktree: values[values.length - 1],
        allowSyntheticCreate: false,
      }),
      'worktree',
    );
    if (denied) return denied;
  }

  if (targetsByKind.has('task')) {
    const values = targetsByKind.get('task');
    const denied = runChecker(
      'task',
      values,
      taskOwnershipCheck,
      (v, all) => ({
        args: Array.isArray(args) ? args : [],
        taskId: v,
        taskIds: all.map((t) => (t == null || t === '' ? null : t)),
        tokens,
        matched_prefix: matchedPrefix ? [...matchedPrefix] : null,
      }),
      'taskId',
    );
    if (denied) return denied;
  }

  if (targetsByKind.has('run')) {
    const values = targetsByKind.get('run');
    const denied = runChecker(
      'run',
      values,
      runOwnershipCheck,
      (v, all) => ({
        args: Array.isArray(args) ? args : [],
        runId: v,
        runIds: all.map((t) => (t == null || t === '' ? null : t)),
        tokens,
        matched_prefix: matchedPrefix ? [...matchedPrefix] : null,
      }),
      'runId',
    );
    if (denied) return denied;
  }

  if (targetsByKind.has('id')) {
    let values = targetsByKind.get('id');
    // msg_* on reply/ask: gate allows only because spawn ALWAYS overwrites --from
    // (applySpawnPathSenderInject). delivery_* and other ids still resolve.
    const isReplyOrAsk = isCmd('orchestration', 'reply') || isCmd('orchestration', 'ask');
    if (isReplyOrAsk) {
      values = values.filter((v) => {
        const s = v == null ? '' : String(v);
        return !s.startsWith('msg_');
      });
    }
    if (!values.length) {
      // only msg_* ids on reply/ask — pin-scoped allow
    } else {
    const denied = runChecker(
      'id',
      values,
      idOwnershipCheck,
      (v, all) => ({
        args: Array.isArray(args) ? args : [],
        id: v,
        ids: all.map((t) => (t == null || t === '' ? null : t)),
        tokens,
        matched_prefix: matchedPrefix ? [...matchedPrefix] : null,
      }),
      'genericId',
    );
    if (denied) return denied;
    } // end non-msg id values
  }

  if (targetsByKind.has('page')) {
    const values = targetsByKind.get('page');
    const denied = runChecker(
      'page',
      values,
      pageOwnershipCheck,
      (v, all) => ({
        args: Array.isArray(args) ? args : [],
        pageId: v,
        pageIds: all.map((t) => (t == null || t === '' ? null : t)),
        tokens,
        matched_prefix: matchedPrefix ? [...matchedPrefix] : null,
      }),
      'genericId',
    );
    if (denied) return denied;
  }

  if (targetsByKind.has('repo')) {
    const values = targetsByKind.get('repo');
    const denied = runChecker(
      'repo',
      values,
      repoOwnershipCheck,
      (v, all) => ({
        args: Array.isArray(args) ? args : [],
        repo: v,
        repos: all.map((t) => (t == null || t === '' ? null : t)),
        tokens,
        matched_prefix: matchedPrefix ? [...matchedPrefix] : null,
      }),
      'genericId',
    );
    if (denied) return denied;
  }

  // Fail-closed: target kind present but checker missing already handled in runChecker.

  if (formAllowed) {
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

  // Not on exact-form allowlist (and not unlocked admin).
  const formReason = formMatch.reason || 'unknown_command';
  const formDetail = formMatch.detail || '';
  const warning = {
    code: 'cli_policy_would_deny',
    rejected_subcommand: rejectedSubcommand,
    rejected_argv: Array.isArray(args) ? [...args] : args,
    allowed_surface: surface,
    admin_surface: adminSurface,
    admin_required: adminRequired,
    hardening: hardening,
    form_reason: formReason,
    message: adminRequired
      ? `argv "${rejectedSubcommand}" requires admin unlock (ORCA_BRIDGE_CLI_ADMIN=1); hardening=${hardening ? 'on' : 'off'}`
      : `argv "${rejectedSubcommand}" is outside the exact-form cli allowlist (${formReason}); hardening=${hardening ? 'on' : 'off'}`,
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
    form_reason: formReason,
    detail: adminRequired
      ? `Blocked by cli allowlist: "${rejectedSubcommand}" requires admin unlock ` +
        `(set ORCA_BRIDGE_CLI_ADMIN=1) while CLI hardening is on.`
      : `Blocked by exact-form cli allowlist: "${rejectedSubcommand}"` +
        (formDetail ? ` (${formDetail})` : '') +
        `. Set ORCA_BRIDGE_CLI_HARDENING=0 to restore warn-only migration mode.`,
    next: {
      action: 'guide',
      detail: 'See raw_cli_ok / policy.allowed_surface for the permitted exact command forms.',
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
 * Always deny an ownership miss (NAS-248/252 invariant).
 * Hardening does not soften this path; onWarning still fires for observability.
 *
 * Deny path is UNIFORM (P1-3): one code, one message. Do not emit
 * ownership_status, distinguishing reasons, or owned_handles/owned_worktrees
 * to the caller. Keep distinctions only in the local onWarning audit payload.
 *
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
    worktree = null,
    taskId = null,
    runId = null,
    genericId = null,
    status,
    ownedHandles = [],
    ownedDispatches = [],
    ownedWorktrees = [],
    reason,
    kind = 'handle',
    detailOverride = null,
  } = p;

  const statusLabel = status === 'not-owned' ? 'not-owned' : 'unknown';

  // Uniform caller-facing detail — no existence oracle, no owned_* lists.
  const detail =
    detailOverride ||
    `Blocked: target is not owned by this client. ` +
      `Use a handle, dispatch, worktree, task, or run this client owns.`;

  // Local audit payload MAY keep distinctions for operators.
  const warning = {
    code: 'handle_not_owned',
    rejected_subcommand: rejectedSubcommand,
    rejected_argv: Array.isArray(args) ? [...args] : args,
    handle: handle == null || handle === '' ? null : String(handle),
    dispatch_id:
      dispatchId == null || dispatchId === '' ? null : String(dispatchId),
    worktree: worktree == null || worktree === '' ? null : String(worktree),
    task_id: taskId == null || taskId === '' ? null : String(taskId),
    run_id: runId == null || runId === '' ? null : String(runId),
    id: genericId == null || genericId === '' ? null : String(genericId),
    // audit-only fields (NOT copied into rejection):
    _audit_owned_handles: [...ownedHandles],
    _audit_owned_dispatches: [...ownedDispatches],
    _audit_owned_worktrees: [...ownedWorktrees],
    _audit_ownership_status: statusLabel,
    _audit_ownership_kind: kind,
    _audit_reason: reason || undefined,
    allowed_surface: surface,
    admin_surface: adminSurface,
    admin_required: adminRequired,
    hardening,
    message: `argv "${rejectedSubcommand}" ownership miss; hardening=${hardening ? 'on' : 'off'}`,
  };

  if (onWarning) {
    try {
      onWarning(warning);
    } catch {
      // warning hooks must not break the deny path
    }
  }

  // Caller-facing rejection: uniform. No ownership_status, no reason oracle,
  // no owned_handles / owned_worktrees / owned_dispatches.
  const rejection = {
    ok: false,
    error: 'cli_policy_denied',
    code: 'handle_not_owned',
    rejected_subcommand: rejectedSubcommand,
    rejected_argv: Array.isArray(args) ? [...args] : args,
    allowed_surface: surface,
    admin_surface: adminSurface,
    admin_required: adminRequired,
    detail,
    next: {
      action: 'guide',
      detail:
        'Pass a target this client owns (worker handle from dispatch, pinned sender, or a worktree/task/run registered to this client).',
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

