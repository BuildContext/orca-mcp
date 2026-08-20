/**
 * Canonical coordinator discipline.
 *
 * Single source for:
 *   - action=guide wire payload (structured)
 *   - MCP tool / action schema description strings
 *   - generated regions in COORDINATOR.md and README.md
 *
 * Keep free of process I/O so docs scripts and tests can import without TOKEN.
 */

/** Prefer this await window; client wrappers are often ~60s. Hard max is separate. */
export const PREFERRED_WAIT_MS = 45_000;
export const WAIT_MS_HARD_MAX = 240_000;

/**
 * Stop-condition ceilings (NAS-240). Derived from ~45s preferred windows:
 *   - escalate after 8 empty windows (~6 min) or liveness=stalled
 *   - hard ceiling ~15 min without progress before owner report is mandatory
 */
export const AWAIT_EMPTY_ESCALATE_AFTER = 8;
export const AWAIT_STALL_MS = 8 * 60_000;
export const AWAIT_HARD_CEILING_MS = 15 * 60_000;

/** Static doctrine fields (version injected at guide build time). */
export const DOCTRINE = {
  tool: 'Single MCP tool `orca` with action field (Hyperagent only exposes one tool).',
  /** flow templates; `{minVersion}` is substituted from bridge constants. */
  flow: [
    '1. orca{action:"dispatch",spec,agent,worktree,name?,repo?,runId?} — save run_id,task_id,dispatch_id,terminal_handle ' +
      '(runtime/version checks run lazily inside dispatch/await/release; health is optional diagnostics)',
    '2. loop orca{action:"await",runId,waitMs:45000,ack?} until summary.status=worker_done — honor liveness on empty windows',
    '3. orca{action:"release",dispatchId,terminalHandle} — inject path: terminal close (dispatch_not_found on worker-release is OK)',
    '4. optional read-only verify; any write = new dispatch',
  ],
  await_statuses: {
    empty_or_timeout:
      'NORMAL early. Re-call await with same runId while liveness is active|idle. ' +
      'Do not restart worker. Honor await.liveness + emptyWindowsConsecutive — not "empty forever".',
    empty_stalled:
      `STOP-CONDITION: liveness=stalled (typically >= ${AWAIT_EMPTY_ESCALATE_AFTER} empty windows ` +
      `or ~${AWAIT_STALL_MS / 60000}min without activity). ` +
      'Do check --peek (or action=check peek), optional worker ping via ' +
      'cli `terminal send --terminal <owned> --text … --enter` (shell submits on that first Enter; ' +
      'a TUI compose box needs a following empty `--enter`; there is no `--submit`; ' +
      '`--interrupt` if the TUI is stuck), ' +
      'then release with diagnostics and report to owner. Never loop await past hard ceiling ' +
      `~${AWAIT_HARD_CEILING_MS / 60000}min without progress.`,
    question:
      'Reply: orca{action:"cli",args:["orchestration","reply","--id","<question.id>","--body","<answer>","--json"]} ' +
      'then await with ack=deliveryId.',
    escalation:
      'Reply via cli orchestration reply --id <escalation.id> --body … --json (bridge dual-routes ' +
      'non-question replies onto dispatch:<id> so the waiting worker unblocks); then await+ack. ' +
      'Prefer orchestration ask for true back-and-forth instead of send --type escalation + check.',
    worker_done: 'release with dispatchId + terminalHandle; report outcome+body+filesModified.',
    fake_worker_done:
      'Template or placeholder worker_done — do NOT release as success. Diagnose the tab (often a shell, not an agent TUI).',
    rejected_worker_done:
      'Orca rejected the worker_done (_orcaLifecycleRejection). Not success. ' +
      'Do NOT release as succeeded. Read summary.rejected_worker_done + original body; the dispatch is not settled.',
  },
  health:
    'Optional diagnostics (compact default: version, versionOk, statusProbe.ok, defaultRepo, next). ' +
    'Pass verbose:true for full statusProbe/actionAnnotations. ' +
    'Not required before each wave — dispatch/await/release self-diagnose runtime/version failures.',
  next_action:
    'Field next.action is a HINT. Prefer summary.status when they disagree. ' +
    'On empty windows also honor liveness (stalled → diagnose, not blind re-await).',
  waves: [
    'One wave = one run_id (omit runId on first dispatch; pass same runId on later workers).',
    'Parallel: N dispatch then one await loop — bridge serializes dispatch/await per OAuth client (0.2.11+); safe to issue N in parallel.',
    'Each OAuth client gets a durable sender pin-by-handle (0.2.12+) — shell may rewrite tab title; bridge must not recreate mid-wave.',
    'Two coordinators on one bridge no longer fence each other when they use separate OAuth tokens.',
    'Keep-list (worktree path/id + dispatch_id + terminal_handle) is yours; do not copy foreign inventory into it.',
    'await may report foreign_messages — never release those; next.action never targets foreign dispatch_id.',
  ],
  brief_template: [
    'Goal + Definition of Done + explicit non-goals (no merge/main/eas without owner order).',
    'Repo/worktree context; linked issue id if any.',
    'worker_done contract is auto-appended by the bridge — you may still restate it.',
    'Cleanup tasks: only touch keep-list objects; never foreign terminals in default-worktree.',
    'UI tasks: devices/dev.mjs acquire → exec → release in finally; stable --owner; no positional UDID.',
  ],
  anti_patterns: [
    'worktree create --agent --prompt (blocked on action=cli; no completion signal)',
    'terminal wait --for tui-idle/exit as completion (idle ≠ done; omp rarely exits)',
    'single await waitMs > 45000 when client wrapper ~60s (prefer 45000 and re-call; hard max 240000)',
    'success from terminal preview text instead of worker_done+outcome',
    'treat template worker_done (subject <short status>, filesModified path/a path/b) as success',
    'treat runtime-rejected worker_done (_orcaLifecycleRejection) as success',
    'release on timeout / empty window while liveness is still active|idle',
    'health before every wave as a ritual (use on demand; runtime errors self-diagnose)',
    'infinite await on empty when liveness=stalled (diagnose / ping / release+report)',
  ],
  raw_cli_ok: [
    'orchestration reply (questions)',
    'skills get, status, worktree show/list',
    'terminal list/read/close/send for YOUR keep-list handles only ' +
      '(shell: one `--text … --enter`; TUI compose box: that plus a following empty `--enter`; `--interrupt` to break a stuck TUI; no `--submit`)',
    'worker-show / worker-read on escalation',
  ],
  raw_cli_forbidden: [
    'worktree create --agent --prompt as main work path (enforced reject)',
    'prefer action=await over raw orchestration check except debug / stalled diagnose',
  ],
  devices: {
    slot: 'One UI slot; only one worker should hold devices at a time.',
    script: 'devices/dev.mjs acquire → exec → release; DEVICES_OWNER / --owner stable',
    platforms: 'iOS Simulator = Mac only; Android usually VM',
  },
  release_inject:
    'After inject-path worker_done, dispatch is already settled; worker-release often returns ' +
    'dispatch_not_found. release closes the worker with terminal close --terminal <handle> --json ' +
    '(no --tab). tab_not_found / workspace_session_unavailable means the tab is already gone.',
};

/**
 * Wire payload for action=guide. Keys and shapes are part of the coordinator contract —
 * do not rename or drop fields without a coordinated client migration.
 *
 * @param {{ version: string, minVersion: string }} versions
 */
export function buildCoordinatorGuide({ version, minVersion }) {
  const v = String(version);
  const min = String(minVersion);
  return {
    bridge: { version: v, minVersion: min },
    tool: DOCTRINE.tool,
    flow: DOCTRINE.flow.map((step) => step.replaceAll('{minVersion}', min)),
    await_statuses: { ...DOCTRINE.await_statuses },
    health: DOCTRINE.health,
    next_action: DOCTRINE.next_action,
    waves: [...DOCTRINE.waves],
    brief_template: [...DOCTRINE.brief_template],
    anti_patterns: [...DOCTRINE.anti_patterns],
    raw_cli_ok: [...DOCTRINE.raw_cli_ok],
    raw_cli_forbidden: [...DOCTRINE.raw_cli_forbidden],
    devices: { ...DOCTRINE.devices },
    release_inject: DOCTRINE.release_inject,
    liveness: {
      empty_escalate_after: AWAIT_EMPTY_ESCALATE_AFTER,
      stall_ms: AWAIT_STALL_MS,
      hard_ceiling_ms: AWAIT_HARD_CEILING_MS,
      preferred_wait_ms: PREFERRED_WAIT_MS,
      values: ['active', 'idle', 'stalled', 'unknown'],
    },
  };
}

/**
 * Dense MCP tool `description` (Hyperagent surfaces this as the sole tool blurb).
 * @param {{ minVersion: string }} p
 */
export function buildToolDescription({ minVersion }) {
  const min = String(minVersion);
  return (
    'Orca bridge control plane (single tool for Hyperagent). ' +
    'Actions: health | dispatch | await | release | guide | check | cli. ' +
    'ANNOTATIONS: tool-level hints are conservative (readOnlyHint=false, destructiveHint=true, ' +
    'idempotentHint=false, openWorldHint=true) because this ONE tool multiplexes all actions — ' +
    'MCP annotations are per-tool, not per-action. Per-action semantics: ' +
    'health/guide = read-only idempotent; await/check = mailbox (ack consumes); ' +
    'dispatch/release/cli = potentially destructive open-world. Full table in health(verbose:true).actionAnnotations ' +
    'and resources orca-bridge://audit/*. ' +
    'SUPERVISED WORKERS: ' +
    '(1) dispatch {spec, agent?, worktree?, name?, repo?, runId?} — saves run_id/task_id/dispatch_id/terminal_handle; ' +
    'bridge auto-appends worker_done contract; inject liveness recovers idle Grok if needed; ' +
    'runtime/version self-checked lazily (errors name code+recovery; min bridge ' +
    min +
    '). ' +
    '(2) loop await {runId, waitMs:45000, ack?} until summary.status=worker_done. ' +
    'empty/timeout carries liveness active|idle|stalled|unknown — re-call while active/idle; ' +
    `stalled (≈${AWAIT_EMPTY_ESCALATE_AFTER}+ empty windows / ~${AWAIT_STALL_MS / 60000}min quiet) → diagnose ` +
    '(check --peek, ping, release+report), not infinite re-await. ' +
    'question → cli args=["orchestration","reply","--id",id,"--body",answer,"--json"] then await+ack. ' +
    'escalation → cli orchestration reply (dual-routes onto dispatch:<id>), then await+ack; ' +
    'prefer orchestration ask for true back-and-forth. ' +
    '(3) release {dispatchId, terminalHandle} — inject path closes tab; worker-release dispatch_not_found is OK. ' +
    'Prefer summary.status over next.action when they disagree; on empty also honor liveness. ' +
    'health — optional compact diagnostics (verbose:true for full dump); not required before each wave. ' +
    'guide — waves/brief/devices discipline (call once if unsure). ' +
    'FORBIDDEN: worktree create --agent --prompt (rejected on cli). Prefer waitMs 45000 (max 240000).'
  );
}

/** `inputSchema.properties.action.description` */
export function buildActionPropertyDescription() {
  return (
    'health | dispatch | await | release | guide | check | cli. ' +
    'Default: health if no args; cli if args[] present. ' +
    'health: compact diagnostics (verbose:true for full statusProbe); optional, not a pre-wave ritual. ' +
    'dispatch: start supervised worker (not handoff); runtime self-checked. ' +
    'await: one wait window; empty carries liveness — re-call when active/idle, diagnose when stalled. ' +
    'release: after worker_done only (not on active/idle timeout). ' +
    'guide: coordinator discipline (waves, brief template, devices, stop-conditions). ' +
    'cli: raw orca argv; handoff create+prompt rejected.'
  );
}

/** `inputSchema.properties.args.description` (cli surface). */
export function buildArgsPropertyDescription() {
  return (
    'For action=cli: orca argv without binary name. ' +
    'OK: orchestration reply, skills get, status, worktree show/list, terminal read/close (own handles). ' +
    'REJECTED: worktree create --agent --prompt (use action=dispatch).'
  );
}

/** `inputSchema.properties.waitMs.description` */
export function buildWaitMsPropertyDescription() {
  return (
    'Await/check window ms. Prefer ' +
    PREFERRED_WAIT_MS +
    ' (client wrappers often ~60s). Hard max ' +
    WAIT_MS_HARD_MAX +
    '. Re-call on timeout while liveness is active|idle; diagnose when stalled.'
  );
}

// --- Markdown derivation -------------------------------------------------------

export const GENERATED_BEGIN = '<!-- BEGIN GENERATED: coordinator-discipline -->';
export const GENERATED_END = '<!-- END GENERATED: coordinator-discipline -->';

/**
 * Long-form COORDINATOR.md body (inside generated markers). Derived from DOCTRINE.
 */
export function renderCoordinatorMarkdown() {
  const guide = buildCoordinatorGuide({ version: 'VERSION', minVersion: 'MIN' });
  const flowLine = compactFlowLine();
  const statusRows = [
    [
      'empty / timeout (active|idle)',
      'Call `await` again — **normal** early; watch `liveness` + `emptyWindowsConsecutive`',
    ],
    [
      'empty + liveness=stalled',
      '`check --peek` → optional ping → `release` + report owner (**stop-condition**)',
    ],
    [
      'question',
      '`cli` → `orchestration reply --id … --body … --json`, then `await` + `ack`',
    ],
    [
      'escalation',
      '`cli` → `orchestration reply` (bridge dual-routes onto `dispatch:<id>`), then `await` + `ack`; prefer `orchestration ask` for back-and-forth',
    ],
    [
      'worker_done',
      '`release` with `dispatchId` + worker `terminalHandle`; outcome = body + filesModified',
    ],
    [
      'fake_worker_done',
      'Template/placeholder `worker_done` rejected — do **not** release as success; diagnose the tab',
    ],
    [
      'rejected_worker_done',
      'Runtime rejected `worker_done` (`_orcaLifecycleRejection`) — do **not** treat as success; original body stays on `summary.worker_done.body`',
    ],
  ];

  const antiRows = guide.anti_patterns.map(splitAntiPattern);

  const lines = [
    '# Coordinator discipline (served by `orca{action:"guide"}`)',
    '',
    'Long-form rules that **should not** live in the MCP client system prompt.',
    'Bridge ≥ 0.2.9 returns the same structure via `action=guide`.',
    '',
    '> **Generated** from `lib/coordinator-doctrine.mjs`. Edit the doctrine module, then run `npm run docs:build`.',
    '',
    '## Supervised flow',
    '',
    '```text',
    flowLine,
    '```',
    '',
    guide.health,
    '',
    '| await `summary.status` | Action |',
    '|------------------------|--------|',
    ...statusRows.map(([k, v]) => `| ${k} | ${v} |`),
    '',
    guide.next_action.replace(/^Field /, '').replace('is a HINT', 'is a **hint**'),
    '',
    '### Liveness stop-condition',
    '',
    `- Escalate when \`liveness=stalled\` (default: ≥ **${AWAIT_EMPTY_ESCALATE_AFTER}** empty ~${PREFERRED_WAIT_MS / 1000}s windows, or ~**${AWAIT_STALL_MS / 60000} min** without activity).`,
    `- Hard ceiling ~**${AWAIT_HARD_CEILING_MS / 60000} min** without progress → release with diagnostics and report to owner.`,
    '- Protocol: `check`/`cli` peek → optional worker ping (`terminal send --enter`; `--interrupt` if stuck) → release + owner report. Do **not** infinite-loop `await` on empty.',
    '',
    '## Waves',
    '',
    ...guide.waves.map((w) => `- ${w}`),
    '',
    '## Brief template (`spec`)',
    '',
    'The bridge **appends** a `worker_done` contract itself. Still spell out in the brief:',
    '',
    ...guide.brief_template.map((b, i) => `${i + 1}. ${b}`),
    '',
    '## Anti-patterns (“wait until ready”)',
    '',
    "| Don't | Why |",
    '| --- | --- |',
    ...antiRows.map(([d, w]) => `| \`${d.replace(/`/g, '')}\` | ${w} |`),
    '',
    '`terminal read --limit N` is for liveness/debug, not a substitute for `await`.',
    '',
    '## Raw `cli` — when it is OK',
    '',
    ...guide.raw_cli_ok.map((x) => `- ${x}`),
    '',
    'Not allowed:',
    '',
    ...guide.raw_cli_forbidden.map((x) => `- ${x}`),
    '',
    '## Devices',
    '',
    `- ${guide.devices.slot}`,
    `- ${guide.devices.platforms}`,
    `- ${guide.devices.script}`,
    '',
    '## Release (inject path)',
    '',
    guide.release_inject,
    '',
    'Pass the **worker** `terminal_handle` from the `dispatch` response, never the',
    'coordinator sender from `health`.',
    '',
    '## Post-done read-only',
    '',
    'After `worker_done` the coordinator may inspect: git status/diff/log, grep, files.',
    'Patches / commits / package installs / fixes → **new dispatch** (flow step 4).',
    'Close any raw terminals you opened immediately after reading.',
    '',
  ];
  return lines.join('\n');
}

/**
 * README "Supervised orchestration" section body (inside generated markers).
 */
export function renderReadmeOrchestrationMarkdown() {
  const flowLine = compactFlowLine();
  const lines = [
    '## Supervised orchestration (for coordinators)',
    '',
    '> **Generated** from `lib/coordinator-doctrine.mjs`. Edit the doctrine module, then run `npm run docs:build`.',
    '',
    'Raw `worktree create --agent --prompt` is **rejected** (`forbidden_handoff`). Use the action API:',
    '',
    '```text',
    flowLine,
    '```',
    '',
    'Runtime/version gates run **lazily** inside `dispatch` / `await` / `release` (self-diagnosing errors). `health` is optional compact diagnostics (`verbose:true` for the full dump).',
    '',
    '| `await` summary.status | Meaning |',
    '| --- | --- |',
    '| empty / timeout (active\\|idle) | Re-call `await` — normal early; watch `liveness` |',
    '| empty + liveness=stalled | Stop-condition: peek → ping → release + report |',
    '| question | Reply via `cli` → `orchestration reply`, then await + ack |',
    '| escalation | Reply via `cli` → `orchestration reply` (dual-routes onto `dispatch:<id>`), then await + ack; prefer `ask` for back-and-forth |',
    '| worker_done | `release` with `dispatchId` + worker `terminalHandle` |',
    '| fake_worker_done | Template `worker_done` rejected — diagnose, do not release as success |',
    '| rejected_worker_done | Runtime rejected `worker_done` — not success; original body remains recoverable |',
    '',
    'Full discipline: tool description, `action=guide`, and [`COORDINATOR.md`](./COORDINATOR.md).',
    '',
    'Example wave:',
    '',
    '```jsonc',
    '// 1. start work',
    '{ "action": "dispatch", "spec": "…", "repo": "path:/path/to/repo", "agent": "omp" }',
    '',
    '// 2. poll until worker_done (repeat; honor liveness on empty)',
    '{ "action": "await", "runId": "<from dispatch>", "waitMs": 45000 }',
    '',
    '// 3. cleanup',
    '{ "action": "release", "dispatchId": "<…>", "terminalHandle": "<worker handle from dispatch>" }',
    '```',
    '',
  ];
  return lines.join('\n');
}

/** Split an anti_patterns line into Don't / Why columns. */
function splitAntiPattern(line) {
  const cut = line.indexOf(' (');
  if (cut === -1) {
    // Prefer a short Don't cell; fall back to full text in Why.
    if (line.startsWith('success from ')) {
      return ['success from terminal preview text', 'only `worker_done` + outcome'];
    }
    if (line.startsWith('release on timeout')) {
      return ['release on timeout / empty while active|idle', 'only after `worker_done` (or stalled diagnose)'];
    }
    if (line.startsWith('health before every')) {
      return ['health before every wave as a ritual', 'on demand; runtime errors self-diagnose'];
    }
    if (line.startsWith('infinite await')) {
      return ['infinite await when liveness=stalled', 'diagnose / ping / release+report'];
    }
    if (line.startsWith('treat template worker_done')) {
      return ['treat template worker_done as success', 'status=fake_worker_done; do not release'];
    }
    if (line.startsWith('treat runtime-rejected')) {
      return ['treat runtime-rejected worker_done as success', 'status=rejected_worker_done; outcome is not succeeded'];
    }
    return [line, line];
  }
  return [line.slice(0, cut), line.slice(cut + 2).replace(/\)$/, '')];
}

/** Compact one-line flow for docs diagrams. */
function compactFlowLine() {
  return (
    'dispatch → await(≤45s)×N [honor liveness] → worker_done → release(dispatchId, terminalHandle) → read-only'
  );
}

/**
 * Splice generated body between markers. If markers are missing and wholeFileIfMissing,
 * replace the entire file; otherwise throw.
 */
export function applyGeneratedRegion(source, body, { wholeFileIfMissing = false } = {}) {
  const begin = GENERATED_BEGIN;
  const end = GENERATED_END;
  const block = `${begin}\n${body.replace(/\s+$/, '')}\n${end}`;
  const start = source.indexOf(begin);
  const stop = source.indexOf(end);
  if (start === -1 || stop === -1 || stop < start) {
    if (wholeFileIfMissing) return `${block}\n`;
    throw new Error('missing generated-region markers');
  }
  return source.slice(0, start) + block + source.slice(stop + end.length);
}
