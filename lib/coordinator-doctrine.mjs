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

/** Static doctrine fields (version injected at guide build time). */
export const DOCTRINE = {
  tool: 'Single MCP tool `orca` with action field (Hyperagent only exposes one tool).',
  /** flow templates; `{minVersion}` is substituted from bridge constants. */
  flow: [
    '1. orca{action:"health"} — require statusProbe.ok and bridge.version >= {minVersion}',
    '2. orca{action:"dispatch",spec,agent,worktree,name?,repo?,runId?} — save run_id,task_id,dispatch_id,terminal_handle',
    '3. loop orca{action:"await",runId,waitMs:45000,ack?} until summary.status=worker_done',
    '4. orca{action:"release",dispatchId,terminalHandle} — inject path: terminal close (dispatch_not_found on worker-release is OK)',
    '5. optional read-only verify; any write = new dispatch',
  ],
  await_statuses: {
    empty_or_timeout: 'NORMAL for long tasks. Re-call await with same runId. Do not restart worker.',
    question:
      'Reply: orca{action:"cli",args:["orchestration","reply","--id","<question.id>","--body","<answer>","--json"]} ' +
      'then await with ack=deliveryId.',
    escalation: 'Read body; answer / new task / fail; always ack deliveryId.',
    worker_done: 'release with dispatchId + terminalHandle; report outcome+body+filesModified.',
  },
  next_action: 'Field next.action is a HINT. Prefer summary.status when they disagree.',
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
    'release on timeout / empty window',
  ],
  raw_cli_ok: [
    'orchestration reply (questions)',
    'skills get, status, worktree show/list',
    'terminal list/read/close for YOUR keep-list handles only',
    'worker-show / worker-read on escalation',
  ],
  raw_cli_forbidden: [
    'worktree create --agent --prompt as main work path (enforced reject)',
    'prefer action=await over raw orchestration check except debug',
  ],
  devices: {
    slot: 'One UI slot; only one worker should hold devices at a time.',
    script: 'devices/dev.mjs acquire → exec → release; DEVICES_OWNER / --owner stable',
    platforms: 'iOS Simulator = Mac only; Android usually VM',
  },
  release_inject:
    'After inject-path worker_done, dispatch is already settled; worker-release often returns ' +
    'dispatch_not_found. release still closes the tab when terminalHandle is passed — that is success.',
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
    next_action: DOCTRINE.next_action,
    waves: [...DOCTRINE.waves],
    brief_template: [...DOCTRINE.brief_template],
    anti_patterns: [...DOCTRINE.anti_patterns],
    raw_cli_ok: [...DOCTRINE.raw_cli_ok],
    raw_cli_forbidden: [...DOCTRINE.raw_cli_forbidden],
    devices: { ...DOCTRINE.devices },
    release_inject: DOCTRINE.release_inject,
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
    'dispatch/release/cli = potentially destructive open-world. Full table in health.actionAnnotations ' +
    'and resources orca-bridge://audit/*. ' +
    'SUPERVISED WORKERS ONLY: ' +
    '(1) health — require statusProbe.ok and bridge.version >= ' +
    min +
    ' (else STOP, ask owner to restart bridge). ' +
    '(2) dispatch {spec, agent?, worktree?, name?, repo?, runId?} — saves run_id/task_id/dispatch_id/terminal_handle; ' +
    'bridge auto-appends worker_done contract to spec; inject liveness recovers idle Grok if needed. ' +
    '(3) loop await {runId, waitMs:45000, ack?} until summary.status=worker_done. ' +
    'empty/timeout = NORMAL re-call (not failure). ' +
    'question → cli args=["orchestration","reply","--id",id,"--body",answer,"--json"] then await+ack. ' +
    'escalation → read body, decide, ack. ' +
    '(4) release {dispatchId, terminalHandle} — inject path closes tab; worker-release dispatch_not_found is OK. ' +
    'Prefer summary.status over next.action when they disagree. ' +
    'guide — waves/brief/devices discipline (call once if unsure). ' +
    'FORBIDDEN: worktree create --agent --prompt (rejected on cli). Prefer waitMs 45000 (max 240000).'
  );
}

/** `inputSchema.properties.action.description` */
export function buildActionPropertyDescription() {
  return (
    'health | dispatch | await | release | guide | check | cli. ' +
    'Default: health if no args; cli if args[] present. ' +
    'health: version gate + statusProbe. ' +
    'dispatch: start supervised worker (not handoff). ' +
    'await: one wait window; re-call on empty/timeout. ' +
    'release: after worker_done only (not on timeout). ' +
    'guide: coordinator discipline (waves, brief template, devices). ' +
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
    '. Re-call on timeout.'
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
    ['empty / timeout', 'Call `await` again — **normal**, not a failure'],
    [
      'question',
      '`cli` → `orchestration reply --id … --body … --json`, then `await` + `ack`',
    ],
    ['escalation', 'Read body; answer / new task / fail; always ack'],
    [
      'worker_done',
      '`release` with `dispatchId` + worker `terminalHandle`; outcome = body + filesModified',
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
    '| await `summary.status` | Action |',
    '|------------------------|--------|',
    ...statusRows.map(([k, v]) => `| ${k} | ${v} |`),
    '',
    guide.next_action.replace(/^Field /, '').replace('is a HINT', 'is a **hint**'),
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
    'Patches / commits / package installs / fixes → **new dispatch** (flow step 5).',
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
    '| `await` summary.status | Meaning |',
    '| --- | --- |',
    '| empty / timeout | Re-call `await` — normal |',
    '| question | Reply via `cli` → `orchestration reply`, then await + ack |',
    '| escalation | Read body; answer / re-task / fail; always ack |',
    '| worker_done | `release` with `dispatchId` + worker `terminalHandle` |',
    '',
    'Full discipline: tool description, `action=guide`, and [`COORDINATOR.md`](./COORDINATOR.md).',
    '',
    'Example wave:',
    '',
    '```jsonc',
    '// 1. start work',
    '{ "action": "dispatch", "spec": "…", "repo": "path:/path/to/repo", "agent": "omp" }',
    '',
    '// 2. poll until worker_done (repeat)',
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
      return ['release on timeout / empty window', 'only after `worker_done`'];
    }
    return [line, line];
  }
  return [line.slice(0, cut), line.slice(cut + 2).replace(/\)$/, '')];
}

/** Compact one-line flow for docs diagrams. */
function compactFlowLine() {
  return (
    'health → dispatch → await(≤45s)×N → worker_done → release(dispatchId, terminalHandle) → read-only'
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
