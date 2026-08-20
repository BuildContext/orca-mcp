/**
 * Pure security-critical helpers extracted from server.mjs for unit testing.
 * No process I/O at import time; fs helpers take explicit paths/deps.
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';

/** orchestration subcommands that accept --from on current Orca CLI. */
export const ORCH_FROM_CMDS = new Set([
  'run-create',
  'run-use',
  'task-create',
  'task-update',
  'dispatch',
  'dispatch-show',
  'reply',
  'send',
  'worker-start',
  'ask',
  'gate-create',
  'gate-resolve',
]);

export const CHECK_WAIT_DEFAULT_MS = 45_000;
export const CHECK_WAIT_MAX_MS = 45_000;
/**
 * Coordinator await/check wake filter (comma string for --types).
 * Omits high-volume heartbeat. `status` is intentionally NOT included:
 * dual-routed escalation replies go to the worker dispatch mailbox, not the
 * Run consumer filter (see buildEscalationReplyFollowupSendArgv / NAS-239).
 */
export const DEFAULT_WAIT_TYPES = 'worker_done,escalation,question';

/** Orca message id prefix (mailbox rows). Not valid for check --ack. */
export const MESSAGE_ID_PREFIX = 'msg_';
/** Orca delivery id prefix (ack tokens from check/await). */
export const DELIVERY_ID_PREFIX = 'delivery_';

/**
 * Reject handoff path via raw CLI: worktree create --agent … --prompt …
 * (no worker_done signal). Supervised action=dispatch is the only start path.
 * Behavior must match server.mjs gate used by action=cli.
 *
 * Matching is case-insensitive on the subcommand path and long flags, and
 * recognizes short aliases `-a` / `-p`. Joined `--flag=value` forms count.
 * Tokens after `--` are still scanned: a real CLI may or may not treat `--`
 * as end-of-options, so the gate fails closed on flag-shaped tokens anywhere.
 */
export function isForbiddenHandoffArgv(args) {
  if (!Array.isArray(args) || args.length < 2) return false;
  const a = args.map((x) => String(x));
  if (a[0].toLowerCase() !== 'worktree' || a[1].toLowerCase() !== 'create') return false;

  let hasAgent = false;
  let hasPrompt = false;
  for (let i = 2; i < a.length; i++) {
    const raw = a[i];
    const tok = raw.toLowerCase();
    // Long flags (separated or --flag=value), any letter case.
    if (tok === '--agent' || tok.startsWith('--agent=')) hasAgent = true;
    if (tok === '--prompt' || tok.startsWith('--prompt=')) hasPrompt = true;
    // Short aliases used by Orca CLI / common getopt style.
    if (tok === '-a' || tok.startsWith('-a=')) hasAgent = true;
    if (tok === '-p' || tok.startsWith('-p=')) hasPrompt = true;
  }
  return hasAgent && hasPrompt;
}

export function argvHasFlag(argv, flag) {
  for (const x of argv) {
    if (x === flag) return true;
    if (String(x).startsWith(`${flag}=`)) return true;
  }
  return false;
}

export function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * PKCE verification (S256 / plain). Empty challenge is tolerated (legacy clients).
 */
export function pkceOk(verifier, challenge, method) {
  if (!challenge) return true; // client without PKCE — tolerate
  if (method === 'plain') return verifier === challenge;
  return b64url(createHash('sha256').update(String(verifier)).digest()) === challenge;
}

/** S256 code_challenge from a verifier (client-side derivation helper for tests/docs). */
export function pkceS256Challenge(verifier) {
  return b64url(createHash('sha256').update(String(verifier)).digest());
}

/**
 * Constant-time master-token compare via SHA-256 digests + timingSafeEqual.
 * @param {string} candidate
 * @param {string} token master ORCA_BRIDGE_TOKEN
 */
export function tokenMatches(candidate, token) {
  if (typeof candidate !== 'string' || !candidate) return false;
  if (typeof token !== 'string' || !token) return false;
  const a = createHash('sha256').update(candidate).digest();
  const b = createHash('sha256').update(token).digest();
  return timingSafeEqual(a, b);
}

export function extractBearer(req) {
  const header = req?.headers?.['authorization'];
  const raw = Array.isArray(header) ? header[0] : header;
  if (typeof raw !== 'string') return '';
  // RFC 7235: scheme case-insensitive.
  const m = raw.match(/^\s*Bearer\s+(.+?)\s*$/i);
  return m ? m[1] : '';
}

/**
 * Inject sender identity into orchestration argv (sync form of withSender).
 * - mutations in ORCH_FROM_CMDS: --from <handle>
 * - check / inbox: --terminal <handle> (mailbox scope)
 */
/**
 * Strip every occurrence of a long-flag (space or = form) from argv.
 * @param {string[]} argv
 * @param {string} flag long name without dashes, e.g. 'from'
 */
export function stripFlagFromArgv(argv, flag) {
  if (!Array.isArray(argv)) return argv;
  const name = String(flag || '').toLowerCase();
  const out = [];
  for (let i = 0; i < argv.length; i++) {
    const t = String(argv[i]);
    const low = t.toLowerCase();
    if (low === `--${name}`) {
      // skip flag and its value if present and not another flag
      if (i + 1 < argv.length && !String(argv[i + 1]).startsWith('-')) i += 1;
      continue;
    }
    if (low.startsWith(`--${name}=`)) continue;
    out.push(argv[i]);
  }
  return out;
}

export function injectSenderArgv(argv, senderHandle, orchFromCmds = ORCH_FROM_CMDS) {
  if (!Array.isArray(argv) || argv.length < 2) return argv;
  if (argv[0] !== 'orchestration') return argv;
  const sub = argv[1];
  const needsFrom = orchFromCmds.has(sub);
  // NAS-252 P0-3: scope inbox to the caller's mailbox the same way check is scoped.
  const needsTerminal = sub === 'check' || sub === 'inbox';
  if (!needsFrom && !needsTerminal) return argv;

  let out = [...argv];
  // Always bridge-control --from: strip any caller-supplied value, then pin.
  if (needsFrom) {
    out = stripFlagFromArgv(out, 'from');
    out.push('--from', senderHandle);
  }
  // Mailbox scope: overwrite caller --terminal too so pin cannot be spoofed.
  if (needsTerminal) {
    out = stripFlagFromArgv(out, 'terminal');
    out.push('--terminal', senderHandle);
  }
  return out;
}

/**
 * Mirror of server.mjs withSender gating — which orchestration subs need a pin.
 * Tests MUST cover this (spawn path), not only injectSenderArgv.
 * @param {string} sub
 */
export function orchestrationNeedsSenderPin(sub, orchFromCmds = ORCH_FROM_CMDS) {
  const s = String(sub || '');
  return {
    needsFrom: orchFromCmds.has(s),
    needsTerminal: s === 'check' || s === 'inbox',
  };
}

/**
 * Production spawn-path sender inject (sync). Same decisions as server withSender
 * after resolveSenderTerminal — tests drive THIS, not only injectSenderArgv.
 */
export function applySpawnPathSenderInject(argv, senderHandle, orchFromCmds = ORCH_FROM_CMDS) {
  if (!Array.isArray(argv) || argv.length < 2) return argv;
  if (String(argv[0]) !== 'orchestration') return argv;
  const { needsFrom, needsTerminal } = orchestrationNeedsSenderPin(argv[1], orchFromCmds);
  if (!needsFrom && !needsTerminal) return argv;
  return injectSenderArgv(argv, senderHandle, orchFromCmds);
}

/**
 * worktree create argv for supervised dispatch (new-top-level | new-child).
 * Does NOT include --prompt (handoff forbidden path).
 */
export function buildDispatchWorktreeArgv({
  name,
  agent,
  repo,
  worktree = 'new-top-level',
  setup = 'run',
  baseBranch = '',
} = {}) {
  const repoArg = repo.includes(':') ? repo : (repo.startsWith('/') ? `path:${repo}` : repo);
  const wtArgv = [
    'worktree', 'create',
    '--name', String(name),
    '--agent', String(agent),
    '--repo', repoArg,
    '--json',
  ];
  if (worktree === 'new-top-level') wtArgv.push('--no-parent');
  if (setup) wtArgv.push('--setup', String(setup));
  if (baseBranch) wtArgv.push('--base-branch', String(baseBranch));
  return wtArgv;
}

/** terminal create argv for worktree=current dispatch path. */
export function buildDispatchCurrentTerminalArgv({ repo, name, agent } = {}) {
  let worktreeSel = repo;
  if (!(repo.startsWith('path:') || repo.startsWith('id:') || repo.startsWith('name:'))) {
    worktreeSel = repo.startsWith('/') ? `path:${repo}` : repo;
  }
  // Prefer path: for bare absolute paths (matches server.mjs double-check)
  if (!repo.includes(':') && repo.startsWith('/')) {
    worktreeSel = `path:${repo}`;
  }
  return [
    'terminal', 'create',
    '--worktree', worktreeSel,
    '--title', String(name),
    '--command', String(agent),
    '--json',
  ];
}

export function buildRunCreateArgv(objective) {
  return ['orchestration', 'run-create', '--objective', String(objective), '--json'];
}

export function buildRunUseArgv(runId) {
  return ['orchestration', 'run-use', '--id', String(runId), '--json'];
}

export function buildTaskCreateArgv({ spec, runId } = {}) {
  return ['orchestration', 'task-create', '--spec', String(spec), '--run', String(runId), '--json'];
}

export function buildDispatchInjectArgv({ taskId, handle } = {}) {
  return ['orchestration', 'dispatch', '--task', String(taskId), '--to', String(handle), '--inject', '--json'];
}

/**
 * `terminal send` argv. `--enter` ("Append Enter after sending text") is the
 * real submit flag — there is no `--submit` on any Orca CLI command.
 * `orchestration dispatch --inject` types a brief but cannot express Enter;
 * omit `text` to send Enter alone and submit that compose box.
 * A shell target submits on one `--enter`. A Grok TUI draft buffer needs a
 * following empty-text `--enter` after a payload send (verified live
 * 2026-08-15); that second send is harmless when the first already submitted.
 * `--interrupt` breaks a stuck TUI; it is not a submit substitute.
 */
export function buildTerminalSendArgv({
  handle,
  text,
  enter = true,
  interrupt = false,
  json = true,
} = {}) {
  const argv = ['terminal', 'send', '--terminal', String(handle)];
  if (text != null) argv.push('--text', String(text));
  if (enter) argv.push('--enter');
  if (interrupt) argv.push('--interrupt');
  if (json) argv.push('--json');
  return argv;
}

export function buildTerminalWaitIdleArgv(handle) {
  return ['terminal', 'wait', '--terminal', String(handle), '--for', 'tui-idle', '--timeout-ms', '60000', '--json'];
}

/**
 * await / check mailbox argv (before sender inject).
 * Optional params omitted when empty/false/zero as in server.mjs buildCheckArgv.
 */
export function buildAwaitCheckArgv({
  runId,
  ackId = null,
  peek = false,
  types = DEFAULT_WAIT_TYPES,
  waitMs = CHECK_WAIT_DEFAULT_MS,
} = {}) {
  const argv = ['orchestration', 'check', '--run', String(runId), '--json'];
  if (ackId) argv.push('--ack', String(ackId));
  if (peek) argv.push('--peek');
  if (types) argv.push('--types', String(types));
  if (waitMs > 0) argv.push('--wait', '--timeout-ms', String(waitMs));
  return argv;
}

/** clamp wait window the same way awaitDispatch / check do. */
export function clampWaitMs(waitMs, {
  defaultMs = CHECK_WAIT_DEFAULT_MS,
  maxMs = CHECK_WAIT_MAX_MS,
} = {}) {
  const n = waitMs == null ? defaultMs : Number(waitMs);
  if (!Number.isFinite(n)) return defaultMs;
  return Math.min(Math.max(n, 0), maxMs);
}

export function buildWorkerReleaseArgv(dispatchId) {
  return ['orchestration', 'worker-release', '--dispatch', String(dispatchId), '--json'];
}

export function buildTerminalCloseArgv(handle) {
  return ['terminal', 'close', '--terminal', String(handle), '--tab', '--json'];
}

export function buildDispatchShowArgv(taskId) {
  return ['orchestration', 'dispatch-show', '--task', String(taskId), '--json'];
}

export function buildWorkerShowArgv(dispatchId) {
  return ['orchestration', 'worker-show', '--dispatch', String(dispatchId), '--json'];
}

/**
 * Parse `orchestration reply` argv into flags. Returns null when argv is not a reply.
 * Values stay single argv slots (no shell splitting) — safe for re-exec.
 */
export function parseOrchestrationReplyArgv(argv) {
  if (!Array.isArray(argv) || argv.length < 2) return null;
  if (String(argv[0]).toLowerCase() !== 'orchestration') return null;
  if (String(argv[1]).toLowerCase() !== 'reply') return null;
  const out = {
    id: null,
    body: null,
    run: null,
    from: null,
    json: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const t = String(argv[i]);
    const next = () => (i + 1 < argv.length ? String(argv[++i]) : '');
    if (t === '--json') {
      out.json = true;
      continue;
    }
    if (t === '--id') {
      out.id = next();
      continue;
    }
    if (t.startsWith('--id=')) {
      out.id = t.slice('--id='.length);
      continue;
    }
    if (t === '--body') {
      out.body = next();
      continue;
    }
    if (t.startsWith('--body=')) {
      out.body = t.slice('--body='.length);
      continue;
    }
    if (t === '--run') {
      out.run = next();
      continue;
    }
    if (t.startsWith('--run=')) {
      out.run = t.slice('--run='.length);
      continue;
    }
    if (t === '--from') {
      out.from = next();
      continue;
    }
    if (t.startsWith('--from=')) {
      out.from = t.slice('--from='.length);
      continue;
    }
  }
  if (!out.id) return { ...out, ok: false, reason: 'missing_id' };
  return { ...out, ok: true };
}

/**
 * Pull a dispatch id out of an orchestration message row / envelope object.
 * Handles payload JSON, dispatch: from_handle, and top-level fields.
 */
export function extractDispatchIdFromMessage(message) {
  if (!message || typeof message !== 'object') return null;
  const strip = (v) => {
    if (v == null || v === '') return null;
    const s = String(v).trim();
    if (!s) return null;
    return s.startsWith('dispatch:') ? s.slice('dispatch:'.length) : s;
  };
  const top =
    strip(message.dispatchId) ||
    strip(message.dispatch_id) ||
    strip(message.dispatchID);
  if (top) return top;

  for (const key of ['from_handle', 'from', 'to_handle', 'to']) {
    const v = message[key];
    if (typeof v === 'string' && v.startsWith('dispatch:')) return strip(v);
  }

  let payload = message.payload;
  if (typeof payload === 'string' && payload.trim()) {
    try {
      payload = JSON.parse(payload);
    } catch {
      payload = null;
    }
  }
  if (payload && typeof payload === 'object') {
    const nested =
      strip(payload.dispatchId) ||
      strip(payload.dispatch_id) ||
      strip(payload.dispatchID);
    if (nested) return nested;
  }
  return null;
}

/**
 * Resolve which supervised dispatch should receive a dual-routed reply.
 * Prefer the original message (escalation payload), then reply envelope, then
 * worker-list terminal→dispatch map.
 */
export function resolveWorkerDispatchId({
  originalMessage = null,
  replyMessage = null,
  workers = [],
} = {}) {
  const fromOriginal = extractDispatchIdFromMessage(originalMessage);
  if (fromOriginal) return fromOriginal;

  const fromReply = extractDispatchIdFromMessage(replyMessage);
  if (fromReply) return fromReply;

  const terminal =
    (replyMessage && (replyMessage.to_handle || replyMessage.to)) ||
    (originalMessage && (originalMessage.from_handle || originalMessage.from)) ||
    null;
  if (terminal && Array.isArray(workers)) {
    for (const w of workers) {
      if (!w || typeof w !== 'object') continue;
      const handles = [
        w.agentTerminalHandle,
        w.terminalHandle,
        w.terminal_handle,
        w.resource?.terminalHandle,
        w.resource?.terminal_handle,
      ]
        .filter(Boolean)
        .map(String);
      if (handles.includes(String(terminal))) {
        const id = w.dispatchId || w.dispatch_id;
        if (id) return String(id).replace(/^dispatch:/, '');
      }
    }
  }
  return null;
}

/**
 * Follow-up send that delivers a coordinator reply onto the worker Dispatch
 * mailbox (`dispatch:<id>`). Orca's native `orchestration reply` for non-question
 * messages targets the worker *terminal handle* and defaults type to `status`.
 * A worker with an active Dispatch reads `dispatch:<id>` on check, so the native
 * reply never unblocks them (NAS-239).
 */
export function buildEscalationReplyFollowupSendArgv({
  dispatchId,
  body,
  subject = 'Re: escalation',
  threadId = null,
  runId = null,
  from = null,
} = {}) {
  const id = String(dispatchId || '')
    .replace(/^dispatch:/, '')
    .trim();
  if (!id) throw new Error('dispatchId is required');
  const argv = [
    'orchestration',
    'send',
    '--to',
    `dispatch:${id}`,
    '--type',
    'status',
    '--subject',
    String(subject || 'Re: escalation'),
    '--body',
    body == null ? '' : String(body),
    '--json',
  ];
  if (threadId) argv.push('--thread-id', String(threadId));
  if (runId) argv.push('--run', String(runId));
  if (from) argv.push('--from', String(from));
  return argv;
}

/**
 * True when a native reply envelope already used the question_threads path
 * (Orca delivers the answer to dispatch:<id> itself).
 */
export function replyEnvelopeIsQuestionAnswer(envelope) {
  if (!envelope || typeof envelope !== 'object') return false;
  const result =
    envelope.result && typeof envelope.result === 'object' ? envelope.result : envelope;
  if (result.question && typeof result.question === 'object') return true;
  return false;
}

/** Detect Orca stale_delivery errors from code/message. */
export function isStaleDeliveryError(errorCode, errorMessage) {
  const code = String(errorCode || '');
  const msg = String(errorMessage || '');
  return (
    code === 'stale_delivery' ||
    /stale_delivery/i.test(msg) ||
    /does not belong to this Run/i.test(msg)
  );
}

/**
 * Classify Orca stale_delivery failures into a self-explanatory hint.
 * Coordinators often pass messages[].id (msg_…) into await/check --ack; Orca
 * only accepts deliveryId from the prior Delivery batch. Reading the run
 * mailbox by message id succeeds; acknowledgeRunDelivery looks up deliveries.
 */
export function explainStaleDeliveryError({
  ackId = null,
  errorCode = null,
  errorMessage = null,
} = {}) {
  if (!isStaleDeliveryError(errorCode, errorMessage)) return null;

  const ack = ackId != null && String(ackId).trim() !== '' ? String(ackId).trim() : null;
  const msg = String(errorMessage || '');
  const looksLikeMessageId =
    !!ack &&
    (ack.startsWith(MESSAGE_ID_PREFIX) ||
      (/^msg[_-]/i.test(ack) && !ack.startsWith(DELIVERY_ID_PREFIX)));
  const looksLikeDeliveryId =
    !!ack &&
    (ack.startsWith(DELIVERY_ID_PREFIX) ||
      /^del[_-]/i.test(ack) ||
      /^delivery[_-]/i.test(ack));

  if (looksLikeMessageId) {
    return {
      code: 'stale_delivery',
      hint: 'ack_message_id_not_delivery_id',
      ackId: ack,
      message:
        `Ack target ${ack} looks like a message id, not a delivery id. ` +
        `orchestration check/await --ack expects the deliveryId from the prior ` +
        `check/await response (usually delivery_…), not messages[].id (msg_…). ` +
        `Run mailbox listings show message ids; deliveries are generation-scoped ack tokens. ` +
        `Re-check without ack (or with the real deliveryId), then ack that deliveryId.`,
    };
  }

  return {
    code: 'stale_delivery',
    hint: looksLikeDeliveryId
      ? 'delivery_not_in_run_or_wrong_generation'
      : 'ack_not_a_delivery_for_this_run',
    ackId: ack,
    message:
      (msg || `Delivery ${ack || '?'} does not belong to this Run.`) +
      ' --ack must be the deliveryId from await/check for this Run consumer generation ' +
      '(not a message id, and not a delivery from a prior run-use generation).',
  };
}

/**
 * Dynamic Client Registration response shape (RFC 7591 public client).
 * clientId must be supplied by caller (random).
 */
export function buildDcrResponse(body = {}, { clientId, issuedAt = Math.floor(Date.now() / 1000) } = {}) {
  if (!clientId) throw new Error('clientId required');
  return {
    client_id: clientId,
    client_id_issued_at: issuedAt,
    redirect_uris: body.redirect_uris || [],
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code'],
    response_types: ['code'],
  };
}

/** Load issued OAuth access tokens from JSON array file. */
export function loadIssuedTokens(storePath, { readFileSync = fs.readFileSync, existsSync = fs.existsSync } = {}) {
  try {
    if (!existsSync(storePath)) return new Set();
    return new Set(JSON.parse(readFileSync(storePath, 'utf8')));
  } catch {
    return new Set();
  }
}

/** Persist issued OAuth access tokens (mode 600). */
export function persistIssuedTokens(storePath, tokens, {
  writeFileSync = fs.writeFileSync,
  mode = 0o600,
} = {}) {
  writeFileSync(storePath, JSON.stringify([...tokens]), { mode });
}

/**
 * Authenticate a request against master token / OAuth set / path token / session.
 * Pure relative to injected session helpers and token set.
 *
 * @returns {{ path: string, sessionId: string, authKind: string, clientKey: string, bearer: string } | null}
 */
export function authenticateRequest(req, {
  token,
  issuedTokens,
  deriveClientKey,
  sessionIdFrom,
  touchSession,
  pruneSessions,
} = {}) {
  if (typeof pruneSessions === 'function') pruneSessions();
  const rawPath = req.url || '/';
  const bearer = extractBearer(req);
  let authKind = '';
  if (bearer) {
    if (tokenMatches(bearer, token)) authKind = 'bearer-master';
    else if (issuedTokens && issuedTokens.has(bearer)) authKind = 'bearer-oauth';
  }
  let pathOut = null;
  if (authKind) {
    pathOut = rawPath;
  } else {
    const m = rawPath.match(/^\/t\/([^/]+)(\/.*)?$/);
    if (m && tokenMatches(decodeURIComponent(m[1]), token)) {
      authKind = 'path-token';
      pathOut = m[2] || '/';
    }
  }
  const sid = typeof sessionIdFrom === 'function' ? sessionIdFrom(req) : '';
  let sessionRec = null;
  if (!authKind && sid) {
    sessionRec = touchSession(sid);
    if (sessionRec) {
      authKind = 'session';
      pathOut = rawPath;
    }
  } else if (authKind && sid) {
    sessionRec = typeof touchSession === 'function' ? touchSession(sid) : null;
  }
  if (!authKind || pathOut == null) return null;

  const clientKey = deriveClientKey({
    authKind,
    bearer: authKind === 'bearer-oauth' ? bearer : '',
    sessionId: sid,
    sessionClientKey: sessionRec?.clientKey || null,
  });
  if (sid && sessionRec) {
    sessionRec.clientKey = clientKey;
    sessionRec.authKind = authKind || sessionRec.authKind;
  }

  return {
    path: pathOut,
    sessionId: sid,
    authKind,
    clientKey,
    bearer: authKind === 'bearer-oauth' ? bearer : '',
  };
}
