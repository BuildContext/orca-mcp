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

export const CHECK_WAIT_DEFAULT_MS = 60_000;
export const CHECK_WAIT_MAX_MS = 240_000;
export const DEFAULT_WAIT_TYPES = 'worker_done,escalation,question';

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
 * - check: --terminal <handle>
 */
export function injectSenderArgv(argv, senderHandle, orchFromCmds = ORCH_FROM_CMDS) {
  if (!Array.isArray(argv) || argv.length < 2) return argv;
  if (argv[0] !== 'orchestration') return argv;
  const sub = argv[1];
  const needsFrom = orchFromCmds.has(sub);
  const needsTerminal = sub === 'check';
  if (!needsFrom && !needsTerminal) return argv;

  const out = [...argv];
  if (needsTerminal && !argvHasFlag(out, '--terminal')) {
    out.push('--terminal', senderHandle);
  }
  if (needsFrom && !argvHasFlag(out, '--from')) {
    out.push('--from', senderHandle);
  }
  return out;
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
