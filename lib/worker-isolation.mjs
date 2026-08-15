/**
 * NAS-255 — dedicated worker OS uid (bridge ↔ worker trust boundary).
 *
 * Scope (deliberately cut): ONE service account for all dispatched workers
 * (default `orca-worker`), NOT a uid per dispatch. That closes the class where
 * the worker IS the bridge user and can therefore read/write bridge secrets or
 * forge coordinator identity. Per-dispatch uid / worker-to-worker isolation is
 * NOT done here — file a follow-up; "done" must not read as "per-dispatch uid".
 *
 * Design (no Orca source change required):
 *   1. Bridge keeps running as the bridge service account (e.g. `orca`).
 *   2. Agent launch is re-routed through a host wrapper that setuid/setpriv's
 *      into ORCA_BRIDGE_WORKER_USER before exec'ing the real agent binary.
 *   3. Bridge secret files stay mode 0600 / dir 0700 owned by the bridge uid.
 *      The worker uid cannot open them — FS is the primary boundary; the argv
 *      gate becomes second echelon.
 *   4. Worker→runtime orchestration (worker_done / ask / check) uses a
 *      bridge-minted HMAC capability, not the 0600 Orca daemon token.
 *
 * Pure helpers are free of process I/O so unit tests need no root. FS probes
 * accept injectable access/stat for hermetic tests and optional live checks.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isSafeCapId } from './worker-cap-file.mjs';

/** Default unprivileged account name for all dispatched workers. */
export const DEFAULT_WORKER_USER = 'orca-worker';

/**
 * Env opt-in. When unset/off the bridge behaves as today (same-uid workers).
 * Operators enable after creating the worker account + installing the wrapper.
 */
export const WORKER_ISOLATION_ENV = 'ORCA_BRIDGE_WORKER_ISOLATION';

export const WORKER_USER_ENV = 'ORCA_BRIDGE_WORKER_USER';
export const WORKER_UID_ENV = 'ORCA_BRIDGE_WORKER_UID';
export const WORKER_LAUNCH_WRAPPER_ENV = 'ORCA_BRIDGE_WORKER_LAUNCH_WRAPPER';
export const WORKER_HMAC_SECRET_ENV = 'ORCA_BRIDGE_WORKER_HMAC_SECRET';
export const WORKER_REAL_AGENT_ENV = 'ORCA_BRIDGE_WORKER_REAL_AGENT';

/** Default install path for the Linux agent-launch wrapper (deploy/linux). */
export const DEFAULT_LINUX_LAUNCH_WRAPPER =
  '/usr/local/lib/orca-mcp/orca-omp-as-worker.sh';

/** Capability token TTL for worker_done / ask / check helpers (seconds). */
export const DEFAULT_CAPABILITY_TTL_SEC = 24 * 60 * 60;

/**
 * Bridge-held secrets the worker uid MUST NOT read or write.
 * Paths are resolved against a HOME root (bridge account home).
 */
export const BRIDGE_SECRET_BASENAMES = Object.freeze([
  '.orca-bridge-tokens.json',
  '.orca-bridge-sender-pins.json',
]);

export const BRIDGE_SECRET_DIR_BASENAMES = Object.freeze([
  '.orca-bridge',
]);

/**
 * Runtime / daemon tokens (Orca, not bridge). Same class: worker must not open.
 * Relative to the bridge account home / XDG config.
 */
export const RUNTIME_SECRET_REL_PATHS = Object.freeze([
  path.join('.config', 'orca', 'orca-runtime.json'),
  path.join('.config', 'orca', 'daemon', 'daemon-v32.token'),
]);

/**
 * @param {NodeJS.ProcessEnv|Record<string,string|undefined>} [env]
 * @param {{ getuid?: () => number|null, platform?: string }} [deps]
 */
export function resolveWorkerIsolationConfig(env = process.env, deps = {}) {
  const e = env || {};
  const getuid =
    typeof deps.getuid === 'function'
      ? deps.getuid
      : typeof process.getuid === 'function'
        ? () => process.getuid()
        : () => null;
  const platform = deps.platform || process.platform;

  const enabled = e[WORKER_ISOLATION_ENV] === '1';
  const workerUser = String(e[WORKER_USER_ENV] || DEFAULT_WORKER_USER).trim() || DEFAULT_WORKER_USER;
  const uidRaw = e[WORKER_UID_ENV];
  let workerUid = null;
  if (uidRaw != null && String(uidRaw).trim() !== '') {
    const n = Number(uidRaw);
    if (Number.isInteger(n) && n >= 0) workerUid = n;
  }

  const bridgeUid = getuid();
  const launchWrapper = String(
    e[WORKER_LAUNCH_WRAPPER_ENV] ||
      (platform === 'linux' ? DEFAULT_LINUX_LAUNCH_WRAPPER : ''),
  ).trim();

  // Prefer dedicated HMAC secret; fall back to master token only when isolation
  // is on and operator has not split secrets yet (documented as weaker).
  const hmacSecret = String(
    e[WORKER_HMAC_SECRET_ENV] || (enabled ? e.ORCA_BRIDGE_TOKEN || '' : '') || '',
  );

  const realAgent = String(e[WORKER_REAL_AGENT_ENV] || 'omp').trim() || 'omp';

  return {
    enabled,
    workerUser,
    workerUid,
    bridgeUid: typeof bridgeUid === 'number' ? bridgeUid : null,
    launchWrapper,
    hmacSecret,
    realAgent,
    platform,
    /**
     * True when enabled AND bridge uid is known AND (worker uid set and
     * different, or worker user name is non-empty for deploy-time wrap).
     * FS denial proofs need numeric workerUid; launch wrap needs wrapper path.
     */
    active: enabled && Boolean(launchWrapper),
    sameUid:
      typeof bridgeUid === 'number' &&
      typeof workerUid === 'number' &&
      bridgeUid === workerUid,
  };
}

/**
 * Resolve absolute paths of bridge + runtime secrets under a HOME root.
 * @param {string} homeDir bridge account home
 * @param {{ auditDir?: string|null }} [opts]
 * @returns {string[]}
 */
export function listBridgeSecretPaths(homeDir, opts = {}) {
  const home = path.resolve(String(homeDir || ''));
  const out = [];
  for (const base of BRIDGE_SECRET_BASENAMES) {
    out.push(path.join(home, base));
  }
  for (const base of BRIDGE_SECRET_DIR_BASENAMES) {
    out.push(path.join(home, base));
    // Durable dispatch ownership lives inside the audit dir.
    out.push(path.join(home, base, 'dispatch-ownership.json'));
    out.push(path.join(home, base, 'audit.ndjson'));
  }
  if (opts.auditDir) {
    const ad = path.resolve(String(opts.auditDir));
    out.push(ad);
    out.push(path.join(ad, 'dispatch-ownership.json'));
    out.push(path.join(ad, 'audit.ndjson'));
  }
  for (const rel of RUNTIME_SECRET_REL_PATHS) {
    out.push(path.join(home, rel));
  }
  // de-dupe preserving order
  return [...new Set(out)];
}

/**
 * Pure FS-fact classification: can `workerUid` read or write this secret?
 *
 * Fail closed toward "blocked" when facts are incomplete only if the mode
 * bits clearly exclude other/group — otherwise report unknown.
 *
 * @param {{
 *   path: string,
 *   exists: boolean,
 *   uid?: number,
 *   gid?: number,
 *   mode?: number,
 *   workerUid: number,
 *   workerGid?: number|null,
 *   isDirectory?: boolean,
 * }} facts
 * @returns {{
 *   path: string,
 *   ok: boolean,
 *   blocked: boolean,
 *   canRead: boolean,
 *   canWrite: boolean,
 *   code: 'missing'|'blocked'|'exposed'|'unknown',
 *   message: string|null,
 * }}
 */
export function classifyWorkerSecretAccess(facts) {
  const filePath = String(facts?.path || '');
  const workerUid = facts?.workerUid;
  if (typeof workerUid !== 'number') {
    return {
      path: filePath,
      ok: false,
      blocked: false,
      canRead: false,
      canWrite: false,
      code: 'unknown',
      message: 'workerUid required',
    };
  }
  if (!facts?.exists) {
    // Missing secret is fine at classify time — nothing to leak yet.
    return {
      path: filePath,
      ok: true,
      blocked: true,
      canRead: false,
      canWrite: false,
      code: 'missing',
      message: null,
    };
  }

  const owner = typeof facts.uid === 'number' ? facts.uid : null;
  const mode = typeof facts.mode === 'number' ? facts.mode : null;
  const isDir = facts.isDirectory === true;
  const perm = mode != null ? mode & 0o777 : null;

  // Owner is the worker itself → fully exposed.
  if (owner === workerUid) {
    return {
      path: filePath,
      ok: false,
      blocked: false,
      canRead: true,
      canWrite: true,
      code: 'exposed',
      message:
        `${filePath} is owned by worker uid=${workerUid}. ` +
        'Bridge secrets must be owned by the bridge service account only.',
    };
  }

  let canRead = false;
  let canWrite = false;

  if (perm != null) {
    const otherR = Boolean(perm & 0o004);
    const otherW = Boolean(perm & 0o002);
    const groupR = Boolean(perm & 0o040);
    const groupW = Boolean(perm & 0o020);
    // Group bits only help if worker shares the file gid — unknown without
    // workerGid + file gid match. Treat group R/W as exposure unless we know
    // worker is not in that group (workerGid provided and differs, and we do
    // not model supplementary groups here — operators must avoid shared groups).
    const sameGroup =
      typeof facts.gid === 'number' &&
      typeof facts.workerGid === 'number' &&
      facts.gid === facts.workerGid;

    canRead = otherR || (groupR && sameGroup !== false && sameGroup);
    canWrite = otherW || (groupW && sameGroup !== false && sameGroup);

    // If group bits set but workerGid unknown → conservative exposure signal.
    if ((groupR || groupW) && facts.workerGid == null) {
      canRead = canRead || groupR;
      canWrite = canWrite || groupW;
    }

    // Root-owned 0600/0700 with no other/group → blocked for non-root worker.
    if (workerUid !== 0 && !canRead && !canWrite) {
      return {
        path: filePath,
        ok: true,
        blocked: true,
        canRead: false,
        canWrite: false,
        code: 'blocked',
        message: null,
      };
    }
  } else if (owner != null && owner !== workerUid && workerUid !== 0) {
    // No mode bits — cannot prove; unknown.
    return {
      path: filePath,
      ok: false,
      blocked: false,
      canRead: false,
      canWrite: false,
      code: 'unknown',
      message: `${filePath}: mode unknown; cannot prove worker denial`,
    };
  }

  if (canRead || canWrite) {
    return {
      path: filePath,
      ok: false,
      blocked: false,
      canRead,
      canWrite,
      code: 'exposed',
      message:
        `${filePath} is reachable by worker uid=${workerUid} ` +
        `(read=${canRead} write=${canWrite}` +
        (isDir ? ', directory' : '') +
        '). Tighten to owner-only 0600/0700 on the bridge account, ' +
        'and do NOT put the worker into a shared group with the bridge secrets.',
    };
  }

  return {
    path: filePath,
    ok: true,
    blocked: true,
    canRead: false,
    canWrite: false,
    code: 'blocked',
    message: null,
  };
}

/**
 * Inspect one path on disk for worker reachability.
 * @param {string} filePath
 * @param {number} workerUid
 * @param {{
 *   fsImpl?: Pick<typeof fs, 'statSync'>,
 *   workerGid?: number|null,
 * }} [deps]
 */
export function inspectWorkerSecretAccess(filePath, workerUid, deps = {}) {
  const fsImpl = deps.fsImpl || fs;
  let st;
  try {
    st = fsImpl.statSync(filePath);
  } catch {
    return classifyWorkerSecretAccess({
      path: filePath,
      exists: false,
      workerUid,
      workerGid: deps.workerGid,
    });
  }
  return classifyWorkerSecretAccess({
    path: filePath,
    exists: true,
    uid: st.uid,
    gid: st.gid,
    mode: st.mode,
    isDirectory: typeof st.isDirectory === 'function' ? st.isDirectory() : false,
    workerUid,
    workerGid: deps.workerGid,
  });
}

/**
 * Boot / operator check: every bridge secret under home must be blocked.
 * @param {{
 *   homeDir: string,
 *   workerUid: number,
 *   workerGid?: number|null,
 *   auditDir?: string|null,
 *   fsImpl?: Pick<typeof fs, 'statSync'>,
 * }} opts
 */
export function assertWorkerDeniedBridgeSecrets(opts) {
  const paths = listBridgeSecretPaths(opts.homeDir, { auditDir: opts.auditDir });
  const results = paths.map((p) =>
    inspectWorkerSecretAccess(p, opts.workerUid, {
      fsImpl: opts.fsImpl,
      workerGid: opts.workerGid,
    }),
  );
  const exposed = results.filter((r) => r.code === 'exposed');
  return {
    ok: exposed.length === 0 && results.every((r) => r.code !== 'unknown'),
    results,
    exposed,
  };
}

// ---------------------------------------------------------------------------
// Agent launch wrap (dispatch path)
// ---------------------------------------------------------------------------

/**
 * Whether this agent id should be launched via the worker wrapper.
 * @param {string} agent
 * @param {ReturnType<typeof resolveWorkerIsolationConfig>} cfg
 */
export function shouldWrapAgentLaunch(agent, cfg) {
  if (!cfg?.enabled || !cfg?.launchWrapper) return false;
  if (cfg.sameUid) return false;
  const a = String(agent || '').trim();
  return Boolean(a);
}

/**
 * Build the shell command string for `terminal create --command` so the agent
 * process runs as the worker uid (wrapper performs setpriv/sudo).
 *
 * For `worktree create --agent`, prefer the no-agent + terminal-create path
 * (see {@link planIsolatedAgentPlacement}) — Orca has no CLI flag for
 * agentCmdOverrides; the wrapper is the host-side indirection.
 *
 * @param {string} agent agent id or bare binary (e.g. omp)
 * @param {ReturnType<typeof resolveWorkerIsolationConfig>} cfg
 * @param {{ taskId?: string|null }} [opts]
 * @returns {string} command for --command
 */
export function buildWorkerLaunchCommand(agent, cfg, opts = {}) {
  const wrapper = String(cfg?.launchWrapper || '').trim();
  const a = String(agent || cfg?.realAgent || 'omp').trim() || 'omp';
  if (!wrapper) return a;
  const taskId = opts?.taskId != null ? String(opts.taskId).trim() : '';
  const taskFlag = taskId && isSafeCapId(taskId) ? ` --task-id ${taskId}` : '';
  // Wrapper receives the real agent binary name as argv0 intent via env + args.
  // Quote-safe: wrapper path and agent token are operator-controlled identifiers.
  if (/[\s"$`\\]/.test(wrapper) || /[\s"$`\\]/.test(a)) {
    // Unusual paths — still produce a deterministic form; operator should avoid.
    return `${wrapper}${taskFlag} ${a}`;
  }
  return `${wrapper}${taskFlag} ${a}`;
}

/**
 * Plan how dispatch places the agent terminal under worker isolation.
 *
 * When isolation is active we NEVER pass `--agent` to `worktree create`
 * (Orca would spawn the agent as the bridge uid). Instead: create the
 * worktree bare, then `terminal create --command <wrapper agent>`.
 *
 * @param {{
 *   worktree: string,
 *   agent: string,
 *   name: string,
 *   repo: string,
 *   setup?: string,
 *   baseBranch?: string,
 *   taskId?: string|null,
 * }} args
 * @param {ReturnType<typeof resolveWorkerIsolationConfig>} cfg
 * @returns {{
 *   mode: 'legacy-agent'|'isolated-command',
 *   worktreeArgv: string[]|null,
 *   terminalArgv: string[]|null,
 *   launchCommand: string|null,
 * }}
 */
export function planIsolatedAgentPlacement(args, cfg) {
  const worktree = String(args.worktree || 'new-top-level');
  const agent = String(args.agent || 'omp');
  const name = String(args.name || 'worker');
  const repo = String(args.repo || '');
  const setup = args.setup != null ? String(args.setup) : 'run';
  const baseBranch = args.baseBranch ? String(args.baseBranch) : '';

  if (!shouldWrapAgentLaunch(agent, cfg)) {
    return {
      mode: 'legacy-agent',
      worktreeArgv: null,
      terminalArgv: null,
      launchCommand: null,
    };
  }

  const launchCommand = buildWorkerLaunchCommand(agent, cfg, { taskId: args.taskId });
  const repoArg = repo.includes(':')
    ? repo
    : repo.startsWith('/')
      ? `path:${repo}`
      : repo;

  if (worktree === 'current') {
    let worktreeSel = repoArg;
    if (!repo.includes(':') && repo.startsWith('/')) worktreeSel = `path:${repo}`;
    return {
      mode: 'isolated-command',
      worktreeArgv: null,
      terminalArgv: [
        'terminal',
        'create',
        '--worktree',
        worktreeSel,
        '--title',
        name,
        '--command',
        launchCommand,
        '--json',
      ],
      launchCommand,
    };
  }

  const wtArgv = [
    'worktree',
    'create',
    '--name',
    name,
    '--repo',
    repoArg,
    '--json',
  ];
  // Deliberately NO --agent: agent is placed in a follow-up terminal create.
  if (worktree === 'new-top-level') wtArgv.push('--no-parent');
  if (setup) wtArgv.push('--setup', setup);
  if (baseBranch) wtArgv.push('--base-branch', baseBranch);

  return {
    mode: 'isolated-command',
    worktreeArgv: wtArgv,
    // terminal argv filled by caller after worktree path is known
    terminalArgv: null,
    launchCommand,
  };
}

/**
 * Terminal-create argv after an isolated worktree create returned a path/id.
 * @param {{ worktreeSelector: string, name: string, launchCommand: string }} p
 */
export function buildIsolatedTerminalCreateArgv(p) {
  return [
    'terminal',
    'create',
    '--worktree',
    String(p.worktreeSelector),
    '--title',
    String(p.name),
    '--command',
    String(p.launchCommand),
    '--json',
  ];
}

// ---------------------------------------------------------------------------
// HMAC worker capability (orchestration without runtime token)
// ---------------------------------------------------------------------------

/**
 * Stable payload bytes for HMAC (key-sorted JSON, no whitespace).
 * @param {Record<string, unknown>} obj
 */
export function canonicalCapabilityPayload(obj) {
  const keys = Object.keys(obj).sort();
  const ordered = {};
  for (const k of keys) {
    const v = obj[k];
    if (v === undefined) continue;
    ordered[k] = v;
  }
  return JSON.stringify(ordered);
}

/**
 * Mint a worker capability token.
 * Format: v1.<base64url(payload)>.<base64url(hmac-sha256)>
 *
 * @param {{
 *   dispatchId: string,
 *   taskId: string,
 *   terminalHandle?: string|null,
 *   clientKey?: string|null,
 *   ops?: string[],
 *   ttlSec?: number,
 *   nowMs?: number,
 * }} claims
 * @param {string} secret
 */
export function mintWorkerCapability(claims, secret) {
  if (!secret || typeof secret !== 'string') {
    throw new Error('mintWorkerCapability: secret required');
  }
  const nowMs = typeof claims.nowMs === 'number' ? claims.nowMs : Date.now();
  const ttlSec =
    typeof claims.ttlSec === 'number' && claims.ttlSec > 0
      ? claims.ttlSec
      : DEFAULT_CAPABILITY_TTL_SEC;
  const payload = {
    v: 1,
    dispatchId: String(claims.dispatchId || ''),
    taskId: String(claims.taskId || ''),
    terminalHandle: claims.terminalHandle ? String(claims.terminalHandle) : null,
    clientKey: claims.clientKey ? String(claims.clientKey) : null,
    ops: Array.isArray(claims.ops)
      ? claims.ops.map(String)
      : ['worker_done', 'ask', 'check', 'heartbeat', 'escalation'],
    iat: Math.floor(nowMs / 1000),
    exp: Math.floor(nowMs / 1000) + ttlSec,
  };
  if (!payload.dispatchId || !payload.taskId) {
    throw new Error('mintWorkerCapability: dispatchId and taskId required');
  }
  const body = canonicalCapabilityPayload(payload);
  const bodyB64 = Buffer.from(body, 'utf8').toString('base64url');
  const sig = createHmac('sha256', secret).update(body).digest('base64url');
  return `v1.${bodyB64}.${sig}`;
}

/**
 * Verify a worker capability token.
 * @param {string} token
 * @param {string} secret
 * @param {{ nowMs?: number, expectedDispatchId?: string, expectedTaskId?: string, op?: string }} [opts]
 * @returns {{ ok: true, payload: object } | { ok: false, code: string, message: string }}
 */
export function verifyWorkerCapability(token, secret, opts = {}) {
  if (!token || typeof token !== 'string') {
    return { ok: false, code: 'missing_token', message: 'capability token required' };
  }
  if (!secret || typeof secret !== 'string') {
    return { ok: false, code: 'missing_secret', message: 'server secret not configured' };
  }
  const parts = String(token).split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') {
    return { ok: false, code: 'malformed', message: 'capability token malformed' };
  }
  let body;
  try {
    body = Buffer.from(parts[1], 'base64url').toString('utf8');
  } catch {
    return { ok: false, code: 'malformed', message: 'capability payload not base64url' };
  }
  const expectedSig = createHmac('sha256', secret).update(body).digest();
  let gotSig;
  try {
    gotSig = Buffer.from(parts[2], 'base64url');
  } catch {
    return { ok: false, code: 'malformed', message: 'capability sig not base64url' };
  }
  if (gotSig.length !== expectedSig.length || !timingSafeEqual(gotSig, expectedSig)) {
    return { ok: false, code: 'bad_signature', message: 'capability signature mismatch' };
  }
  let payload;
  try {
    payload = JSON.parse(body);
  } catch {
    return { ok: false, code: 'malformed', message: 'capability payload not JSON' };
  }
  // Re-canonicalise — reject if body was not canonical (bit-flips that still parse).
  if (canonicalCapabilityPayload(payload) !== body) {
    return { ok: false, code: 'malformed', message: 'capability payload not canonical' };
  }

  const nowMs = typeof opts.nowMs === 'number' ? opts.nowMs : Date.now();
  const now = Math.floor(nowMs / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < now) {
    return { ok: false, code: 'expired', message: 'capability expired' };
  }
  if (typeof payload.iat === 'number' && payload.iat > now + 60) {
    return { ok: false, code: 'not_yet_valid', message: 'capability iat in future' };
  }
  if (opts.expectedDispatchId && String(payload.dispatchId) !== String(opts.expectedDispatchId)) {
    return { ok: false, code: 'dispatch_mismatch', message: 'capability dispatchId mismatch' };
  }
  if (opts.expectedTaskId && String(payload.taskId) !== String(opts.expectedTaskId)) {
    return { ok: false, code: 'task_mismatch', message: 'capability taskId mismatch' };
  }
  if (opts.op) {
    const ops = Array.isArray(payload.ops) ? payload.ops.map(String) : [];
    if (!ops.includes(String(opts.op))) {
      return { ok: false, code: 'op_not_allowed', message: `op ${opts.op} not in capability` };
    }
  }
  return { ok: true, payload };
}

/**
 * Env block injected into the worker launch for capability-based orch.
 * Bridge secrets are explicitly stripped by the wrapper; this only adds the
 * capability + helper hints.
 *
 * @param {{ capability: string, bridgeOrigin?: string|null }} p
 */
export function workerCapabilityEnv(p) {
  const env = {
    ORCA_WORKER_CAPABILITY: String(p.capability),
  };
  if (p.bridgeOrigin) {
    env.ORCA_WORKER_BRIDGE_ORIGIN = String(p.bridgeOrigin);
  }
  // Hint the worker-facing orch shim (deployed next to the wrapper).
  env.ORCA_WORKER_ORCH_HELPER = '/usr/local/lib/orca-mcp/orca-worker-orch.sh';
  return env;
}

// ---------------------------------------------------------------------------
// Attack catalogue × worker-uid posture (argv gate DISABLED)
// ---------------------------------------------------------------------------

/**
 * NAS-250/251/252 attack catalogue entries relevant to the single-uid trust
 * class. Under a dedicated worker uid, each either:
 *   - requires opening a bridge secret (FS blocked), or
 *   - requires acting as the bridge/coordinator identity (process uid blocked),
 *   - or is a coordinator-path concern (still gated by ownership — not the
 *     worker-uid boundary; listed as coordinator_path).
 *
 * PRIMARY criterion (NAS-255 DoD #3): with argv gate disabled, no catalogue
 * attack that depends on same-uid trust may pass when evaluated as the worker.
 *
 * @typedef {{
 *   id: string,
 *   title: string,
 *   argv?: string[],
 *   requiresBridgeSecret?: boolean,
 *   requiresBridgeUid?: boolean,
 *   forgesClientKey?: boolean,
 *   coordinatorPath?: boolean,
 * }} AttackCase
 */

/** @type {AttackCase[]} */
export const WORKER_UID_ATTACK_CATALOGUE = Object.freeze([
  {
    id: 'nas250-foreign-terminal-preview',
    title: 'terminal show --json --terminal <foreign> leaks preview',
    argv: ['terminal', 'show', '--json', '--terminal', 'term_FOREIGN'],
    requiresBridgeUid: true,
    coordinatorPath: true,
  },
  {
    id: 'nas251-foreign-worktree-stop',
    title: 'terminal stop --worktree <foreign> soft-executes',
    argv: ['terminal', 'stop', '--worktree', 'path:/foreign'],
    requiresBridgeUid: true,
    coordinatorPath: true,
  },
  {
    id: 'nas252-dispatch-show-preamble',
    title: 'orchestration dispatch-show --task <foreign> --preamble',
    argv: ['orchestration', 'dispatch-show', '--task', 'task_FOREIGN', '--preamble', '--json'],
    requiresBridgeUid: true,
    coordinatorPath: true,
  },
  {
    id: 'nas252-task-list-foreign-run',
    title: 'orchestration task-list --run <foreign> dumps specs',
    argv: ['orchestration', 'task-list', '--run', 'run_FOREIGN', '--json'],
    requiresBridgeUid: true,
    coordinatorPath: true,
  },
  {
    id: 'nas252-run-show-foreign',
    title: 'orchestration run-show --id <foreign>',
    argv: ['orchestration', 'run-show', '--id', 'run_FOREIGN', '--json'],
    requiresBridgeUid: true,
    coordinatorPath: true,
  },
  {
    id: 'nas252-unscoped-inbox',
    title: 'orchestration inbox --json host-wide mailbox',
    argv: ['orchestration', 'inbox', '--json'],
    requiresBridgeUid: true,
    coordinatorPath: true,
  },
  {
    id: 'nas252-unscoped-run-list',
    title: 'orchestration run-list --json',
    argv: ['orchestration', 'run-list', '--json'],
    requiresBridgeUid: true,
    coordinatorPath: true,
  },
  {
    id: 'nas252-unscoped-worker-list',
    title: 'orchestration worker-list --json',
    argv: ['orchestration', 'worker-list', '--json'],
    requiresBridgeUid: true,
    coordinatorPath: true,
  },
  {
    id: 'nas252-file-open-foreign',
    title: 'file open path:/foreign',
    argv: ['file', 'open', 'path:/foreign'],
    requiresBridgeUid: true,
    coordinatorPath: true,
  },
  {
    id: 'nas252-workspace-foreign',
    title: 'automations create --workspace path:/foreign',
    argv: ['automations', 'create', '--workspace', 'path:/foreign', '--json'],
    requiresBridgeUid: true,
    coordinatorPath: true,
  },
  {
    id: 'nas248-steal-sender-pins',
    title: 'read/write ~/.orca-bridge-sender-pins.json to forge clientKey pin',
    requiresBridgeSecret: true,
    forgesClientKey: true,
  },
  {
    id: 'nas248-steal-oauth-tokens',
    title: 'read ~/.orca-bridge-tokens.json issued OAuth access tokens',
    requiresBridgeSecret: true,
    forgesClientKey: true,
  },
  {
    id: 'nas248-rewrite-ownership-store',
    title: 'write dispatch-ownership.json to claim foreign dispatch',
    requiresBridgeSecret: true,
    forgesClientKey: true,
  },
  {
    id: 'nas248-tamper-audit-log',
    title: 'write ~/.orca-bridge/audit.ndjson',
    requiresBridgeSecret: true,
  },
  {
    id: 'nas255-steal-runtime-token',
    title: 'read Orca runtime authToken / daemon token (0600)',
    requiresBridgeSecret: true,
  },
  {
    id: 'nas255-forge-clientkey-via-pin-file',
    title: 'forge another coordinator clientKey by editing sender-pins as same uid',
    requiresBridgeSecret: true,
    forgesClientKey: true,
  },
]);

/**
 * Evaluate one catalogue attack as the unprivileged worker uid.
 * Argv-gate is assumed DISABLED — only uid/FS boundary may stop the attack.
 *
 * @param {AttackCase} attack
 * @param {{
 *   workerUid: number,
 *   bridgeUid: number,
 *   secretAccessByPath?: Map<string, ReturnType<typeof classifyWorkerSecretAccess>>,
 *   secretAccessDefault?: ReturnType<typeof classifyWorkerSecretAccess>|null,
 * }} ctx
 * @returns {{
 *   id: string,
 *   passes: boolean,
 *   blockedBy: 'fs'|'uid'|'not_applicable'|null,
 *   reason: string,
 * }}
 */
export function evaluateAttackAsWorker(attack, ctx) {
  const workerUid = ctx.workerUid;
  const bridgeUid = ctx.bridgeUid;

  if (typeof workerUid !== 'number' || typeof bridgeUid !== 'number') {
    return {
      id: attack.id,
      passes: true,
      blockedBy: null,
      reason: 'uid facts missing — fail open for test visibility',
    };
  }

  // Same uid → primary criterion fails for every same-uid trust attack.
  if (workerUid === bridgeUid) {
    if (attack.requiresBridgeSecret || attack.forgesClientKey || attack.requiresBridgeUid) {
      return {
        id: attack.id,
        passes: true,
        blockedBy: null,
        reason: 'worker uid equals bridge uid — single-uid trust class still open',
      };
    }
  }

  if (attack.requiresBridgeSecret || attack.forgesClientKey) {
    // FS boundary: all secrets must be blocked for the worker.
    const map = ctx.secretAccessByPath;
    if (map && map.size) {
      for (const verdict of map.values()) {
        if (verdict.code === 'exposed' || verdict.canRead || verdict.canWrite) {
          return {
            id: attack.id,
            passes: true,
            blockedBy: null,
            reason: `secret exposed: ${verdict.path}`,
          };
        }
      }
    } else if (ctx.secretAccessDefault) {
      const v = ctx.secretAccessDefault;
      if (v.code === 'exposed' || v.canRead || v.canWrite) {
        return {
          id: attack.id,
          passes: true,
          blockedBy: null,
          reason: `secret exposed: ${v.path}`,
        };
      }
    }
    // Distinct uid + no exposure facts → blocked by FS ownership model.
    if (workerUid !== bridgeUid) {
      return {
        id: attack.id,
        passes: false,
        blockedBy: 'fs',
        reason:
          'worker uid cannot open bridge-owned 0600/0700 secrets; clientKey forge via pin/token file denied',
      };
    }
  }

  if (attack.requiresBridgeUid || attack.coordinatorPath) {
    // Coordinator action=cli runs inside the bridge process (bridge uid), not
    // inside the worker. A worker process cannot invoke the bridge's runOrca
    // as itself without the runtime token (also a secret). Distinct uid ⇒
    // worker cannot ride the bridge identity.
    if (workerUid !== bridgeUid) {
      return {
        id: attack.id,
        passes: false,
        blockedBy: 'uid',
        reason:
          'attack is coordinator/bridge-identity path; worker uid ≠ bridge uid and runtime token is unreadable',
      };
    }
  }

  return {
    id: attack.id,
    passes: true,
    blockedBy: null,
    reason: 'no blocking rule matched',
  };
}

/**
 * PRIMARY DoD: with argv gate disabled, zero catalogue attacks pass as worker.
 * @param {{
 *   workerUid: number,
 *   bridgeUid: number,
 *   secretAccessByPath?: Map<string, ReturnType<typeof classifyWorkerSecretAccess>>,
 *   homeDir?: string,
 *   fsImpl?: Pick<typeof fs, 'statSync'>,
 *   workerGid?: number|null,
 *   auditDir?: string|null,
 * }} ctx
 */
export function evaluateAttackCatalogueAsWorker(ctx) {
  let secretAccessByPath = ctx.secretAccessByPath;
  if (!secretAccessByPath && ctx.homeDir && typeof ctx.workerUid === 'number') {
    secretAccessByPath = new Map();
    for (const p of listBridgeSecretPaths(ctx.homeDir, { auditDir: ctx.auditDir })) {
      secretAccessByPath.set(
        p,
        inspectWorkerSecretAccess(p, ctx.workerUid, {
          fsImpl: ctx.fsImpl,
          workerGid: ctx.workerGid,
        }),
      );
    }
  }

  const results = WORKER_UID_ATTACK_CATALOGUE.map((attack) =>
    evaluateAttackAsWorker(attack, {
      workerUid: ctx.workerUid,
      bridgeUid: ctx.bridgeUid,
      secretAccessByPath,
    }),
  );
  const passed = results.filter((r) => r.passes);
  return {
    ok: passed.length === 0,
    argvGate: 'disabled',
    total: results.length,
    passedCount: passed.length,
    passed,
    results,
  };
}

/**
 * Health/diagnostic snapshot for action=health verbose.
 * @param {ReturnType<typeof resolveWorkerIsolationConfig>} cfg
 */
export function workerIsolationHealth(cfg) {
  return {
    enabled: Boolean(cfg?.enabled),
    active: Boolean(cfg?.active),
    workerUser: cfg?.workerUser || DEFAULT_WORKER_USER,
    workerUid: cfg?.workerUid ?? null,
    bridgeUid: cfg?.bridgeUid ?? null,
    sameUid: Boolean(cfg?.sameUid),
    launchWrapper: cfg?.launchWrapper || null,
    hmacConfigured: Boolean(cfg?.hmacSecret),
    perDispatchUid: false,
    perWorktreeAcl: true,
    note:
      'NAS-255: one dedicated worker uid closes bridge↔worker trust. ' +
      'Per-dispatch uid / worker-to-worker isolation is NOT shipped. ' +
      'NAS-259 variant 2: per-worktree ACL is applied at worktree-create; ' +
      'NAS-266 gitdir-pointer guard runs before 997 git.',
  };
}

/**
 * Convenience: home dir helper for tests.
 */
export function defaultHomeDir() {
  return os.homedir();
}
