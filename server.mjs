#!/usr/bin/env node
// orca-mcp — external MCP server for Orca CLI (+ optional Hindsight proxy).
//
// What this is: a minimal MCP server (Streamable HTTP, JSON-RPC 2.0) with zero
// external dependencies. Runs next to Orca on the host; publish outward via
// Tailscale Funnel. Hyperagent registers it as a custom MCP.
//
// Design decisions (see docs/design.md):
//  - Zero npm deps: `node server.mjs`.
//  - Spawns ONLY the orca binary (execFile, no shell).
//  - Parses orca --json envelope from stdout lines (banner may precede it;
//    envelope beats exit code; unreadable envelope + exit 0 trusts exit code).
//  - Auth: Bearer token OR path prefix /t/<token>/…
//  - Listens on 127.0.0.1 only; publish via funnel/proxy, not raw port forward.
//
// Launch:
//   ORCA_BRIDGE_TOKEN=<hex> node server.mjs [--port 8787]          # Streamable HTTP (default)
//   ORCA_BRIDGE_TOKEN=<hex> node server.mjs --stdio               # local MCP hosts (Claude Desktop / Cursor / VS Code)
// Env:
//   ORCA_BRIDGE_TOKEN  — required; refuse to start if missing/short
//   ORCA_CLI_COMMAND   — override orca binary (see Orca docs / docs/design.md#orca-binary-resolution)
//   ORCA_BRIDGE_DEFAULT_REPO — default --repo for dispatch (path:/… or name:…)
//   ORCA_BRIDGE_SENDER_TERMINAL / ORCA_BRIDGE_FROM — pin headless orchestration sender
//   ORCA_BRIDGE_SENDER_TITLE — title for auto-created coordinator tab (default orca-bridge-coordinator)
//   ORCA_BRIDGE_SENDER_SHARED=1 — force all clients onto the env pin (single-tenant; multi-coord OFF)
//   ORCA_BRIDGE_STORE_SIGNER_SOCKET — unix socket of the separate-uid store signer (NAS-249/253)
//   ORCA_BRIDGE_STORE_SIGNER_KEY    — in-process HMAC key for tests/isolated HOME only (never production)
//   HINDSIGHT_URL      — proxy target (default http://127.0.0.1:8888; HTTP mode)
//   PORT               — listen port (default 8787; --port wins; HTTP mode only)
//
// 0.2.11+: each OAuth client / MCP session gets its own durable sender
// terminal; orchestration mutations for one client are serialized.
// See docs/design.md#sender-pinning.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile as execFileCb, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { URL, fileURLToPath } from 'node:url';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createInterface } from 'node:readline';
import {
  deriveClientKey,
  senderTitleForClient,
  shouldUseSharedSenderPin,
  partitionMailbox,
  releaseRefusesCoordinator,
  senderPinPlan,
  createSerialLockMap,
} from './lib/orch-isolation.mjs';
import {
  ORCH_FROM_CMDS,
  CHECK_WAIT_DEFAULT_MS,
  CHECK_WAIT_MAX_MS,
  DEFAULT_WAIT_TYPES,
  b64url,
  pkceOk,
  tokenMatches as tokenMatchesCore,
  extractBearer,
  injectSenderArgv,
  buildTerminalSendArgv,
  parseOrchestrationReplyArgv,
  resolveWorkerDispatchId,
  buildEscalationReplyFollowupSendArgv,
  replyEnvelopeIsQuestionAnswer,
  isStaleDeliveryError,
  explainStaleDeliveryError,
} from './lib/security-core.mjs';
import {
  createCliPolicy,
  resolveCliPolicyConfig,
} from './lib/cli-policy.mjs';
import { createToolsetGate } from './lib/toolsets.mjs';
import {
  buildCoordinatorGuide,
  buildToolDescription,
  buildActionPropertyDescription,
  buildArgsPropertyDescription,
  buildWaitMsPropertyDescription,
} from './lib/coordinator-doctrine.mjs';
import {
  versionGte,
  RuntimeGuardError,
  createRuntimeProbeCache,
  assertRuntimeReady,
  compactHealthPayload,
  computeLiveness,
  nextStepForLiveness,
  pickLastActivityAt,
  isDeadRuntimeSignal,
  deadRuntimeFailure,
  HEALTH_DIAGNOSTICS_HINT,
} from './lib/runtime-guard.mjs';

import {
  ORCA_TOOL_ANNOTATIONS,
  ACTION_ANNOTATIONS,
  ORCA_OUTPUT_SCHEMA,
  STRUCTURED_OUTPUT_ACTIONS,
  createAuditLog,
  createDispatchRegistry,
  listMcpResources,
  readMcpResource,
  resolveOrcaAction,
  redactValue,
} from './lib/audit.mjs';
import {
  STATE_FILE_MODE,
  stateOwnershipWarnings,
  writeFilePreservingOwner,
  resolveTerminalHandleOwnership,
  resolveDispatchOwnership,
  resolveWorktreeOwnership,
  resolveTaskOwnership,
  resolveRunOwnership,
  resolveGenericIdOwnership,
  resolvePageOwnership,
  resolveRepoOwnership,
  listOwnedTerminalHandles,
  applyOwnershipListRedaction,
} from './lib/state-ownership.mjs';
import {
  resolveStoreSigner,
  readSignedJsonFile,
  writeSignedJsonFile,
  SIGNED_STORE_MISSING,
} from './lib/store-signer.mjs';
import { executeReleaseWorker } from './lib/release-worker.mjs';
import {
  resolveWorkerIsolationConfig,
  planIsolatedAgentPlacement,
  buildIsolatedTerminalCreateArgv,
  mintWorkerCapability,
  verifyWorkerCapability,
  workerCapabilityEnv,
  workerIsolationHealth,
} from './lib/worker-isolation.mjs';
import {
  capStagePath,
  capPurgeMarkerPath,
  capFilePath,
  serializeWorkerCapFile,
  SEED_HELPER,
  DEFAULT_BRIDGE_ORIGIN,
} from './lib/worker-cap-file.mjs';
import {
  parseWorkerOrchArgv,
  authorizeWorkerOrch,
  getArgFlag,
} from './lib/worker-orch-relay.mjs';
import { looksLikeAgentTui } from './lib/agent-tui.mjs';
import { summarizeMessages, nextStepForAwait, REJECTED_WORKER_DONE } from './lib/await-summary.mjs';
import { hardenIsolatedWorktree, inferExpectedGitdir } from './lib/worktree-acl.mjs';

const execFile = promisify(execFileCb);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'),
).version;
/** `--stdio` → NDJSON on stdin/stdout; default remains Streamable HTTP. */
const STDIO_MODE = process.argv.includes('--stdio');

/** Coordinators must refuse work if bridge reports version below this. */
const MIN_BRIDGE_VERSION = '0.2.0';
/** Protocol target for this bridge (stdio + HTTP). Roadmap: 2026-07-28 stateless HTTP. */
const PROTOCOL_TARGET = '2025-11-25';
const PROTOCOL_FALLBACK = PROTOCOL_TARGET;
const KNOWN_PROTOCOLS = new Set(['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25']);
const MAX_OUTPUT_CHARS = 30_000;      // tail of stdout/stderr returned in tool results
const MAX_BUFFER = 16 * 1024 * 1024;  // execFile maxBuffer
const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_TIMEOUT_MS = 570_000;       // under typical tunnel/platform minute caps
const WORKER_START_TIMEOUT_MS = 180_000; // agent TUI ready + inject
const SESSION_TTL_MS = 24 * 60 * 60_000;
const SSE_KEEPALIVE_MS = 15_000;
// Default repo for Hyperagent dispatches (optional). Example: path:/home/USER/repo
const DEFAULT_REPO = (process.env.ORCA_BRIDGE_DEFAULT_REPO || '').trim();
const DEFAULT_AGENT = (process.env.ORCA_BRIDGE_DEFAULT_AGENT || 'omp').trim() || 'omp';
// ORCA_BRIDGE_DEBUG=0 mutes the verbose access log (on by default).
const DEBUG_REQ = process.env.ORCA_BRIDGE_DEBUG !== '0';
// Headless bridge has no ORCA_TERMINAL_HANDLE. Orca ≤1.4.173 requires an explicit
// sender terminal (--from / check --terminal) for orchestration mutations.
// Prefer a per-client durable coordinator tab (pin-by-handle); optional env pin.
const SENDER_ENV = (
  process.env.ORCA_BRIDGE_SENDER_TERMINAL ||
  process.env.ORCA_BRIDGE_FROM ||
  ''
).trim();
const SENDER_TERMINAL_TITLE = (
  process.env.ORCA_BRIDGE_SENDER_TITLE || 'orca-bridge-coordinator'
).trim() || 'orca-bridge-coordinator';
/** When true, every client reuses ORCA_BRIDGE_SENDER_TERMINAL (single-tenant). */
const SENDER_SHARED = process.env.ORCA_BRIDGE_SENDER_SHARED === '1';
// Capability toolsets. Default = all tiers enabled (owner decision).
// ORCA_BRIDGE_TOOLSETS=status,dispatch  → restrict; --read-only → status only.
// Precedence: --read-only > ORCA_BRIDGE_TOOLSETS > default-all.
// ORCA_BRIDGE_CLI_ADMIN=1 unions admin into the enabled set (ignored under --read-only).
const TOOLSET_GATE = createToolsetGate({ env: process.env, argv: process.argv });
// NAS-255: dedicated worker uid (opt-in). Off by default — same-uid legacy.
const WORKER_ISOLATION = resolveWorkerIsolationConfig(process.env);
// CLI exact-form allowlist. Default ON (NAS-227).
// ORCA_BRIDGE_CLI_HARDENING=0|false|off restores warn-only migration posture.
// Admin unlock follows the effective toolset admin bit (toolset collapse).
// ownershipCheck / dispatchOwnershipCheck close over live maps (resolved at
// call time). client_key comes from requestContext via currentClientKey().
// NAS-248: ownership is a system invariant independent of the hardening flag.
// Hardening governs allowlisting only. action=release gates via requireOwned*.
const CLI_POLICY = createCliPolicy({
  ...resolveCliPolicyConfig(process.env),
  admin: TOOLSET_GATE.admin,
  onWarning: (warning) => {
    console.error(JSON.stringify({
      ts: new Date().toISOString(),
      component: 'orca-bridge',
      event: 'cli_policy_warning',
      ...warning,
    }));
  },
  ownershipCheck: (ctx) => resolveTerminalHandleOwnership(
    ctx.handle,
    currentClientKey(),
    {
      dispatchRegistry,
      clientOwnership,
      senderCaches,
      coordinatorHandles,
    },
  ),
  dispatchOwnershipCheck: (ctx) => resolveDispatchOwnership(
    ctx.dispatchId,
    currentClientKey(),
    {
      dispatchRegistry,
      clientOwnership,
    },
  ),
  worktreeOwnershipCheck: (ctx) => resolveWorktreeOwnership(
    ctx.worktree,
    currentClientKey(),
    {
      dispatchRegistry,
      clientOwnership,
      allowSyntheticCreate: ctx.allowSyntheticCreate === true,
    },
  ),
  taskOwnershipCheck: (ctx) => resolveTaskOwnership(
    ctx.taskId,
    currentClientKey(),
    {
      dispatchRegistry,
      clientOwnership,
    },
  ),
  runOwnershipCheck: (ctx) => resolveRunOwnership(
    ctx.runId,
    currentClientKey(),
    {
      dispatchRegistry,
      clientOwnership,
    },
  ),
  idOwnershipCheck: (ctx) => resolveGenericIdOwnership(
    ctx.id,
    currentClientKey(),
    {
      dispatchRegistry,
      clientOwnership,
    },
  ),
  pageOwnershipCheck: (ctx) => resolvePageOwnership(
    ctx.pageId,
    currentClientKey(),
    {},
  ),
  repoOwnershipCheck: (ctx) => resolveRepoOwnership(
    ctx.repo,
    currentClientKey(),
    {},
  ),
  parentWorktreeOwnershipCheck: (ctx) => resolveWorktreeOwnership(
    ctx.worktree,
    currentClientKey(),
    {
      dispatchRegistry,
      clientOwnership,
      allowSyntheticCreate: false,
    },
  ),
});
const SENDER_CACHE_TTL_MS = 15_000;
// ORCH_FROM_CMDS, CHECK_WAIT_*, DEFAULT_WAIT_TYPES imported from security-core.mjs

/** Request-scoped client identity (OAuth / session) for sender + orch lock. */
const requestContext = new AsyncLocalStorage();
function currentClientKey() {
  return requestContext.getStore()?.clientKey || 'default';
}

/** @type {Map<string, { handle: string, at: number, source: string, title?: string }>} */
const senderCaches = new Map();
/** Handles of bridge-owned coordinator sender tabs — never release/close these. */
const coordinatorHandles = new Set();
/**
 * Per-client ownership for mailbox filtering + run binding.
 * boundRunId/boundSender: last successful run-use for this client pin.
 * Skipping redundant run-use preserves consumer_generation so ack works (0.2.13).
 *
 * NAS-248 P0 #4: dispatch/terminal ownership is established only at dispatch
 * (or hydrate from durable store). await/check must never claim a dispatchId.
 * @type {Map<string, { runs: Set<string>, dispatches: Set<string>, workerHandles: Set<string>, boundRunId: string|null, boundSender: string|null }>}
 */
const clientOwnership = new Map();
const withClientOrchLock = createSerialLockMap();

function ownershipFor(clientKey) {
  const k = clientKey || currentClientKey();
  let reg = clientOwnership.get(k);
  if (!reg) {
    reg = {
      runs: new Set(),
      dispatches: new Set(),
      workerHandles: new Set(),
      tasks: new Set(),
      boundRunId: null,
      boundSender: null,
    };
    clientOwnership.set(k, reg);
  }
  return reg;
}

/**
 * Record in-memory ownership bits for a client.
 * When `clientKey` is omitted, uses the active request client.
 * runId-only calls (await/check rebind) do NOT claim dispatch ownership.
 */
function registerOwnedDispatch({ runId, dispatchId, terminalHandle, taskId, clientKey } = {}) {
  const reg = ownershipFor(clientKey || currentClientKey());
  if (runId) reg.runs.add(String(runId));
  if (dispatchId) reg.dispatches.add(String(dispatchId));
  if (terminalHandle) reg.workerHandles.add(String(terminalHandle));
  if (taskId) {
    if (!reg.tasks) reg.tasks = new Set();
    reg.tasks.add(String(taskId));
  }
}

function rememberCoordinatorHandle(handle) {
  if (handle) coordinatorHandles.add(String(handle));
}

function markRunBound(runId, senderHandle) {
  const reg = ownershipFor(currentClientKey());
  reg.boundRunId = runId ? String(runId) : null;
  reg.boundSender = senderHandle ? String(senderHandle) : null;
}

function isRunBound(runId, senderHandle) {
  const reg = ownershipFor(currentClientKey());
  return (
    Boolean(runId) &&
    Boolean(senderHandle) &&
    reg.boundRunId === String(runId) &&
    reg.boundSender === String(senderHandle)
  );
}

/** Persist pin handles across bridge restarts. */
const SENDER_PIN_STORE = path.join(os.homedir(), '.orca-bridge-sender-pins.json');

// Append-only audit log + in-memory dispatch/transcript registry for MCP resources.
// Override dir with ORCA_BRIDGE_AUDIT_DIR; default ~/.orca-bridge/audit.ndjson
const AUDIT_DIR = (process.env.ORCA_BRIDGE_AUDIT_DIR || '').trim()
  || path.join(os.homedir(), '.orca-bridge');
/**
 * Separate-uid store signer (NAS-249 / NAS-253).
 * Socket path in production; ORCA_BRIDGE_STORE_SIGNER_KEY only for tests/isolated HOME.
 * Not keyed on runtimeId — bindings survive bridge and runtime restarts.
 */
const storeSigner = resolveStoreSigner();
if (!storeSigner) {
  console.error(
    'WARN: no store signer configured (set ORCA_BRIDGE_STORE_SIGNER_SOCKET or ' +
      'ORCA_BRIDGE_STORE_SIGNER_KEY); pin/ownership store writes will fail closed',
  );
}

/**
 * Load sender pins. File must be signed by the store signer (NAS-253).
 * Unsigned / foreign-key / corrupt → reject entire file (empty pins), not warn-and-accept.
 */
async function loadPersistedPins() {
  try {
    if (!storeSigner) {
      if (fs.existsSync(SENDER_PIN_STORE)) {
        console.error('WARN: sender pins rejected: store signer unavailable');
      }
      return 0;
    }
    const res = await readSignedJsonFile(SENDER_PIN_STORE, storeSigner);
    if (!res.ok) {
      if (res.reason === SIGNED_STORE_MISSING) return 0;
      console.error(
        `WARN: sender pins rejected (${res.reason}${res.error ? `: ${res.error}` : ''}); ` +
          'unsigned/corrupt/foreign-key store is not loaded',
      );
      return 0;
    }
    const raw = res.payload;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      console.error('WARN: sender pins rejected: malformed payload');
      return 0;
    }
    let n = 0;
    for (const [k, v] of Object.entries(raw)) {
      if (v && typeof v.handle === 'string' && v.handle) {
        senderCaches.set(k, {
          handle: v.handle,
          at: 0,
          source: 'persisted',
          title: v.title || undefined,
        });
        rememberCoordinatorHandle(v.handle);
        n += 1;
      }
    }
    return n;
  } catch (e) {
    console.error('WARN: sender pins rejected:', e.message);
    return 0;
  }
}

async function persistSenderPin(clientKey, { handle, title, source } = {}) {
  if (!clientKey || !handle) return;
  if (!storeSigner) {
    console.error('WARN: cannot persist sender pin: store signer unavailable');
    return;
  }
  // Read-merge current signed store; reject unsigned so a forged base cannot be extended.
  let all = {};
  try {
    const existing = await readSignedJsonFile(SENDER_PIN_STORE, storeSigner);
    if (existing.ok && existing.payload && typeof existing.payload === 'object' && !Array.isArray(existing.payload)) {
      all = { ...existing.payload };
    } else if (existing.reason && existing.reason !== SIGNED_STORE_MISSING) {
      console.error(
        `WARN: sender pin store unreadable for merge (${existing.reason}); writing sole pin for ${clientKey}`,
      );
      all = {};
    }
  } catch {
    all = {};
  }
  all[clientKey] = {
    handle: String(handle),
    title: title || null,
    source: source || null,
    at: new Date().toISOString(),
  };
  try {
    const res = await writeSignedJsonFile(SENDER_PIN_STORE, all, storeSigner);
    if (!res.ok) {
      console.error(
        `WARN: cannot persist sender pin (${res.reason}${res.error ? `: ${res.error}` : ''})`,
      );
      return;
    }
    if (res.write && res.write.chownError) {
      console.error(`WARN: sender pin store owner not restored (${res.write.chownError}); ` +
        `chown it back to the service user or the bridge loses its pins after restart`);
    }
  } catch (e) {
    console.error('WARN: cannot persist sender pin:', e.message);
  }
}

const auditLog = createAuditLog({ dir: AUDIT_DIR });
const dispatchRegistry = createDispatchRegistry();

/**
 * Durable dispatch ownership bindings (NAS-248 P0 #4 + NAS-249).
 * Survives bridge process restart so coordinators can still release workers they
 * legitimately dispatched. Never written from await/check claim paths — only from
 * dispatch-time bindOwner / hydrate. Not keyed on runtimeId. HMAC-signed via the
 * separate-uid store signer — unsigned/forged files are rejected on load.
 */
const OWNERSHIP_STORE = path.join(AUDIT_DIR, 'dispatch-ownership.json');

async function persistOwnershipBindings() {
  if (!storeSigner) {
    console.error('WARN: cannot persist dispatch ownership: store signer unavailable');
    return;
  }
  try {
    if (!fs.existsSync(AUDIT_DIR)) {
      fs.mkdirSync(AUDIT_DIR, { recursive: true, mode: 0o700 });
    }
    const payload = {
      version: 1,
      updatedAt: new Date().toISOString(),
      bindings: dispatchRegistry.listOwnershipBindings(),
    };
    const res = await writeSignedJsonFile(OWNERSHIP_STORE, payload, storeSigner);
    if (!res.ok) {
      console.error(
        `WARN: cannot persist dispatch ownership (${res.reason}${res.error ? `: ${res.error}` : ''})`,
      );
      return;
    }
    if (res.write && res.write.chownError) {
      console.error(
        `WARN: ownership store owner not restored (${res.write.chownError}); ` +
          `chown it back to the service user or release-after-restart will fail closed`,
      );
    }
  } catch (e) {
    console.error('WARN: cannot persist dispatch ownership:', e.message);
  }
}

/**
 * Hydrate registry + clientOwnership from durable bindings after process restart.
 * bindOwner refuses reassignment — first writer wins.
 * File must verify under the store signer (NAS-249); forge → zero bindings.
 */
async function loadPersistedOwnership() {
  try {
    if (!storeSigner) {
      if (fs.existsSync(OWNERSHIP_STORE)) {
        console.error('WARN: dispatch ownership rejected: store signer unavailable');
      }
      return 0;
    }
    const res = await readSignedJsonFile(OWNERSHIP_STORE, storeSigner);
    if (!res.ok) {
      if (res.reason === SIGNED_STORE_MISSING) return 0;
      console.error(
        `WARN: dispatch ownership rejected (${res.reason}${res.error ? `: ${res.error}` : ''}); ` +
          'unsigned/corrupt/foreign-key store is not loaded',
      );
      return 0;
    }
    const raw = res.payload;
    const bindings = Array.isArray(raw?.bindings)
      ? raw.bindings
      : Array.isArray(raw)
        ? raw
        : [];
    let n = 0;
    for (const b of bindings) {
      if (!b || typeof b !== 'object') continue;
      const dispatchId = b.dispatchId != null ? String(b.dispatchId).trim() : '';
      const clientKey = b.clientKey != null ? String(b.clientKey).trim() : '';
      if (!dispatchId || !clientKey) continue;
      const bound = dispatchRegistry.bindOwner(dispatchId, {
        status: b.status || 'running',
        runId: b.runId || null,
        taskId: b.taskId || null,
        terminalHandle: b.terminalHandle || null,
        clientKey,
        agent: b.agent || null,
        worktree: b.worktree || null,
        name: b.name || null,
        dispatchedAt: b.dispatchedAt || null,
        lastActivityAt: b.lastActivityAt || b.dispatchedAt || null,
        source: 'persisted',
        ...(b.workerIsolation === true || b.workerIsolation === false
          ? { workerIsolation: b.workerIsolation }
          : {}),
        ...(b.workerCapabilityMinted === true || b.workerCapabilityMinted === false
          ? { workerCapabilityMinted: b.workerCapabilityMinted }
          : {}),
      });
      if (!bound.ok) continue;
      registerOwnedDispatch({
        runId: b.runId || null,
        dispatchId,
        terminalHandle: b.terminalHandle || null,
        taskId: b.taskId || null,
        clientKey,
      });
      n += 1;
    }
    return n;
  } catch (e) {
    console.error('WARN: dispatch ownership rejected:', e.message);
    return 0;
  }
}

/**
 * Authoritative dispatch-time ownership bind + durable persist.
 * The only path that may create a clientKey binding for a dispatch id.
 */
async function bindOwnedDispatch({
  runId,
  dispatchId,
  terminalHandle,
  taskId,
  status = 'running',
  agent = null,
  worktree = null,
  name = null,
  clientKey,
  extra = {},
} = {}) {
  const ck = clientKey || currentClientKey();
  const id = dispatchId != null ? String(dispatchId).trim() : '';
  if (!id) {
    // No dispatch id yet — track run/handle/task only (not a claimable ownership row).
    registerOwnedDispatch({ runId, terminalHandle, taskId, clientKey: ck });
    return { ok: true, claimed: false };
  }
  const bound = dispatchRegistry.bindOwner(id, {
    status,
    runId: runId || null,
    taskId: taskId || null,
    terminalHandle: terminalHandle || null,
    clientKey: ck,
    agent,
    worktree,
    name,
    dispatchedAt: extra.dispatchedAt || new Date().toISOString(),
    lastActivityAt: extra.lastActivityAt || new Date().toISOString(),
    emptyWindowsConsecutive: 0,
    ...extra,
  });
  if (!bound.ok) {
    return bound;
  }
  registerOwnedDispatch({
    runId,
    dispatchId: id,
    terminalHandle,
    taskId,
    clientKey: ck,
  });
  await persistOwnershipBindings();
  return bound;
}

// Top-level await is valid in this ESM module; hydrate before accepting traffic.
await loadPersistedPins();
const _ownershipHydrated = await loadPersistedOwnership();
if (_ownershipHydrated > 0) {
  console.error(`orca-bridge: restored ${_ownershipHydrated} durable dispatch ownership binding(s)`);
}

/** Marker so we do not double-append the worker_done contract to specs. */
const WORKER_CONTRACT_MARKER = '<!-- orca-bridge-worker-contract -->';
const WORKER_CONTRACT_BLOCK =
  `${WORKER_CONTRACT_MARKER}\n` +
  'On completion: emit exactly one worker_done with --outcome succeeded|failed and a concise 3-sentence body. ' +
  'Do not close the terminal yourself — the coordinator releases it.\n' +
  'For a blocking coordinator answer use orchestration ask (not send --type escalation + check). ' +
  'Escalation notifies the coordinator; a bridge dual-routes reply onto dispatch:<id> so worker check can see it.\n';

/**
 * Append the supervised completion contract unless already present.
 * Coordinator briefs can omit the boilerplate; bridge enforces it.
 */
function withWorkerContract(spec) {
  const s = String(spec || '').trim();
  if (!s) return s;
  if (s.includes(WORKER_CONTRACT_MARKER)) return s;
  return `${s}\n\n${WORKER_CONTRACT_BLOCK}`;
}


// versionGte / parseSemver live in lib/runtime-guard.mjs (unit-tested).


/** Long discipline docs for coordinators (also generated into COORDINATOR.md). */
function coordinatorGuide() {
  return buildCoordinatorGuide({ version: VERSION, minVersion: MIN_BRIDGE_VERSION });
}

// Allow `orca-mcp --version` / `-V` without requiring auth (install smoke checks).
if (process.argv.includes('--version') || process.argv.includes('-V')) {
  process.stdout.write(`${VERSION}\n`);
  process.exit(0);
}

const TOKEN = process.env.ORCA_BRIDGE_TOKEN || '';
if (!TOKEN || TOKEN.length < 16) {
  console.error('FATAL: set ORCA_BRIDGE_TOKEN (>=16 chars), e.g. `openssl rand -hex 32`');
  process.exit(1);
}
const HINDSIGHT_URL = new URL(process.env.HINDSIGHT_URL || 'http://127.0.0.1:8888');
const startedAt = Date.now();
/** Lazy runtime probe cache (NAS-246) — TTL'd status for dispatch/await/release. */
const runtimeProbeCache = createRuntimeProbeCache();


// Public origin for OAuth discovery/endpoints. Set to the Funnel host.
// When unset, endpoints are built from the request Host header.
// See docs/design.md#public-origin-and-open-redirect.
const PUBLIC_ORIGIN = (process.env.ORCA_BRIDGE_PUBLIC_ORIGIN || '').replace(/\/$/, '');
// Allowed post-authorize redirect prefixes (open-redirect protection).
const REDIRECT_ALLOW = (process.env.ORCA_BRIDGE_REDIRECT_ALLOW || 'https://hyperagent.com/')
  .split(',').map((s) => s.trim()).filter(Boolean);

// --- OAuth 2.0 (PKCE) state -------------------------------------------------
// Bridge is its own authorization server + resource server. A human enters the
// master token on /authorize (browser, not the MCP client settings form).
// Hyperagent gets a separate revocable access token. Issued tokens persist so
// a bridge restart does not force re-pairing. See docs/design.md#oauth-and-session-auth.
const TOKEN_STORE = path.join(os.homedir(), '.orca-bridge-tokens.json');
const AUTH_CODE_TTL_MS = 5 * 60_000;
const authCodes = new Map(); // code -> {codeChallenge, method, redirectUri, clientId, expiresAt}
let issuedTokens = new Set();
// Streamable HTTP sessions (Mcp-Session-Id). After initialize the client sends
// the id on every request; some clients omit Authorization on GET SSE — a
// valid session alone is enough for auth (see authenticate / docs/design.md#sessions).
const sessions = new Map(); // id -> { createdAt, lastSeen, authKind }
try {
  if (fs.existsSync(TOKEN_STORE)) issuedTokens = new Set(JSON.parse(fs.readFileSync(TOKEN_STORE, 'utf8')));
} catch { /* empty / unreadable store */ }
function persistTokens() {
  try {
    // Ownership-preserving write: if this process is root (upgrade script,
    // migration) the store must stay owned by the service user, otherwise the
    // unit silently loses read+write on its own tokens (NAS-241).
    const res = writeFilePreservingOwner(TOKEN_STORE, JSON.stringify([...issuedTokens]), {
      mode: STATE_FILE_MODE,
    });
    if (res.chownError) {
      console.error(`WARN: token store owner not restored (${res.chownError}); ` +
        `run \`chown\` back to the service user or clients will need to re-authorize`);
    }
  } catch (e) { console.error('WARN: cannot persist tokens:', e.message); }
}
function pruneCodes() {
  const now = Date.now();
  for (const [c, v] of authCodes) if (v.expiresAt < now) authCodes.delete(c);
}
function newSessionId() {
  return b64url(randomBytes(18));
}
function touchSession(id) {
  const s = sessions.get(id);
  if (!s) return null;
  if (Date.now() - s.createdAt > SESSION_TTL_MS) {
    sessions.delete(id);
    return null;
  }
  s.lastSeen = Date.now();
  return s;
}
function pruneSessions() {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now - s.createdAt > SESSION_TTL_MS || now - s.lastSeen > SESSION_TTL_MS) sessions.delete(id);
  }
}
function sessionIdFrom(req) {
  const h = req.headers['mcp-session-id'];
  if (typeof h === 'string' && h) return h.trim();
  if (Array.isArray(h) && h[0]) return String(h[0]).trim();
  return '';
}
function headerHas(req, name) {
  const v = req.headers[name];
  if (v == null) return false;
  if (Array.isArray(v)) return v.some((x) => String(x).trim() !== '');
  return String(v).trim() !== '';
}
/** Access log without secrets: method, path (token redacted), auth/accept/session flags. */
function logRequest(req, extra = '') {
  if (!DEBUG_REQ) return;
  const raw = (req.url || '/').split('?')[0];
  const pathLog = raw.replace(/^\/t\/[^/]+/, '/t/<token>');
  const accept = String(req.headers['accept'] || '');
  const acceptShort = accept
    ? accept.split(',').map((s) => s.trim().split(';')[0]).filter(Boolean).slice(0, 4).join(',')
    : '-';
  const sid = sessionIdFrom(req);
  const bits = [
    req.method || '?',
    pathLog,
    `auth=${headerHas(req, 'authorization') ? '1' : '0'}`,
    `sid=${sid ? '1' : '0'}`,
    `accept=${acceptShort}`,
  ];
  if (extra) bits.push(extra);
  log(bits.join(' '));
}
function redirectAllowed(uri) {
  try { return REDIRECT_ALLOW.some((p) => uri.startsWith(p)); } catch { return false; }
}
function originFor(req) {
  if (PUBLIC_ORIGIN) return PUBLIC_ORIGIN;
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const proto = req.headers['x-forwarded-proto'] || 'https';
  return `${proto}://${host}`;
}

// --- Resolve orca binary (Orca docs rule) -----------------------------------
// ORCA_CLI_COMMAND if set; else on Linux outside an Orca terminal → orca-ide
// (bare `orca` on Linux is the GNOME screen reader); else → orca.
// See docs/design.md#orca-binary-resolution.
function orcaBinary() {
  if (process.env.ORCA_CLI_COMMAND) return process.env.ORCA_CLI_COMMAND;
  return process.platform === 'linux' ? 'orca-ide' : 'orca';
}

// --- CLI transport: runOrcaCli contract from orca_terminal.mjs --------------
// Never throws on non-zero exit; failed spawn is spawnError (error.code string),
// CLI exit is a number. See docs/design.md#envelope-parsing-quirks.
async function runOrca(args, { timeoutMs = DEFAULT_TIMEOUT_MS, cwd } = {}) {
  try {
    const { stdout, stderr } = await execFile(orcaBinary(), args, {
      timeout: Math.min(timeoutMs, MAX_TIMEOUT_MS),
      maxBuffer: MAX_BUFFER,
      cwd: cwd || process.env.HOME,
    });
    return { code: 0, stdout: stdout || '', stderr: stderr || '' };
  } catch (error) {
    if (typeof error?.code === 'string') {
      return { code: null, stdout: error.stdout || '', stderr: error.stderr || '', spawnError: error.code };
    }
    return {
      code: typeof error?.code === 'number' ? error.code : null,
      stdout: error?.stdout || '',
      stderr: error?.stderr || '',
      timedOut: error?.killed === true || undefined,
    };
  }
}

// --- Parse --json envelope (adapted from orca_terminal.mjs) -----------------
function findEnvelopeBody(stdout) {
  const whole = String(stdout).trim();
  if (!whole) return null;
  const candidates = [whole, ...whole.split('\n').map((l) => l.trim()).reverse()];
  for (const candidate of candidates) {
    if (!candidate.startsWith('{')) continue;
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && typeof parsed === 'object') return parsed;
    } catch { /* not an envelope — try previous candidate */ }
  }
  return null;
}

function tail(s) {
  const str = String(s || '');
  return str.length > MAX_OUTPUT_CHARS ? `…[truncated ${str.length - MAX_OUTPUT_CHARS} chars]…` + str.slice(-MAX_OUTPUT_CHARS) : str;
}

function describeRun(run, wantJson) {
  const out = {
    exitCode: run.code,
    spawnError: run.spawnError,
    timedOut: run.timedOut,
  };
  if (run.spawnError === 'ENOENT') {
    out.error = `orca CLI not found (binary: ${orcaBinary()})`;
    return out;
  }
  if (wantJson) {
    const body = findEnvelopeBody(run.stdout);
    if (body) {
      // Envelope is authoritative over the process exit code.
      out.envelope = body;
      out.ok = body.ok === true;
      if (run.stderr) out.stderrTail = tail(run.stderr);
      return out;
    }
    out.envelopeMissing = true; // broken transport or a command without envelopes
  }
  out.ok = run.code === 0 && !run.spawnError && !run.timedOut;
  out.stdout = tail(run.stdout);
  out.stderr = tail(run.stderr);
  return out;
}

/** True when argv requests JSON (`--json`, `--json=true`, `--json=`). */
function argvWantsJson(args) {
  if (!Array.isArray(args)) return false;
  for (const a of args) {
    const tok = String(a);
    if (tok === '--json') return true;
    if (tok.startsWith('--json=')) return true;
  }
  return false;
}

/**
 * NAS-252 output parity: human stdout cannot be structurally walked.
 * Inject --json on spawn for commands whose responses may carry foreign content
 * so applyOwnershipListRedaction always sees an envelope/JSON body.
 */
function ensureWalkableCliArgv(args) {
  if (!Array.isArray(args)) return args;
  if (argvWantsJson(args)) return args;
  return [...args, '--json'];
}


/**
 * NAS-248/250: strip foreign PTY content from action=cli responses.
 * Recursive content-key redaction (preview/scrollback/…) on any node whose
 * terminal handle is not proven owned. Mutates `described` in place.
 * Never call from runJson internals (resolveSenderTerminal needs full inventory).
 *
 * @param {object} described
 * @param {string[]} [_args] retained for call-site compatibility; ignored
 * @param {Iterable<string>|Set<string>} [ownedHandles]
 */
function applyCliOwnershipRedaction(described, _args, ownedHandles) {
  if (!described || typeof described !== 'object') return described;
  const owned =
    ownedHandles ??
    listOwnedTerminalHandles(currentClientKey(), {
      dispatchRegistry,
      clientOwnership,
      senderCaches,
      coordinatorHandles,
    });
  return applyOwnershipListRedaction(described, owned);
}



/**
 * Lazy runtime/version gate for dispatch/await/release (NAS-246).
 * Uses TTL cache so waves do not re-probe every call.
 * Throws RuntimeGuardError with code/reason/recovery.
 */
async function ensureRuntimeReady({ force = false } = {}) {
  // Bridge process version is local — always check, no I/O.
  assertRuntimeReady({ version: VERSION, minVersion: MIN_BRIDGE_VERSION });

  if (!force) {
    const cached = runtimeProbeCache.get();
    if (cached) {
      assertRuntimeReady({ version: VERSION, minVersion: MIN_BRIDGE_VERSION, probe: cached });
      return cached;
    }
  }

  const run = await runOrca(['status', '--json'], { timeoutMs: 15_000 });
  const probe = describeRun(run, true);
  // Cache both success and failure briefly so a dead runtime does not stampede.
  runtimeProbeCache.set(probe);
  assertRuntimeReady({ version: VERSION, minVersion: MIN_BRIDGE_VERSION, probe });
  return probe;
}

/** Best-effort map RuntimeGuardError (or unknown) to a structured tool result. */
function runtimeGuardRejection(err) {
  if (err instanceof RuntimeGuardError) return err.toJSON();
  return {
    ok: false,
    error: {
      code: 'runtime_unavailable',
      message: String(err?.message || err),
      reason: String(err?.message || err),
      recovery: `Retry once; if it persists, ${HEALTH_DIAGNOSTICS_HINT}`,
    },
    next: { action: 'diagnose', detail: 'Unexpected runtime error before supervised action.' },
  };
}

/** Prefer structured runtime_unavailable when a step shows a dead CLI/runtime. */
function maybeDeadRuntime(described, ctx = {}) {
  if (!isDeadRuntimeSignal(described)) return null;
  return deadRuntimeFailure(described, ctx);
}


// --- Helpers: orchestration envelopes ---------------------------------------
function envOk(described) {
  return described && described.ok === true && described.envelope;
}
function pick(obj, ...keys) {
  if (!obj || typeof obj !== 'object') return undefined;
  for (const k of keys) {
    if (obj[k] != null && obj[k] !== '') return obj[k];
  }
  return undefined;
}
function msgType(m) {
  return String(pick(m, 'type', 'messageType', 'kind') || '').toLowerCase();
}

/**
 * NAS-239: after a successful non-question orchestration reply, dual-route the
 * body onto dispatch:<id>. Orca's native reply targets the worker terminal
 * handle with type=status; workers with an active Dispatch read dispatch:<id>.
 * Question answers already land on dispatch via question_threads — skip those.
 */
async function dualRouteNonQuestionReply(argv, replyDescribed) {
  const parsed = parseOrchestrationReplyArgv(argv);
  if (!parsed || !parsed.ok) return null;
  if (!replyDescribed || replyDescribed.ok === false) return null;
  const env = replyDescribed.envelope || {};
  if (env.ok === false) return null;
  if (replyEnvelopeIsQuestionAnswer(env)) {
    return { skipped: true, reason: 'question_answer_already_on_dispatch' };
  }

  const result = env.result && typeof env.result === 'object' ? env.result : env;
  const replyMessage = result.message || result;

  // Prefer payload/dispatch on the original escalation (inbox / worker-show).
  let originalMessage = null;
  try {
    const inbox = await runJson(
      ['orchestration', 'inbox', '--full', '--limit', '100', '--json'],
      { timeoutMs: 20_000 },
    );
    const messages =
      inbox.envelope?.result?.messages ||
      inbox.envelope?.messages ||
      inbox.envelope?.result ||
      [];
    if (Array.isArray(messages)) {
      originalMessage =
        messages.find((m) => pick(m, 'id', 'messageId', 'message_id') === parsed.id) || null;
    }
  } catch {
    /* best-effort */
  }

  let workers = [];
  try {
    const listed = await runJson(['orchestration', 'worker-list', '--json'], { timeoutMs: 20_000 });
    workers =
      listed.envelope?.result?.workers ||
      listed.envelope?.workers ||
      [];
    if (!Array.isArray(workers)) workers = [];
  } catch {
    workers = [];
  }

  const dispatchId = resolveWorkerDispatchId({
    originalMessage,
    replyMessage,
    workers,
  });
  if (!dispatchId) {
    return {
      skipped: true,
      reason: 'dispatch_id_unresolved',
      reply_to: pick(replyMessage, 'to_handle', 'to') || null,
      original_id: parsed.id,
    };
  }

  // If native reply already targeted dispatch:<id>, do not double-send.
  const nativeTo = String(pick(replyMessage, 'to_handle', 'to') || '');
  if (nativeTo === `dispatch:${dispatchId}` || nativeTo === dispatchId) {
    return { skipped: true, reason: 'native_reply_already_on_dispatch', dispatchId };
  }

  const subject =
    pick(replyMessage, 'subject', 'title') ||
    (originalMessage
      ? `Re: ${pick(originalMessage, 'subject', 'title') || 'escalation'}`
      : 'Re: escalation');
  const threadId =
    pick(replyMessage, 'thread_id', 'threadId') ||
    pick(originalMessage || {}, 'thread_id', 'threadId', 'id') ||
    parsed.id;
  const body =
    parsed.body != null
      ? parsed.body
      : pick(replyMessage, 'body', 'text', 'content') || '';
  const runId =
    parsed.run ||
    pick(replyMessage, 'run_id', 'runId') ||
    pick(originalMessage || {}, 'run_id', 'runId') ||
    null;
  const from =
    parsed.from ||
    pick(replyMessage, 'from_handle', 'from') ||
    null;

  const sendArgv = buildEscalationReplyFollowupSendArgv({
    dispatchId,
    body,
    subject,
    threadId,
    runId,
    from: from && String(from).startsWith('run:') ? null : from,
  });
  const sendDescribed = await runJson(sendArgv, { timeoutMs: 30_000 });
  return {
    dual_routed: sendDescribed.ok !== false && sendDescribed.envelope?.ok !== false,
    dispatchId,
    send: sendDescribed.envelope || sendDescribed,
    reason: 'worker_dispatch_mailbox',
  };
}

function staleFromDescribed(described, ackId) {
  const env = described?.envelope || {};
  const err = env.error || {};
  return explainStaleDeliveryError({
    ackId,
    errorCode: err.code,
    errorMessage: err.message || err.code,
  });
}



/**
 * Resolve a live terminal handle the headless bridge can use as orchestration
 * sender/consumer. Orca 1.4.173 rejects run-create/task-create/dispatch/run-use
 * without ORCA_TERMINAL_HANDLE or --from; check needs --terminal.
 *
 * Per-client durable sender pin (handle is identity, not tab title).
 * Shell TUIs rewrite --title to "user@host: path", so title re-discovery would
 * create a second tab mid-wave and fence task-create (regression on 0.2.11).
 * Order: trust pin → revalidate pin → env → title best-effort → create once.
 */
async function resolveSenderTerminal({ force = false } = {}) {
  const clientKey = currentClientKey();
  const clientTitle = senderTitleForClient(SENDER_TERMINAL_TITLE, clientKey);
  const cached = senderCaches.get(clientKey);
  const plan = senderPinPlan(cached, {
    force,
    now: Date.now(),
    ttlMs: SENDER_CACHE_TTL_MS,
  });

  if (plan.mode === 'trust_cache') {
    return {
      handle: plan.handle,
      source: `${plan.source || cached?.source || 'cache'}+cache`,
      clientKey,
      title: cached?.title || clientTitle,
    };
  }

  async function accept(handle, source) {
    if (!handle) return null;
    const show = await runJson(
      ['terminal', 'show', '--terminal', handle, '--json'],
      { timeoutMs: 15_000, injectSender: false },
    );
    if (!envOk(show)) return null;
    const term = show.envelope?.result?.terminal || show.envelope?.result || {};
    if (term.connected === false || term.orphaned === true) return null;
    if (term.writable === false) return null;
    rememberCoordinatorHandle(handle);
    const title = term.title || clientTitle;
    senderCaches.set(clientKey, {
      handle,
      at: Date.now(),
      source,
      title,
    });
    // Persist so bridge restart reuses the same handle (keeps run binding).
    if (source === 'created' || source === 'pinned' || source === 'persisted' || source === 'title' || source === 'env' || source === 'env-shared' || source === 'title-suffix') {
      await persistSenderPin(clientKey, { handle, title, source });
    }
    return {
      handle,
      source,
      title,
      clientKey,
    };
  }

  // Durable pin: re-show the same handle after TTL. Never create a sibling while pin lives.
  if (plan.mode === 'revalidate_pin' && plan.handle) {
    const hit = await accept(plan.handle, 'pinned');
    if (hit) return hit;
    // Pin dead (closed/orphaned) — drop and resolve fresh.
    senderCaches.delete(clientKey);
  }

  if (shouldUseSharedSenderPin(clientKey, { senderEnv: SENDER_ENV, senderShared: SENDER_SHARED })) {
    const hit = await accept(SENDER_ENV, SENDER_SHARED ? 'env-shared' : 'env');
    if (hit) return hit;
  }

  const list = await runJson(['terminal', 'list', '--json'], {
    timeoutMs: 20_000,
    injectSender: false,
  });
  const terminals = envOk(list)
    ? (list.envelope?.result?.terminals || []).filter(
      (t) => t?.handle && t.connected !== false && t.writable !== false && !t.orphaned,
    )
    : [];

  // Best-effort title match only when we have no live pin (titles are often rewritten).
  const byExactTitle = terminals.find((t) => String(t.title || '') === clientTitle);
  if (byExactTitle) {
    const hit = await accept(byExactTitle.handle, 'title');
    if (hit) return hit;
  }
  // Suffix match: oauth/sid short id still visible in title if Orca preserved any of it.
  const short = clientKey.replace(/^(oauth|sid):/, '').slice(0, 10);
  if (short && clientTitle !== SENDER_TERMINAL_TITLE) {
    const bySuffix = terminals.find((t) => String(t.title || '').includes(short));
    if (bySuffix) {
      const hit = await accept(bySuffix.handle, 'title-suffix');
      if (hit) return hit;
    }
  }
  if (clientTitle === SENDER_TERMINAL_TITLE) {
    const byBase = terminals.find((t) => String(t.title || '').includes(SENDER_TERMINAL_TITLE));
    if (byBase) {
      const hit = await accept(byBase.handle, 'title');
      if (hit) return hit;
    }
  }

  // No discovery of random live terminals (mechanism A root cause: mid-wave recreate).
  // Create a durable coordinator shell tab dedicated to this client — once, then pin.
  let worktreeSel = null;
  if (DEFAULT_REPO) {
    worktreeSel = DEFAULT_REPO.includes(':')
      ? DEFAULT_REPO
      : (DEFAULT_REPO.startsWith('/') ? `path:${DEFAULT_REPO}` : DEFAULT_REPO);
  } else {
    const wtl = await runJson(['worktree', 'list', '--limit', '50', '--json'], {
      timeoutMs: 20_000,
      injectSender: false,
    });
    const wts = envOk(wtl) ? (wtl.envelope?.result?.worktrees || []) : [];
    const main = wts.find((w) => w.isMainWorktree) || wts[0];
    if (main?.path) worktreeSel = `path:${main.path}`;
    else if (main?.worktreeId) worktreeSel = `id:${main.worktreeId}`;
  }

  if (!worktreeSel) {
    throw new Error(
      'no_sender_terminal: no live Orca terminal and cannot create coordinator. ' +
      'Create any Orca terminal on this host, set ORCA_BRIDGE_SENDER_TERMINAL=term_…, ' +
      'or set ORCA_BRIDGE_DEFAULT_REPO so the bridge can create ' +
      `${clientTitle}.`,
    );
  }

  const created = await runJson(
    [
      'terminal', 'create',
      '--worktree', worktreeSel,
      '--title', clientTitle,
      '--json',
    ],
    { timeoutMs: 60_000, injectSender: false },
  );
  if (!envOk(created)) {
    throw new Error(
      `no_sender_terminal: create ${clientTitle} failed: ` +
      JSON.stringify(created.envelope?.error || created.error || created),
    );
  }
  const cr = created.envelope?.result || {};
  const handle =
    pick(cr, 'handle') ||
    pick(cr.terminal, 'handle') ||
    pick(cr, 'agentTerminalHandle') ||
    '';
  if (!handle) {
    throw new Error('no_sender_terminal: terminal create returned no handle');
  }
  rememberCoordinatorHandle(handle);
  senderCaches.set(clientKey, {
    handle,
    at: Date.now(),
    source: 'created',
    title: clientTitle,
  });
  await persistSenderPin(clientKey, { handle, title: clientTitle, source: 'created' });
  return { handle, source: 'created', clientKey, title: clientTitle };
}

/**
 * Inject sender identity for headless orchestration argv.
 * - mutations: --from <handle>
 * - check: --terminal <handle> (consumer identity; --from is invalid)
 */
async function withSender(argv) {
  if (!Array.isArray(argv) || argv.length < 2) return argv;
  if (argv[0] !== 'orchestration') return argv;
  const sub = argv[1];
  const needsFrom = ORCH_FROM_CMDS.has(sub);
  // NAS-252 r7 P0: inbox must hit the same pin path as check (spawn path, not just helper).
  const needsTerminal = sub === 'check' || sub === 'inbox';
  if (!needsFrom && !needsTerminal) return argv;

  const sender = await resolveSenderTerminal();
  return injectSenderArgv(argv, sender.handle);
}

async function runJson(argv, { timeoutMs, cwd, injectSender = true } = {}) {
  let finalArgv = argv;
  if (injectSender && Array.isArray(argv) && argv[0] === 'orchestration') {
    try {
      finalArgv = await withSender(argv);
    } catch (e) {
      const sub = argv[1];
      if (ORCH_FROM_CMDS.has(sub) || sub === 'check' || sub === 'inbox') {
        return {
          ok: false,
          envelope: {
            ok: false,
            error: {
              code: 'no_sender_terminal',
              message: String(e?.message || e),
            },
          },
          error: String(e?.message || e),
        };
      }
    }
  }
  const run = await runOrca(finalArgv, { timeoutMs, cwd });
  return describeRun(run, true);
}

function autoName(prefix = 'ha') {
  return `${prefix}-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** Snapshot terminal preview/tail for inject liveness. */
async function terminalSnapshot(handle) {
  const show = await runJson(['terminal', 'show', '--terminal', handle, '--json'], { timeoutMs: 20_000 });
  const read = await runJson(
    ['terminal', 'read', '--terminal', handle, '--limit', '80', '--json'],
    { timeoutMs: 20_000 },
  );
  const term = show.envelope?.result?.terminal || show.envelope?.result || {};
  const readTerm = read.envelope?.result?.terminal || read.envelope?.result || {};
  const preview = String(term.preview || '');
  const tail = Array.isArray(readTerm.tail) ? readTerm.tail.join('\n') : String(readTerm.text || '');
  const blob = `${preview}\n${tail}`;
  const turnsMatch = blob.match(/Turns:\s*(\d+)/i);
  const toolsMatch = blob.match(/Tool calls:\s*(\d+)/i);
  const turns = turnsMatch ? Number(turnsMatch[1]) : null;
  const toolCalls = toolsMatch ? Number(toolsMatch[1]) : null;
  const busyHint =
    /Waiting for response|Run Web search|Run tool|thinking|Compacting|Working|tool-call|⠋|⠙|⠹|⠸|⠼|⠴|⠦|⠧|⠇|⠏/i.test(blob);
  const idlePrompt =
    /Enter:send/i.test(blob) &&
    !busyHint &&
    (turns === 0 || turns === null) &&
    (toolCalls === 0 || toolCalls === null);
  const lastOutputAt = term.lastOutputAt || null;
  const title = String(term.title || term.name || readTerm.title || readTerm.name || '');
  return {
    ok: envOk(show),
    title,
    preview: preview.slice(-800),
    tailTail: tail.slice(-1200),
    turns,
    toolCalls,
    busyHint,
    idlePrompt,
    lastOutputAt,
    connected: term.connected === true,
    writable: term.writable === true,
  };
}

function looksWorking(snap) {
  if (!snap) return false;
  if (snap.busyHint) return true;
  if (typeof snap.turns === 'number' && snap.turns > 0) return true;
  if (typeof snap.toolCalls === 'number' && snap.toolCalls > 0) return true;
  return false;
}

/**
 * If inject did not land in TUI (common for grok: accepted but Turns:0 idle),
 * push the task text via terminal send + Enter, with worker_done recovery trailer.
 * There is no `--submit` flag. A shell target submits on the first `--enter`;
 * a Grok TUI draft buffer needs a following empty-text `--enter` (see below).
 */
async function ensureInjectLanded({ handle, taskId, dispatchId, spec, agent, workerCapability = null }) {
  const settleMs = Number(process.env.ORCA_BRIDGE_INJECT_SETTLE_MS || 10_000);
  const probes = [];
  await sleep(Math.min(Math.max(settleMs, 3_000), 25_000));
  let snap = await terminalSnapshot(handle);
  probes.push({ phase: 'post-inject', ...snap, working: looksWorking(snap) });

  if (looksWorking(snap)) {
    return { recovered: false, landed: true, probes };
  }

  // Still idle — send recovery prompt (spec + ids + worker_done contract)
  const capLine = workerCapability
    ? `Worker capability file is at /run/orca-mcp/worker-caps/<dispatchId>.json (uid 994, 0600). Use orca orchestration send as documented.\n`
    : '';
  const recovery =
    `${spec}\n\n` +
    `[coordinator inject-recovery] Dispatch inject may not have landed in this TUI (idle Turns:0). ` +
    `Treat this message as live task input.\n` +
    `task_id: ${taskId}\n` +
    `dispatch_id: ${dispatchId || '(unknown)'}\n` +
    `agent: ${agent}\n` +
    capLine +
    `When finished, send exactly one worker_done (do not paste a shell one-liner).\n` +
    `# example: orca orchestration send --from ${handle} --type worker_done --subject "done" --body "three sentences" ` +
    `--task-id ${taskId}` +
    (dispatchId ? ` --dispatch-id ${dispatchId}` : '') +
    ` --outcome succeeded --json\n` +
    `On failure use --outcome failed. Do not close the terminal.`;

  // Wait for idle readiness before send
  const idleWait = await runJson(
    ['terminal', 'wait', '--terminal', handle, '--for', 'tui-idle', '--timeout-ms', '30000', '--json'],
    { timeoutMs: 45_000 },
  );

  const sendRes = await runJson(
    buildTerminalSendArgv({ handle, text: recovery, enter: true }),
    { timeoutMs: 30_000 },
  );
  // Shell target submits on the first --enter. A Grok TUI draft buffer
  // needs the second empty-text --enter to leave compose (verified live
  // 2026-08-15: --text <payload> --enter left the brief sitting in the
  // box; only a subsequent bare CR submitted it). The second send is
  // harmless when redundant (plain bash already submitted on the first).
  await sleep(800);
  const enterRes = await runJson(
    buildTerminalSendArgv({ handle, text: '', enter: true }),
    { timeoutMs: 15_000 },
  );

  await sleep(5_000);
  snap = await terminalSnapshot(handle);
  probes.push({
    phase: 'post-recovery',
    ...snap,
    working: looksWorking(snap),
    idleWaitOk: envOk(idleWait),
    sendOk: envOk(sendRes),
    enterOk: envOk(enterRes),
    send: sendRes.envelope?.result || null,
  });

  return {
    recovered: true,
    landed: looksWorking(snap) || envOk(sendRes),
    probes,
  };
}

function workerBridgeOrigin() {
  const port = Number(process.env.ORCA_BRIDGE_PORT || process.env.PORT || 8787);
  if (Number.isInteger(port) && port > 0 && port < 65536) {
    return `http://127.0.0.1:${port}`;
  }
  return DEFAULT_BRIDGE_ORIGIN;
}

async function sudoSeedWorkerCreds() {
  await execFile('sudo', ['-n', SEED_HELPER, 'seed']);
}

async function writeAtomic0600(dest, body) {
  await fs.promises.mkdir(path.dirname(dest), { recursive: true, mode: 0o700 });
  const tmp = `${dest}.tmp.${process.pid}`;
  await fs.promises.writeFile(tmp, body, { mode: 0o600, flag: 'w' });
  await fs.promises.chmod(tmp, 0o600);
  await fs.promises.rename(tmp, dest);
}

/**
 * Mint HMAC capability, write a 997-owned staging file, then invoke the
 * existing `seed` sudoers verb so root materializes 994:994 0600 files.
 * workerCapabilityEnv() is the field map — this is what makes that helper live.
 */
async function mintAndInstallWorkerCap({ dispatchId, taskId, handle }) {
  const capability = mintWorkerCapability({
    dispatchId,
    taskId,
    terminalHandle: handle,
    clientKey: currentClientKey(),
  }, WORKER_ISOLATION.hmacSecret);
  const envBlock = workerCapabilityEnv({
    capability,
    bridgeOrigin: workerBridgeOrigin(),
  });
  const body = serializeWorkerCapFile({
    capability: envBlock.ORCA_WORKER_CAPABILITY,
    dispatchId,
    taskId,
    bridgeOrigin: envBlock.ORCA_WORKER_BRIDGE_ORIGIN,
    orchHelper: envBlock.ORCA_WORKER_ORCH_HELPER,
    terminalHandle: handle,
  });
  const staging = capStagePath(dispatchId);
  try {
    await writeAtomic0600(staging, body);
  } catch (e) {
    // Staging dir is created by seed (root). First call may need dirs first.
    await sudoSeedWorkerCreds();
    await writeAtomic0600(staging, body);
  }
  await sudoSeedWorkerCreds();
  return {
    capability,
    path: capFilePath(dispatchId),
    meta: {
      path: capFilePath(dispatchId),
      staged: staging,
      origin: envBlock.ORCA_WORKER_BRIDGE_ORIGIN,
      helper: envBlock.ORCA_WORKER_ORCH_HELPER,
    },
  };
}

async function markWorkerCapPurge(dispatchId) {
  if (!dispatchId) return;
  const marker = capPurgeMarkerPath(dispatchId);
  try {
    await writeAtomic0600(marker, `${dispatchId}\n`);
  } catch {
    await sudoSeedWorkerCreds();
    await writeAtomic0600(marker, `${dispatchId}\n`);
  }
  await sudoSeedWorkerCreds();
}

/**
 * Supervised start for bridge/Hyperagent (CLI outside agent terminal).
 *
 * `orchestration worker-start` returns selector_not_found from bare shell cwd
 * (e.g. $HOME). Working path verified on this host:
 *   run-create → task-create → worktree create --agent → terminal wait tui-idle
 *   → orchestration dispatch --inject → terminal send --enter → liveness probe
 *   → optional send --text … --enter + empty --enter recovery (TUI draft buffer)
 */
async function dispatchWorker(args = {}) {

  try {
    await ensureRuntimeReady();
  } catch (e) {
    return runtimeGuardRejection(e);
  }
  const rawSpec = String(args.spec || '').trim();
  if (!rawSpec) throw new Error('spec is required (worker brief)');
  // Bridge enforces worker_done contract so system prompts need not repeat it.
  const spec = withWorkerContract(rawSpec);

  const agent = String(args.agent || DEFAULT_AGENT).trim() || DEFAULT_AGENT;
  const worktree = String(args.worktree || 'new-top-level').trim();
  const allowedWt = new Set(['new-top-level', 'new-child', 'current']);
  if (!allowedWt.has(worktree)) {
    throw new Error(`worktree must be one of ${[...allowedWt].join('|')}`);
  }
  const name = String(args.name || '').trim() || (worktree === 'current' ? undefined : autoName('ha'));
  const repo = String(args.repo || DEFAULT_REPO || '').trim();
  const setup = String(args.setup || 'run').trim();
  const objective = String(args.objective || '').trim() || rawSpec.slice(0, 200);
  const baseBranch = args.base_branch != null ? String(args.base_branch).trim() : '';
  const runIdProvided = args.run_id != null && String(args.run_id).trim() !== '';
  let runId = runIdProvided ? String(args.run_id).trim() : '';

  const steps = [];

  // 1) Run
  if (!runId) {
    const created = await runJson(
      ['orchestration', 'run-create', '--objective', objective, '--json'],
      { timeoutMs: 60_000 },
    );
    steps.push({ step: 'run-create', ...created });
    if (!envOk(created)) {
      const dead = maybeDeadRuntime(created, { stage: 'run-create' });
      if (dead) return { ...dead, steps };
      return {
        ok: false,
        stage: 'run-create',
        error: 'run-create failed',
        steps,
        next: {
          action: 'fix',
          detail: `Check Orca runtime / orchestration experimental. ${HEALTH_DIAGNOSTICS_HINT}`,
        },
      };
    }
    runId = pick(created.envelope?.result?.run, 'id') || pick(created.envelope?.result, 'runId', 'id');
    if (!runId) {
      return { ok: false, stage: 'run-create', error: 'run id missing in envelope', steps };
    }
    // run-create already injects --from our pin; remember bind for await/ack.
    try {
      const s = await resolveSenderTerminal();
      markRunBound(runId, s.handle);
    } catch { /* pin resolve failed later stages will surface */ }
  } else {
    // Wave continuation: rebind THIS client's durable sender to the existing run
    // before task-create. Without run-use, a re-resolved --from that is not bound
    // to the run fails with consumer_fenced (mid-wave recreate regression).
    const useRes = await runJson(
      ['orchestration', 'run-use', '--id', runId, '--json'],
      { timeoutMs: 30_000 },
    );
    steps.push({ step: 'run-use', ...useRes });
    if (!envOk(useRes) && useRes.envelope?.error?.code !== 'already_bound') {
      const code = useRes.envelope?.error?.code || useRes.error || 'run-use failed';
      return {
        ok: false,
        stage: 'run-use',
        run_id: runId,
        error: code,
        steps,
        next: {
          action: 'retry_or_new_wave',
          detail:
            'Could not bind this client sender to the wave runId. Retry dispatch once; ' +
            'if sender was recreated (bridge <0.2.12), restart bridge 0.2.12+ and keep the same runId.',
        },
      };
    }
    try {
      const s = await resolveSenderTerminal();
      markRunBound(runId, s.handle);
    } catch { /* ignore */ }
  }

  // 2) Task (spec includes auto-appended worker_done contract)
  const taskRes = await runJson(
    ['orchestration', 'task-create', '--spec', spec, '--run', runId, '--json'],
    { timeoutMs: 60_000 },
  );
  steps.push({ step: 'task-create', ...taskRes });
  if (!envOk(taskRes)) {
    return {
      ok: false,
      stage: 'task-create',
      run_id: runId,
      error: 'task-create failed',
      steps,
    };
  }
  const taskId =
    pick(taskRes.envelope?.result?.task, 'id') ||
    pick(taskRes.envelope?.result, 'taskId', 'id');
  if (!taskId) {
    return { ok: false, stage: 'task-create', run_id: runId, error: 'task id missing', steps };
  }

  // 3) Place agent terminal
  // NAS-255: when worker isolation is active, never pass --agent to worktree
  // create (Orca would spawn as the bridge uid). Create the worktree bare, then
  // terminal create --command <wrapper agent> so the agent runs as orca-worker.
  let handle = '';
  let worktreePath = null;
  let worktreeId = null;
  let workerLaunchCommand = null;

  const isolationPlan = planIsolatedAgentPlacement(
    {
      worktree,
      agent,
      name: name || autoName('ha'),
      repo: repo || '',
      setup,
      baseBranch,
      taskId,
    },
    WORKER_ISOLATION,
  );

  if (isolationPlan.mode === 'isolated-command') {
    workerLaunchCommand = isolationPlan.launchCommand;
    if (worktree === 'current') {
      const termArgv = isolationPlan.terminalArgv;
      const termRes = await runJson(termArgv, { timeoutMs: WORKER_START_TIMEOUT_MS });
      steps.push({ step: 'terminal-create-isolated', launchCommand: workerLaunchCommand, ...termRes });
      if (!envOk(termRes)) {
        return {
          ok: false,
          stage: 'terminal-create',
          run_id: runId,
          task_id: taskId,
          error: 'terminal create (worker-uid wrapper) failed',
          worker_isolation: workerIsolationHealth(WORKER_ISOLATION),
          steps,
        };
      }
      const tr = termRes.envelope?.result || {};
      handle =
        pick(tr, 'handle') ||
        pick(tr.terminal, 'handle') ||
        pick(tr, 'agentTerminalHandle') ||
        '';
    } else {
      if (!repo) {
        return {
          ok: false,
          stage: 'worktree-create',
          run_id: runId,
          task_id: taskId,
          error: 'repo is required for new worktree (pass repo or set ORCA_BRIDGE_DEFAULT_REPO)',
          steps,
        };
      }
      const wtArgv = isolationPlan.worktreeArgv;
      const wtRes = await runJson(wtArgv, { timeoutMs: WORKER_START_TIMEOUT_MS });
      steps.push({ step: 'worktree-create-isolated', ...wtRes });
      if (!envOk(wtRes)) {
        return {
          ok: false,
          stage: 'worktree-create',
          run_id: runId,
          task_id: taskId,
          error: 'worktree create (no --agent; worker-uid path) failed',
          steps,
        };
      }
      const wr = wtRes.envelope?.result || {};
      worktreePath = pick(wr, 'path') || pick(wr.worktree, 'path') || null;
      worktreeId = pick(wr, 'id') || null;
      const wtSel = worktreePath
        ? (String(worktreePath).startsWith('path:') ? String(worktreePath) : `path:${worktreePath}`)
        : (worktreeId ? String(worktreeId) : null);
      if (!wtSel) {
        return {
          ok: false,
          stage: 'place-agent',
          run_id: runId,
          task_id: taskId,
          error: 'isolated worktree create returned no path/id for terminal create',
          steps,
        };
      }
      if (worktreePath) {
        const expectedGitdir = inferExpectedGitdir(worktreePath);
        const harden = hardenIsolatedWorktree(worktreePath, expectedGitdir, {
          workerUser: WORKER_ISOLATION.workerUser,
          setfacl: (args) => {
            execFileSync('setfacl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
          },
        });
        steps.push({
          step: 'worktree-harden',
          ok: harden.ok,
          git: harden.git && { ok: harden.git.ok, code: harden.git.code },
          acl: harden.acl && {
            ok: harden.acl.ok,
            skipped: harden.acl.skipped,
            parentGranted: harden.acl.parentGranted,
            gitGranted: harden.acl.gitGranted,
          },
        });
        if (harden.git && harden.git.ok === false) {
          return {
            ok: false,
            stage: 'worktree-harden',
            run_id: runId,
            task_id: taskId,
            worktree: worktreePath,
            error: harden.git.message || 'isolated worktree gitdir pointer is unsafe',
            steps,
          };
        }
      }
      const termArgv = buildIsolatedTerminalCreateArgv({
        worktreeSelector: wtSel,
        name: name || autoName('ha'),
        launchCommand: workerLaunchCommand,
      });
      const termRes = await runJson(termArgv, { timeoutMs: WORKER_START_TIMEOUT_MS });
      steps.push({ step: 'terminal-create-isolated', launchCommand: workerLaunchCommand, ...termRes });
      if (!envOk(termRes)) {
        return {
          ok: false,
          stage: 'terminal-create',
          run_id: runId,
          task_id: taskId,
          error: 'terminal create (worker-uid wrapper) failed after isolated worktree',
          worktree: worktreePath,
          steps,
        };
      }
      const tr = termRes.envelope?.result || {};
      handle =
        pick(tr, 'handle') ||
        pick(tr.terminal, 'handle') ||
        pick(tr, 'agentTerminalHandle') ||
        '';
    }
  } else if (worktree === 'current') {
    if (!repo) {
      return {
        ok: false,
        stage: 'terminal-create',
        run_id: runId,
        task_id: taskId,
        error: 'worktree=current requires repo selector (or ORCA_BRIDGE_DEFAULT_REPO)',
        steps,
      };
    }
    const termArgv = [
      'terminal', 'create',
      '--worktree', repo.startsWith('path:') || repo.startsWith('id:') || repo.startsWith('name:')
        ? (repo.startsWith('path:') ? repo : repo)
        : `path:${repo}`,
      '--title', name || autoName('ha'),
      '--command', agent,
      '--json',
    ];
    // Prefer path: for bare absolute paths
    if (!repo.includes(':') && repo.startsWith('/')) {
      termArgv[termArgv.indexOf('--worktree') + 1] = `path:${repo}`;
    }
    const termRes = await runJson(termArgv, { timeoutMs: WORKER_START_TIMEOUT_MS });
    steps.push({ step: 'terminal-create', ...termRes });
    if (!envOk(termRes)) {
      return {
        ok: false,
        stage: 'terminal-create',
        run_id: runId,
        task_id: taskId,
        error: 'terminal create failed',
        steps,
      };
    }
    const tr = termRes.envelope?.result || {};
    handle =
      pick(tr, 'handle') ||
      pick(tr.terminal, 'handle') ||
      pick(tr, 'agentTerminalHandle') ||
      '';
  } else {
    if (!repo) {
      return {
        ok: false,
        stage: 'worktree-create',
        run_id: runId,
        task_id: taskId,
        error: 'repo is required for new worktree (pass repo or set ORCA_BRIDGE_DEFAULT_REPO)',
        steps,
      };
    }
    const wtArgv = [
      'worktree', 'create',
      '--name', name || autoName('ha'),
      '--agent', agent,
      '--repo', repo.includes(':') ? repo : (repo.startsWith('/') ? `path:${repo}` : repo),
      '--json',
    ];
    if (worktree === 'new-top-level') wtArgv.push('--no-parent');
    if (setup) wtArgv.push('--setup', setup);
    if (baseBranch) wtArgv.push('--base-branch', baseBranch);

    const wtRes = await runJson(wtArgv, { timeoutMs: WORKER_START_TIMEOUT_MS });
    steps.push({ step: 'worktree-create', ...wtRes });
    if (!envOk(wtRes)) {
      return {
        ok: false,
        stage: 'worktree-create',
        run_id: runId,
        task_id: taskId,
        error: 'worktree create --agent failed',
        steps,
      };
    }
    const wr = wtRes.envelope?.result || {};
    handle =
      pick(wr, 'agentTerminalHandle') ||
      pick(wr.startupTerminal, 'handle') ||
      pick(wr, 'handle') ||
      '';
    worktreePath = pick(wr, 'path') || pick(wr.worktree, 'path') || null;
    worktreeId = pick(wr, 'id') || null;
  }

    if (!handle) {
    return {
      ok: false,
      stage: 'place-agent',
      run_id: runId,
      task_id: taskId,
      error: 'no agent terminal handle after create',
      steps,
    };
  }

  const isolated = isolationPlan.mode === 'isolated-command';

  // Isolated: bind dispatch BEFORE grok starts so we have a real dispatchId
  // to name /run/orca-mcp/worker-caps/<dispatchId>.json. The wrapper is
  // blocked on the by-task pointer until mintAndInstallWorkerCap returns.
  // Legacy: wait for TUI, then dispatch --inject as before.
  let waitRes = null;
  let dispRes;
  if (isolated) {
    dispRes = await runJson(
      ['orchestration', 'dispatch', '--task', taskId, '--to', handle, '--return-preamble', '--json'],
      { timeoutMs: 60_000 },
    );
    steps.push({ step: 'dispatch-bind', isolated: true, ...dispRes });
  } else {
    waitRes = await runJson(
      ['terminal', 'wait', '--terminal', handle, '--for', 'tui-idle', '--timeout-ms', '60000', '--json'],
      { timeoutMs: 90_000 },
    );
    steps.push({ step: 'tui-idle', ...waitRes });
    dispRes = await runJson(
      ['orchestration', 'dispatch', '--task', taskId, '--to', handle, '--inject', '--json'],
      { timeoutMs: 60_000 },
    );
    steps.push({ step: 'dispatch-inject', ...dispRes });
    // Runtime `--inject` types the brief into the compose box and has no
    // Enter flag. Submit it with `terminal send --enter` (not `--submit`).
    if (envOk(dispRes)) {
      await sleep(800);
      const injectEnter = await runJson(
        buildTerminalSendArgv({ handle, enter: true }),
        { timeoutMs: 15_000 },
      );
      steps.push({ step: 'dispatch-inject-enter', ok: envOk(injectEnter) });
    }
  }
  if (!envOk(dispRes)) {
    return {
      ok: false,
      stage: isolated ? 'dispatch-bind' : 'dispatch-inject',
      run_id: runId,
      task_id: taskId,
      terminal_handle: handle,
      worktree: worktreePath,
      error: isolated ? 'dispatch (pre-inject bind) failed' : 'dispatch --inject failed',
      steps,
    };
  }

  const dr = dispRes.envelope?.result || {};
  const dispatchId = pick(dr.dispatch, 'id') || pick(dr, 'dispatchId', 'dispatch_id');
  const dispatchPreamble = pick(dr, 'preamble') || '';

  // 6) Mint worker capability to a 994:994 0600 file (NAS-258).
  // workerCapabilityEnv() is invoked inside mintAndInstallWorkerCap.
  let workerCapability = null;
  let workerCapFile = null;
  if (WORKER_ISOLATION.enabled && WORKER_ISOLATION.hmacSecret && dispatchId && taskId) {
    try {
      const installed = await mintAndInstallWorkerCap({ dispatchId, taskId, handle });
      workerCapability = installed.capability;
      workerCapFile = installed.path;
      steps.push({ step: 'worker-capability-file', ...installed.meta });
    } catch (e) {
      steps.push({ step: 'worker-capability-file', error: String(e?.message || e) });
    }
  }

  if (isolated) {
    waitRes = await runJson(
      ['terminal', 'wait', '--terminal', handle, '--for', 'tui-idle', '--timeout-ms', '60000', '--json'],
      { timeoutMs: 90_000 },
    );
    steps.push({ step: 'tui-idle', ...waitRes });
    const tuiSnap = await terminalSnapshot(handle);
    const tui = looksLikeAgentTui(tuiSnap);
    steps.push({
      step: 'agent-tui',
      ok: tui.ok,
      reason: tui.reason || null,
      title: tuiSnap.title || '',
    });
    if (!tui.ok) {
      return {
        ok: false,
        stage: 'agent-tui',
        run_id: runId,
        task_id: taskId,
        dispatch_id: dispatchId || null,
        terminal_handle: handle,
        worktree: worktreePath,
        error: `isolated agent TUI did not come up (${tui.reason || 'not_agent'})`,
        agent_tui: tui,
        worker_isolation: workerIsolationHealth(WORKER_ISOLATION),
        steps,
      };
    }
    // Runtime preamble carries --from + --dispatch-capability (dcap_).
    // Isolated bind skipped --inject so the waiting wrapper never saw it;
    // deliver it now that grok is up.
    if (dispatchPreamble) {
      const preSend = await runJson(
        buildTerminalSendArgv({ handle, text: dispatchPreamble, enter: true }),
        { timeoutMs: 30_000 },
      );
      // Same two-send rule as inject recovery: shell submits on the first
      // --enter; a Grok TUI draft buffer needs the following empty --enter
      // (verified live 2026-08-15). Harmless when the first already submitted.
      await sleep(800);
      const preEnter = await runJson(
        buildTerminalSendArgv({ handle, text: '', enter: true }),
        { timeoutMs: 15_000 },
      );
      steps.push({
        step: 'dispatch-preamble-send',
        ok: envOk(preSend),
        enterOk: envOk(preEnter),
        preamble_len: dispatchPreamble.length,
      });
    }
  }

  // Skip only if ORCA_BRIDGE_INJECT_RECOVERY=0
  let injectRecovery = { recovered: false, landed: true, probes: [], skipped: false };
  if (process.env.ORCA_BRIDGE_INJECT_RECOVERY === '0') {
    injectRecovery = { recovered: false, landed: null, probes: [], skipped: true };
  } else {
    try {
      injectRecovery = await ensureInjectLanded({
        handle,
        taskId,
        dispatchId,
        spec,
        agent,
        workerCapability,
      });
      steps.push({
        step: 'inject-liveness',
        recovered: injectRecovery.recovered,
        landed: injectRecovery.landed,
        probes: injectRecovery.probes?.map((p) => ({
          phase: p.phase,
          turns: p.turns,
          toolCalls: p.toolCalls,
          busyHint: p.busyHint,
          idlePrompt: p.idlePrompt,
          working: p.working,
          sendOk: p.sendOk,
        })),
      });
    } catch (e) {
      steps.push({ step: 'inject-liveness', error: String(e?.message || e) });
      injectRecovery = { recovered: false, landed: false, probes: [], error: String(e?.message || e) };
    }
  }

  // Authoritative ownership bind at dispatch-time only (NAS-248 P0 #4).
  // await/check must never create or reassign clientKey bindings.
  await bindOwnedDispatch({
    runId,
    dispatchId: dispatchId || null,
    terminalHandle: handle,
    taskId,
    status: 'running',
    agent,
    worktree: worktreePath || null,
    name: name || null,
    extra: {
      workerIsolation: isolationPlan.mode === 'isolated-command',
      workerCapabilityMinted: Boolean(workerCapability),
    },
  });


    return {
    ok: true,
    stage: 'ready',
    run_id: runId,
    task_id: taskId,
    dispatch_id: dispatchId || null,
    agent,
    worktree_mode: worktree,
    name: name || null,
    repo: repo || null,
    terminal_handle: handle,
    worktree: worktreePath,
    worktree_id: worktreeId,
    injected: dr.injected === true,
    inject_recovered: injectRecovery.recovered === true,
    inject_landed: injectRecovery.landed,
    client_key: currentClientKey(),
    worker_isolation: workerIsolationHealth(WORKER_ISOLATION),
    worker_launch_command: workerLaunchCommand,
    worker_capability_minted: Boolean(workerCapability),
    // Capability is a 994:994 0600 file; never echoed in full to coordinators.
    worker_capability_len: workerCapability ? workerCapability.length : 0,
    worker_capability_file: workerCapFile,
    next: {
      action: 'await',
      detail:
        'Poll: orca { action:"await", runId, waitMs:45000 }. Empty/timeout = continue. ' +
        'worker_done -> orca { action:"release", dispatchId, terminalHandle }. ' +
        'If inject_recovered=true, prompt was re-sent via terminal send --text … --enter plus a following empty --enter (Grok TUI draft buffer). ' +
        'Stuck TUI: terminal send --interrupt on the worker handle.',
      run_id: runId,
      dispatch_id: dispatchId || null,
      terminal_handle: handle,
    },
  };
}

async function awaitDispatch(args = {}) {
  try {
    await ensureRuntimeReady();
  } catch (e) {
    return runtimeGuardRejection(e);
  }
  const runId = String(args.run_id || '').trim();
  if (!runId) throw new Error('run_id is required');
  const waitMs = Math.min(Math.max(args.wait_ms ?? CHECK_WAIT_DEFAULT_MS, 0), CHECK_WAIT_MAX_MS);
  const types = String(args.types || DEFAULT_WAIT_TYPES).trim() || DEFAULT_WAIT_TYPES;

  // Pin first — check --terminal and run-use --from must be the same durable handle.
  // NAS-248 P0 #4: do NOT registerOwnedDispatch on await — reads never claim ownership.
  const sender = await resolveSenderTerminal();

  /**
   * Mechanism B (0.2.13):
   * run-use bumps consumer_generation. Deliveries (and their deliveryId for --ack)
   * are generation-scoped. Calling run-use on every await made ack always fail with
   * consumer_fenced even for a single coordinator.
   * Rule: run-use only when this pin is not already bound to runId; if we rebind,
   * drop any client-provided ack (it belongs to the previous generation).
   */
  let useRes = null;
  let runUseSkipped = false;
  let ack = args.ack != null && String(args.ack).trim() !== '' ? String(args.ack).trim() : null;
  let ackDropped = null;

  async function bindRun() {
    const res = await runJson(
      ['orchestration', 'run-use', '--id', runId, '--json'],
      { timeoutMs: 30_000 },
    );
    useRes = res;
    const ok = envOk(res) || res.envelope?.error?.code === 'already_bound';
    if (ok) markRunBound(runId, sender.handle);
    return ok;
  }

  if (isRunBound(runId, sender.handle)) {
    runUseSkipped = true;
  } else {
    const ok = await bindRun();
    if (ok && ack) {
      // Generation advanced (or first bind after restart) — prior deliveryId is invalid.
      ackDropped = {
        deliveryId: ack,
        reason: 'run_rebound_or_first_bind_invalidates_prior_delivery',
      };
      ack = null;
    }
  }

  function buildCheckArgv(ackId) {
    const argv = ['orchestration', 'check', '--run', runId, '--json'];
    if (ackId) argv.push('--ack', String(ackId));
    if (args.peek) argv.push('--peek');
    if (types) argv.push('--types', types);
    if (waitMs > 0) argv.push('--wait', '--timeout-ms', String(waitMs));
    return argv;
  }

  let described = await runJson(buildCheckArgv(ack), { timeoutMs: waitMs + 30_000 });
  let env = described.envelope || {};
  let fence =
    env.error?.code === 'consumer_fenced' ||
    /consumer_fenced|not run_|fenced consumer|no longer bound/i.test(
      String(env.error?.message || env.error?.code || ''),
    );
  let staleInfo = ack ? staleFromDescribed(described, ack) : null;

  // Stale in-memory bind (stolen by another client, or process disagreed with runtime):
  // rebind once; drop ack if any.
  if (fence) {
    const ok = await bindRun();
    if (ack) {
      ackDropped = {
        deliveryId: ack,
        reason: 'rebinding_after_consumer_fenced',
      };
      ack = null;
    }
    // Retry check without the fenced ack (and after rebind).
    described = await runJson(buildCheckArgv(null), { timeoutMs: waitMs + 30_000 });
    env = described.envelope || {};
    fence =
      env.error?.code === 'consumer_fenced' ||
      /consumer_fenced|not run_|fenced consumer|no longer bound/i.test(
        String(env.error?.message || env.error?.code || ''),
      );
    staleInfo = null;
  } else if (staleInfo && ack) {
    // msg_… ack or foreign/expired deliveryId — drop and retry once without ack.
    ackDropped = {
      deliveryId: ack,
      reason: staleInfo.hint || 'stale_delivery',
      detail: staleInfo.message,
    };
    ack = null;
    described = await runJson(buildCheckArgv(null), { timeoutMs: waitMs + 30_000 });
    env = described.envelope || {};
    fence =
      env.error?.code === 'consumer_fenced' ||
      /consumer_fenced|not run_|fenced consumer|no longer bound/i.test(
        String(env.error?.message || env.error?.code || ''),
      );
    staleInfo = staleFromDescribed(described, ackDropped.deliveryId);
    // If retry still stale with no ack, clear — shouldn't happen without ack.
    if (!ack) staleInfo = null;
  }

  if ((!described.envelope && described.ok === false) || fence || (env.error && isStaleDeliveryError(env.error?.code, env.error?.message))) {
    const stillStale = staleFromDescribed(described, ackDropped?.deliveryId || args.ack);
    if (!fence && !stillStale) {
      const dead = maybeDeadRuntime(described, { stage: 'await-check', runId });
      if (dead) {
        return {
          ...dead,
          window_ms: waitMs,
          client_key: currentClientKey(),
          sender_handle: sender.handle,
          run_use: useRes?.envelope || useRes || null,
          run_use_skipped: runUseSkipped || undefined,
          ack_dropped: ackDropped || undefined,
          raw: described,
        };
      }
    }
    return {
      ok: false,
      run_id: runId,
      window_ms: waitMs,
      error: fence
        ? 'consumer_fenced'
        : stillStale
          ? 'stale_delivery'
          : 'check failed',
      errorCode: fence
        ? 'consumer_fenced'
        : stillStale
          ? 'stale_delivery'
          : 'check_failed',
      error_detail: stillStale || undefined,
      client_key: currentClientKey(),
      sender_handle: sender.handle,
      run_use: useRes?.envelope || useRes || null,
      run_use_skipped: runUseSkipped || undefined,
      ack_dropped: ackDropped || undefined,
      raw: described,
      next: {
        action: 'retry_await_without_ack_once',
        detail: stillStale
          ? stillStale.message
          : fence
            ? 'Mailbox check failed (consumer_fenced). Bridge skips run-use when already bound (0.2.13+). ' +
              'If another session shares this OAuth token it can steal the bind — use a separate OAuth token. ' +
              'Retry await without ack once (bridge already dropped invalid ack on rebind). ' +
              'Or worker-show --dispatch for inject-path status.'
            : `Mailbox check failed. ${HEALTH_DIAGNOSTICS_HINT}`,
      },
    };
  }

  const res = env.result || env;
  const rawMessages = res.messages || [];
  const deliveryId = pick(res, 'deliveryId', 'delivery_id');
  const owned = ownershipFor(currentClientKey()).dispatches;
  const { own: messages, foreign: foreignMessages, filtered } = partitionMailbox(
    rawMessages,
    owned,
    pick,
  );
  const summary = summarizeMessages(messages);
  if (summary.status === 'worker_done' && summary.worker_done && !summary.worker_done.outcome) {
    try {
      const rawPayload = messages.find((m) => msgType(m) === 'worker_done')?.payload;
      const p = typeof rawPayload === 'string' ? JSON.parse(rawPayload) : rawPayload;
      if (p && typeof p === 'object') {
        summary.worker_done.outcome = p.outcome || summary.worker_done.outcome;
        summary.worker_done.dispatchId = summary.worker_done.dispatchId || p.dispatchId || p.dispatch_id;
        summary.worker_done.taskId = summary.worker_done.taskId || p.taskId || p.task_id;
      }
    } catch { /* ignore */ }
  }
  if (summary.worker_done?.dispatchId && owned.size > 0 && !owned.has(String(summary.worker_done.dispatchId))) {
    summary.worker_done = null;
    summary.status = foreignMessages.length && !messages.length ? 'foreign_only' : summary.status;
  }
  const empty = summary.status === 'empty' || summary.status === 'foreign_only';
  const effectiveTimedOut = res.timedOut === true || (empty && !deliveryId && !filtered);

  // --- NAS-240: liveness from dispatch registry + optional terminal activity ---
  const ck = currentClientKey();
  const ownedEntries = dispatchRegistry
    .list({ clientKey: ck })
    .filter((d) => d.runId === runId || (d.dispatchId && owned.has(String(d.dispatchId))));
  // Prefer entries still running / recently updated for this run.
  let primaryEntry =
    ownedEntries.find((d) => d.status === 'running') ||
    ownedEntries.sort((a, b) => String(b.updatedAt || '').localeCompare(String(a.updatedAt || '')))[0] ||
    null;

  let terminalLastOutputAt = null;
  let terminalProbe = null;
  if (empty && primaryEntry?.terminalHandle) {
    try {
      const snap = await terminalSnapshot(primaryEntry.terminalHandle);
      terminalProbe = {
        ok: snap.ok === true,
        turns: snap.turns,
        toolCalls: snap.toolCalls,
        busyHint: snap.busyHint === true,
        connected: snap.connected === true,
        lastOutputAt: snap.lastOutputAt || null,
      };
      terminalLastOutputAt = snap.lastOutputAt || null;
      // Treat busy / turns growth as activity even without lastOutputAt.
      if (looksWorking(snap) && !terminalLastOutputAt) {
        terminalLastOutputAt = new Date().toISOString();
      }
    } catch {
      terminalProbe = { ok: false };
    }
  }

  const prevEmpty = primaryEntry?.emptyWindowsConsecutive || 0;
  const emptyWindowsConsecutive = empty ? prevEmpty + 1 : 0;
  const lastActivityAt = pickLastActivityAt({
    registryUpdatedAt: primaryEntry?.lastActivityAt || primaryEntry?.updatedAt || null,
    terminalLastOutputAt,
    lastMessageAt: empty ? null : new Date().toISOString(),
  });
  const livenessInfo = computeLiveness({
    now: Date.now(),
    dispatchedAt: primaryEntry?.dispatchedAt || primaryEntry?.createdAt || null,
    lastActivityAt,
    emptyWindowsConsecutive,
    hasDispatch: Boolean(primaryEntry) || owned.size > 0,
  });

  let next = nextStepForAwait(summary, {
    timedOut: effectiveTimedOut,
    deliveryId,
    livenessInfo: empty ? livenessInfo : null,
  });
  if (summary.status === 'foreign_only' || (filtered && summary.status === 'empty')) {
    next = {
      action: 'await',
      detail:
        'Mailbox had only foreign deliveries (other coordinator). Re-call await; do NOT release foreign dispatch_id. ' +
        'Prefer summary.status; foreign_messages is informational.',
      deliveryId: deliveryId || null,
      note: 'Foreign worker_done never yields next.action=release.',
      liveness: livenessInfo.liveness,
    };
  }
  if (next.action === 'release' && next.dispatchId && owned.size > 0 && !owned.has(String(next.dispatchId))) {
    next = {
      action: 'await',
      detail: 'Suppressed release of foreign dispatch_id. Re-await for your own worker_done.',
      deliveryId: deliveryId || null,
      foreignDispatchId: next.dispatchId,
      note: 'next.action never releases another coordinator\'s worker.',
    };
  }

  // Surface dispatch status + redacted transcript snippets via resources.
  // NAS-248 P0 #4: never bind/claim clientKey here. Only update rows already
  // owned by this client (partitionMailbox is fail-closed; this is defense in depth).
  for (const m of messages) {
    const did =
      pick(m, 'dispatchId', 'dispatch_id') ||
      pick(m?.payload || {}, 'dispatchId', 'dispatch_id') ||
      summary.worker_done?.dispatchId ||
      null;
    if (!did) continue;
    const didStr = String(did);
    if (!owned.has(didStr)) continue;
    const existing = dispatchRegistry.get(didStr);
    // No claim-on-read for unbound or foreign ids.
    if (!existing?.clientKey || String(existing.clientKey) !== ck) continue;
    const t = msgType(m);
    dispatchRegistry.upsert(didStr, {
      status:
        t === 'worker_done' && (summary.status === 'fake_worker_done' || summary.status === REJECTED_WORKER_DONE)
          ? summary.status
          : t === 'worker_done'
            ? 'worker_done'
            : (t || 'message'),
      runId,
      lastDeliveryId: deliveryId || null,
      lastMessageType: t || null,
      lastActivityAt: new Date().toISOString(),
      emptyWindowsConsecutive: 0,
    });
    let body = '';
    try {
      const p = m?.payload;
      body = typeof p === 'string' ? p : JSON.stringify(p ?? m);
    } catch {
      body = String(m?.body || '');
    }
    dispatchRegistry.appendTranscript(didStr, {
      type: t || 'message',
      body: String(redactValue(body, 'body')).slice(0, 4000),
      deliveryId: deliveryId || pick(m, 'deliveryId', 'delivery_id') || null,
    });
  }
  if (summary.status === 'worker_done' && summary.worker_done?.dispatchId) {
    const didStr = String(summary.worker_done.dispatchId);
    if (owned.has(didStr)) {
      const existing = dispatchRegistry.get(didStr);
      if (existing?.clientKey && String(existing.clientKey) === ck) {
        dispatchRegistry.upsert(didStr, {
          status: 'worker_done',
          runId,
          outcome: summary.worker_done.outcome || null,
          taskId: summary.worker_done.taskId || null,
          lastActivityAt: new Date().toISOString(),
          emptyWindowsConsecutive: 0,
        });
      }
    }
  } else if (primaryEntry?.dispatchId && empty) {
    // Advance empty-window counter + activity on the tracked worker.
    const didStr = String(primaryEntry.dispatchId);
    if (owned.has(didStr) && primaryEntry.clientKey && String(primaryEntry.clientKey) === ck) {
      dispatchRegistry.upsert(didStr, {
        emptyWindowsConsecutive,
        lastActivityAt: lastActivityAt || primaryEntry.lastActivityAt || null,
        liveness: livenessInfo.liveness,
        runId,
      });
    }
  }

  return {
    ok: described.ok !== false && !env.error,
    run_id: pick(res, 'runId', 'run_id') || runId,
    window_ms: waitMs,
    timedOut: effectiveTimedOut,
    deliveryId: deliveryId || null,
    count: typeof res.count === 'number' ? res.count : messages.length,
    summary,
    next,
    // NAS-240 liveness signal (always present so clients need not special-case).
    liveness: livenessInfo.liveness,
    msSinceDispatch: livenessInfo.msSinceDispatch,
    msSinceActivity: livenessInfo.msSinceActivity,
    emptyWindowsConsecutive: livenessInfo.emptyWindowsConsecutive,
    livenessReason: livenessInfo.reason,
    terminalProbe: terminalProbe || undefined,
    messages,
    foreign_messages: foreignMessages.length ? foreignMessages : undefined,
    foreign_filtered: filtered || undefined,
    client_key: currentClientKey(),
    sender_handle: sender.handle,
    run_use_skipped: runUseSkipped || undefined,
    ack_dropped: ackDropped || undefined,
  };
}


async function releaseWorker(args = {}) {
  try {
    await ensureRuntimeReady();
  } catch (e) {
    return runtimeGuardRejection(e);
  }
  // NAS-248 / NAS-202: ownership of dispatchId AND handle is judged BEFORE any
  // effect (lookup, worker-release, close). executeReleaseWorker enforces that
  // ordering; this wrapper only supplies live deps + I/O.
  const ownershipDeps = {
    dispatchRegistry,
    clientOwnership,
    senderCaches,
    coordinatorHandles,
  };
  return executeReleaseWorker(args, {
    clientKey: currentClientKey(),
    ownershipDeps,
    runJson,
    envOk,
    pick,
    releaseRefusesCoordinator,
    coordinatorHandles,
    upsertDispatch: (id, row) => dispatchRegistry.upsert(id, row),
    purgeWorkerCreds: async (opts = {}) => {
      const did = opts.dispatchId != null ? String(opts.dispatchId).trim() : '';
      const out = { ok: true, cap: null, creds: null };
      if (did) {
        try {
          await markWorkerCapPurge(did);
          out.cap = { ok: true, dispatchId: did };
        } catch (e) {
          out.ok = false;
          out.cap = { ok: false, error: String(e?.message || e) };
        }
      }
      if (opts.creds === false) {
        out.creds = { skipped: 'other_live_isolated_dispatch' };
        return out;
      }
      try {
        await execFile('sudo', ['-n', SEED_HELPER, 'purge']);
        out.creds = { ok: true };
      } catch (e) {
        out.ok = false;
        out.creds = { ok: false, error: String(e?.message || e) };
      }
      return out;
    },
  });
}


// --- MCP tools ---------------------------------------------------------------
// Hyperagent custom MCP currently exports only ONE action from this server
// (always mcp-orca__orca). So the entire control plane is multiplexed into the
// single tool `orca` via `action`. Multi-name tools/list is useless for HA.
//
// action:
//   health   — bridge version + orca status + version gate
//   dispatch — supervised worker start (worker_done path; auto worker_done contract)
//   await    — one check window (poll until worker_done); empty/timeout = re-call
//   release  — worker-release OR terminal close (inject path; dispatch_not_found is OK)
//   guide    — coordinator discipline (waves, brief, devices) — replaces long system prompts
//   check    — raw orchestration check
//   cli      — raw orca argv (handoff worktree create --agent --prompt REJECTED)
const TOOLS = [
  {
    name: 'orca',
    description: buildToolDescription({ minVersion: MIN_BRIDGE_VERSION }),
    annotations: { ...ORCA_TOOL_ANNOTATIONS },
    outputSchema: ORCA_OUTPUT_SCHEMA,
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: {
          type: 'string',
          description: buildActionPropertyDescription(),
        },
        // cli
        args: {
          type: 'array',
          items: { type: 'string' },
          description: buildArgsPropertyDescription(),
        },
        timeoutMs: { type: 'number', description: 'CLI exec timeout ms' },
        cwd: { type: 'string', description: 'CLI working directory' },
        // dispatch
        spec: {
          type: 'string',
          description:
            'For dispatch: full worker brief (goal, DoD, non-goals, issue id). ' +
            'worker_done contract is auto-appended by the bridge.',
        },
        objective: { type: 'string', description: 'For dispatch: short run objective (defaults to spec head)' },
        agent: { type: 'string', description: `For dispatch: TUI agent (omp|grok|…); default ${DEFAULT_AGENT}` },
        worktree: {
          type: 'string',
          description: 'For dispatch: new-top-level | new-child | current (default new-top-level)',
        },
        name: { type: 'string', description: 'For dispatch: short worktree slug (auto if omitted)' },
        repo: {
          type: 'string',
          description: 'For dispatch: repo selector path:… / name:… (or ORCA_BRIDGE_DEFAULT_REPO on host)',
        },
        setup: { type: 'string', description: 'For dispatch: run | skip | inherit' },
        baseBranch: { type: 'string', description: 'For dispatch: git base ref' },
        // shared ids
        runId: {
          type: 'string',
          description: 'Run id: omit on first dispatch of a wave; pass same runId for more workers / await / check',
        },
        dispatchId: { type: 'string', description: 'For release: dispatch id from dispatch or worker_done' },
        terminalHandle: {
          type: 'string',
          description:
            'For release (inject path): terminal_handle from dispatch. Preferred cleanup = terminal close --terminal <handle> --json (no --tab).',
        },
        taskId: { type: 'string', description: 'Optional task id for dispatch-show lookup on release' },
        // await / check
        waitMs: {
          type: 'number',
          description: buildWaitMsPropertyDescription(),
        },
        ack: { type: 'string', description: 'Prior deliveryId to ack on next await/check' },
        types: { type: 'string', description: `Message types; default ${DEFAULT_WAIT_TYPES}` },
        peek: { type: 'boolean', description: 'Peek without consuming' },
        all: { type: 'boolean', description: 'For check: all messages' },
        verbose: {
          type: 'boolean',
          description:
            'For health: when true, return full statusProbe/actionAnnotations/coordinator dump. ' +
            'Default false = compact (version, versionOk, statusProbe.ok, defaultRepo, next).',
        },
      },
      required: [],
    },

  },
];

// Legacy multi-tool names still route if a non-HA client calls them.
const TOOL_ALIASES = {
  orca: 'orca',
  dispatch: 'dispatch',
  dispatch_worker: 'dispatch',
  awaitDispatch: 'await',
  await_dispatch: 'await',
  await: 'await',
  release: 'release',
  release_worker: 'release',
  health: 'health',
  bridge_health: 'health',
  guide: 'guide',
  coordinator: 'guide',
  check: 'check',
  orca_check: 'check',
};

function pickArgs(args = {}) {
  const a = { ...args };
  if (a.run_id != null && a.runId == null) a.runId = a.run_id;
  if (a.wait_ms != null && a.waitMs == null) a.waitMs = a.wait_ms;
  if (a.dispatch_id != null && a.dispatchId == null) a.dispatchId = a.dispatch_id;
  if (a.timeout_ms != null && a.timeoutMs == null) a.timeoutMs = a.timeout_ms;
  if (a.base_branch != null && a.baseBranch == null) a.baseBranch = a.base_branch;
  return a;
}

async function healthPayload({ verbose = false } = {}) {
  const probeRun = await runOrca(['status', '--json'], { timeoutMs: 15_000 });
  const probe = describeRun(probeRun, true);
  // Keep lazy gate warm so the next dispatch/await skips a probe within TTL.
  runtimeProbeCache.set(probe);
  const versionOk = versionGte(VERSION, MIN_BRIDGE_VERSION);
  let sender = null;
  try {
    sender = await resolveSenderTerminal();
  } catch (e) {
    sender = { ok: false, error: String(e?.message || e) };
  }
  const full = {
    bridge: {
      version: VERSION,
      minVersion: MIN_BRIDGE_VERSION,
      versionOk,
      uptimeSec: Math.round((Date.now() - startedAt) / 1000),
      node: process.version,
      platform: process.platform,
      transport: STDIO_MODE ? 'stdio' : 'streamable-http',
      protocolTarget: PROTOCOL_TARGET,
    },
    orcaBinary: orcaBinary(),
    defaultAgent: DEFAULT_AGENT,
    defaultRepo: DEFAULT_REPO || null,
    senderTerminal: sender && sender.handle
      ? {
          ok: true,
          handle: sender.handle,
          source: sender.source,
          clientKey: sender.clientKey || currentClientKey(),
          title: sender.title || null,
        }
      : { ok: false, ...(sender || {}), clientKey: currentClientKey() },
    isolation: {
      perClientSender: !SENDER_SHARED,
      senderShared: SENDER_SHARED,
      clientKey: currentClientKey(),
      note:
        '0.2.13+: pin-by-handle + persist; await skips run-use when already bound (ack-safe); ' +
        'two coordinators need two OAuth tokens. ORCA_BRIDGE_SENDER_SHARED=1 = single-tenant only.',
      workerUid: workerIsolationHealth(WORKER_ISOLATION),
    },
    hindsightTarget: HINDSIGHT_URL.href,
    actions: ['health', 'dispatch', 'await', 'release', 'guide', 'check', 'cli'],
    toolsets: TOOLSET_GATE.snapshot(),
    actionAnnotations: ACTION_ANNOTATIONS,
    audit: {
      path: auditLog.path,
      ...auditLog.stat(),
    },
    resources: [
      'orca-bridge://audit/log',
      'orca-bridge://audit/tail',
      'orca-bridge://dispatches',
      'orca-bridge://dispatches/{id}',
      'orca-bridge://transcripts/{id}',
    ],
    statusProbe: probe,
    coordinator: {
      stop_if_version_below: MIN_BRIDGE_VERSION,
      versionOk,
      flow: 'dispatch → await(≤45s)×N [honor liveness] → worker_done → release(+terminalHandle) → read-only',
      on_question:
        'orca{action:"cli",args:["orchestration","reply","--id","<id>","--body","<answer>","--json"]} then await+ack',
      prefer_status_over_next: true,
      liveness_on_empty: true,
      guide: 'orca{action:"guide"} for waves / brief / devices / stop-conditions',
      handoff_blocked: true,
      worker_contract_auto_appended: true,
      health_optional:
        'health is diagnostics (compact default; verbose:true for full dump). ' +
        'dispatch/await/release self-check runtime/version — no pre-wave health ritual.',
      sender_auto_injected:
        'Headless orchestration gets --from / check --terminal from bridge (0.2.10+). ' +
        '0.2.11+: per-OAuth-client sender. 0.2.12+: pin-by-handle (shell rewrites titles; no mid-wave recreate). ' +
        'Pin with ORCA_BRIDGE_SENDER_TERMINAL only for master/single-tenant; multi-coord needs separate OAuth tokens.',
    },
    next: versionOk
      ? (sender && sender.handle
        ? {
            action: 'dispatch_or_guide',
            detail:
              'Bridge ready. Start workers with action=dispatch. Call action=guide once if you need waves/brief/devices discipline. ' +
              'health is optional diagnostics — not required before each wave.',
          }
        : {
            action: 'fix_sender',
            detail:
              'statusProbe may be ok, but no sender terminal for orchestration. ' +
              'Open an Orca terminal, set ORCA_BRIDGE_SENDER_TERMINAL, or ORCA_BRIDGE_DEFAULT_REPO.',
          })
      : {
          action: 'stop',
          detail:
            `bridge.version ${VERSION} < min ${MIN_BRIDGE_VERSION}. Ask owner to restart/upgrade bridge. ` +
            'Do NOT fall back to worktree create --agent --prompt.',
        },
  };

  if (verbose) {
    return { ...full, verbose: true, ok: versionOk && full.statusProbe?.ok !== false };
  }
  return compactHealthPayload(full);
}


async function callTool(name, args = {}) {
  const a = pickArgs(args);
  let op = TOOL_ALIASES[name] || name;

  // Single-tool multiplex: tool name is always `orca` for Hyperagent.
  if (op === 'orca') {
    const action = String(a.action || '').trim().toLowerCase();
    if (action === 'health' || action === 'bridge_health') op = 'health';
    else if (action === 'dispatch' || action === 'dispatch_worker') op = 'dispatch';
    else if (action === 'await' || action === 'awaitdispatch' || action === 'await_dispatch') op = 'await';
    else if (action === 'release' || action === 'release_worker') op = 'release';
    else if (action === 'guide' || action === 'coordinator') op = 'guide';
    else if (action === 'check' || action === 'orca_check') op = 'check';
    else if (action === 'cli' || action === '') {
      // default: raw CLI if args present, else health (so empty call still useful)
      if (Array.isArray(a.args) && a.args.length) op = 'cli';
      else if (!action) op = 'health';
      else op = 'cli';
    } else {
      throw new Error(`unknown action "${a.action}". Use health|dispatch|await|release|guide|check|cli`);
    }
  }
  // Capability toolset gate (after action resolve, before orch lock).
  // Default-all is a no-op; restricted configs return structured toolset_denied.
  const toolsetDecision = TOOLSET_GATE.evaluate(
    op,
    op === 'cli' ? a.args : undefined,
  );
  if (!toolsetDecision.ok) {
    return toolsetDecision.rejection;
  }

  // Serialize orch mutations per client so parallel dispatch/await of the same
  // coordinator cannot rebind its own sender mid-flight (mechanism A′).
  const needsOrchLock = op === 'dispatch' || op === 'await' || op === 'release' || op === 'check'
    || (op === 'cli' && Array.isArray(a.args) && a.args[0] === 'orchestration');
  if (needsOrchLock) {
    return withClientOrchLock(currentClientKey(), () => callToolUnlocked(op, a));
  }
  return callToolUnlocked(op, a);
}

async function callToolUnlocked(op, a) {
  if (op === 'health') return healthPayload({ verbose: a.verbose === true });


  if (op === 'guide') return coordinatorGuide();

  if (op === 'dispatch') {
    return dispatchWorker({
      spec: a.spec,
      objective: a.objective,
      agent: a.agent,
      worktree: a.worktree,
      name: a.name,
      repo: a.repo,
      run_id: a.runId,
      setup: a.setup,
      base_branch: a.baseBranch,
    });
  }

  if (op === 'await') {
    return awaitDispatch({
      run_id: a.runId,
      wait_ms: a.waitMs,
      ack: a.ack,
      types: a.types,
      peek: a.peek,
    });
  }

  if (op === 'release') {
    return releaseWorker({
      dispatch_id: a.dispatchId,
      terminal_handle: a.terminalHandle || a.terminal_handle || a.handle,
      task_id: a.taskId || a.task_id,
    });
  }

  if (op === 'check') {
    const waitMs = Math.min(Math.max(a.waitMs ?? CHECK_WAIT_DEFAULT_MS, 0), CHECK_WAIT_MAX_MS);
    const types = a.types != null ? String(a.types) : DEFAULT_WAIT_TYPES;
    let ack = a.ack != null && String(a.ack).trim() !== '' ? String(a.ack).trim() : null;
    let ackDropped = null;
    let argv = ['orchestration', 'check'];
    if (a.runId) argv.push('--run', String(a.runId));
    if (ack) argv.push('--ack', ack);
    if (a.peek) argv.push('--peek');
    if (a.all) argv.push('--all');
    if (types) argv.push('--types', types);
    if (waitMs > 0) argv.push('--wait', '--timeout-ms', String(waitMs));
    argv.push('--json');
    // Rebind only when not already bound (same rule as await — preserve ack generation).
    // NAS-248 P0 #4: check must not registerOwnedDispatch / claim ownership.
    if (a.runId) {
      const rid = String(a.runId);
      const sender = await resolveSenderTerminal();
      if (!isRunBound(rid, sender.handle)) {
        const useRes = await runJson(
          ['orchestration', 'run-use', '--id', rid, '--json'],
          { timeoutMs: 30_000 },
        );
        if (envOk(useRes) || useRes.envelope?.error?.code === 'already_bound') {
          markRunBound(rid, sender.handle);
        }
      }
    }
    try {
      argv = await withSender(argv);
    } catch (e) {
      return {
        ok: false,
        window_ms: waitMs,
        error: {
          code: 'no_sender_terminal',
          message: String(e?.message || e),
        },
      };
    }
    let run = await runOrca(argv, { timeoutMs: waitMs + 30_000 });
    let described = describeRun(run, true);
    let staleInfo = ack ? staleFromDescribed(described, ack) : null;
    if (staleInfo && ack) {
      // Drop bad ack (often messages[].id) and retry once without it.
      ackDropped = {
        deliveryId: ack,
        reason: staleInfo.hint || 'stale_delivery',
        detail: staleInfo.message,
      };
      const retryArgv = argv.filter((t, i, arr) => {
        if (t === '--ack') return false;
        if (i > 0 && arr[i - 1] === '--ack') return false;
        return true;
      });
      run = await runOrca(retryArgv, { timeoutMs: waitMs + 30_000 });
      described = describeRun(run, true);
      staleInfo = staleFromDescribed(described, ackDropped.deliveryId);
      // Successful retry clears stale; if still stale without ack, keep envelope.
      if (described.ok !== false && !described.envelope?.error) staleInfo = null;
    }
    return {
      window_ms: waitMs,
      client_key: currentClientKey(),
      ...described,
      ack_dropped: ackDropped || undefined,
      error_detail: staleInfo || undefined,
      next: staleInfo
        ? {
            action: 'retry_check_without_ack',
            detail: staleInfo.message,
          }
        : undefined,
    };
  }

  if (op === 'cli') {
    if (!Array.isArray(a.args) || a.args.length === 0 || !a.args.every((x) => typeof x === 'string')) {
      throw new Error('action=cli requires args: non-empty string array');
    }
    const policyResult = CLI_POLICY.evaluate(a.args);
    if (!policyResult.ok) {
      return policyResult.rejection;
    }
    let argv = a.args;
    try {
      argv = await withSender(a.args);
    } catch (e) {
      const sub = a.args[0] === 'orchestration' ? a.args[1] : null;
      if (ORCH_FROM_CMDS.has(sub) || sub === 'check' || sub === 'inbox') {
        return {
          ok: false,
          error: 'no_sender_terminal',
          message: String(e?.message || e),
          rejected_argv: a.args,
        };
      }
    }
    // Output parity: always spawn walkable JSON so redaction is never a no-op.
    argv = ensureWalkableCliArgv(argv);
    const run = await runOrca(argv, { timeoutMs: a.timeoutMs, cwd: a.cwd });
    const described = describeRun(run, true);
    // NAS-248: redact foreign scrollback by RESPONSE SHAPE, not argv spelling.
    // Internal runJson (resolveSenderTerminal) is unredacted on purpose.
    applyCliOwnershipRedaction(described, a.args);
    // NAS-239 dual-route: non-question reply → also send to dispatch:<id>.
    if (
      a.args[0] === 'orchestration' &&
      String(a.args[1] || '').toLowerCase() === 'reply' &&
      described.ok !== false
    ) {
      try {
        const dual = await dualRouteNonQuestionReply(a.args, described);
        if (dual) described.escalation_reply_route = dual;
      } catch (e) {
        described.escalation_reply_route = {
          dual_routed: false,
          error: String(e?.message || e),
        };
      }
    }
    return described;
  }

  throw new Error(`unknown tool: ${op}`);
}

// --- JSON-RPC / MCP ----------------------------------------------------------
function rpcResult(id, result) { return { jsonrpc: '2.0', id, result }; }
function rpcError(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }

async function handleRpc(msg, { sessionId } = {}) {
  const { id, method, params } = msg;
  const isNotification = id === undefined || id === null;
  try {
    if (method === 'initialize') {
      const requested = params?.protocolVersion;
      // Fresh MCP session on every initialize (client may omit the old id).
      const sid = sessionId && touchSession(sessionId) ? sessionId : newSessionId();
      const clientKey = currentClientKey();
      if (!sessions.has(sid)) {
        sessions.set(sid, {
          createdAt: Date.now(),
          lastSeen: Date.now(),
          authKind: 'init',
          clientKey,
        });
      } else {
        const s = touchSession(sid);
        if (s) s.clientKey = clientKey || s.clientKey;
      }
      return {
        response: rpcResult(id, {
          protocolVersion: KNOWN_PROTOCOLS.has(requested) ? requested : PROTOCOL_FALLBACK,
          capabilities: {
            tools: { listChanged: true },
            resources: { listChanged: true, subscribe: false },
          },
          serverInfo: { name: 'orca-bridge', version: VERSION },
          instructions:
            'orca-bridge v' + VERSION + ' (min ' + MIN_BRIDGE_VERSION + '). Single tool `orca` + action. ' +
            'Workers: dispatch → await(waitMs:45000)×N → worker_done → release(dispatchId,terminalHandle). ' +
            'Runtime/version self-checked lazily on dispatch/await/release (errors include code+recovery). ' +
            'Empty await carries liveness active|idle|stalled|unknown — re-call while active/idle; stalled → diagnose (peek/ping/release+report). ' +
            'question → cli orchestration reply then await+ack. Prefer summary.status over next.action; honor liveness on empty. ' +
            'health = optional compact diagnostics (verbose:true for full dump). guide = waves/brief/devices/stop-conditions. ' +
            'worker_done contract auto-appended on dispatch. ' +
            'Per-OAuth-client sender pin-by-handle (0.2.12+) — no mid-wave recreate; multi-coord safe. ' +
            'worktree create --agent --prompt rejected on cli.',
        }),
        sessionId: sid,
        isInitialize: true,
      };

    }
    if (method === 'notifications/initialized' || method?.startsWith('notifications/')) {
      return { response: null, sessionId };
    }
    if (method === 'ping') return { response: rpcResult(id, {}), sessionId };
    if (method === 'tools/list') return { response: rpcResult(id, { tools: TOOLS }), sessionId };
    if (method === 'resources/list') {
      const listed = listMcpResources({
        audit: auditLog,
        registry: dispatchRegistry,
        clientKey: currentClientKey(),
      });
      return { response: rpcResult(id, listed), sessionId };
    }
    if (method === 'resources/templates/list') {
      return {
        response: rpcResult(id, {
          resourceTemplates: [
            {
              uriTemplate: 'orca-bridge://dispatches/{dispatchId}',
              name: 'dispatch-status',
              title: 'Dispatch status by id',
              description: 'In-memory status for a single dispatch_id',
              mimeType: 'application/json',
            },
            {
              uriTemplate: 'orca-bridge://transcripts/{dispatchId}',
              name: 'dispatch-transcript',
              title: 'Redacted await transcript by dispatch id',
              description: 'Mailbox excerpts captured during await (bodies redacted)',
              mimeType: 'application/json',
            },
          ],
        }),
        sessionId,
      };
    }
    if (method === 'resources/read') {
      const uri = params?.uri;
      const read = readMcpResource(uri, {
        audit: auditLog,
        registry: dispatchRegistry,
        clientKey: currentClientKey(),
      });
      if (read.error) {
        return { response: rpcError(id, -32002, read.error), sessionId };
      }
      return { response: rpcResult(id, read), sessionId };
    }
    if (method === 'tools/call') {
      const started = Date.now();
      const toolName = params?.name;
      const toolArgs = params?.arguments || {};
      const action = resolveOrcaAction(toolName, toolArgs);
      try {
        const result = await callTool(toolName, toolArgs);
        const durationMs = Date.now() - started;
        log(`tool ${toolName} action=${action} ok ${durationMs}ms`);
        try {
          auditLog.appendEvent({
            tool: toolName || 'orca',
            action,
            args: toolArgs,
            clientKey: currentClientKey(),
            outcome: 'ok',
            durationMs,
          });
        } catch (ae) {
          log(`audit append WARN ${ae.message || ae}`);
        }
        // Back-compat: existing coordinators parse content[0].text JSON.
        const payload = {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
          isError: false,
        };
        // structuredContent for health + await (outputSchema on tool).
        if (STRUCTURED_OUTPUT_ACTIONS.has(action) && result && typeof result === 'object') {
          payload.structuredContent = result;
        }
        return {
          response: rpcResult(id, payload),
          sessionId,
        };
      } catch (e) {
        const durationMs = Date.now() - started;
        log(`tool ${toolName} action=${action} ERROR ${e.message}`);
        try {
          auditLog.appendEvent({
            tool: toolName || 'orca',
            action,
            args: toolArgs,
            clientKey: currentClientKey(),
            outcome: 'error',
            error: e.message,
            durationMs,
          });
        } catch (ae) {
          log(`audit append WARN ${ae.message || ae}`);
        }
        return {
          response: rpcResult(id, { content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true }),
          sessionId,
        };
      }
    }
    if (isNotification) return { response: null, sessionId };
    return { response: rpcError(id, -32601, `method not found: ${method}`), sessionId };
  } catch (e) {
    return { response: isNotification ? null : rpcError(id, -32603, e.message), sessionId };
  }
}

// --- Auth ---------------------------------------------------------------------
function tokenMatches(candidate) {
  return tokenMatchesCore(candidate, TOKEN);
}
// extractBearer imported from security-core.mjs

/**
 * Auth for protected paths.
 * Accepts (in order):
 *  1) Bearer master token or issued OAuth access token
 *  2) path prefix /t/<master-token>/…
 *  3) valid Mcp-Session-Id (session created after a successful initialize) —
 *     needed because Streamable HTTP clients on GET SSE often send only the sid.
 * @returns {{ path: string, sessionId: string, authKind: string, clientKey: string, bearer: string } | null}
 * See docs/design.md#auth-order-for-protected-paths.
 */
function authenticate(req) {
  pruneSessions();
  const rawPath = req.url || '/';
  const bearer = extractBearer(req);
  let authKind = '';
  if (bearer) {
    if (tokenMatches(bearer)) authKind = 'bearer-master';
    else if (issuedTokens.has(bearer)) authKind = 'bearer-oauth';
  }
  let pathOut = null;
  if (authKind) {
    pathOut = rawPath;
  } else {
    const m = rawPath.match(/^\/t\/([^/]+)(\/.*)?$/);
    if (m && tokenMatches(decodeURIComponent(m[1]))) {
      authKind = 'path-token';
      pathOut = m[2] || '/';
    }
  }
  const sid = sessionIdFrom(req);
  let sessionRec = null;
  if (!authKind && sid) {
    sessionRec = touchSession(sid);
    if (sessionRec) {
      authKind = 'session';
      pathOut = rawPath.replace(/^\/t\/[^/]+/, '') || '/';
      // path-token prefix already stripped only in branch above; for session-only
      // the URL is normally /mcp without /t/.
      if (rawPath.startsWith('/t/')) {
        // session alone must not unlock arbitrary /t/<wrong>/ — keep raw if no path auth
        pathOut = rawPath;
      } else {
        pathOut = rawPath;
      }
    }
  } else if (authKind && sid) {
    sessionRec = touchSession(sid);
  }
  if (!authKind || pathOut == null) return null;

  const clientKey = deriveClientKey({
    authKind,
    bearer: authKind === 'bearer-oauth' ? bearer : '',
    sessionId: sid,
    sessionClientKey: sessionRec?.clientKey || null,
  });
  // Persist identity on the MCP session so SSE / sid-only requests keep the same sender.
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

function wantsEventStream(req) {
  const accept = String(req.headers['accept'] || '');
  return accept.split(',').some((part) => part.trim().toLowerCase().startsWith('text/event-stream'));
}

/** CORS for browser-based MCP clients (Hyperagent OAuth UI / fetch). Bearer, not cookies. */
function corsHeaders() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, DELETE, OPTIONS',
    'access-control-allow-headers':
      'Authorization, Content-Type, Accept, Mcp-Session-Id, Last-Event-ID, MCP-Protocol-Version',
    'access-control-expose-headers':
      'Mcp-Session-Id, mcp-session-id, WWW-Authenticate, www-authenticate',
    'access-control-max-age': '86400',
  };
}

/**
 * Streamable HTTP POST response.
 * When Accept includes text/event-stream, many clients (incl. strict Streamable HTTP)
 * only parse SSE `event: message` frames — plain application/json → empty tool list.
 */
function sendRpc(req, res, reply, { sessionId, status = 200 } = {}) {
  const headers = { ...corsHeaders() };
  if (sessionId) headers['mcp-session-id'] = sessionId;
  if (reply === null) {
    res.writeHead(202, headers);
    return res.end();
  }
  const body = JSON.stringify(reply);
  if (wantsEventStream(req)) {
    res.writeHead(status, {
      ...headers,
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });
    // Single-message SSE stream; final response ends the stream (spec OK).
    res.write(`event: message\ndata: ${body}\n\n`);
    return res.end();
  }
  res.writeHead(status, { ...headers, 'content-type': 'application/json' });
  return res.end(body);
}

/** Open SSE stream for GET (server→client). Keepalive comment every SSE_KEEPALIVE_MS. */
function openSse(req, res, { sessionId } = {}) {
  const headers = {
    ...corsHeaders(),
    'content-type': 'text/event-stream; charset=utf-8',
    'cache-control': 'no-cache, no-transform',
    connection: 'keep-alive',
    'x-accel-buffering': 'no',
  };
  if (sessionId) headers['mcp-session-id'] = sessionId;
  res.writeHead(200, headers);
  // First bytes: padding/comment so proxies commit response headers.
  res.write(': connected\n\n');
  const timer = setInterval(() => {
    if (res.writableEnded) return;
    try { res.write(`: keepalive ${Date.now()}\n\n`); }
    catch { /* closed */ }
  }, SSE_KEEPALIVE_MS);
  if (typeof timer.unref === 'function') timer.unref();
  const cleanup = () => clearInterval(timer);
  req.on('close', cleanup);
  res.on('close', cleanup);
  res.on('error', cleanup);
}

// --- hindsight proxy ------------------------------------------------------------
function proxyHindsight(req, res, subPath) {
  const target = new URL(subPath + (req.url.includes('?') ? '?' + req.url.split('?').slice(1).join('?') : ''), HINDSIGHT_URL);
  const headers = { ...req.headers, host: HINDSIGHT_URL.host };
  delete headers['authorization'];
  const upstream = http.request(target, { method: req.method, headers }, (up) => {
    res.writeHead(up.statusCode || 502, up.headers);
    up.pipe(res); // SSE passes through unchanged
  });
  upstream.on('error', (e) => {
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'hindsight upstream unreachable', detail: e.message }));
  });
  req.pipe(upstream);
}

// --- HTTP server ---------------------------------------------------------------
// In --stdio mode stdout is the JSON-RPC stream only — all logs go to stderr.
function log(...a) {
  const sink = STDIO_MODE ? console.error : console.log;
  sink(new Date().toISOString(), ...a);
}

function readBody(req, limit = 4 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > limit) { reject(new Error('body too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res, status, obj, extraHeaders = {}) {
  res.writeHead(status, { 'content-type': 'application/json', ...extraHeaders });
  res.end(JSON.stringify(obj));
}

// --- OAuth endpoints (open: they are the auth mechanism) --------------------
// See docs/design.md#path-inserted-well-known-rfc-8414--9728.
async function handleOAuth(req, res, cleanPath, origin) {
  // Discovery: authorization server metadata (RFC 8414).
  // Prefix match: RFC 8414/9728 allow path-inserted well-known
  // (/.well-known/oauth-authorization-server/<resource-path>) — clients hit both
  // forms. Exact equality broke registration of path-scoped resources
  // (e.g. /hindsight/mcp/omp/).
  if (cleanPath.startsWith('/.well-known/oauth-authorization-server') || cleanPath.startsWith('/.well-known/openid-configuration')) {
    return sendJson(res, 200, {
      issuer: origin,
      authorization_endpoint: `${origin}/authorize`,
      token_endpoint: `${origin}/token`,
      registration_endpoint: `${origin}/register`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256', 'plain'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
      scopes_supported: ['orca'],
    }, { 'access-control-allow-origin': '*' });
  }
  // Discovery: protected resource metadata (RFC 9728), path-inserted form:
  // /.well-known/oauth-protected-resource/<resource-path>. `resource` in the
  // response must match the URL the client registers (/mcp,
  // /hindsight/mcp/omp/, …) or a strict client rejects the metadata.
  if (cleanPath.startsWith('/.well-known/oauth-protected-resource')) {
    const suffix = cleanPath.slice('/.well-known/oauth-protected-resource'.length) || '/mcp';
    return sendJson(res, 200, {
      resource: `${origin}${suffix}`,
      authorization_servers: [origin],
      scopes_supported: ['orca'],
    }, { 'access-control-allow-origin': '*' });
  }
  // Dynamic Client Registration (RFC 7591) — accept any public client.
  if (cleanPath === '/register' && req.method === 'POST') {
    let body = {};
    try { body = JSON.parse(await readBody(req)); } catch { /* empty body */ }
    const clientId = 'orca-bridge-' + b64url(randomBytes(9));
    return sendJson(res, 201, {
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: body.redirect_uris || [],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code'],
      response_types: ['code'],
    });
  }
  // Authorization endpoint — GET shows the form; POST checks the master token.
  if (cleanPath === '/authorize') {
    const u = new URL(req.url, origin);
    const q = u.searchParams;
    if (req.method === 'GET') {
      const redirectUri = q.get('redirect_uri') || '';
      if (!redirectAllowed(redirectUri)) {
        return sendJson(res, 400, { error: 'invalid redirect_uri', allowed_prefixes: REDIRECT_ALLOW });
      }
      const hidden = ['client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'scope', 'response_type']
        .map((k) => `<input type="hidden" name="${k}" value="${(q.get(k) || '').replace(/"/g, '&quot;')}">`).join('');
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(`<!doctype html><meta charset="utf-8"><title>orca-bridge · authorize</title>
<style>body{font:15px/1.5 system-ui;max-width:420px;margin:12vh auto;padding:0 20px}
h1{font-size:19px}input[type=password]{width:100%;padding:10px;font-size:15px;box-sizing:border-box}
button{margin-top:14px;padding:10px 18px;font-size:15px;cursor:pointer}small{color:#666}</style>
<h1>orca-bridge → Hyperagent</h1>
<p>Paste the bridge master token to grant Hyperagent access.</p>
<form method="POST" action="/authorize">${hidden}
<input type="password" name="master_token" placeholder="ORCA_BRIDGE_TOKEN" autofocus>
<button type="submit">Authorize</button></form>
<p><small>The token is not stored in Hyperagent settings — only here, once.</small></p>`);
    }
    if (req.method === 'POST') {
      const form = new URLSearchParams(await readBody(req));
      if (!tokenMatches(form.get('master_token') || '')) {
        res.writeHead(401, { 'content-type': 'text/html; charset=utf-8' });
        return res.end('<meta charset="utf-8"><p>Invalid token. <a href="javascript:history.back()">Back</a></p>');
      }
      const redirectUri = form.get('redirect_uri') || '';
      if (!redirectAllowed(redirectUri)) return sendJson(res, 400, { error: 'invalid redirect_uri' });
      pruneCodes();
      const code = b64url(randomBytes(24));
      authCodes.set(code, {
        codeChallenge: form.get('code_challenge') || '',
        method: form.get('code_challenge_method') || 'plain',
        redirectUri,
        clientId: form.get('client_id') || '',
        expiresAt: Date.now() + AUTH_CODE_TTL_MS,
      });
      const back = new URL(redirectUri);
      back.searchParams.set('code', code);
      if (form.get('state')) back.searchParams.set('state', form.get('state'));
      log('oauth: authorization code issued');
      res.writeHead(302, { location: back.href });
      return res.end();
    }
    res.writeHead(405); return res.end();
  }
  // Token endpoint — exchange code (with PKCE check) for an access token.
  if (cleanPath === '/token' && req.method === 'POST') {
    const form = new URLSearchParams(await readBody(req));
    if (form.get('grant_type') !== 'authorization_code') {
      return sendJson(res, 400, { error: 'unsupported_grant_type' });
    }
    pruneCodes();
    const code = form.get('code') || '';
    const entry = authCodes.get(code);
    if (!entry) return sendJson(res, 400, { error: 'invalid_grant' });
    authCodes.delete(code);
    if (form.get('redirect_uri') && form.get('redirect_uri') !== entry.redirectUri) {
      return sendJson(res, 400, { error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
    }
    if (!pkceOk(form.get('code_verifier') || '', entry.codeChallenge, entry.method)) {
      return sendJson(res, 400, { error: 'invalid_grant', error_description: 'PKCE failed' });
    }
    const accessToken = 'obt_' + b64url(randomBytes(32));
    issuedTokens.add(accessToken);
    persistTokens();
    log('oauth: access token issued');
    return sendJson(res, 200, { access_token: accessToken, token_type: 'Bearer', scope: 'orca' },
      { 'cache-control': 'no-store' });
  }
  return false; // not an OAuth path
}

/**
 * Unauthenticated (HMAC capability) worker orch relay.
 * Lives before the bearer gate so uid 994 never needs ORCA_BRIDGE_TOKEN.
 */
async function handleWorkerOrchHttp(req, res) {
  if (req.method !== 'POST') {
    return sendJson(res, 405, { ok: false, error: 'method not allowed' }, { allow: 'POST' });
  }
  if (!WORKER_ISOLATION.hmacSecret) {
    return sendJson(res, 503, { ok: false, error: 'worker hmac not configured' });
  }
  let body;
  try {
    body = JSON.parse(await readBody(req, 256 * 1024));
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: 'invalid json: ' + (e?.message || e) });
  }
  const token = typeof body?.capability === 'string' ? body.capability : '';
  const argv = Array.isArray(body?.argv) ? body.argv.map(String) : [];
  const verified = verifyWorkerCapability(token, WORKER_ISOLATION.hmacSecret, {});
  if (!verified.ok) {
    log(`worker-orch deny code=${verified.code}`);
    return sendJson(res, 401, { ok: false, error: verified.code, message: verified.message });
  }
  const parsed = parseWorkerOrchArgv(argv);
  const authz = authorizeWorkerOrch({ parsed, payload: verified.payload });
  if (!authz.ok) {
    log(`worker-orch deny code=${authz.code}`);
    return sendJson(res, 403, { ok: false, error: authz.code, message: authz.message });
  }

  const relayArgv = [...parsed.relayArgv];
  if (!relayArgv.includes('--json')) relayArgv.push('--json');
  const expectedDispatch = verified.payload.dispatchId;
  const expectedTask = verified.payload.taskId;
  if (expectedDispatch && !relayArgv.includes('--dispatch-id')) {
    relayArgv.push('--dispatch-id', String(expectedDispatch));
  }
  if (expectedTask && !relayArgv.includes('--task-id')) {
    relayArgv.push('--task-id', String(expectedTask));
  }
  // Do NOT inject the coordinator pin. Worker lifecycle signals must come
  // from the dispatched pane; --from is the worker terminal handle.
  const fromHandle = getArgFlag(relayArgv, '--from') || verified.payload.terminalHandle;
  if (fromHandle && !relayArgv.includes('--from')) {
    relayArgv.push('--from', String(fromHandle));
  }

  const timeoutMs = parsed.verb === 'ask' ? 620_000 : 60_000;
  log(`worker-orch relay op=${authz.op} dispatch=${expectedDispatch || '-'} verb=${parsed.verb}`);
  const described = await runJson(relayArgv, { timeoutMs, injectSender: false });
  const lifecycle = described?.envelope?.result?.lifecycle;
  const rejected = lifecycle && lifecycle.action === 'rejected';
  const ok = !rejected && (envOk(described) || described?.ok === true);
  return sendJson(res, ok ? 200 : 502, {
    ok,
    exitCode: ok ? 0 : 1,
    stdout: described?.stdout || '',
    result: described?.envelope?.result ?? described?.envelope ?? null,
    error: ok
      ? undefined
      : (lifecycle?.reason
        || described?.envelope?.error
        || described?.error
        || 'relay failed'),
  });
}

const server = http.createServer(async (req, res) => {
  const origin = originFor(req);
  const preAuthPath = (req.url || '/').split('?')[0];
  logRequest(req);

  // CORS preflight — must not require auth (browser OAuth / MCP fetch).
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders());
    return res.end();
  }

  // NAS-258: HMAC-gated worker orch relay — before bearer token gate.
  if (preAuthPath === '/worker/orch') {
    return handleWorkerOrchHttp(req, res);
  }

  // OAuth endpoints and discovery are handled BEFORE the token gate.
  if (preAuthPath.startsWith('/.well-known/') || preAuthPath === '/authorize'
      || preAuthPath === '/token' || preAuthPath === '/register') {
    const handled = await handleOAuth(req, res, preAuthPath, origin);
    if (handled !== false) return;
  }

  const auth = authenticate(req);
  if (auth === null) {
    log(`401 ${req.method} <redacted-path> auth=0 sid=${sessionIdFrom(req) ? '1' : '0'}`);
    res.writeHead(401, {
      ...corsHeaders(),
      'content-type': 'application/json',
      // MCP clients use this header to find protected-resource metadata → OAuth.
      // Path-inserted (RFC 9728): metadata for the specific requested resource.
      'www-authenticate': `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource${preAuthPath === '/' ? '/mcp' : preAuthPath}"`,
    });
    return res.end(JSON.stringify({ error: 'unauthorized' }));
  }
  const cleanPath = auth.path.split('?')[0];
  let sessionId = (auth.sessionId && touchSession(auth.sessionId)) ? auth.sessionId : '';
  const clientKey = auth.clientKey || 'default';

  return requestContext.run({ clientKey, sessionId, authKind: auth.authKind }, async () => {
  if (cleanPath.startsWith('/hindsight/') || cleanPath === '/hindsight') {
    const sub = cleanPath.replace(/^\/hindsight/, '') || '/';
    log(`${req.method} hindsight${sub}`);
    return proxyHindsight(req, res, sub);
  }

  if (cleanPath === '/mcp' || cleanPath === '/') {
    // --- Streamable HTTP: GET opens optional server→client SSE ---
    if (req.method === 'GET') {
      if (!wantsEventStream(req)) {
        res.writeHead(405, {
          ...corsHeaders(),
          'content-type': 'application/json',
          allow: 'GET, POST, DELETE, OPTIONS',
        });
        return res.end(JSON.stringify({
          error: 'method not allowed without Accept: text/event-stream; use POST for JSON-RPC or GET with SSE Accept',
        }));
      }
      // Session optional on GET: if the client arrived with only Bearer, mint a sid
      // so later POSTs with Mcp-Session-Id are recognized.
      if (!sessionId || !touchSession(sessionId)) {
        sessionId = newSessionId();
        sessions.set(sessionId, {
          createdAt: Date.now(),
          lastSeen: Date.now(),
          authKind: auth.authKind,
          clientKey,
        });
      } else {
        const s = sessions.get(sessionId);
        if (s) s.clientKey = clientKey;
      }
      log(`sse open sid=${sessionId.slice(0, 6)}… auth=${auth.authKind} client=${clientKey.slice(0, 18)}`);
      return openSse(req, res, { sessionId });
    }

    if (req.method === 'DELETE') {
      if (sessionId && sessions.has(sessionId)) {
        sessions.delete(sessionId);
        log(`session deleted ${sessionId.slice(0, 6)}…`);
      }
      res.writeHead(200, {
        ...corsHeaders(),
        ...(sessionId ? { 'mcp-session-id': sessionId } : {}),
      });
      return res.end();
    }

    if (req.method !== 'POST') {
      res.writeHead(405, {
        ...corsHeaders(),
        'content-type': 'application/json',
        allow: 'GET, POST, DELETE, OPTIONS',
      });
      return res.end(JSON.stringify({ error: 'method not allowed' }));
    }

    let msg;
    try { msg = JSON.parse(await readBody(req)); }
    catch (e) {
      return sendRpc(req, res, rpcError(null, -32700, 'parse error: ' + e.message), { status: 400 });
    }
    if (Array.isArray(msg)) {
      return sendRpc(req, res, rpcError(null, -32600, 'batching not supported'), { status: 400 });
    }

    log(`rpc ${msg.method} auth=${auth.authKind} client=${clientKey.slice(0, 18)}`);
    const handled = await handleRpc(msg, { sessionId });
    const reply = handled.response;
    sessionId = handled.sessionId || sessionId;
    // Keep session identity aligned after initialize issues a new sid.
    if (sessionId) {
      const s = sessions.get(sessionId);
      if (s) s.clientKey = clientKey;
      else {
        sessions.set(sessionId, {
          createdAt: Date.now(),
          lastSeen: Date.now(),
          authKind: auth.authKind,
          clientKey,
        });
      }
    }
    return sendRpc(req, res, reply, { sessionId });
  }

  res.writeHead(404, { ...corsHeaders(), 'content-type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
  }); // requestContext.run
});

// --- Transport selection: --stdio (local hosts) or Streamable HTTP (default) ---

/**
 * Boot check: the bridge must own the state it persists.
 *
 * A privileged install/upgrade/migration can replace ~/.orca-bridge-tokens.json
 * with a root-owned inode. Nothing then fails loudly — the bridge just starts
 * with an empty token set and every client silently re-authorizes, so this is
 * worth one noisy line at boot. See docs/design.md#state-file-ownership.
 */
function logStateOwnershipWarnings() {
  const warnings = stateOwnershipWarnings([TOKEN_STORE, SENDER_PIN_STORE, OWNERSHIP_STORE, AUDIT_DIR]);
  for (const w of warnings) log(`WARN: ${w}`);
  return warnings.length;
}

/**
 * stdio transport (MCP 2025-11-25): newline-delimited JSON-RPC on stdin/stdout.
 * Auth is env-only (ORCA_BRIDGE_TOKEN already required at boot). No OAuth browser flow.
 * Shared handleRpc / callTool — identical tool surface to HTTP mode.
 */
function writeStdioMessage(msg) {
  // Compact single-line JSON; embedded newlines in string values are escaped.
  process.stdout.write(JSON.stringify(msg) + '\n');
}

function startStdioServer() {
  const clientKey = 'master'; // env master token; same identity as bearer-master over HTTP
  let sessionId = '';
  let shuttingDown = false;

  const shutdown = (reason) => {
    if (shuttingDown) return;
    shuttingDown = true;
    log(`stdio shutdown (${reason})`);
    try { rl.close(); } catch { /* already closed */ }
    // Drain in-flight RPC before exit so the last response is not dropped.
    Promise.resolve(chain)
      .catch(() => {})
      .finally(() => process.exit(0));
  };

  const rl = createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
    terminal: false,
  });

  // Serialize RPC handling so concurrent lines still run in order.
  let chain = Promise.resolve();

  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    chain = chain.then(async () => {
      if (shuttingDown) return;
      let msg;
      try {
        msg = JSON.parse(trimmed);
      } catch (e) {
        writeStdioMessage(rpcError(null, -32700, 'parse error: ' + e.message));
        return;
      }
      if (Array.isArray(msg)) {
        writeStdioMessage(rpcError(null, -32600, 'batching not supported'));
        return;
      }
      log(`stdio rpc ${msg.method || '(response)'} client=${clientKey}`);
      try {
        const handled = await requestContext.run(
          { clientKey, sessionId, authKind: 'stdio-env' },
          () => handleRpc(msg, { sessionId }),
        );
        if (handled.sessionId) sessionId = handled.sessionId;
        if (handled.response != null) writeStdioMessage(handled.response);
      } catch (e) {
        const id = msg && typeof msg === 'object' ? msg.id : null;
        if (id !== undefined && id !== null) {
          writeStdioMessage(rpcError(id, -32603, e.message || String(e)));
        }
        log(`stdio rpc ERROR ${e.message || e}`);
      }
    }).catch((e) => {
      log(`stdio chain ERROR ${e.message || e}`);
    });
  });

  rl.on('close', () => shutdown('stdin-eof'));
  process.stdin.on('end', () => shutdown('stdin-end'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  log(`orca-bridge v${VERSION} stdio mode (protocol ${PROTOCOL_TARGET})`);
  log(`orca binary: ${orcaBinary()} | auth=ORCA_BRIDGE_TOKEN (env)`);
  logStateOwnershipWarnings();
}

function startHttpServer() {
  const portArg = process.argv.indexOf('--port');
  const PORT = portArg > -1 ? Number(process.argv[portArg + 1]) : Number(process.env.PORT || 8787);
  server.listen(PORT, '127.0.0.1', () => {
    log(`orca-bridge v${VERSION} listening on 127.0.0.1:${PORT}`);
    log(`orca binary: ${orcaBinary()} | hindsight proxy → ${HINDSIGHT_URL.href}`);
    log(`toolsets: [${TOOLSET_GATE.enabledList.join(',')}] source=${TOOLSET_GATE.source}` +
      (TOOLSET_GATE.readOnly ? ' read-only' : ''));
    log('expose via: tailscale funnel --bg ' + PORT);
    logStateOwnershipWarnings();
  });
}

if (STDIO_MODE) {
  startStdioServer();
} else {
  startHttpServer();
}
