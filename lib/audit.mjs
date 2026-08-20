/**
 * Append-only audit log + argument redaction for orca-mcp.
 * Pure helpers are free of process I/O at import time; fs paths/deps are injected.
 *
 * Audit format is NDJSON (one JSON object per line). Compatible later with a
 * replayable run archive without committing to that shape yet.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

/** Keys whose values must never land in the audit log verbatim. */
export const SENSITIVE_KEY_RE =
  /^(?:.*[_-]?)?(?:token|secret|password|passwd|authorization|auth|api[_-]?key|bearer|cookie|set-cookie|credential|private[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|prompt|spec|body|brief|message|content|text|email)(?:[_-]?.*)?$/i;

/** CLI flags whose following argv value is sensitive. */
export const SENSITIVE_ARGV_FLAGS = new Set([
  '--prompt',
  '--spec',
  '--body',
  '--token',
  '--authorization',
  '--password',
  '--secret',
  '--api-key',
  '--apikey',
  '--access-token',
  '--refresh-token',
  '--client-secret',
  '--bearer',
]);

const REDACTED = '[REDACTED]';
const REDACTED_LEN = '[REDACTED len=';

/** Default max size of the active audit file before rotation (4 MiB). */
export const DEFAULT_AUDIT_MAX_BYTES = 4 * 1024 * 1024;
/** Keep this many rotated `audit.N.ndjson` siblings. */
export const DEFAULT_AUDIT_MAX_FILES = 5;

/**
 * Heuristic: string looks like a bearer/master/oauth token or Authorization header.
 * Conservative — false positives only hide more.
 */
export function looksLikeSecret(value) {
  if (typeof value !== 'string') return false;
  const s = value.trim();
  if (!s) return false;
  if (/^bearer\s+\S+/i.test(s)) return true;
  if (/^obt_[A-Za-z0-9_-]{8,}$/.test(s)) return true;
  if (/^orca[_-]?bridge[_-]?token=/i.test(s)) return true;
  // long hex / base64url blobs commonly used as tokens
  if (s.length >= 24 && /^[A-Fa-f0-9]+$/.test(s)) return true;
  if (s.length >= 32 && /^[A-Za-z0-9_-]+$/.test(s) && /[A-Z]/.test(s) && /[a-z]/.test(s) && /\d/.test(s)) {
    return true;
  }
  return false;
}

function redactString(value, keyHint = '') {
  if (SENSITIVE_KEY_RE.test(String(keyHint || ''))) {
    return `${REDACTED_LEN}${value.length}]`;
  }
  if (looksLikeSecret(value)) {
    return `${REDACTED_LEN}${value.length}]`;
  }
  // Scrub embedded Authorization: Bearer … / token=… fragments inside free text.
  let out = value;
  out = out.replace(/(Authorization\s*:\s*)Bearer\s+\S+/gi, `$1Bearer ${REDACTED}`);
  out = out.replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/g, `Bearer ${REDACTED}`);
  out = out.replace(/\b(obt_[A-Za-z0-9_-]{8,})\b/g, REDACTED);
  out = out.replace(/\b([A-Fa-f0-9]{32,})\b/g, REDACTED);
  return out;
}

/**
 * Redact a single value. `keyHint` is the property name when walking objects.
 * Pure: never throws on cycles (replaces with [Circular]).
 */
export function redactValue(value, keyHint = '', seen = new WeakSet()) {
  if (value == null) return value;
  if (typeof value === 'string') return redactString(value, keyHint);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (typeof value === 'bigint') return String(value);
  if (typeof value === 'function') return '[Function]';
  if (typeof value !== 'object') return String(value);

  if (seen.has(value)) return '[Circular]';
  seen.add(value);

  if (Array.isArray(value)) {
    // CLI argv special-case when parent key is args/argv
    if (/^(args|argv)$/i.test(String(keyHint || ''))) {
      return redactArgv(value);
    }
    return value.map((v, i) => redactValue(v, String(i), seen));
  }

  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (SENSITIVE_KEY_RE.test(k)) {
      if (typeof v === 'string') out[k] = `${REDACTED_LEN}${v.length}]`;
      else if (v == null) out[k] = v;
      else out[k] = REDACTED;
      continue;
    }
    out[k] = redactValue(v, k, seen);
  }
  return out;
}

/**
 * Redact an orca CLI argv array: flag+value pairs and inline --flag=value.
 */
export function redactArgv(argv) {
  if (!Array.isArray(argv)) return [];
  const out = [];
  for (let i = 0; i < argv.length; i++) {
    const raw = argv[i];
    const s = raw == null ? '' : String(raw);
    const eq = s.match(/^(--[^=]+)=(.*)$/);
    if (eq) {
      const flag = eq[1];
      if (SENSITIVE_ARGV_FLAGS.has(flag) || SENSITIVE_KEY_RE.test(flag.slice(2))) {
        out.push(`${flag}=${REDACTED_LEN}${eq[2].length}]`);
      } else if (looksLikeSecret(eq[2])) {
        out.push(`${flag}=${REDACTED_LEN}${eq[2].length}]`);
      } else {
        out.push(`${flag}=${redactString(eq[2], flag.slice(2))}`);
      }
      continue;
    }
    if (SENSITIVE_ARGV_FLAGS.has(s) || (s.startsWith('--') && SENSITIVE_KEY_RE.test(s.slice(2)))) {
      out.push(s);
      if (i + 1 < argv.length) {
        const next = argv[i + 1];
        const n = next == null ? '' : String(next);
        out.push(n.startsWith('--') ? n : `${REDACTED_LEN}${n.length}]`);
        if (!n.startsWith('--')) i += 1;
      }
      continue;
    }
    out.push(typeof raw === 'string' ? redactString(raw, '') : redactValue(raw, ''));
  }
  return out;
}

/**
 * Redact tool-call arguments for audit persistence.
 * Always a plain JSON-serializable object/array/primitive.
 */
export function redactArgs(args) {
  if (args == null) return {};
  if (typeof args !== 'object') return { value: redactValue(args, 'value') };
  return redactValue(args, '');
}

/**
 * Per-action annotation semantics (tool-level MCP annotations cannot vary by action).
 * Documented in tool description and returned under health.actionAnnotations.
 */
export const ACTION_ANNOTATIONS = Object.freeze({
  health: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
    note: 'Optional diagnostics (compact default; verbose:true for full dump). Not a pre-wave ritual.',
  },

  guide: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    note: 'Static coordinator doctrine payload.',
  },
  await: {
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
    note: 'Mailbox wait; ack consumes deliveries (not read-only).',
  },
  check: {
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
    note: 'Raw orchestration check; ack may consume.',
  },
  dispatch: {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
    note: 'Creates worktree/terminal and injects a worker.',
  },
  release: {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: true,
    openWorldHint: true,
    note: 'Releases worker / closes worker terminal tab.',
  },
  cli: {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
    note: 'Raw orca argv; destructiveness depends on subcommand — treat as open-world.',
  },
});

/** Tool-level MCP annotations: conservative union of all actions. */
export const ORCA_TOOL_ANNOTATIONS = Object.freeze({
  title: 'Orca bridge',
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: true,
});

/**
 * Loose outputSchema covering health + await structured results.
 * additionalProperties allowed so other actions remain valid if attached later.
 */
export const ORCA_OUTPUT_SCHEMA = Object.freeze({
  type: 'object',
  additionalProperties: true,
  properties: {
    // health
    bridge: {
      type: 'object',
      additionalProperties: true,
      properties: {
        version: { type: 'string' },
        minVersion: { type: 'string' },
        versionOk: { type: 'boolean' },
        uptimeSec: { type: 'number' },
        node: { type: 'string' },
        platform: { type: 'string' },
      },
    },
    orcaBinary: { type: 'string' },
    defaultAgent: { type: 'string' },
    actions: { type: 'array', items: { type: 'string' } },
    actionAnnotations: { type: 'object', additionalProperties: true },
    statusProbe: { type: 'object', additionalProperties: true },
    next: { type: 'object', additionalProperties: true },
    // await (+ liveness NAS-240)
    ok: { type: 'boolean' },
    run_id: { type: 'string' },
    window_ms: { type: 'number' },
    timedOut: { type: 'boolean' },
    deliveryId: { type: ['string', 'null'] },
    count: { type: 'number' },
    summary: { type: 'object', additionalProperties: true },
    messages: { type: 'array' },
    client_key: { type: 'string' },
    sender_handle: { type: 'string' },
    liveness: { type: 'string' },
    msSinceDispatch: { type: ['number', 'null'] },
    msSinceActivity: { type: ['number', 'null'] },
    emptyWindowsConsecutive: { type: 'number' },
    livenessReason: { type: 'string' },
    verbose: { type: 'boolean' },

  },
});

/**
 * Actions that emit structuredContent alongside the legacy text payload.
 */
export const STRUCTURED_OUTPUT_ACTIONS = new Set(['health', 'await']);

/**
 * Resolve multiplex action name the same way callTool does (best-effort, pure).
 */
export function resolveOrcaAction(toolName, args = {}) {
  const name = String(toolName || '');
  const a = args && typeof args === 'object' ? args : {};
  const aliases = {
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
  let op = aliases[name] || name;
  if (op === 'orca') {
    const action = String(a.action || '').trim().toLowerCase();
    if (action === 'health' || action === 'bridge_health') return 'health';
    if (action === 'dispatch' || action === 'dispatch_worker') return 'dispatch';
    if (action === 'await' || action === 'awaitdispatch' || action === 'await_dispatch') return 'await';
    if (action === 'release' || action === 'release_worker') return 'release';
    if (action === 'guide' || action === 'coordinator') return 'guide';
    if (action === 'check' || action === 'orca_check') return 'check';
    if (action === 'cli' || action === '') {
      if (Array.isArray(a.args) && a.args.length) return 'cli';
      if (!action) return 'health';
      return 'cli';
    }
    return action || 'unknown';
  }
  return op;
}

/**
 * Build one audit record (already redacted).
 */
export function buildAuditRecord({
  tool = 'orca',
  action = null,
  args = {},
  clientKey = 'default',
  outcome = 'ok',
  error = null,
  durationMs = 0,
  ts = new Date().toISOString(),
} = {}) {
  return {
    ts: typeof ts === 'string' ? ts : new Date(ts).toISOString(),
    tool: String(tool || 'orca'),
    action: action == null ? null : String(action),
    args: redactArgs(args),
    clientKey: String(clientKey || 'default'),
    outcome: outcome === 'error' || outcome === 'ok' ? outcome : String(outcome),
    error: error == null ? null : String(error).slice(0, 2000),
    durationMs: Number.isFinite(durationMs) ? Math.max(0, Math.round(durationMs)) : 0,
  };
}

/**
 * Append-only NDJSON audit log with size-based rotation.
 * No rewrite/update API — only append + read.
 */
export function createAuditLog(options = {}) {
  const {
    dir = path.join(os.homedir(), '.orca-bridge'),
    filename = 'audit.ndjson',
    maxBytes = DEFAULT_AUDIT_MAX_BYTES,
    maxFiles = DEFAULT_AUDIT_MAX_FILES,
    fs: fsImpl = fs,
    now = () => new Date(),
  } = options;

  const filePath = path.join(dir, filename);

  function ensureDir() {
    try {
      fsImpl.mkdirSync(dir, { recursive: true, mode: 0o700 });
    } catch {
      /* race ok */
    }
  }

  function rotateIfNeeded() {
    try {
      if (!fsImpl.existsSync(filePath)) return;
      const st = fsImpl.statSync(filePath);
      if (st.size < maxBytes) return;
      // audit.ndjson -> audit.1.ndjson -> … -> delete oldest
      for (let i = maxFiles - 1; i >= 1; i--) {
        const src = path.join(dir, `audit.${i}.ndjson`);
        const dst = path.join(dir, `audit.${i + 1}.ndjson`);
        if (fsImpl.existsSync(src)) {
          try {
            if (i + 1 > maxFiles) fsImpl.unlinkSync(src);
            else fsImpl.renameSync(src, dst);
          } catch {
            /* best-effort */
          }
        }
      }
      const first = path.join(dir, 'audit.1.ndjson');
      try {
        if (fsImpl.existsSync(first)) fsImpl.unlinkSync(first);
      } catch {
        /* */
      }
      try {
        fsImpl.renameSync(filePath, first);
      } catch {
        /* */
      }
    } catch {
      /* rotation must never block append path hard */
    }
  }

  function append(record) {
    ensureDir();
    rotateIfNeeded();
    const line = JSON.stringify(record) + '\n';
    fsImpl.appendFileSync(filePath, line, { mode: 0o600 });
    return record;
  }

  function appendEvent(fields) {
    const record = buildAuditRecord({
      ...fields,
      ts: fields.ts || now().toISOString(),
    });
    return append(record);
  }

  /**
   * Read up to `limit` most recent records (from active file only).
   */
  function readTail(limit = 200) {
    const n = Math.max(1, Math.min(Number(limit) || 200, 5000));
    if (!fsImpl.existsSync(filePath)) return [];
    let text = '';
    try {
      text = fsImpl.readFileSync(filePath, 'utf8');
    } catch {
      return [];
    }
    const lines = text.split('\n').filter((l) => l.trim());
    const slice = lines.slice(-n);
    const out = [];
    for (const line of slice) {
      try {
        out.push(JSON.parse(line));
      } catch {
        out.push({ ts: null, parseError: true, raw: line.slice(0, 500) });
      }
    }
    return out;
  }

  /**
   * Read full active file as NDJSON text (for resources/read).
   */
  function readText() {
    if (!fsImpl.existsSync(filePath)) return '';
    try {
      return fsImpl.readFileSync(filePath, 'utf8');
    } catch {
      return '';
    }
  }

  function stat() {
    try {
      if (!fsImpl.existsSync(filePath)) {
        return { path: filePath, exists: false, bytes: 0, lines: 0 };
      }
      const st = fsImpl.statSync(filePath);
      const text = fsImpl.readFileSync(filePath, 'utf8');
      const lines = text ? text.split('\n').filter((l) => l.trim()).length : 0;
      return { path: filePath, exists: true, bytes: st.size, lines, mtimeMs: st.mtimeMs };
    } catch (e) {
      return { path: filePath, exists: false, bytes: 0, lines: 0, error: String(e.message || e) };
    }
  }

  return {
    path: filePath,
    dir,
    append,
    appendEvent,
    readTail,
    readText,
    stat,
    /** test/debug only — not a public rewrite API */
    _filePath: filePath,
  };
}

/**
 * In-memory dispatch + transcript registry for MCP resources.
 * Updated by the server on dispatch / await / release.
 *
 * NAS-248 P0 #4: `clientKey` is an ownership binding, not a free-form patch
 * field. Once set, it is authoritative and not claimable from a later read
 * path (await/check). Callers that legitimately establish ownership at
 * dispatch-time use {@link bindOwner}; plain {@link upsert} never creates or
 * overwrites a different client's binding.
 */
export function createDispatchRegistry() {
  /** @type {Map<string, object>} */
  const byId = new Map();
  /** @type {Map<string, Array<object>>} */
  const transcripts = new Map();

  /**
   * Merge non-ownership fields. `clientKey` is always ignored here — use bindOwner.
   */
  function upsert(dispatchId, patch = {}) {
    const id = String(dispatchId || '').trim();
    if (!id) return null;
    const prev = byId.get(id) || { dispatchId: id, createdAt: new Date().toISOString() };
    // Strip ownership claim fields from general upserts. Status/liveness/transcript
    // metadata may update; identity may not.
    const safePatch = patch && typeof patch === 'object' ? { ...patch } : {};
    delete safePatch.clientKey;
    // terminalHandle is part of the ownership surface used by release resolvers —
    // allow setting only when previously empty, never overwrite with a different handle.
    if (
      prev.terminalHandle &&
      safePatch.terminalHandle != null &&
      String(safePatch.terminalHandle) !== '' &&
      String(safePatch.terminalHandle) !== String(prev.terminalHandle)
    ) {
      delete safePatch.terminalHandle;
    }
    const next = {
      ...prev,
      ...safePatch,
      dispatchId: id,
      // Preserve authoritative owner even if a stale spread tried to clear it.
      clientKey: prev.clientKey,
      updatedAt: new Date().toISOString(),
    };
    byId.set(id, next);
    return next;
  }

  /**
   * Authoritative ownership bind — dispatch-time (or durable hydrate) only.
   * Refuses to reassign an existing different clientKey.
   *
   * @param {string} dispatchId
   * @param {{ clientKey: string, terminalHandle?: string|null, runId?: string|null, taskId?: string|null, status?: string, [k: string]: unknown }} binding
   * @returns {{ ok: true, row: object, created: boolean } | { ok: false, reason: string, row: object|null }}
   */
  function bindOwner(dispatchId, binding = {}) {
    const id = String(dispatchId || '').trim();
    if (!id) return { ok: false, reason: 'missing_dispatch_id', row: null };
    const ck = binding.clientKey == null ? '' : String(binding.clientKey).trim();
    if (!ck) return { ok: false, reason: 'missing_client_key', row: null };

    const prev = byId.get(id) || null;
    if (prev?.clientKey && String(prev.clientKey) !== ck) {
      return { ok: false, reason: 'owner_mismatch', row: prev };
    }

    const base = prev || { dispatchId: id, createdAt: new Date().toISOString() };
    const next = {
      ...base,
      ...binding,
      dispatchId: id,
      clientKey: ck,
      updatedAt: new Date().toISOString(),
    };
    byId.set(id, next);
    return { ok: true, row: next, created: !prev };
  }

  function get(dispatchId) {
    return byId.get(String(dispatchId || '')) || null;
  }

  function list({ clientKey } = {}) {
    const all = [...byId.values()].sort((a, b) =>
      String(b.updatedAt || '').localeCompare(String(a.updatedAt || '')),
    );
    if (clientKey) return all.filter((d) => !d.clientKey || d.clientKey === clientKey);
    return all;
  }

  function appendTranscript(dispatchId, entry) {
    const id = String(dispatchId || '').trim();
    if (!id || !entry) return;
    const row = {
      ts: entry.ts || new Date().toISOString(),
      type: entry.type || 'event',
      // body must already be redacted by caller
      body: entry.body == null ? null : String(entry.body).slice(0, 8000),
      deliveryId: entry.deliveryId || null,
    };
    const arr = transcripts.get(id) || [];
    arr.push(row);
    // cap per dispatch
    if (arr.length > 200) arr.splice(0, arr.length - 200);
    transcripts.set(id, arr);
  }

  function getTranscript(dispatchId) {
    return transcripts.get(String(dispatchId || '')) || [];
  }

  function listTranscriptIds() {
    return [...transcripts.keys()];
  }

  /**
   * Snapshot ownership bindings for durable persistence (no transcripts).
   * @returns {object[]}
   */
  function listOwnershipBindings() {
    return [...byId.values()]
      .filter((d) => d && d.dispatchId && d.clientKey)
      .map((d) => {
        const row = {
          dispatchId: String(d.dispatchId),
          clientKey: String(d.clientKey),
          terminalHandle: d.terminalHandle || null,
          runId: d.runId || null,
          taskId: d.taskId || null,
          status: d.status || null,
          agent: d.agent || null,
          worktree: d.worktree || null,
          name: d.name || null,
          dispatchedAt: d.dispatchedAt || d.createdAt || null,
        };
        if (d.workerIsolation === true || d.workerIsolation === false) {
          row.workerIsolation = d.workerIsolation;
        }
        if (d.workerCapabilityMinted === true || d.workerCapabilityMinted === false) {
          row.workerCapabilityMinted = d.workerCapabilityMinted;
        }
        return row;
      });
  }

  return {
    upsert,
    bindOwner,
    get,
    list,
    appendTranscript,
    getTranscript,
    listTranscriptIds,
    listOwnershipBindings,
  };
}

/** Resource URI helpers */
export const RESOURCE_URIS = Object.freeze({
  auditLog: 'orca-bridge://audit/log',
  auditTail: 'orca-bridge://audit/tail',
  dispatches: 'orca-bridge://dispatches',
  dispatchPrefix: 'orca-bridge://dispatches/',
  transcriptPrefix: 'orca-bridge://transcripts/',
});

/**
 * Build resources/list payload from audit + dispatch registry.
 */
export function listMcpResources({ audit, registry, clientKey } = {}) {
  const resources = [
    {
      uri: RESOURCE_URIS.auditLog,
      name: 'audit-log',
      title: 'Bridge audit log (NDJSON)',
      description:
        'Append-only audit trail of orca tool calls (redacted args). MIME application/x-ndjson.',
      mimeType: 'application/x-ndjson',
    },
    {
      uri: RESOURCE_URIS.auditTail,
      name: 'audit-tail',
      title: 'Bridge audit log tail (JSON)',
      description: 'Last ~200 audit records as a JSON array (already redacted).',
      mimeType: 'application/json',
    },
    {
      uri: RESOURCE_URIS.dispatches,
      name: 'dispatches',
      title: 'Dispatch status index',
      description: 'In-memory status of dispatches owned/seen by this bridge process.',
      mimeType: 'application/json',
    },
  ];

  const dispatches = registry ? registry.list({ clientKey }) : [];
  for (const d of dispatches) {
    resources.push({
      uri: RESOURCE_URIS.dispatchPrefix + encodeURIComponent(d.dispatchId),
      name: `dispatch-${d.dispatchId}`,
      title: `Dispatch ${d.dispatchId}`,
      description: `Status=${d.status || 'unknown'} run=${d.runId || '?'}`,
      mimeType: 'application/json',
    });
    resources.push({
      uri: RESOURCE_URIS.transcriptPrefix + encodeURIComponent(d.dispatchId),
      name: `transcript-${d.dispatchId}`,
      title: `Transcript ${d.dispatchId}`,
      description: 'Redacted worker mailbox excerpts captured during await.',
      mimeType: 'application/json',
    });
  }

  // Orphan transcripts (if any)
  if (registry) {
    for (const id of registry.listTranscriptIds()) {
      const uri = RESOURCE_URIS.transcriptPrefix + encodeURIComponent(id);
      if (!resources.some((r) => r.uri === uri)) {
        resources.push({
          uri,
          name: `transcript-${id}`,
          title: `Transcript ${id}`,
          description: 'Redacted worker mailbox excerpts captured during await.',
          mimeType: 'application/json',
        });
      }
    }
  }

  return { resources };
}

/**
 * resources/read implementation (pure given deps).
 * @returns {{ contents: Array<{uri,mimeType,text}> } | { error: string }}
 */
export function readMcpResource(uri, { audit, registry, clientKey, tailLimit = 200 } = {}) {
  const u = String(uri || '');
  if (!u) return { error: 'uri required' };

  if (u === RESOURCE_URIS.auditLog) {
    const text = audit ? audit.readText() : '';
    return {
      contents: [
        {
          uri: u,
          mimeType: 'application/x-ndjson',
          text: text || '',
        },
      ],
    };
  }

  if (u === RESOURCE_URIS.auditTail) {
    const rows = audit ? audit.readTail(tailLimit) : [];
    return {
      contents: [
        {
          uri: u,
          mimeType: 'application/json',
          text: JSON.stringify({ count: rows.length, records: rows }, null, 2),
        },
      ],
    };
  }

  if (u === RESOURCE_URIS.dispatches) {
    const list = registry ? registry.list({ clientKey }) : [];
    return {
      contents: [
        {
          uri: u,
          mimeType: 'application/json',
          text: JSON.stringify({ count: list.length, dispatches: list }, null, 2),
        },
      ],
    };
  }

  if (u.startsWith(RESOURCE_URIS.dispatchPrefix)) {
    const id = decodeURIComponent(u.slice(RESOURCE_URIS.dispatchPrefix.length));
    const row = registry ? registry.get(id) : null;
    if (!row) return { error: `unknown dispatch: ${id}` };
    if (clientKey && row.clientKey && row.clientKey !== clientKey) {
      return { error: `dispatch not visible to client` };
    }
    return {
      contents: [
        {
          uri: u,
          mimeType: 'application/json',
          text: JSON.stringify(row, null, 2),
        },
      ],
    };
  }

  if (u.startsWith(RESOURCE_URIS.transcriptPrefix)) {
    const id = decodeURIComponent(u.slice(RESOURCE_URIS.transcriptPrefix.length));
    const entries = registry ? registry.getTranscript(id) : [];
    const meta = registry ? registry.get(id) : null;
    if (clientKey && meta?.clientKey && meta.clientKey !== clientKey) {
      return { error: `transcript not visible to client` };
    }
    return {
      contents: [
        {
          uri: u,
          mimeType: 'application/json',
          text: JSON.stringify(
            {
              dispatchId: id,
              count: entries.length,
              entries,
              status: meta || null,
            },
            null,
            2,
          ),
        },
      ],
    };
  }

  return { error: `unknown resource uri: ${u}` };
}

/**
 * Shallow structural check that `value` satisfies a tiny subset of JSON Schema
 * used by ORCA_OUTPUT_SCHEMA (type object + known property types).
 * Not a full validator — enough for unit tests of health/await payloads.
 */
export function conformsToOutputSchema(value, schema = ORCA_OUTPUT_SCHEMA) {
  if (!schema || schema.type !== 'object') return true;
  if (value == null || typeof value !== 'object' || Array.isArray(value)) return false;
  const props = schema.properties || {};
  for (const [key, def] of Object.entries(props)) {
    if (!(key in value) || value[key] === undefined) continue;
    const v = value[key];
    const types = Array.isArray(def.type) ? def.type : def.type ? [def.type] : null;
    if (!types) continue;
    const ok = types.some((t) => {
      if (t === 'null') return v === null;
      if (t === 'array') return Array.isArray(v);
      if (t === 'object') return v != null && typeof v === 'object' && !Array.isArray(v);
      return typeof v === t;
    });
    if (!ok) return false;
  }
  return true;
}
