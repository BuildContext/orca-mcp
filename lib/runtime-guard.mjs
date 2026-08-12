/**
 * Runtime readiness + await liveness helpers (pure / injectable I/O).
 *
 * NAS-246: self-diagnosing runtime errors replace "call health first" ritual.
 * NAS-240: empty await windows carry liveness so coordinators can stop.
 *
 * Keep free of process globals so unit tests can import without TOKEN.
 */

/** Cache TTL for lazy status probes inside dispatch/await/release. */
export const RUNTIME_PROBE_TTL_MS = 30_000;

/**
 * Liveness thresholds (derived from PREFERRED_WAIT_MS=45s windows).
 *
 * - active: recent terminal/output activity, or fewer than 2 empty windows
 * - idle: thinking is still plausible (2–7 empty ~45s windows, or 90s–8min quiet)
 * - stalled: 8+ empty windows (~6min) OR 8+ minutes without activity signal
 * - unknown: no dispatch/terminal signal to judge
 *
 * Rationale: 15–60 min tasks are normal, so idle must be wide; stalled only
 * after several consecutive empty windows *and* no activity, matching the
 * ticket failure mode (12 min of empty=normal with a dead worker).
 */
export const LIVENESS_THRESHOLDS = Object.freeze({
  /** Below this ms-since-activity → active (when activity known). */
  activeMs: 90_000,
  /** Above this ms-since-activity (with enough empty windows) → stalled. */
  stalledMs: 8 * 60_000,
  /** emptyWindowsConsecutive below this stays active when no better signal. */
  activeEmptyMax: 1,
  /** emptyWindowsConsecutive at/above this → stalled (even without activity ts). */
  stalledEmptyMin: 8,
  /** emptyWindowsConsecutive at/above this (with quiet activity) → stalled. */
  stalledEmptyWithQuiet: 4,
});

export function parseSemver(v) {
  const m = String(v || '')
    .trim()
    .match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

export function versionGte(a, b) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return false;
  for (let i = 0; i < 3; i++) {
    if (pa[i] > pb[i]) return true;
    if (pa[i] < pb[i]) return false;
  }
  return true;
}

/**
 * Structured runtime failure for dispatch/await/release.
 * Thrown as Error with `.code` / `.payload` so call sites can return JSON.
 */
export class RuntimeGuardError extends Error {
  /**
   * @param {{ code: string, message: string, reason?: string, recovery?: string, details?: object }} p
   */
  constructor({ code, message, reason, recovery, details } = {}) {
    super(message || code || 'runtime_unavailable');
    this.name = 'RuntimeGuardError';
    this.code = code || 'runtime_unavailable';
    this.reason = reason || message || this.code;
    this.recovery = recovery || null;
    this.details = details || null;
  }

  toJSON() {
    return {
      ok: false,
      error: {
        code: this.code,
        message: this.message,
        reason: this.reason,
        recovery: this.recovery,
        details: this.details,
      },
      next: {
        action: 'diagnose',
        detail:
          this.recovery ||
          'Runtime check failed. Fix the cause above, then retry the same action (no ritual health required).',
      },
    };
  }
}

/**
 * In-memory TTL cache for lazy runtime probes.
 * @param {{ ttlMs?: number, now?: () => number }} [opts]
 */
export function createRuntimeProbeCache(opts = {}) {
  const ttlMs = Number.isFinite(opts.ttlMs) ? opts.ttlMs : RUNTIME_PROBE_TTL_MS;
  const now = typeof opts.now === 'function' ? opts.now : () => Date.now();
  /** @type {{ at: number, value: object } | null} */
  let entry = null;

  function get() {
    if (!entry) return null;
    if (now() - entry.at > ttlMs) {
      entry = null;
      return null;
    }
    return entry.value;
  }

  function set(value) {
    entry = { at: now(), value };
    return value;
  }

  function clear() {
    entry = null;
  }

  return { get, set, clear, ttlMs };
}

/**
 * Validate bridge version + optional status probe snapshot.
 * @param {{
 *   version: string,
 *   minVersion: string,
 *   probe?: { ok?: boolean, exitCode?: number|null, spawnError?: string|null, error?: string|null, envelope?: object },
 * }} p
 * @returns {{ ok: true, versionOk: true } | never}
 */
export function assertRuntimeReady({ version, minVersion, probe } = {}) {
  const versionOk = versionGte(version, minVersion);
  if (!versionOk) {
    throw new RuntimeGuardError({
      code: 'bridge_version_too_old',
      message: `bridge.version ${version} < min ${minVersion}`,
      reason: `Installed bridge version ${version} is below required minimum ${minVersion}.`,
      recovery:
        `Ask the owner to restart/upgrade orca-mcp to >= ${minVersion}. ` +
        'Do NOT fall back to worktree create --agent --prompt.',
      details: { version, minVersion, versionOk: false },
    });
  }

  if (probe == null) {
    return { ok: true, versionOk: true };
  }

  const spawnError = probe.spawnError || null;
  const exitCode = probe.exitCode;
  const envelopeOk = probe.envelope?.ok;
  const explicitOk = probe.ok;
  const runtimeOk =
    explicitOk === true ||
    (explicitOk !== false &&
      !spawnError &&
      (exitCode === 0 || exitCode == null) &&
      envelopeOk !== false);

  if (!runtimeOk) {
    const reasonParts = [];
    if (spawnError) reasonParts.push(`spawn failed: ${spawnError}`);
    if (exitCode != null && exitCode !== 0) reasonParts.push(`orca status exit ${exitCode}`);
    if (probe.error) reasonParts.push(String(probe.error));
    if (envelopeOk === false) {
      const code = probe.envelope?.error?.code || 'status_failed';
      reasonParts.push(`status envelope ok=false (${code})`);
    }
    throw new RuntimeGuardError({
      code: 'runtime_unavailable',
      message: 'Orca runtime is unavailable or status probe failed',
      reason: reasonParts.join('; ') || 'status probe not ok',
      recovery:
        'Ensure the `orca` CLI is on PATH (or set ORCA_CLI_COMMAND), the daemon is running, ' +
        'and `orca status --json` succeeds on the host. Then retry the same action.',
      details: {
        version,
        minVersion,
        versionOk: true,
        statusProbe: {
          ok: false,
          exitCode: exitCode ?? null,
          spawnError: spawnError || null,
          error: probe.error || null,
        },
      },
    });
  }

  return { ok: true, versionOk: true };
}

/**
 * Compact health view — default wire shape (units of lines, not full status dump).
 * Preserves fields clients actually read: bridge.version, versionOk, statusProbe.ok.
 *
 * @param {object} full — full health payload (verbose shape)
 * @returns {object}
 */
export function compactHealthPayload(full = {}) {
  const bridge = full.bridge && typeof full.bridge === 'object' ? full.bridge : {};
  const sender = full.senderTerminal && typeof full.senderTerminal === 'object' ? full.senderTerminal : {};
  const toolsets = full.toolsets && typeof full.toolsets === 'object' ? full.toolsets : null;
  const probe = full.statusProbe && typeof full.statusProbe === 'object' ? full.statusProbe : {};

  const probeOk =
    probe.ok === true ||
    (probe.ok !== false &&
      !probe.spawnError &&
      (probe.exitCode === 0 || probe.exitCode == null) &&
      probe.envelope?.ok !== false);

  let toolsetsBrief = null;
  if (toolsets) {
    toolsetsBrief = {
      mode: toolsets.mode ?? toolsets.policy ?? null,
      enabled: Array.isArray(toolsets.enabled)
        ? toolsets.enabled
        : Array.isArray(toolsets.toolsets)
          ? toolsets.toolsets
          : toolsets.allowed ?? null,
      denied: toolsets.denied ?? toolsets.blocked ?? undefined,
    };
  }

  return {
    ok: bridge.versionOk !== false && probeOk,
    bridge: {
      version: bridge.version ?? null,
      minVersion: bridge.minVersion ?? null,
      versionOk: bridge.versionOk === true,
      uptimeSec: bridge.uptimeSec ?? null,
      transport: bridge.transport ?? null,
    },
    statusProbe: {
      ok: probeOk,
      exitCode: probe.exitCode ?? null,
      spawnError: probe.spawnError ?? null,
    },
    senderTerminal: sender.handle
      ? {
          ok: sender.ok !== false,
          handle: sender.handle,
          source: sender.source ?? null,
        }
      : {
          ok: false,
          error: sender.error || 'no_sender_terminal',
        },
    toolsets: toolsetsBrief,
    defaultAgent: full.defaultAgent ?? null,
    actions: full.actions ?? undefined,
    next: full.next ?? null,
    // Hint for clients that need the previous giant dump.
    verbose: false,
    note:
      'Compact health (default). Pass verbose:true for full statusProbe/actionAnnotations/coordinator dump, ' +
      'or read MCP resources orca-bridge://audit/*.',
  };
}

/**
 * Compute worker liveness for an empty/timeout await window.
 *
 * @param {{
 *   now?: number,
 *   dispatchedAt?: string|number|null,
 *   lastActivityAt?: string|number|null,
 *   emptyWindowsConsecutive?: number,
 *   hasDispatch?: boolean,
 *   thresholds?: typeof LIVENESS_THRESHOLDS,
 * }} p
 * @returns {{
 *   liveness: 'active'|'idle'|'stalled'|'unknown',
 *   msSinceDispatch: number|null,
 *   msSinceActivity: number|null,
 *   emptyWindowsConsecutive: number,
 *   thresholds: object,
 *   reason: string,
 * }}
 */
export function computeLiveness(p = {}) {
  const th = { ...LIVENESS_THRESHOLDS, ...(p.thresholds || {}) };
  const now = Number.isFinite(p.now) ? p.now : Date.now();
  const emptyWindowsConsecutive = Math.max(0, Number(p.emptyWindowsConsecutive) || 0);

  const dispatchedMs = toEpochMs(p.dispatchedAt);
  const activityMs = toEpochMs(p.lastActivityAt);

  const msSinceDispatch = dispatchedMs != null ? Math.max(0, now - dispatchedMs) : null;
  const msSinceActivity = activityMs != null ? Math.max(0, now - activityMs) : null;

  const hasDispatch = p.hasDispatch === true || dispatchedMs != null;
  if (!hasDispatch && msSinceActivity == null && emptyWindowsConsecutive === 0) {
    return {
      liveness: 'unknown',
      msSinceDispatch,
      msSinceActivity,
      emptyWindowsConsecutive,
      thresholds: th,
      reason: 'No dispatch registry entry or activity signal for this run.',
    };
  }

  // Strong positive activity signal.
  if (msSinceActivity != null && msSinceActivity <= th.activeMs) {
    return {
      liveness: 'active',
      msSinceDispatch,
      msSinceActivity,
      emptyWindowsConsecutive,
      thresholds: th,
      reason: `Terminal/activity within ${th.activeMs}ms.`,
    };
  }

  // Hard stall: many empty windows, or long quiet with enough empties.
  const stalledByEmpty = emptyWindowsConsecutive >= th.stalledEmptyMin;
  const stalledByQuiet =
    msSinceActivity != null &&
    msSinceActivity >= th.stalledMs &&
    emptyWindowsConsecutive >= th.stalledEmptyWithQuiet;
  const stalledByAgeOnly =
    msSinceActivity == null &&
    msSinceDispatch != null &&
    msSinceDispatch >= th.stalledMs &&
    emptyWindowsConsecutive >= th.stalledEmptyWithQuiet;

  if (stalledByEmpty || stalledByQuiet || stalledByAgeOnly) {
    return {
      liveness: 'stalled',
      msSinceDispatch,
      msSinceActivity,
      emptyWindowsConsecutive,
      thresholds: th,
      reason: stalledByEmpty
        ? `${emptyWindowsConsecutive} consecutive empty await windows (>= ${th.stalledEmptyMin}).`
        : `No progress for >= ${th.stalledMs}ms with ${emptyWindowsConsecutive} empty windows.`,
    };
  }

  // Early empties without activity still count as active (worker may be booting).
  if (emptyWindowsConsecutive <= th.activeEmptyMax && (msSinceActivity == null || msSinceActivity < th.stalledMs)) {
    return {
      liveness: 'active',
      msSinceDispatch,
      msSinceActivity,
      emptyWindowsConsecutive,
      thresholds: th,
      reason:
        emptyWindowsConsecutive === 0
          ? 'No empty windows yet.'
          : `Only ${emptyWindowsConsecutive} empty window(s); still within active band.`,
    };
  }

  // Middle band — thinking is normal.
  if (hasDispatch || emptyWindowsConsecutive > 0 || msSinceActivity != null) {
    return {
      liveness: 'idle',
      msSinceDispatch,
      msSinceActivity,
      emptyWindowsConsecutive,
      thresholds: th,
      reason:
        'Empty await is still normal for long tasks; no stall threshold crossed. ' +
        'Re-call await, but watch emptyWindowsConsecutive / msSinceActivity.',
    };
  }

  return {
    liveness: 'unknown',
    msSinceDispatch,
    msSinceActivity,
    emptyWindowsConsecutive,
    thresholds: th,
    reason: 'Insufficient signals to classify liveness.',
  };
}

/**
 * next.detail / next.action for empty await, branched on liveness.
 * @param {{ liveness: string, emptyWindowsConsecutive?: number, msSinceActivity?: number|null, deliveryId?: string|null }} p
 */
export function nextStepForLiveness(p = {}) {
  const liveness = p.liveness || 'unknown';
  const emptyN = Math.max(0, Number(p.emptyWindowsConsecutive) || 0);
  const baseNote = 'next.action is a hint; prefer summary.status if they disagree. Honor liveness on empty windows.';

  if (liveness === 'stalled') {
    return {
      action: 'diagnose',
      detail:
        `liveness=stalled after ${emptyN} empty window(s). Do NOT loop await forever. ` +
        'Protocol: (1) orca{action:"check",runId,peek:true,waitMs:0} or cli orchestration check --peek; ' +
        '(2) optional terminal read / cli orchestration send heartbeat ping to worker; ' +
        '(3) if still dead: release with diagnostics and report to owner. ' +
        'Empty is normal early; stalled means stop-condition.',
      deliveryId: p.deliveryId || null,
      liveness: 'stalled',
      note: baseNote,
    };
  }

  if (liveness === 'idle') {
    return {
      action: 'await',
      detail:
        `liveness=idle (${emptyN} empty window(s)). Re-call orca{action:"await",runId,waitMs:45000} — still normal. ` +
        'If emptyWindows keeps climbing or msSinceActivity exceeds ~8min, treat as stalled: check --peek, ping, or release+report.',
      deliveryId: null,
      liveness: 'idle',
      note: baseNote,
    };
  }

  if (liveness === 'active') {
    return {
      action: 'await',
      detail:
        'liveness=active. Empty/timeout window is NORMAL. Re-call orca{action:"await",runId,waitMs:45000} ' +
        '(no ack unless you have a prior deliveryId). Not a failure; do not restart the worker.',
      deliveryId: null,
      liveness: 'active',
      note: baseNote,
    };
  }

  return {
    action: 'await',
    detail:
      'liveness=unknown (no dispatch/terminal activity signal). Re-call await once or twice; ' +
      'if still empty, run check --peek and inspect worker terminal before assuming progress.',
    deliveryId: null,
    liveness: 'unknown',
    note: baseNote,
  };
}

/**
 * Pick the freshest activity timestamp from known signals.
 * @param {{ registryUpdatedAt?: string|null, terminalLastOutputAt?: string|null, lastMessageAt?: string|null }} p
 */
export function pickLastActivityAt(p = {}) {
  const candidates = [p.terminalLastOutputAt, p.lastMessageAt, p.registryUpdatedAt]
    .map(toEpochMs)
    .filter((n) => n != null);
  if (!candidates.length) return null;
  return new Date(Math.max(...candidates)).toISOString();
}

function toEpochMs(v) {
  if (v == null || v === '') return null;
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  const t = Date.parse(String(v));
  return Number.isFinite(t) ? t : null;
}
