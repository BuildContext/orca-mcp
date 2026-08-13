/**
 * State-file ownership guards for the bridge (NAS-242, incident NAS-241).
 *
 * The bridge keeps its durable state in the HOME of the account it runs as:
 *   ~/.orca-bridge-tokens.json      issued OAuth access tokens
 *   ~/.orca-bridge-sender-pins.json per-client sender terminal pins
 *   ~/.orca-bridge/                 audit log
 *
 * Failure mode this module exists for: something privileged (a global
 * `npm i -g` postinstall, an upgrade script, a one-off migration) rewrites one
 * of those files **as root**. An atomic `rename()`/`os.replace()` swaps in a
 * fresh inode owned by `root`, mode 600. The unit runs as the service user, so
 * the bridge silently loses both read and write on its own state: tokens issued
 * after that point live only in memory and the next restart drops every MCP
 * client back to a fresh OAuth flow. Nothing crashes — the bridge answers
 * normally — so the breakage is only visible if you look at the file mode.
 *
 * Two narrow guards, both no-ops in the normal (non-root) case:
 *   1. writeFilePreservingOwner — when running as root, restore the previous
 *      owner after replacing an existing state file.
 *   2. inspectStateFile / stateOwnershipWarnings — at boot, say loudly when a
 *      state file exists but the current process cannot read or write it.
 *
 * Pure logic is separated from fs so it stays testable without root.
 */

import fs from 'node:fs';
import path from 'node:path';

/** Mode every bridge state file is written with. */
export const STATE_FILE_MODE = 0o600;

/** Verdict codes from {@link classifyStateFile}. */
export const STATE_OK = 'ok';
export const STATE_MISSING = 'missing';
export const STATE_FOREIGN_OWNER = 'foreign-owner';
export const STATE_UNREADABLE = 'unreadable';
export const STATE_UNWRITABLE = 'unwritable';
export const STATE_LOOSE_MODE = 'loose-mode';

/**
 * Pure classification of one state file. No fs access — callers pass the facts.
 *
 * @param {object} facts
 * @param {string} facts.path
 * @param {boolean} facts.exists
 * @param {number} [facts.uid] owner uid of the file
 * @param {number} [facts.gid] owner gid of the file
 * @param {number} [facts.mode] st_mode (permission bits are masked here)
 * @param {boolean} [facts.isDirectory] true for the audit dir (mode target 700, not 600)
 * @param {boolean} [facts.readable] result of an access(R_OK) probe
 * @param {boolean} [facts.writable] result of an access(W_OK) probe
 * @param {number} [facts.runningUid] uid of this process
 * @returns {{ path: string, code: string, ok: boolean, message: string|null }}
 */
export function classifyStateFile(facts) {
  const {
    path: filePath,
    exists,
    uid,
    gid,
    mode,
    readable = true,
    writable = true,
    runningUid,
  } = facts || {};

  if (!exists) {
    return { path: filePath, code: STATE_MISSING, ok: true, message: null };
  }

  const owner = typeof uid === 'number' ? uid : null;
  const running = typeof runningUid === 'number' ? runningUid : null;
  const foreign = owner !== null && running !== null && owner !== running && running !== 0;

  if (!readable) {
    return {
      path: filePath,
      code: STATE_UNREADABLE,
      ok: false,
      message:
        `${filePath} is not readable by uid=${running} (owner uid=${owner} gid=${gid}). ` +
        'The bridge starts with EMPTY state — every MCP client will have to re-authorize. ' +
        `Fix: chown the file to the service account, e.g. \`sudo chown $(id -un):$(id -gn) ${filePath}\`.`,
    };
  }

  if (!writable) {
    return {
      path: filePath,
      code: STATE_UNWRITABLE,
      ok: false,
      message:
        `${filePath} is not writable by uid=${running} (owner uid=${owner} gid=${gid}). ` +
        'Newly issued tokens/pins will live in memory only and vanish on restart. ' +
        `Fix: \`sudo chown $(id -un):$(id -gn) ${filePath}\`.`,
    };
  }

  if (foreign) {
    return {
      path: filePath,
      code: STATE_FOREIGN_OWNER,
      ok: false,
      message:
        `${filePath} is owned by uid=${owner} gid=${gid}, but this process runs as uid=${running}. ` +
        'It is readable today, but a privileged rewrite will lock the bridge out of its own state. ' +
        `Fix: \`sudo chown $(id -un):$(id -gn) ${filePath}\`.`,
    };
  }

  if (typeof mode === 'number' && (mode & 0o077) !== 0) {
    const want = facts.isDirectory ? '700' : '600';
    const kind = facts.isDirectory ? 'state directory' : 'secret file';
    return {
      path: filePath,
      code: STATE_LOOSE_MODE,
      ok: false,
      message:
        `${filePath} has mode ${(mode & 0o777).toString(8)}; this ${kind} should be ${want}. ` +
        `Fix: \`chmod ${want} ${filePath}\`.`,
    };
  }

  return { path: filePath, code: STATE_OK, ok: true, message: null };
}

/**
 * Stat + access-probe one path, then classify it.
 *
 * @param {string} filePath
 * @param {object} [deps] injectable for tests
 * @returns {{ path: string, code: string, ok: boolean, message: string|null }}
 */
export function inspectStateFile(filePath, deps = {}) {
  const {
    fsImpl = fs,
    getuid = typeof process.getuid === 'function' ? () => process.getuid() : () => null,
  } = deps;

  let st;
  try {
    st = fsImpl.statSync(filePath);
  } catch {
    return { path: filePath, code: STATE_MISSING, ok: true, message: null };
  }

  const probe = (bits) => {
    try {
      fsImpl.accessSync(filePath, bits);
      return true;
    } catch {
      return false;
    }
  };

  const runningUid = getuid();
  return classifyStateFile({
    path: filePath,
    exists: true,
    uid: st.uid,
    gid: st.gid,
    mode: st.mode,
    isDirectory: typeof st.isDirectory === 'function' ? st.isDirectory() : false,
    readable: probe(fs.constants.R_OK),
    writable: probe(fs.constants.W_OK),
    runningUid: typeof runningUid === 'number' ? runningUid : undefined,
  });
}

/**
 * Boot-time check over every durable state path. Returns human-readable
 * warnings (empty array = healthy). Callers decide where to log them.
 *
 * @param {string[]} paths
 * @param {object} [deps]
 * @returns {string[]}
 */
export function stateOwnershipWarnings(paths, deps = {}) {
  const out = [];
  for (const p of paths || []) {
    if (!p) continue;
    const verdict = inspectStateFile(p, deps);
    if (!verdict.ok && verdict.message) out.push(verdict.message);
  }
  return out;
}

/**
 * Write a state file, keeping it owned by the account that owns the state.
 *
 * Normal (non-root) case: a plain `writeFileSync` with the given mode — same
 * behaviour as before this module existed, and no chown is attempted.
 *
 * When the process IS root, the file is handed to the account that should own
 * the state:
 *   - the file exists and belongs to a normal account: keep that owner (the
 *     plain "root rewrote it" case);
 *   - the file is missing, or is already root-owned inside someone else's home
 *     (what a root migration's `os.replace()` leaves behind): fall back to the
 *     owner of the containing directory, i.e. the service account's HOME. That
 *     repairs the NAS-241 damage on the next write instead of cementing it.
 *
 * Never throws on the chown step alone: a failed ownership restore is reported
 * through the return value, the data is already on disk.
 *
 * @param {string} filePath
 * @param {string|Buffer} data
 * @param {object} [opts]
 * @param {number} [opts.mode] default 0600
 * @param {object} [opts.fsImpl] injectable for tests
 * @param {() => number|null} [opts.getuid]
 * @returns {{ ownerRestored: boolean, previousOwner: {uid:number,gid:number,from:string}|null, chownError: string|null }}
 */
export function writeFilePreservingOwner(filePath, data, opts = {}) {
  const {
    mode = STATE_FILE_MODE,
    fsImpl = fs,
    getuid = typeof process.getuid === 'function' ? () => process.getuid() : () => null,
  } = opts;

  const statOrNull = (p) => {
    try {
      return fsImpl.statSync(p);
    } catch {
      return null;
    }
  };

  // Who should own this file? Its current owner, unless that is root — a
  // root-owned state file inside someone else's home is the NAS-241 damage,
  // not an intentional state, so the directory owner wins in that case.
  const fileStat = statOrNull(filePath);
  let previousOwner = fileStat && fileStat.uid !== 0
    ? { uid: fileStat.uid, gid: fileStat.gid, from: 'file' }
    : null;
  if (!previousOwner) {
    const dirStat = statOrNull(path.dirname(filePath));
    if (dirStat) {
      previousOwner = {
        uid: dirStat.uid,
        gid: dirStat.gid,
        from: fileStat ? 'directory (file was root-owned)' : 'directory',
      };
    }
  }

  fsImpl.writeFileSync(filePath, data, { mode });

  const runningUid = getuid();
  const isRoot = runningUid === 0;
  if (!isRoot || !previousOwner || previousOwner.uid === 0) {
    return { ownerRestored: false, previousOwner, chownError: null };
  }

  try {
    fsImpl.chownSync(filePath, previousOwner.uid, previousOwner.gid);
    return { ownerRestored: true, previousOwner, chownError: null };
  } catch (e) {
    return {
      ownerRestored: false,
      previousOwner,
      chownError: e && e.message ? e.message : String(e),
    };
  }
}

// ---------------------------------------------------------------------------
// Terminal / dispatch ownership (NAS-247, NAS-248)
//
// Source of truth is what the bridge already tracks per OAuth client:
//   - senderCaches / pinned sender handle
//   - clientOwnership.workerHandles (registerOwnedDispatch on dispatch)
//   - clientOwnership.dispatches (same registration; dispatch-id paths)
//   - dispatchRegistry entries (terminalHandle + clientKey + dispatchId)
// Do not invent a parallel store — callers pass those structures in.
//
// NAS-248: ownership is a system invariant. Every handle- or dispatch-id
// accepting effect must go through resolveTerminalHandleOwnership /
// resolveDispatchOwnership (or the pure gates below). CLI policy is one
// consumer; action=release and response redaction are others. Never reimplement
// argv extraction outside collectTerminalHandlesFromArgv /
// collectDispatchIdsFromArgv / collectWorktreeSelectorsFromArgv.
// ---------------------------------------------------------------------------

/** Verdicts from {@link resolveTerminalHandleOwnership}. */
export const HANDLE_OWNED = 'owned';
export const HANDLE_NOT_OWNED = 'not-owned';
export const HANDLE_UNKNOWN = 'unknown';

/**
 * Normalize a terminal handle string. Empty / whitespace-only / multi-token
 * values are malformed → null (caller treats as unknown, fail-closed).
 * @param {unknown} handle
 * @returns {string|null}
 */
export function normalizeTerminalHandle(handle) {
  if (handle == null) return null;
  const s = String(handle).trim();
  if (!s) return null;
  // Handles are single tokens (term_…); reject embedded whitespace.
  if (/\s/.test(s)) return null;
  return s;
}

/**
 * Collect every `--terminal <handle>` / `--terminal=<handle>` occurrence
 * left-to-right (raw strings, not normalized).
 *
 * Spaced form with a missing or flag-shaped value records `null` for that
 * occurrence and continues — callers deny-any on multi-value argv.
 *
 * Shared by cli-policy and getTerminalHandle so first/last semantics cannot
 * drift (NAS-247 duplicate-flag bypass).
 *
 * @param {unknown} argv
 * @returns {Array<string|null>}
 */
export function collectTerminalHandlesFromArgv(argv) {
  if (!Array.isArray(argv)) return [];
  const out = [];
  for (let i = 0; i < argv.length; i++) {
    const t = String(argv[i]);
    if (t === '--terminal') {
      if (i + 1 >= argv.length) {
        out.push(null);
        continue;
      }
      const next = String(argv[i + 1]);
      if (next.startsWith('-')) {
        out.push(null);
        continue;
      }
      // Spaced form keeps raw value (including '' / whitespace) so callers can
      // distinguish malformed empty from missing.
      out.push(next);
      i += 1;
      continue;
    }
    if (t.startsWith('--terminal=')) {
      const v = t.slice('--terminal='.length);
      // Empty `=` form is missing — same as historical extractTerminalHandleFromArgv.
      // Distinct from spaced `--terminal ''` which stays ''.
      out.push(v === '' ? null : v);
    }
  }
  return out;
}

/**
 * Pull the CLI-effective terminal handle from argv.
 * Orca CLI parseArgs last-wins for non-repeatable flags, so this returns the
 * last `--terminal` / `--terminal=` value (normalized). Multi-value ownership
 * checks must use {@link collectTerminalHandlesFromArgv} and deny-any.
 *
 * @param {unknown} argv
 * @returns {string|null}
 */
export function getTerminalHandle(argv) {
  const all = collectTerminalHandlesFromArgv(argv);
  if (!all.length) return null;
  return normalizeTerminalHandle(all[all.length - 1]);
}

function mapGet(mapOrObj, key) {
  if (!mapOrObj) return undefined;
  if (typeof mapOrObj.get === 'function') return mapOrObj.get(key);
  return mapOrObj[key];
}

function mapValues(mapOrObj) {
  if (!mapOrObj) return [];
  if (typeof mapOrObj.values === 'function') return [...mapOrObj.values()];
  return Object.values(mapOrObj);
}

function mapEntries(mapOrObj) {
  if (!mapOrObj) return [];
  if (typeof mapOrObj.entries === 'function') return [...mapOrObj.entries()];
  return Object.entries(mapOrObj);
}

/**
 * Handles this client already owns, from existing bridge structures.
 *
 * @param {string} clientKey
 * @param {object} [deps]
 * @param {{ list?: (q?: object) => object[] }} [deps.dispatchRegistry]
 * @param {Map|Record<string, object>} [deps.clientOwnership]
 * @param {Map|Record<string, { handle?: string }>} [deps.senderCaches]
 * @param {string|null} [deps.senderHandle] explicit pin for this call
 * @param {Iterable<string>} [deps.ownedHandles] extra owned inject (tests)
 * @param {Iterable<string>} [deps.knownHandles] extra known inject (tests)
 * @param {Set|Iterable<string>} [deps.coordinatorHandles]
 * @returns {{ owned: Set<string>, known: Set<string> }}
 */
export function collectTerminalHandleSets(clientKey, deps = {}) {
  const ck = clientKey == null ? '' : String(clientKey);
  const owned = new Set();
  const known = new Set();
  const addKnown = (h) => {
    const n = normalizeTerminalHandle(h);
    if (n) known.add(n);
  };
  const addOwned = (h) => {
    const n = normalizeTerminalHandle(h);
    if (n) {
      owned.add(n);
      known.add(n);
    }
  };

  if (deps.senderHandle) addOwned(deps.senderHandle);

  if (deps.ownedHandles) {
    for (const h of deps.ownedHandles) addOwned(h);
  }
  if (deps.knownHandles) {
    for (const h of deps.knownHandles) addKnown(h);
  }

  // Sender pins: every pin is known; this client's pin is owned.
  for (const [k, v] of mapEntries(deps.senderCaches)) {
    const hv = v && v.handle != null ? v.handle : null;
    if (!hv) continue;
    addKnown(hv);
    if (String(k) === ck) addOwned(hv);
  }

  // Per-client ownership registry (workerHandles + boundSender).
  for (const [k, reg] of mapEntries(deps.clientOwnership)) {
    if (!reg) continue;
    const isSelf = String(k) === ck;
    if (reg.boundSender) {
      if (isSelf) addOwned(reg.boundSender);
      else addKnown(reg.boundSender);
    }
    if (reg.workerHandles) {
      for (const h of reg.workerHandles) {
        if (isSelf) addOwned(h);
        else addKnown(h);
      }
    }
  }

  // Dispatch registry rows carry terminalHandle + clientKey.
  const registry = deps.dispatchRegistry;
  if (registry && typeof registry.list === 'function') {
    try {
      for (const d of registry.list() || []) {
        if (!d || d.terminalHandle == null) continue;
        const rowKey = d.clientKey != null ? String(d.clientKey) : '';
        if (rowKey && rowKey === ck) addOwned(d.terminalHandle);
        else addKnown(d.terminalHandle);
      }
    } catch {
      // registry read must not throw into the policy funnel
    }
  }

  // Coordinator sender handles known to the bridge (may include other clients).
  if (deps.coordinatorHandles) {
    const iter =
      typeof deps.coordinatorHandles[Symbol.iterator] === 'function'
        ? deps.coordinatorHandles
        : [];
    for (const h of iter) addKnown(h);
  }

  return { owned, known };
}

/**
 * List owned handle strings for a client (sorted).
 * @param {string} clientKey
 * @param {object} [deps]
 * @returns {string[]}
 */
export function listOwnedTerminalHandles(clientKey, deps = {}) {
  return [...collectTerminalHandleSets(clientKey, deps).owned].sort();
}

/**
 * Resolve whether `clientKey` owns `handle`.
 *
 *   owned     — handle is this client's sender pin and/or a worker it dispatched
 *   not-owned — handle is tracked under a different client (or known but not ours)
 *   unknown   — malformed / missing handle, or handle not present in any store
 *               (fail-closed: treat like not-owned at the policy layer)
 *
 * Return shape uses both `status` and `verdict` (same value) plus
 * `owned_handles` / `ownedHandles` for callers that prefer either style.
 *
 * @param {unknown} handle
 * @param {string} clientKey
 * @param {object} [deps]
 * @returns {{
 *   status: 'owned'|'not-owned'|'unknown',
 *   verdict: 'owned'|'not-owned'|'unknown',
 *   handle: string|null,
 *   clientKey: string,
 *   owned_handles: string[],
 *   ownedHandles: string[],
 *   reason?: string,
 * }}
 */
export function resolveTerminalHandleOwnership(handle, clientKey, deps = {}) {
  const ck = clientKey == null ? '' : String(clientKey);
  const h = normalizeTerminalHandle(handle);
  const { owned, known } = collectTerminalHandleSets(ck, deps);
  const ownedHandles = [...owned].sort();

  const pack = (status, reason) => ({
    status,
    verdict: status,
    handle: h,
    clientKey: ck,
    owned_handles: ownedHandles,
    ownedHandles,
    reason,
  });

  if (!h) {
    return pack(HANDLE_UNKNOWN, 'missing_or_malformed_handle');
  }

  if (owned.has(h)) {
    return pack(HANDLE_OWNED, 'client_owned');
  }

  // No ownership structures provided at all → unknown (missing registry).
  const hasAnySource = Boolean(
    deps.dispatchRegistry ||
      deps.clientOwnership ||
      deps.senderCaches ||
      deps.senderHandle ||
      deps.ownedHandles ||
      deps.knownHandles ||
      deps.coordinatorHandles,
  );
  if (!hasAnySource) {
    return pack(HANDLE_UNKNOWN, 'missing_registry');
  }

  if (known.has(h)) {
    return pack(HANDLE_NOT_OWNED, 'foreign_handle');
  }

  return pack(HANDLE_UNKNOWN, 'handle_not_in_registry');
}

// ---------------------------------------------------------------------------
// Dispatch-id ownership (NAS-248) — worker-read / worker-show / release-by-id
// ---------------------------------------------------------------------------

/**
 * Normalize a dispatch id. Empty / whitespace-only / multi-token → null.
 * @param {unknown} id
 * @returns {string|null}
 */
export function normalizeDispatchId(id) {
  if (id == null) return null;
  const s = String(id).trim();
  if (!s) return null;
  if (/\s/.test(s)) return null;
  return s;
}

/**
 * Collect every `--dispatch <id>` / `--dispatch=<id>` occurrence left-to-right
 * (raw strings, not normalized). Same rules as collectTerminalHandlesFromArgv:
 * spaced missing/flag-shaped → null; empty `=` → null; spaced '' stays ''.
 *
 * @param {unknown} argv
 * @returns {Array<string|null>}
 */
export function collectDispatchIdsFromArgv(argv) {
  if (!Array.isArray(argv)) return [];
  const out = [];
  for (let i = 0; i < argv.length; i++) {
    const t = String(argv[i]);
    if (t === '--dispatch') {
      if (i + 1 >= argv.length) {
        out.push(null);
        continue;
      }
      const next = String(argv[i + 1]);
      if (next.startsWith('-')) {
        out.push(null);
        continue;
      }
      out.push(next);
      i += 1;
      continue;
    }
    if (t.startsWith('--dispatch=')) {
      const v = t.slice('--dispatch='.length);
      out.push(v === '' ? null : v);
    }
  }
  return out;
}

/**
 * Collect every `--dispatch-id <id>` / `--dispatch-id=<id>` occurrence.
 * Live CLI send payload uses --dispatch-id; worker-* use --dispatch.
 * Same null rules as collectDispatchIdsFromArgv.
 * @param {unknown} argv
 * @returns {Array<string|null>}
 */
export function collectDispatchIdFlagFromArgv(argv) {
  if (!Array.isArray(argv)) return [];
  const out = [];
  for (let i = 0; i < argv.length; i++) {
    const t = String(argv[i]);
    if (t === '--dispatch-id') {
      if (i + 1 >= argv.length) {
        out.push(null);
        continue;
      }
      const next = String(argv[i + 1]);
      if (next.startsWith('-')) {
        out.push(null);
        continue;
      }
      out.push(next);
      i += 1;
      continue;
    }
    if (t.startsWith('--dispatch-id=')) {
      const v = t.slice('--dispatch-id='.length);
      out.push(v === '' ? null : v);
    }
  }
  return out;
}

/**
 * Union of --dispatch and --dispatch-id values (ownership deny-any).
 * @param {unknown} argv
 * @returns {Array<string|null>}
 */
export function collectAllDispatchTargetIdsFromArgv(argv) {
  return [
    ...collectDispatchIdsFromArgv(argv),
    ...collectDispatchIdFlagFromArgv(argv),
  ];
}

/**
 * Collect every `--worktree <selector>` / `--worktree=<selector>` occurrence.
 * @param {unknown} argv
 * @returns {Array<string|null>}
 */
export function collectWorktreeSelectorsFromArgv(argv) {
  if (!Array.isArray(argv)) return [];
  const out = [];
  for (let i = 0; i < argv.length; i++) {
    const t = String(argv[i]);
    if (t === '--worktree') {
      if (i + 1 >= argv.length) {
        out.push(null);
        continue;
      }
      const next = String(argv[i + 1]);
      if (next.startsWith('-')) {
        out.push(null);
        continue;
      }
      out.push(next);
      i += 1;
      continue;
    }
    if (t.startsWith('--worktree=')) {
      const v = t.slice('--worktree='.length);
      out.push(v === '' ? null : v);
    }
  }
  return out;
}

/**
 * Normalize a worktree selector for ownership compare.
 * Accepts path:/abs, id:wt_…, name:…, bare paths, bare ids.
 * Synthetic tokens (active/current/new-*) stay as lowercase tokens.
 * @param {unknown} sel
 * @returns {string|null}
 */
export function normalizeWorktreeSelector(sel) {
  if (sel == null) return null;
  const s = String(sel).trim();
  if (!s) return null;
  if (/\s/.test(s)) return null;
  const lower = s.toLowerCase();
  if (
    lower === 'active' ||
    lower === 'current' ||
    lower === 'new-child' ||
    lower === 'new-top-level'
  ) {
    return lower;
  }
  if (lower.startsWith('path:')) {
    const p = s.slice(5);
    return p ? `path:${p}` : null;
  }
  if (lower.startsWith('id:')) {
    const id = s.slice(3);
    return id ? `id:${id}` : null;
  }
  if (lower.startsWith('name:')) {
    const n = s.slice(5);
    return n ? `name:${n}` : null;
  }
  if (s.startsWith('/')) return `path:${s}`;
  // bare token — keep as-is (may match id or name in registry)
  return s;
}

/**
 * Collect owned/known worktree selector strings for a client.
 * Sources: dispatchRegistry rows (worktree / worktreeId / path) for owned clientKey.
 * @param {string} clientKey
 * @param {object} [deps]
 * @returns {{ owned: Set<string>, known: Set<string> }}
 */
export function collectWorktreeSelectorSets(clientKey, deps = {}) {
  const ck = clientKey == null ? '' : String(clientKey);
  const owned = new Set();
  const known = new Set();
  const add = (set, raw) => {
    const n = normalizeWorktreeSelector(raw);
    if (!n) return;
    // Skip pure synthetic create modes — not claimable inventory.
    if (n === 'new-child' || n === 'new-top-level') return;
    set.add(n);
    // Also index bare path/id variants for matching.
    if (n.startsWith('path:')) set.add(n.slice(5));
    if (n.startsWith('id:')) set.add(n.slice(3));
    if (n.startsWith('name:')) set.add(n.slice(5));
  };
  const addOwned = (raw) => {
    add(owned, raw);
    add(known, raw);
  };
  const addKnown = (raw) => add(known, raw);

  if (deps.ownedWorktrees) {
    for (const w of deps.ownedWorktrees) addOwned(w);
  }
  if (deps.knownWorktrees) {
    for (const w of deps.knownWorktrees) addKnown(w);
  }

  const registry = deps.dispatchRegistry;
  if (registry && typeof registry.list === 'function') {
    try {
      for (const d of registry.list() || []) {
        if (!d) continue;
        const rowKey = d.clientKey != null ? String(d.clientKey) : '';
        const candidates = [
          d.worktree,
          d.worktreePath,
          d.worktreeId,
          d.worktree && d.worktree.path,
          d.worktree && d.worktree.id,
        ];
        for (const c of candidates) {
          if (c == null || c === '') continue;
          if (rowKey && rowKey === ck) addOwned(c);
          else addKnown(c);
        }
      }
    } catch {
      // registry read must not throw into the policy funnel
    }
  }

  return { owned, known };
}

/**
 * Resolve whether clientKey owns a worktree selector.
 * Fail-closed: missing/malformed/synthetic-unresolved/unknown → unknown.
 * @param {unknown} selector
 * @param {string} clientKey
 * @param {object} [deps]
 */
export function resolveWorktreeOwnership(selector, clientKey, deps = {}) {
  const ck = clientKey == null ? '' : String(clientKey);
  const n = normalizeWorktreeSelector(selector);
  const { owned, known } = collectWorktreeSelectorSets(ck, deps);
  const ownedList = [...owned].filter((x) => x.includes('/') || x.startsWith('path:') || x.startsWith('id:') || x.startsWith('name:')).sort();

  const pack = (status, reason) => ({
    status,
    verdict: status,
    worktree: n,
    handle: null,
    dispatchId: null,
    clientKey: ck,
    owned_handles: listOwnedTerminalHandles(ck, deps),
    ownedHandles: listOwnedTerminalHandles(ck, deps),
    owned_worktrees: ownedList,
    ownedWorktrees: ownedList,
    reason,
  });

  if (!n) {
    return pack(HANDLE_UNKNOWN, 'missing_or_malformed_worktree');
  }
  // active/current cannot be proven owned without a live resolver — fail closed.
  if (n === 'active' || n === 'current') {
    return pack(HANDLE_UNKNOWN, 'unresolved_worktree_selector');
  }
  if (n === 'new-child' || n === 'new-top-level') {
    // Create-mode tokens are not foreign inventory targets; treat as no-op owned
    // for selector presence on worker-start/create paths.
    return pack(HANDLE_OWNED, 'synthetic_create_selector');
  }

  // Match normalized form and bare variants.
  const candidates = new Set([n]);
  if (n.startsWith('path:')) candidates.add(n.slice(5));
  if (n.startsWith('id:')) candidates.add(n.slice(3));
  if (n.startsWith('name:')) candidates.add(n.slice(5));
  if (n.startsWith('/')) candidates.add(`path:${n}`);

  for (const c of candidates) {
    if (owned.has(c)) return pack(HANDLE_OWNED, 'client_owned');
  }

  const hasAnySource = Boolean(
    deps.dispatchRegistry || deps.ownedWorktrees || deps.knownWorktrees,
  );
  if (!hasAnySource) {
    return pack(HANDLE_UNKNOWN, 'missing_registry');
  }

  for (const c of candidates) {
    if (known.has(c)) return pack(HANDLE_NOT_OWNED, 'foreign_worktree');
  }
  return pack(HANDLE_UNKNOWN, 'worktree_not_in_registry');
}

/**
 * Imperative worktree ownership gate.
 */
export function requireOwnedWorktree(selector, clientKey, deps = {}) {
  const ownership = resolveWorktreeOwnership(selector, clientKey, deps);
  return {
    ok: ownership.status === HANDLE_OWNED,
    ownership,
  };
}

/**
 * Collect owned/known dispatch ids for a client from the same stores as handles.
 *
 * @param {string} clientKey
 * @param {object} [deps]
 * @returns {{ owned: Set<string>, known: Set<string> }}
 */
export function collectDispatchIdSets(clientKey, deps = {}) {
  const ck = clientKey == null ? '' : String(clientKey);
  const owned = new Set();
  const known = new Set();
  const addKnown = (id) => {
    const n = normalizeDispatchId(id);
    if (n) known.add(n);
  };
  const addOwned = (id) => {
    const n = normalizeDispatchId(id);
    if (n) {
      owned.add(n);
      known.add(n);
    }
  };

  if (deps.ownedDispatchIds) {
    for (const id of deps.ownedDispatchIds) addOwned(id);
  }
  if (deps.knownDispatchIds) {
    for (const id of deps.knownDispatchIds) addKnown(id);
  }

  for (const [k, reg] of mapEntries(deps.clientOwnership)) {
    if (!reg || !reg.dispatches) continue;
    const isSelf = String(k) === ck;
    for (const id of reg.dispatches) {
      if (isSelf) addOwned(id);
      else addKnown(id);
    }
  }

  const registry = deps.dispatchRegistry;
  if (registry && typeof registry.list === 'function') {
    try {
      for (const d of registry.list() || []) {
        if (!d) continue;
        const id = d.dispatchId != null ? d.dispatchId : d.id;
        if (id == null) continue;
        const rowKey = d.clientKey != null ? String(d.clientKey) : '';
        if (rowKey && rowKey === ck) addOwned(id);
        else addKnown(id);
      }
    } catch {
      // registry read must not throw into the policy funnel
    }
  }

  return { owned, known };
}

/**
 * Resolve whether `clientKey` owns `dispatchId`.
 *
 * Same status model as resolveTerminalHandleOwnership. Keyed on clientKey only
 * — never runtimeId.
 *
 * @param {unknown} dispatchId
 * @param {string} clientKey
 * @param {object} [deps]
 * @returns {{
 *   status: 'owned'|'not-owned'|'unknown',
 *   verdict: 'owned'|'not-owned'|'unknown',
 *   dispatchId: string|null,
 *   handle: null,
 *   clientKey: string,
 *   owned_handles: string[],
 *   ownedHandles: string[],
 *   owned_dispatches: string[],
 *   ownedDispatches: string[],
 *   reason?: string,
 * }}
 */
export function resolveDispatchOwnership(dispatchId, clientKey, deps = {}) {
  const ck = clientKey == null ? '' : String(clientKey);
  const id = normalizeDispatchId(dispatchId);
  const { owned, known } = collectDispatchIdSets(ck, deps);
  const ownedDispatches = [...owned].sort();
  // Also surface handle owned set so policy error payloads stay uniform.
  const ownedHandles = listOwnedTerminalHandles(ck, deps);

  const pack = (status, reason) => ({
    status,
    verdict: status,
    dispatchId: id,
    // handle stays null — this is a dispatch-id judgement
    handle: null,
    clientKey: ck,
    owned_handles: ownedHandles,
    ownedHandles,
    owned_dispatches: ownedDispatches,
    ownedDispatches,
    reason,
  });

  if (!id) {
    return pack(HANDLE_UNKNOWN, 'missing_or_malformed_dispatch');
  }

  if (owned.has(id)) {
    return pack(HANDLE_OWNED, 'client_owned');
  }

  const hasAnySource = Boolean(
    deps.dispatchRegistry ||
      deps.clientOwnership ||
      deps.ownedDispatchIds ||
      deps.knownDispatchIds,
  );
  if (!hasAnySource) {
    return pack(HANDLE_UNKNOWN, 'missing_registry');
  }

  if (known.has(id)) {
    return pack(HANDLE_NOT_OWNED, 'foreign_dispatch');
  }

  return pack(HANDLE_UNKNOWN, 'dispatch_not_in_registry');
}

/**
 * Imperative handle ownership gate for non-cli effect paths (action=release).
 * Pure: no I/O. Callers map the result onto their rejection envelope.
 *
 * Always fail-closed on not-owned / unknown — release is destructive (NAS-202).
 * Soft/warn mode is a cli-policy migration knob only.
 *
 * @param {unknown} handle
 * @param {string} clientKey
 * @param {object} [deps]
 * @returns {{
 *   ok: boolean,
 *   ownership: ReturnType<typeof resolveTerminalHandleOwnership>,
 * }}
 */
export function requireOwnedHandle(handle, clientKey, deps = {}) {
  const ownership = resolveTerminalHandleOwnership(handle, clientKey, deps);
  return {
    ok: ownership.status === HANDLE_OWNED,
    ownership,
  };
}

/**
 * Imperative dispatch-id ownership gate (release-by-id, worker-read preflight).
 * @param {unknown} dispatchId
 * @param {string} clientKey
 * @param {object} [deps]
 * @returns {{
 *   ok: boolean,
 *   ownership: ReturnType<typeof resolveDispatchOwnership>,
 * }}
 */
export function requireOwnedDispatch(dispatchId, clientKey, deps = {}) {
  const ownership = resolveDispatchOwnership(dispatchId, clientKey, deps);
  return {
    ok: ownership.status === HANDLE_OWNED,
    ownership,
  };
}

/**
 * Content-bearing keys that can carry terminal/PTY body (NAS-250).
 * Enumerated from live CLI v1.4.180 terminal list/show rows + session buffer
 * field names in the runtime shared modules. Inventory keys (handle, title,
 * state, counts, paths, ids) are intentionally absent.
 */
export const TERMINAL_CONTENT_KEYS = Object.freeze([
  'preview',
  'scrollback',
  'buffer',
  'buffers',
  'buffersByLeafId',
  'scrollbackRefsByLeafId',
  'output',
  'lines',
  'tail',
  'snapshot',
  'text',
  'content',
  'body',
  'chunk',
  'chunks',
  'data',
]);

const TERMINAL_CONTENT_KEY_SET = new Set(
  TERMINAL_CONTENT_KEYS.map((k) => String(k).toLowerCase()),
);

/**
 * True when a property name is content-bearing (case-insensitive).
 * @param {unknown} key
 */
export function isTerminalContentKey(key) {
  return TERMINAL_CONTENT_KEY_SET.has(String(key || '').toLowerCase());
}

/**
 * Deep-scan a value for any content-bearing own-key (effect assertion helper).
 * @param {unknown} value
 * @param {string[]} [found]
 * @param {WeakSet<object>} [seen]
 * @returns {string[]} lowercased keys found
 */
export function findTerminalContentKeys(value, found = [], seen = new WeakSet()) {
  if (value == null) return found;
  if (typeof value === 'string') return found;
  if (typeof value !== 'object') return found;
  if (seen.has(value)) return found;
  seen.add(value);
  if (Array.isArray(value)) {
    for (const v of value) findTerminalContentKeys(v, found, seen);
    return found;
  }
  for (const [k, v] of Object.entries(value)) {
    if (isTerminalContentKey(k)) found.push(String(k).toLowerCase());
    findTerminalContentKeys(v, found, seen);
  }
  return found;
}

function buildOwnedHandleSet(ownedHandles) {
  const owned = new Set();
  for (const h of ownedHandles || []) {
    const n = normalizeTerminalHandle(h);
    if (n) owned.add(n);
  }
  return owned;
}

/**
 * Extract a terminal handle from a node if present (handle | terminalHandle).
 * @param {object} node
 * @returns {string|null}
 */
function nodeTerminalHandle(node) {
  if (!node || typeof node !== 'object') return null;
  if (Object.prototype.hasOwnProperty.call(node, 'handle')) {
    return normalizeTerminalHandle(node.handle);
  }
  if (Object.prototype.hasOwnProperty.call(node, 'terminalHandle')) {
    return normalizeTerminalHandle(node.terminalHandle);
  }
  if (
    node.terminal &&
    typeof node.terminal === 'object' &&
    !Array.isArray(node.terminal) &&
    Object.prototype.hasOwnProperty.call(node.terminal, 'handle')
  ) {
    return normalizeTerminalHandle(node.terminal.handle);
  }
  return null;
}

/**
 * Strip content-bearing keys from one plain object (shallow).
 * @param {object} node
 * @returns {object}
 */
function stripContentKeysShallow(node) {
  const out = { ...node };
  for (const k of Object.keys(out)) {
    if (isTerminalContentKey(k)) delete out[k];
  }
  return out;
}

/**
 * Recursive ownership content redaction (NAS-250 inversion).
 *
 * Walk the ENTIRE value. On every object node:
 *   - if a terminal handle is present and owned → keep content keys, recurse
 *   - otherwise → strip content-bearing keys, recurse into children
 * Fail closed: missing/unknown handle ⇒ redact.
 * Inventory (ids, titles, states, counts, paths) is preserved.
 *
 * @param {unknown} payload
 * @param {Iterable<string>|Set<string>} ownedHandles
 * @param {WeakMap<object, unknown>} [memo]
 * @returns {unknown}
 */
export function redactOwnershipContent(payload, ownedHandles, memo = new WeakMap()) {
  if (payload == null || typeof payload !== 'object') return payload;
  if (memo.has(payload)) return memo.get(payload);

  const owned = buildOwnedHandleSet(ownedHandles);

  if (Array.isArray(payload)) {
    const arr = [];
    memo.set(payload, arr);
    for (const item of payload) {
      arr.push(redactOwnershipContent(item, owned, memo));
    }
    return arr;
  }

  const handle = nodeTerminalHandle(payload);
  const keepContent = Boolean(handle && owned.has(handle));

  /** @type {Record<string, unknown>} */
  const out = {};
  memo.set(payload, out);

  for (const [k, v] of Object.entries(payload)) {
    if (!keepContent && isTerminalContentKey(k)) {
      // strip
      continue;
    }
    out[k] = redactOwnershipContent(v, owned, memo);
  }
  return out;
}

/**
 * @deprecated shape-specific path — thin wrapper over redactOwnershipContent
 * kept so existing imports keep working. Prefer redactOwnershipContent.
 */
export function redactTerminalListPayload(payload, ownedHandles) {
  return redactOwnershipContent(payload, ownedHandles);
}

/**
 * Worktree rows have no handle; strip content keys on every node that is not
 * a proven-owned terminal. Equivalent to recursive fail-closed redaction with
 * an empty owned set for pure worktree inventory.
 */
export function redactWorktreeListPayload(payload) {
  return redactOwnershipContent(payload, []);
}

/**
 * Redact foreign `preview:` lines from human `terminal list` / `show` text.
 * Format (live CLI v1.4.x):
 *   handle  title  connected  path
 *   preview: <scrollback>
 *
 * Owned handles keep their preview line; foreign / unknown lose it.
 * Also rewrites JSON-ish "preview": "…" string values fail-closed when the
 * surrounding text is not parseable as JSON (banner+pretty landmine class).
 *
 * @param {string} text
 * @param {Iterable<string>|Set<string>} ownedHandles
 * @returns {string}
 */
export function redactTerminalListHumanStdout(text, ownedHandles) {
  if (typeof text !== 'string') return text;
  if (!text.includes('preview') && !text.includes('scrollback')) return text;
  const owned = buildOwnedHandleSet(ownedHandles);
  const lines = text.split('\n');
  /** @type {string|null} */
  let currentHandle = null;
  const out = [];
  for (const line of lines) {
    const trimmed = line.trimStart();
    // JSON key line: "preview": "…",  or preview: …
    const jsonKey = trimmed.match(/^"?(preview|scrollback|buffer|output|lines|tail|snapshot)"?\s*:/i);
    if (jsonKey || trimmed.toLowerCase().startsWith('preview:')) {
      if (currentHandle && owned.has(currentHandle)) {
        out.push(line);
      } else {
        const indent = line.slice(0, line.length - trimmed.length);
        const key = jsonKey ? jsonKey[1] : 'preview';
        if (trimmed.startsWith('"') || (jsonKey && trimmed.startsWith('"'))) {
          out.push(`${indent}"${key}": "<redacted>"`);
        } else if (jsonKey) {
          out.push(`${indent}${key}: <redacted>`);
        } else {
          out.push(`${indent}preview: <redacted>`);
        }
      }
      continue;
    }
    // Detect a terminal header line: starts with term_… handle token.
    const m = trimmed.match(/^(term_[A-Za-z0-9_-]+)\b/);
    if (m) {
      currentHandle = normalizeTerminalHandle(m[1]);
    }
    // Also detect "handle": "term_…"
    const hm = trimmed.match(/"handle"\s*:\s*"(term_[A-Za-z0-9_-]+)"/);
    if (hm) {
      currentHandle = normalizeTerminalHandle(hm[1]);
    }
    out.push(line);
  }
  return out.join('\n');
}

/**
 * Content-based ownership redaction for action=cli responses (NAS-250).
 *
 * Does NOT inspect argv and does NOT special-case terminals[] vs terminal.
 * Recursively strips every content-bearing field on nodes whose owning
 * terminal is not proven owned. Envelope and/or stdout (JSON or human).
 *
 * Mutates `described` in place and returns it.
 *
 * @param {object} described  describeRun output ({ envelope?, stdout?, … })
 * @param {Iterable<string>|Set<string>} ownedHandles
 * @returns {object}
 */
export function applyOwnershipListRedaction(described, ownedHandles) {
  if (!described || typeof described !== 'object') return described;

  if (described.envelope && typeof described.envelope === 'object') {
    described.envelope = redactOwnershipContent(described.envelope, ownedHandles);
  }

  if (typeof described.stdout === 'string' && described.stdout) {
    const raw = described.stdout;
    const trimmed = raw.trim();
    // Prefer JSON parse of the whole blob or first {…}/{…} body.
    let parsed = null;
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        parsed = null;
      }
    }
    if (parsed == null) {
      // banner + pretty JSON: find first line that starts with { or [
      const lines = raw.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const t = lines[i].trim();
        if (t.startsWith('{') || t.startsWith('[')) {
          const slice = lines.slice(i).join('\n').trim();
          try {
            parsed = JSON.parse(slice);
            break;
          } catch {
            // keep scanning
          }
        }
      }
    }
    if (parsed != null) {
      const next = redactOwnershipContent(parsed, ownedHandles);
      described.stdout = JSON.stringify(next);
    } else if (/preview|scrollback|buffer/i.test(raw)) {
      described.stdout = redactTerminalListHumanStdout(raw, ownedHandles);
    }
  }

  return described;
}

