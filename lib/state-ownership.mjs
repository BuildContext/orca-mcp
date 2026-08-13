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
// Terminal handle ownership (NAS-247)
//
// Source of truth is what the bridge already tracks per OAuth client:
//   - senderCaches / pinned sender handle
//   - clientOwnership.workerHandles (registerOwnedDispatch on dispatch)
//   - dispatchRegistry entries (terminalHandle + clientKey)
// Do not invent a parallel store — callers pass those structures in.
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

