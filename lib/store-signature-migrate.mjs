/**
 * One-shot operator migrator: sign legacy unsigned ownership stores.
 *
 * Target files only:
 *   ~/.orca-bridge-sender-pins.json
 *   ~/.orca-bridge/dispatch-ownership.json  (or $ORCA_BRIDGE_AUDIT_DIR/…)
 *
 * HARD INVARIANT: the runtime load path still rejects unsigned records.
 * This module is an explicit operator action, not a runtime fallback.
 * Do not wire it into server.mjs boot.
 *
 * C5 forgery bound:
 *   - isSignedEnvelope + verify ok        → already-signed (skip)
 *   - isSignedEnvelope + verify fail      → refused-bad-signature (no overwrite)
 *   - bare JSON (reason === unsigned)     → sign payload (legacy 0.3.0 trust)
 *   Bare unsigned has no MAC. Residual risk requires the bridge STOPPED so a
 *   concurrent same-uid attacker cannot race a forge into the file between
 *   read and write. Migration with the bridge running is unsafe.
 *
 * Out of scope: key rotation, signature expiry, any other files.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  SIGNED_STORE_BAD_SIG,
  SIGNED_STORE_MALFORMED,
  SIGNED_STORE_MISSING,
  SIGNED_STORE_SIGNER_UNAVAILABLE,
  SIGNED_STORE_UNSIGNED,
  SIGNED_STORE_UNREADABLE,
  isSignedEnvelope,
  readSignedJsonFile,
  verifyEnvelope,
  writeSignedJsonFile,
} from './store-signer.mjs';
import { writeFilePreservingOwner, STATE_FILE_MODE } from './state-ownership.mjs';

export const DEFAULT_PINS_BASENAME = '.orca-bridge-sender-pins.json';
export const DEFAULT_OWNERSHIP_BASENAME = 'dispatch-ownership.json';
export const DEFAULT_BRIDGE_DIR = '.orca-bridge';

/**
 * Resolve the two store paths the migrator is allowed to touch.
 * @param {object} [opts]
 * @param {string} [opts.home]
 * @param {string} [opts.auditDir]
 * @returns {{ pinsPath: string, ownershipPath: string, home: string, auditDir: string }}
 */
export function resolveMigrateStorePaths(opts = {}) {
  const home = opts.home != null ? String(opts.home) : os.homedir();
  const auditDir = opts.auditDir != null && String(opts.auditDir).trim()
    ? String(opts.auditDir).trim()
    : path.join(home, DEFAULT_BRIDGE_DIR);
  return {
    home,
    auditDir,
    pinsPath: path.join(home, DEFAULT_PINS_BASENAME),
    ownershipPath: path.join(auditDir, DEFAULT_OWNERSHIP_BASENAME),
  };
}

/**
 * Probe that the signer can actually sign (socket reachable / key usable).
 * Refuses silent no-op when the daemon is down.
 * @param {{ sign: Function, verify?: Function }} signer
 * @returns {Promise<{ok:true}|{ok:false,reason:string,error?:string}>}
 */
export async function assertSignerReachable(signer) {
  if (!signer || typeof signer.sign !== 'function') {
    return {
      ok: false,
      reason: SIGNED_STORE_SIGNER_UNAVAILABLE,
      error: 'no store signer configured (set ORCA_BRIDGE_STORE_SIGNER_SOCKET or ORCA_BRIDGE_STORE_SIGNER_KEY)',
    };
  }
  try {
    const probe = await signer.sign({ __orca_migrate_probe: true, t: 0 });
    if (!probe || probe.ok !== true || typeof probe.sig !== 'string') {
      return {
        ok: false,
        reason: SIGNED_STORE_SIGNER_UNAVAILABLE,
        error: (probe && probe.error) || 'signer probe sign failed',
      };
    }
    return { ok: true };
  } catch (e) {
    return {
      ok: false,
      reason: SIGNED_STORE_SIGNER_UNAVAILABLE,
      error: e && e.message ? e.message : String(e),
    };
  }
}

/**
 * @param {string} filePath
 * @param {string} [suffix]
 */
function backupPathFor(filePath, suffix) {
  const stamp = suffix || new Date().toISOString().replace(/[:.]/g, '-');
  return `${filePath}.pre-sign-${stamp}.bak`;
}

/**
 * Classify + optionally migrate one store file.
 *
 * @param {string} filePath
 * @param {object} signer
 * @param {object} [opts]
 * @param {boolean} [opts.dryRun]
 * @param {typeof fs} [opts.fsImpl]
 * @param {string} [opts.backupSuffix]
 */
export async function migrateOneStoreFile(filePath, signer, opts = {}) {
  const fsImpl = opts.fsImpl || fs;
  const dryRun = opts.dryRun === true;
  const label = path.basename(filePath);

  if (!fsImpl.existsSync(filePath)) {
    return {
      ok: true,
      path: filePath,
      label,
      action: 'missing',
    };
  }

  let rawText;
  try {
    rawText = fsImpl.readFileSync(filePath, 'utf8');
  } catch (e) {
    return {
      ok: false,
      path: filePath,
      label,
      action: 'unreadable',
      reason: SIGNED_STORE_UNREADABLE,
      error: e && e.message ? e.message : String(e),
    };
  }

  if (!String(rawText).trim()) {
    return {
      ok: true,
      path: filePath,
      label,
      action: 'empty',
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch (e) {
    return {
      ok: false,
      path: filePath,
      label,
      action: 'malformed',
      reason: SIGNED_STORE_MALFORMED,
      error: e && e.message ? e.message : String(e),
    };
  }

  // Path A: already a signed envelope — verify, never re-sign on bad sig.
  if (isSignedEnvelope(parsed)) {
    const verified = await verifyEnvelope(parsed, signer);
    if (verified.ok) {
      return {
        ok: true,
        path: filePath,
        label,
        action: 'already-signed',
      };
    }
    if (verified.reason === SIGNED_STORE_SIGNER_UNAVAILABLE) {
      return {
        ok: false,
        path: filePath,
        label,
        action: 'signer-unavailable',
        reason: SIGNED_STORE_SIGNER_UNAVAILABLE,
        error: verified.error,
      };
    }
    // bad-signature / malformed envelope → refuse. Do not launder.
    return {
      ok: false,
      path: filePath,
      label,
      action: 'refused-bad-signature',
      reason: verified.reason || SIGNED_STORE_BAD_SIG,
      error: verified.error,
    };
  }

  // Path B: bare JSON (legacy 0.3.0 unsigned). Confirm load path would reject.
  const loadCheck = await readSignedJsonFile(filePath, signer, { fsImpl });
  if (loadCheck.ok) {
    // Unexpected: bare object verified? Treat as already good.
    return {
      ok: true,
      path: filePath,
      label,
      action: 'already-signed',
    };
  }
  if (loadCheck.reason === SIGNED_STORE_SIGNER_UNAVAILABLE) {
    return {
      ok: false,
      path: filePath,
      label,
      action: 'signer-unavailable',
      reason: SIGNED_STORE_SIGNER_UNAVAILABLE,
      error: loadCheck.error,
    };
  }
  if (loadCheck.reason !== SIGNED_STORE_UNSIGNED) {
    // Malformed / unreadable mid-flight etc.
    return {
      ok: false,
      path: filePath,
      label,
      action: loadCheck.reason || 'rejected',
      reason: loadCheck.reason,
      error: loadCheck.error,
    };
  }

  // Only sign bare-unsigned payloads. Residual trust: operator + bridge stopped.
  const payload = parsed;
  if (payload == null || typeof payload !== 'object') {
    return {
      ok: false,
      path: filePath,
      label,
      action: 'malformed',
      reason: SIGNED_STORE_MALFORMED,
      error: 'unsigned store payload must be a JSON object or array',
    };
  }

  if (dryRun) {
    return {
      ok: true,
      path: filePath,
      label,
      action: 'would-sign',
      legacyUnsignedTrust: true,
      dryRun: true,
    };
  }

  const backupPath = backupPathFor(filePath, opts.backupSuffix);
  try {
    fsImpl.copyFileSync(filePath, backupPath);
    try {
      fsImpl.chmodSync(backupPath, STATE_FILE_MODE);
    } catch {
      // best-effort mode match
    }
  } catch (e) {
    return {
      ok: false,
      path: filePath,
      label,
      action: 'backup-failed',
      error: e && e.message ? e.message : String(e),
    };
  }

  const written = await writeSignedJsonFile(filePath, payload, signer, {
    writeFile: opts.writeFile || writeFilePreservingOwner,
    mode: STATE_FILE_MODE,
  });
  if (!written.ok) {
    return {
      ok: false,
      path: filePath,
      label,
      action: 'sign-failed',
      reason: written.reason,
      error: written.error,
      backupPath,
    };
  }

  // Post-condition: bridge load path must accept.
  const after = await readSignedJsonFile(filePath, signer, { fsImpl });
  if (!after.ok) {
    return {
      ok: false,
      path: filePath,
      label,
      action: 'post-verify-failed',
      reason: after.reason,
      error: after.error,
      backupPath,
    };
  }

  return {
    ok: true,
    path: filePath,
    label,
    action: 'signed',
    legacyUnsignedTrust: true,
    backupPath,
  };
}

/**
 * Migrate both ownership stores under an isolated or real HOME.
 *
 * @param {object} opts
 * @param {object} opts.signer
 * @param {string} [opts.home]
 * @param {string} [opts.auditDir]
 * @param {boolean} [opts.dryRun]
 * @param {boolean} [opts.skipReachabilityProbe] — tests only
 * @param {typeof fs} [opts.fsImpl]
 * @param {string} [opts.backupSuffix]
 */
export async function migrateUnsignedStores(opts = {}) {
  const dryRun = opts.dryRun === true;
  const signer = opts.signer;
  const paths = resolveMigrateStorePaths({
    home: opts.home,
    auditDir: opts.auditDir,
  });

  if (!opts.skipReachabilityProbe) {
    const reach = await assertSignerReachable(signer);
    if (!reach.ok) {
      return {
        ok: false,
        dryRun,
        reason: reach.reason || SIGNED_STORE_SIGNER_UNAVAILABLE,
        error: reach.error || 'store signer unreachable; refusing to migrate',
        paths,
        files: {
          pins: { action: 'not-attempted', path: paths.pinsPath },
          ownership: { action: 'not-attempted', path: paths.ownershipPath },
        },
      };
    }
  }

  const common = {
    dryRun,
    fsImpl: opts.fsImpl,
    writeFile: opts.writeFile,
    backupSuffix: opts.backupSuffix,
  };

  const pins = await migrateOneStoreFile(paths.pinsPath, signer, common);
  const ownership = await migrateOneStoreFile(paths.ownershipPath, signer, common);

  const files = { pins, ownership };
  const anyHardFail = [pins, ownership].some((f) => f.ok === false);
  // Soft skips (missing/empty/already-signed/would-sign) are ok.
  return {
    ok: !anyHardFail,
    dryRun,
    paths,
    files,
    error: anyHardFail
      ? [pins, ownership]
          .filter((f) => f.ok === false)
          .map((f) => `${f.label}: ${f.action}${f.error ? ` (${f.error})` : ''}`)
          .join('; ')
      : undefined,
  };
}
