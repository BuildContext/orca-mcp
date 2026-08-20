/**
 * action=release ownership + effect orchestration (NAS-248 / NAS-202).
 *
 * Invariant: no runJson / CLI effect of any kind runs until ownership of the
 * supplied dispatch id AND/OR terminal handle has been judged owned.
 * requireOwnedDispatch / requireOwnedHandle are the only gates; they reuse
 * resolveDispatchOwnership / resolveTerminalHandleOwnership (no third extractor).
 */

import {
  requireOwnedDispatch,
  requireOwnedHandle,
} from './state-ownership.mjs';

/**
 * Fail-closed preflight. Call before any effect (lookup, worker-release, close).
 *
 * @param {{ dispatchId?: string|null, handle?: string|null }} ids
 * @param {string} clientKey
 * @param {object} ownershipDeps
 * @returns {{
 *   ok: true,
 *   dispatchId: string|null,
 *   handle: string|null,
 * } | {
 *   ok: false,
 *   kind: 'dispatch'|'handle'|'missing',
 *   dispatchId: string|null,
 *   handle: string|null,
 *   ownership: object|null,
 * }}
 */
export function preflightReleaseOwnership(ids, clientKey, ownershipDeps = {}) {
  const dispatchId =
    ids?.dispatchId == null || ids.dispatchId === ''
      ? null
      : String(ids.dispatchId).trim() || null;
  const handle =
    ids?.handle == null || ids.handle === ''
      ? null
      : String(ids.handle).trim() || null;

  if (!dispatchId && !handle) {
    return {
      ok: false,
      kind: 'missing',
      dispatchId: null,
      handle: null,
      ownership: null,
    };
  }

  if (dispatchId) {
    const gate = requireOwnedDispatch(dispatchId, clientKey, ownershipDeps);
    if (!gate.ok) {
      return {
        ok: false,
        kind: 'dispatch',
        dispatchId,
        handle,
        ownership: gate.ownership,
      };
    }
  }

  if (handle) {
    const gate = requireOwnedHandle(handle, clientKey, ownershipDeps);
    if (!gate.ok) {
      return {
        ok: false,
        kind: 'handle',
        dispatchId,
        handle,
        ownership: gate.ownership,
      };
    }
  }

  return { ok: true, dispatchId, handle };
}

/**
 * Build the standard ownership_denied envelope for action=release.
 * @param {ReturnType<typeof preflightReleaseOwnership>} pre
 */
export function releaseOwnershipDenial(pre) {
  if (!pre || pre.ok) {
    throw new Error('releaseOwnershipDenial expects a failed preflight');
  }
  if (pre.kind === 'missing') {
    return {
      ok: false,
      mode: 'ownership_denied',
      error: 'handle_not_owned',
      code: 'handle_not_owned',
      ownership_kind: 'missing',
      dispatch_id: null,
      terminal_handle: null,
      ownership_status: 'unknown',
      reason: 'missing_dispatch_and_handle',
      owned_handles: [],
      owned_dispatches: [],
      detail:
        'Blocked: release requires a dispatch id or terminal handle this client owns.',
      next: {
        action: 'release_owned_handle',
        detail:
          "Pass dispatchId / terminalHandle from this client's action=dispatch response.",
      },
    };
  }

  const own = pre.ownership || {};
  const statusLabel = own.status === 'not-owned' ? 'not-owned' : 'unknown';
  const isDispatch = pre.kind === 'dispatch';
  const ownedHandles = own.owned_handles || own.ownedHandles || [];
  const ownedDispatches = own.owned_dispatches || own.ownedDispatches || [];

  if (isDispatch) {
    const idLabel = pre.dispatchId || '(missing)';
    return {
      ok: false,
      mode: 'ownership_denied',
      error: 'handle_not_owned',
      code: 'handle_not_owned',
      ownership_kind: 'dispatch',
      dispatch_id: pre.dispatchId,
      terminal_handle: pre.handle,
      ownership_status: statusLabel,
      reason: own.reason || undefined,
      owned_handles: ownedHandles,
      owned_dispatches: ownedDispatches,
      detail:
        `Blocked: dispatch id "${idLabel}" is ${statusLabel} for this client.` +
        ` Owned dispatches: ${ownedDispatches.join(', ') || '(none)'}.` +
        (own.reason ? ` reason=${own.reason}.` : '') +
        ` Release only tears down dispatches this client owns.`,
      next: {
        action: 'release_owned_dispatch',
        detail:
          "Pass dispatchId from this client's action=dispatch response. " +
          'Foreign and unknown dispatch ids are refused before any worker-release/close.',
      },
    };
  }

  const handleLabel = pre.handle || '(missing)';
  return {
    ok: false,
    mode: 'ownership_denied',
    error: 'handle_not_owned',
    code: 'handle_not_owned',
    ownership_kind: 'handle',
    dispatch_id: pre.dispatchId,
    terminal_handle: pre.handle,
    ownership_status: statusLabel,
    reason: own.reason || undefined,
    owned_handles: ownedHandles,
    owned_dispatches: ownedDispatches,
    detail:
      `Blocked: terminal handle "${handleLabel}" is ${statusLabel} for this client.` +
      ` Owned handles: ${ownedHandles.join(', ') || '(none)'}.` +
      (own.reason ? ` reason=${own.reason}.` : '') +
      ` Release only closes handles this client owns (dispatch worker or pin).`,
    next: {
      action: 'release_owned_handle',
      detail:
        "Pass terminal_handle from this client's action=dispatch response. " +
        'Foreign handles and unknown handles (e.g. after bridge restart wiped workerHandles) are refused.',
    },
  };
}

/**
 * Gate a handle discovered after ownership-cleared lookup, before terminal close.
 * @param {string} handle
 * @param {string|null} dispatchId
 * @param {string} clientKey
 * @param {object} ownershipDeps
 */
export function preflightCloseHandle(handle, dispatchId, clientKey, ownershipDeps) {
  const gate = requireOwnedHandle(handle, clientKey, ownershipDeps);
  if (gate.ok) return { ok: true, handle, dispatchId: dispatchId || null };
  return {
    ok: false,
    kind: 'handle',
    dispatchId: dispatchId || null,
    handle,
    ownership: gate.ownership,
  };
}

/**
 * Isolation creds/caps are purged only when this dispatch provisioned them.
 * Unknown (missing row/flags) fail-closed to purge so isolation-ON is not weakened.
 * Isolation explicitly off and not minted → skip (NAS-271).
 *
 * @param {object|null|undefined} row
 * @returns {boolean}
 */
export function shouldPurgeWorkerCreds(row) {
  if (!row) return true;
  if (row.workerCapabilityMinted === true || row.workerIsolation === true) return true;
  if (row.workerIsolation === false) return false;
  return true;
}

function lookupDispatchRow(ownershipDeps, dispatchId) {
  if (!dispatchId) return null;
  const reg = ownershipDeps?.dispatchRegistry;
  if (!reg) return null;
  if (typeof reg.get === 'function') {
    const got = reg.get(dispatchId);
    if (got) return got;
  }
  const list = typeof reg.list === 'function' ? reg.list() : [];
  return (Array.isArray(list) ? list : []).find((r) => r && r.dispatchId === dispatchId) || null;
}

/**
 * Full release orchestration with injected effects — testable without the server.
 *
 * Ordering invariant (enforced):
 *   1. preflightReleaseOwnership
 *   2. optional handle lookup (runJson) — only after dispatch ownership
 *   3. optional worker-release (runJson)
 *   4. coordinator refuse
 *   5. preflightCloseHandle (if closing)
 *   6. terminal close (runJson)
 *
 * @param {object} args
 * @param {string} [args.dispatch_id]
 * @param {string} [args.terminal_handle]
 * @param {string} [args.handle]
 * @param {string} [args.task_id]
 * @param {object} ctx
 * @param {string} ctx.clientKey
 * @param {object} ctx.ownershipDeps
 * @param {(argv: string[], opts?: object) => Promise<object>} ctx.runJson
 * @param {(env: object) => boolean} ctx.envOk
 * @param {(obj: object, ...keys: string[]) => string} ctx.pick
 * @param {(handle: string, set: Set<string>) => boolean} ctx.releaseRefusesCoordinator
 * @param {Set<string>} ctx.coordinatorHandles
 * @param {(id: string, row: object) => void} [ctx.upsertDispatch]
 */
export async function executeReleaseWorker(args = {}, ctx) {
  const dispatchId = String(args.dispatch_id || '').trim();
  const handleHint = String(args.terminal_handle || args.handle || '').trim();
  if (!dispatchId && !handleHint) {
    throw new Error('dispatch_id (or terminal handle) is required');
  }

  const {
    clientKey,
    ownershipDeps,
    runJson,
    envOk,
    pick,
    releaseRefusesCoordinator,
    coordinatorHandles,
    upsertDispatch,
    purgeWorkerCreds,
  } = ctx;

  // --- GATE FIRST. Zero effects above this line. ---
  const pre = preflightReleaseOwnership(
    { dispatchId: dispatchId || null, handle: handleHint || null },
    clientKey,
    ownershipDeps,
  );
  if (!pre.ok) {
    return releaseOwnershipDenial(pre);
  }

  let handle = handleHint;
  if (!handle && dispatchId) {
    for (const argv of [
      ['orchestration', 'dispatch-show', '--task', String(args.task_id || ''), '--json'],
      ['orchestration', 'worker-show', '--dispatch', dispatchId, '--json'],
    ]) {
      if (argv.includes('--task') && !args.task_id) continue;
      const show = await runJson(argv, { timeoutMs: 30_000 });
      if (!envOk(show)) continue;
      const r = show.envelope?.result || {};
      handle =
        pick(r.dispatch, 'assignee_handle') ||
        pick(r.worker, 'agent_terminal_handle', 'agentTerminalHandle') ||
        pick(r, 'assignee_handle', 'handle') ||
        '';
      if (handle) break;
    }
  }

  let releaseRes = null;
  let releaseNote = null;
  if (dispatchId) {
    releaseRes = await runJson(
      ['orchestration', 'worker-release', '--dispatch', dispatchId, '--json'],
      { timeoutMs: 60_000 },
    );
    if (envOk(releaseRes) || releaseRes?.ok === true) {
      if (typeof upsertDispatch === 'function') {
        // Status-only write. clientKey is authoritative at dispatch-time bind;
        // release must not re-claim or forge ownership (NAS-248 P0 #4).
        upsertDispatch(dispatchId, {
          status: 'released',
          mode: 'worker-release',
          terminalHandle: handle || null,
        });
      }
      return {
        ok: true,
        mode: 'worker-release',
        dispatch_id: dispatchId,
        terminal_handle: handle || null,
        result: releaseRes.envelope?.result ?? releaseRes,
        next: {
          action: 'ack_and_finish',
          detail:
            'worker-release ok (supervised worker-start path). Ack delivery if needed.',
        },
      };
    }
    const code =
      releaseRes?.envelope?.error?.code || releaseRes?.error?.code || '';
    releaseNote =
      code === 'dispatch_not_found'
        ? 'worker-release: dispatch_not_found (normal for inject-path after worker_done)'
        : `worker-release failed: ${code || 'unknown'} — falling back to terminal close`;
  }

  if (!handle) {
    return {
      ok: false,
      mode: 'none',
      dispatch_id: dispatchId || null,
      worker_release: releaseRes?.envelope || releaseRes,
      error:
        'no terminal handle to close; pass terminalHandle from dispatch response',
      note: releaseNote,
      next: {
        action: 'manual',
        detail:
          'Pass terminalHandle from dispatch.terminal_handle, then release again.',
      },
    };
  }

  if (releaseRefusesCoordinator(handle, coordinatorHandles)) {
    return {
      ok: false,
      mode: 'refused_coordinator_terminal',
      dispatch_id: dispatchId || null,
      terminal_handle: handle,
      error:
        'terminalHandle is a bridge coordinator sender — will not close (would fence the run). ' +
        'Pass the worker terminal_handle from the dispatch response, not the sender from health.',
      note: releaseNote,
      worker_release: releaseRes?.envelope || releaseRes || null,
      next: {
        action: 'release_with_worker_handle',
        detail:
          'Use terminal_handle from action=dispatch (worker tab). Coordinator tabs stay open for run-use/await/ack.',
      },
    };
  }

  // Handle may have been discovered post-gate via lookup — re-check before close.
  if (!handleHint || handle !== handleHint) {
    const closePre = preflightCloseHandle(
      handle,
      dispatchId || null,
      clientKey,
      ownershipDeps,
    );
    if (!closePre.ok) {
      const denial = releaseOwnershipDenial(closePre);
      denial.note = releaseNote;
      denial.worker_release = releaseRes?.envelope || releaseRes || null;
      return denial;
    }
  } else {
    // handleHint already cleared preflight; still re-assert before destructive close
    const closePre = preflightCloseHandle(
      handle,
      dispatchId || null,
      clientKey,
      ownershipDeps,
    );
    if (!closePre.ok) {
      const denial = releaseOwnershipDenial(closePre);
      denial.note = releaseNote;
      denial.worker_release = releaseRes?.envelope || releaseRes || null;
      return denial;
    }
  }

  const closeRes = await runJson(
    ['terminal', 'close', '--terminal', handle, '--json'],
    { timeoutMs: 30_000 },
  );
  const closeCode = extractCloseCode(closeRes);
  const alreadyGone = isAlreadyGoneClose(closeCode, closeRes);
  const closed = Boolean(envOk(closeRes) || closeRes?.ok === true || alreadyGone);

  const otherLiveIsolated = Boolean(
    dispatchId &&
      ownershipDeps?.dispatchRegistry?.list?.().some(
        (row) =>
          row?.dispatchId !== dispatchId &&
          row?.status === 'running' &&
          row?.workerIsolation === true,
      ),
  );
  let credentialPurge = null;
  const provisioned = shouldPurgeWorkerCreds(lookupDispatchRow(ownershipDeps, dispatchId));
  if (!provisioned) {
    credentialPurge = { skipped: 'not_provisioned' };
  } else if (typeof purgeWorkerCreds === 'function') {
    credentialPurge = await purgeWorkerCreds({
      dispatchId,
      creds: !otherLiveIsolated,
    });
    if (otherLiveIsolated) {
      credentialPurge = {
        ...(credentialPurge && typeof credentialPurge === 'object' ? credentialPurge : {}),
        skipped: 'other_live_isolated_dispatch',
      };
    }
  }
  const purgeFailed = Boolean(credentialPurge && credentialPurge.ok === false);
  if (dispatchId && typeof upsertDispatch === 'function') {
    // Status-only — do not pass clientKey (not claimable from release either).
    upsertDispatch(dispatchId, {
      status: closed && !purgeFailed ? 'released' : 'release_failed',
      mode: 'terminal-close',
      terminalHandle: handle,
    });
  }

  if (purgeFailed) {
    return {
      ok: false,
      error: 'credential_purge_failed',
      mode: 'terminal-close',
      expected_for_inject_path: true,
      already_gone: alreadyGone,
      close_code: closeCode || null,
      dispatch_id: dispatchId || null,
      terminal_handle: handle,
      note: releaseNote,
      worker_release: releaseRes?.envelope || releaseRes || null,
      result: closeRes.envelope?.result ?? closeRes,
      credential_purge: credentialPurge,
      next: {
        action: 'diagnose_credential_purge',
        detail:
          'Isolation creds/caps were provisioned for this dispatch; purge failed. ' +
          'Release is not clean — do not ignore credential_purge_failed.',
      },
    };
  }

  return {
    ok: closed,
    mode: 'terminal-close',
    expected_for_inject_path: true,
    already_gone: alreadyGone,
    close_code: closeCode || null,
    dispatch_id: dispatchId || null,
    terminal_handle: handle,
    note: releaseNote,
    worker_release: releaseRes?.envelope || releaseRes || null,
    result: closeRes.envelope?.result ?? closeRes,
    credential_purge: credentialPurge,
    next: {
      action: 'ack_and_finish',
      detail:
        'Inject-path cleanup = terminal close --terminal <handle> --json (no --tab). ' +
        'tab_not_found / workspace_session_unavailable means the tab is already gone. ' +
        'Ack mailbox if needed, then report. Not a failure when mode=terminal-close and ok=true.',
    },
  };
}

/**
 * Runtime / envelope error code for a terminal close attempt.
 * @param {object|null} closeRes
 */
export function extractCloseCode(closeRes) {
  const env = closeRes?.envelope || closeRes || {};
  const err = env.error || closeRes?.error || {};
  const code = err.code || err.name || (typeof err === 'string' ? err : '') || '';
  const message = String(err.message || env.message || closeRes?.message || '');
  return String(code || message || '').trim();
}

/**
 * uid 997 cannot kill a 994 pty group; the pty master can. A missing tab after
 * that close is success, not a leftover worker.
 */
export function isAlreadyGoneClose(code, closeRes) {
  const blob = `${code || ''} ${JSON.stringify(closeRes?.envelope || closeRes || {})}`;
  return /tab_not_found|workspace_session_unavailable/i.test(blob);
}
