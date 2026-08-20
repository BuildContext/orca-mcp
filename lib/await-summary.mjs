/**
 * Await mailbox summary + next-step hints (pure).
 *
 * Coordinators prefer summary.status over next.action. Classification must
 * fail closed: a runtime-rejected worker_done is never status=worker_done
 * with outcome=succeeded.
 */

import { isTemplateWorkerDone } from './agent-tui.mjs';
import { nextStepForLiveness } from './runtime-guard.mjs';

function pick(obj, ...keys) {
  if (!obj || typeof obj !== 'object') return undefined;
  for (const k of keys) {
    if (obj[k] != null && obj[k] !== '') return obj[k];
  }
  return undefined;
}

export function msgType(m) {
  return String(pick(m, 'type', 'messageType', 'kind') || '').toLowerCase();
}

/**
 * Coerce a worker_done payload that may be an object or a JSON string.
 * @param {unknown} raw
 * @returns {object}
 */
export function coercePayload(raw) {
  if (!raw) return {};
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch {
      return {};
    }
  }
  if (typeof raw === 'object') return raw;
  return {};
}

/**
 * Runtime lifecycle rejection attached to a worker_done message/payload.
 * @param {object|null} msg
 * @returns {{ code: string, reason: string } | null}
 */
export function lifecycleRejectionOf(msg) {
  if (!msg || typeof msg !== 'object') return null;
  const payload = coercePayload(msg.payload);
  const raw = payload._orcaLifecycleRejection || msg._orcaLifecycleRejection;
  if (!raw || typeof raw !== 'object') return null;
  const code = String(raw.code || '').trim() || 'lifecycle_rejected';
  const reason = String(raw.reason || raw.message || raw.code || '').trim()
    || 'Orca rejected this worker_done';
  return { code, reason };
}

export const REJECTED_WORKER_DONE = 'rejected_worker_done';


export function summarizeMessages(messages = []) {
  const list = Array.isArray(messages) ? messages : [];
  const byType = {};
  for (const m of list) {
    const t = msgType(m) || 'unknown';
    byType[t] = (byType[t] || 0) + 1;
  }
  const done = list.find((m) => msgType(m) === 'worker_done');
  const question = list.find((m) => msgType(m) === 'question');
  const escalation = list.find((m) => msgType(m) === 'escalation');
  const extractDone = (m) => {
    if (!m) return null;
    const payload = coercePayload(m.payload);
    return {
      taskId: pick(m, 'taskId', 'task_id') || pick(payload, 'taskId', 'task_id'),
      dispatchId: pick(m, 'dispatchId', 'dispatch_id') || pick(payload, 'dispatchId', 'dispatch_id'),
      outcome: pick(m, 'outcome') || pick(payload, 'outcome'),
      subject: pick(m, 'subject', 'title'),
      body: pick(m, 'body', 'text', 'content'),
      filesModified: pick(m, 'filesModified', 'files_modified') || pick(payload, 'filesModified', 'files_modified'),
      reportPath: pick(m, 'reportPath', 'report_path') || pick(payload, 'reportPath', 'report_path'),
      id: pick(m, 'id', 'messageId', 'message_id'),
    };
  };

  const extractedDone = extractDone(done);
  const lifecycleRejection = lifecycleRejectionOf(done);
  let primary = 'empty';
  let rejectedWorkerDone = undefined;
  if (done) {
    if (lifecycleRejection) {
      primary = REJECTED_WORKER_DONE;
      rejectedWorkerDone = lifecycleRejection;
      const claimed = extractedDone.outcome || null;
      extractedDone.claimed_outcome = claimed;
      extractedDone.lifecycle_rejection = lifecycleRejection;
      extractedDone.outcome = claimed && claimed !== 'succeeded' ? claimed : 'failed';
    } else if (isTemplateWorkerDone({
      subject: extractedDone?.subject,
      body: extractedDone?.body,
      filesModified: extractedDone?.filesModified,
      payload: done.payload,
    })) {
      primary = 'fake_worker_done';
      rejectedWorkerDone = 'template';
    } else {
      primary = 'worker_done';
    }
  } else if (escalation) primary = 'escalation';
  else if (question) primary = 'question';
  else if (list.length) primary = 'messages';

  return {
    status: primary,
    counts: byType,
    rejected_worker_done: rejectedWorkerDone,
    worker_done: extractedDone,
    question: question
      ? {
          id: pick(question, 'id', 'messageId', 'message_id'),
          subject: pick(question, 'subject', 'title'),
          body: pick(question, 'body', 'text', 'content'),
          dispatchId: pick(question, 'dispatchId', 'dispatch_id'),
        }
      : null,
    escalation: escalation
      ? {
          id: pick(escalation, 'id', 'messageId', 'message_id'),
          subject: pick(escalation, 'subject', 'title'),
          body: pick(escalation, 'body', 'text', 'content'),
          dispatchId: pick(escalation, 'dispatchId', 'dispatch_id'),
        }
      : null,
  };
}

export function nextStepForAwait(summary, { timedOut, deliveryId, livenessInfo = null } = {}) {
  // next.action is a HINT — summary.status wins if they disagree.
  if (summary.status === REJECTED_WORKER_DONE) {
    const rej = summary.rejected_worker_done && typeof summary.rejected_worker_done === 'object'
      ? summary.rejected_worker_done
      : { code: String(summary.rejected_worker_done || 'lifecycle_rejected') };
    return {
      action: 'diagnose_rejected_worker_done',
      detail:
        'summary.status=rejected_worker_done — Orca rejected this worker_done' +
        (rej.code ? ` (${rej.code})` : '') +
        (rej.reason ? `: ${rej.reason}` : '.') +
        ' Do not treat as success. The original worker body remains on summary.worker_done.body.',
      deliveryId: deliveryId || null,
      rejected_worker_done: rej,
      dispatchId: summary.worker_done?.dispatchId || null,
      note: 'next.action is a hint; prefer summary.status if they disagree.',
    };
  }
  if (summary.status === 'fake_worker_done') {
    return {
      action: 'diagnose_fake_worker_done',
      detail:
        'summary.status=fake_worker_done — template or placeholder worker_done rejected. ' +
        'Do not release as success. Inspect the worker tab; treat as a failed agent launch.',
      deliveryId: deliveryId || null,
      rejected_worker_done: summary.rejected_worker_done || 'template',
      note: 'next.action is a hint; prefer summary.status if they disagree.',
    };
  }
  if (summary.status === 'worker_done') {
    return {
      action: 'release',
      detail:
        'summary.status=worker_done (authoritative). Call orca{action:"release",dispatchId,terminalHandle}. ' +
        'Then orca{action:"await",runId,ack:deliveryId,waitMs:0} if more workers remain, else finish. ' +
        'Report outcome+body+filesModified. Inject-path: release may mode=terminal-close (ok).',
      deliveryId: deliveryId || null,
      dispatchId: summary.worker_done?.dispatchId || null,
      note: 'next.action is a hint; prefer summary.status if they disagree.',
    };
  }
  if (summary.status === 'question') {
    const qid = summary.question?.id || '<question.id>';
    return {
      action: 'reply_then_await',
      detail:
        `summary.status=question. Reply: orca{action:"cli",args:["orchestration","reply","--id","${qid}","--body","<answer>","--json"]}, ` +
        'then orca{action:"await",runId,waitMs:45000,ack:deliveryId}.',
      deliveryId: deliveryId || null,
      questionId: summary.question?.id || null,
      reply_argv: ['orchestration', 'reply', '--id', String(qid), '--body', '<answer>', '--json'],
      note: 'next.action is a hint; prefer summary.status if they disagree.',
    };
  }
  if (summary.status === 'escalation') {
    const eid = summary.escalation?.id || '<escalation.id>';
    return {
      action: 'reply_then_ack',
      detail:
        'summary.status=escalation. Reply: orca{action:"cli",args:["orchestration","reply","--id","' +
        eid +
        '","--body","<answer>","--json"]} ' +
        '(bridge dual-routes non-question replies onto dispatch:<id> so the waiting worker unblocks). ' +
        'Then await with ack=deliveryId. Prefer ask for true back-and-forth.',
      deliveryId: deliveryId || null,
      escalationId: summary.escalation?.id || null,
      reply_argv: ['orchestration', 'reply', '--id', String(eid), '--body', '<answer>', '--json'],
      note: 'next.action is a hint; prefer summary.status if they disagree.',
    };
  }
  if (timedOut || summary.status === 'empty') {
    if (livenessInfo && livenessInfo.liveness) {
      return nextStepForLiveness({
        liveness: livenessInfo.liveness,
        emptyWindowsConsecutive: livenessInfo.emptyWindowsConsecutive,
        msSinceActivity: livenessInfo.msSinceActivity,
        deliveryId: null,
      });
    }
    return nextStepForLiveness({ liveness: 'unknown', emptyWindowsConsecutive: 0, deliveryId: null });
  }
  return {
    action: 'process_messages',
    detail: 'Other message types in raw.messages — process, then await with ack=deliveryId.',
    deliveryId: deliveryId || null,
    note: 'next.action is a hint; prefer summary.status if they disagree.',
  };
}
