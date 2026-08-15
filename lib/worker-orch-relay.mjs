/**
 * NAS-258 — authorize worker-side `orca orchestration …` before the bridge
 * relays it as the bridge uid (which holds the runtime token).
 *
 * The isolated worker cannot read orca-runtime.json. /usr/local/bin/orca
 * POSTs argv + HMAC capability here; this module decides whether the
 * command is one of the minted ops and whether ids match the token.
 */

const ALLOWED_VERBS = new Set(['send', 'ask', 'check']);
const SEND_TYPES = new Set(['worker_done', 'ask', 'heartbeat', 'escalation', 'check']);

export function getArgFlag(argv, name) {
  const list = Array.isArray(argv) ? argv : [];
  const i = list.indexOf(name);
  if (i < 0 || i + 1 >= list.length) return null;
  const v = list[i + 1];
  if (v == null || String(v).startsWith('--')) return null;
  return String(v);
}

/**
 * Normalize helper/CLI argv into { verb, type, dispatchId, taskId, argv }.
 * Accepts either `orchestration send …` or a bare helper verb (`send` / `worker_done`).
 *
 * @param {string[]} argv
 * @returns {{
 *   ok: true,
 *   verb: string,
 *   type: string|null,
 *   dispatchId: string|null,
 *   taskId: string|null,
 *   relayArgv: string[],
 * } | { ok: false, code: string, message: string }}
 */
export function parseWorkerOrchArgv(argv) {
  const raw = Array.isArray(argv) ? argv.map(String) : [];
  let rest = raw[0] === 'orchestration' ? raw.slice(1) : raw.slice();
  if (rest[0] === '--') rest = rest.slice(1);
  if (rest.length === 0) {
    return { ok: false, code: 'missing_verb', message: 'orchestration verb required' };
  }
  let verb = rest[0];
  let flags = rest.slice(1);

  // Direct helper forms: `worker_done|heartbeat|…` → send --type <op>
  if (SEND_TYPES.has(verb) && verb !== 'ask' && verb !== 'check') {
    flags = ['--type', verb, ...flags];
    verb = 'send';
  }

  if (!ALLOWED_VERBS.has(verb)) {
    return { ok: false, code: 'verb_not_allowed', message: `orchestration ${verb} is not a worker op` };
  }

  const type = verb === 'send' ? getArgFlag(flags, '--type') : verb;
  if (verb === 'send' && (!type || !SEND_TYPES.has(type))) {
    return { ok: false, code: 'type_not_allowed', message: `send --type ${type || '(missing)'} is not a worker op` };
  }

  return {
    ok: true,
    verb,
    type: type || null,
    dispatchId: getArgFlag(flags, '--dispatch-id') || getArgFlag(raw, '--dispatch-id'),
    taskId: getArgFlag(flags, '--task-id') || getArgFlag(raw, '--task-id'),
    relayArgv: ['orchestration', verb, ...flags],
  };
}

/**
 * @param {{
 *   parsed: ReturnType<typeof parseWorkerOrchArgv>,
 *   payload: { dispatchId?: string, taskId?: string, ops?: string[] },
 * }} p
 */
export function authorizeWorkerOrch(p) {
  const parsed = p?.parsed;
  if (!parsed || parsed.ok !== true) {
    return { ok: false, code: parsed?.code || 'invalid_argv', message: parsed?.message || 'invalid argv' };
  }
  const payload = p.payload || {};
  const ops = Array.isArray(payload.ops) ? payload.ops.map(String) : [];
  const op = parsed.type || parsed.verb;
  if (!ops.includes(String(op))) {
    return { ok: false, code: 'op_not_allowed', message: `op ${op} not in capability` };
  }
  if (parsed.dispatchId && payload.dispatchId && String(parsed.dispatchId) !== String(payload.dispatchId)) {
    return { ok: false, code: 'dispatch_mismatch', message: 'argv dispatchId does not match capability' };
  }
  if (parsed.taskId && payload.taskId && String(parsed.taskId) !== String(payload.taskId)) {
    return { ok: false, code: 'task_mismatch', message: 'argv taskId does not match capability' };
  }
  return { ok: true, op, parsed };
}
