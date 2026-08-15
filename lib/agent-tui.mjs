/**
 * NAS-267 — decide whether an isolated terminal is a real agent TUI,
 * and whether a worker_done is the contract template (bash-executed).
 */

const SHELL_TITLE = /^(bash|zsh|sh|fish|dash|ksh)(?:\b|[-\s:].*)?$/i;
const KNOWN_AGENT_TITLE =
  /\b(Grok|omp|Claude|Codex|Gemini|Cursor|Aider|Amp|OpenCode)\b/i;
const WRAPPER_SEED =
  /orca-omp-as-worker:.*(capability pointer present|credential seed|agent not found)/i;
const COMMAND_NOT_FOUND_CONTRACT =
  /command not found/i;
const CONTRACT_TOKENS = /(?:^|\s)(?:=+|worker_done)\b/;

const DUMMY_FILES = [
  ['path/a', 'path/b'],
  ['foo/a', 'foo/b'],
];

/**
 * @param {object|null} snap terminalSnapshot-like
 * @returns {boolean}
 */
export function looksWorkingFromSnap(snap) {
  if (!snap) return false;
  if (snap.busyHint) return true;
  if (typeof snap.turns === 'number' && snap.turns > 0) return true;
  if (typeof snap.toolCalls === 'number' && snap.toolCalls > 0) return true;
  return false;
}

function screenText(snap) {
  return `${snap?.preview || ''}\n${snap?.tailTail || snap?.tail || snap?.text || ''}`;
}

/**
 * True when the snapshot looks like a real agent TUI, not a shell.
 * @param {object|null} snapshot
 * @returns {{ ok: boolean, reason?: string }}
 */
export function looksLikeAgentTui(snapshot) {
  const title = String(snapshot?.title || snapshot?.name || '').trim();
  const screen = screenText(snapshot);
  const working =
    snapshot?.looksWorking === true || looksWorkingFromSnap(snapshot);

  const wrapperTitle = /orca-omp-as-worker/i.test(title);
  const knownAgent = KNOWN_AGENT_TITLE.test(title) && !wrapperTitle;

  if (title && SHELL_TITLE.test(title) && !knownAgent) {
    return { ok: false, reason: 'shell_title' };
  }
  if ((WRAPPER_SEED.test(screen) || wrapperTitle) && !knownAgent && !working) {
    return { ok: false, reason: 'wrapper_seed_only' };
  }
  if (COMMAND_NOT_FOUND_CONTRACT.test(screen) && CONTRACT_TOKENS.test(screen)) {
    return { ok: false, reason: 'command_not_found' };
  }
  if (!working && !knownAgent) {
    return { ok: false, reason: 'not_agent' };
  }
  return { ok: true };
}

function filesModifiedOf(msg) {
  const payload = msg?.payload && typeof msg.payload === 'object' ? msg.payload : {};
  const raw =
    msg?.filesModified ||
    msg?.files_modified ||
    payload.filesModified ||
    payload.files_modified ||
    null;
  if (!Array.isArray(raw)) return null;
  return raw.map(String);
}

function sameFiles(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  return a.every((x, i) => x === b[i]);
}

/**
 * True when a worker_done still matches the contract template (or is empty).
 * @param {object|null} msg
 */
export function isTemplateWorkerDone(msg) {
  if (!msg || typeof msg !== 'object') return false;
  const subject = String(msg.subject || msg.title || '');
  const body = String(msg.body || msg.text || msg.content || '');
  const files = filesModifiedOf(msg);

  if (/<\s*short status\s*>/i.test(subject)) return true;
  if (/3-sentence summary/i.test(body)) return true;
  if (/<[^>\n]{1,80}>/.test(body)) return true;
  if (DUMMY_FILES.some((dummy) => sameFiles(files, dummy))) return true;

  const trimmed = body.trim();
  if (!trimmed) return true;
  if (/^(TODO|TBD|\.\.\.|…|n\/a|none)$/i.test(trimmed)) return true;
  return false;
}

export const TEMPLATE_WORKER_DONE = 'template_worker_done';
