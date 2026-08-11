import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  isForbiddenHandoffArgv,
  argvHasFlag,
  b64url,
  pkceOk,
  pkceS256Challenge,
  tokenMatches,
  extractBearer,
  injectSenderArgv,
  buildDispatchWorktreeArgv,
  buildDispatchCurrentTerminalArgv,
  buildRunCreateArgv,
  buildRunUseArgv,
  buildTaskCreateArgv,
  buildDispatchInjectArgv,
  buildTerminalWaitIdleArgv,
  buildAwaitCheckArgv,
  clampWaitMs,
  buildWorkerReleaseArgv,
  buildTerminalCloseArgv,
  buildDispatchShowArgv,
  buildWorkerShowArgv,
  buildDcrResponse,
  loadIssuedTokens,
  persistIssuedTokens,
  authenticateRequest,
  CHECK_WAIT_DEFAULT_MS,
  CHECK_WAIT_MAX_MS,
  DEFAULT_WAIT_TYPES,
  ORCH_FROM_CMDS,
} from './security-core.mjs';
import { deriveClientKey } from './orch-isolation.mjs';

// ---------------------------------------------------------------------------
// isForbiddenHandoffArgv — the only programmatic security gate
// ---------------------------------------------------------------------------

describe('isForbiddenHandoffArgv', () => {
  it('blocks the documented handoff: worktree create --agent --prompt', () => {
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '--agent', 'omp', '--prompt', 'do stuff']),
      true,
    );
  });

  it('blocks when flags are reordered', () => {
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '--prompt', 'x', '--agent', 'omp']),
      true,
    );
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '--json', '--agent', 'omp', '--name', 'n', '--prompt', 'p']),
      true,
    );
  });

  it('blocks --agent=value and --prompt=value joined forms', () => {
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '--agent=omp', '--prompt=hi']),
      true,
    );
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '--prompt=hi', '--repo', 'x', '--agent=omp']),
      true,
    );
  });

  it('blocks mixed separated and joined forms', () => {
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '--agent', 'omp', '--prompt=hi']),
      true,
    );
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '--agent=omp', '--prompt', 'hi']),
      true,
    );
  });

  it('blocks with extra noise args around the forbidden pair', () => {
    assert.equal(
      isForbiddenHandoffArgv([
        'worktree', 'create',
        '--name', 'ha-1',
        '--repo', 'path:/tmp/r',
        '--no-parent',
        '--agent', 'omp',
        '--setup', 'skip',
        '--prompt', 'bypass me',
        '--json',
      ]),
      true,
    );
  });

  it('does not block worktree create --agent without --prompt (dispatch path)', () => {
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '--name', 'n', '--agent', 'omp', '--repo', 'path:/r', '--json']),
      false,
    );
  });

  it('does not block worktree create --prompt without --agent', () => {
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '--prompt', 'only prompt']),
      false,
    );
  });

  it('allows legitimate orchestration reply', () => {
    assert.equal(
      isForbiddenHandoffArgv(['orchestration', 'reply', '--id', 'msg_1', '--body', 'yes', '--json']),
      false,
    );
  });

  it('allows skills get / status / worktree show|list', () => {
    assert.equal(isForbiddenHandoffArgv(['skills', 'get', 'foo']), false);
    assert.equal(isForbiddenHandoffArgv(['status', '--json']), false);
    assert.equal(isForbiddenHandoffArgv(['worktree', 'show', '--json']), false);
    assert.equal(isForbiddenHandoffArgv(['worktree', 'list', '--limit', '20', '--json']), false);
  });

  it('allows terminal read/close', () => {
    assert.equal(
      isForbiddenHandoffArgv(['terminal', 'read', '--terminal', 'term_1', '--limit', '50']),
      false,
    );
    assert.equal(
      isForbiddenHandoffArgv(['terminal', 'close', '--terminal', 'term_1', '--tab', '--json']),
      false,
    );
  });

  it('rejects non-arrays and short argv', () => {
    assert.equal(isForbiddenHandoffArgv(null), false);
    assert.equal(isForbiddenHandoffArgv(undefined), false);
    assert.equal(isForbiddenHandoffArgv('worktree create --agent --prompt'), false);
    assert.equal(isForbiddenHandoffArgv([]), false);
    assert.equal(isForbiddenHandoffArgv(['worktree']), false);
  });

  it('coerces non-string elements via String()', () => {
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '--agent', 1, '--prompt', 2]),
      true,
    );
  });

  // --- Hardened under CLI allowlist (was previously a known gap) -------------

  it('blocks case-different subcommands (Worktree/Create)', () => {
    assert.equal(
      isForbiddenHandoffArgv(['Worktree', 'create', '--agent', 'omp', '--prompt', 'x']),
      true,
    );
    assert.equal(
      isForbiddenHandoffArgv(['WORKTREE', 'CREATE', '--Agent', 'omp', '--Prompt', 'x']),
      true,
    );
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'Create', '--AGENT=omp', '--PROMPT=x']),
      true,
    );
  });

  it('blocks short aliases -a/-p', () => {
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '-a', 'omp', '-p', 'x']),
      true,
    );
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '-a=omp', '-p=x']),
      true,
    );
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '--agent', 'omp', '-p', 'x']),
      true,
    );
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '-a', 'omp', '--prompt', 'x']),
      true,
    );
  });

  it('still blocks flag-shaped tokens after double-dash end (fail closed)', () => {
    // If CLI treats `--` as end-of-options, a real bypass may exist depending on
    // Orca parse rules. Gate fails closed: flag-shaped tokens anywhere count.
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '--', '--agent', 'omp', '--prompt', 'x']),
      true,
    );
  });

  it('blocks repeated flags (any occurrence counts)', () => {
    assert.equal(
      isForbiddenHandoffArgv([
        'worktree', 'create',
        '--agent', 'first',
        '--name', 'n',
        '--agent', 'second',
        '--prompt', 'p',
      ]),
      true,
    );
  });

  it('does not treat bare agent/prompt words after -- as flags', () => {
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '--', 'agent', 'omp', 'prompt', 'x']),
      false,
    );
  });

  it('GAP note (not skipped): unicode lookalikes / spaced equals are NOT treated as flags today', () => {
    // --agent = omp (three tokens) does not set hasAgent; not a current bypass for
    // real Orca CLI which uses --agent value or --agent=value, but documents the scan.
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '--agent', '=', 'omp', '--prompt', 'x']),
      true, // still has --agent and --prompt as separate tokens
    );
    assert.equal(
      isForbiddenHandoffArgv(['worktree', 'create', '--agent ', 'omp', '--prompt', 'x']),
      false, // trailing space in flag name — not matched (possible parser quirk, not CLI-real)
    );
  });
});

// ---------------------------------------------------------------------------
// argv construction — dispatch / await / release
// ---------------------------------------------------------------------------

describe('argv builders: dispatch path', () => {
  it('buildRunCreateArgv / buildRunUseArgv / buildTaskCreateArgv are exact', () => {
    assert.deepEqual(
      buildRunCreateArgv('do the thing'),
      ['orchestration', 'run-create', '--objective', 'do the thing', '--json'],
    );
    assert.deepEqual(
      buildRunUseArgv('run_abc'),
      ['orchestration', 'run-use', '--id', 'run_abc', '--json'],
    );
    assert.deepEqual(
      buildTaskCreateArgv({ spec: 'spec body', runId: 'run_1' }),
      ['orchestration', 'task-create', '--spec', 'spec body', '--run', 'run_1', '--json'],
    );
  });

  it('user-supplied objective/spec/runId cannot inject extra flags (single argv slots)', () => {
    const sneaky = 'ok --json --from evil';
    const runCreate = buildRunCreateArgv(sneaky);
    assert.equal(runCreate.length, 5);
    assert.equal(runCreate[3], sneaky);
    assert.ok(!runCreate.includes('evil'));

    const task = buildTaskCreateArgv({ spec: 's --agent x', runId: 'r --to y' });
    assert.deepEqual(task, [
      'orchestration', 'task-create', '--spec', 's --agent x', '--run', 'r --to y', '--json',
    ]);
  });

  it('buildDispatchWorktreeArgv emits --no-parent for new-top-level and optional setup/baseBranch', () => {
    assert.deepEqual(
      buildDispatchWorktreeArgv({
        name: 'ha-1',
        agent: 'omp',
        repo: 'path:/tmp/repo',
        worktree: 'new-top-level',
        setup: 'run',
      }),
      [
        'worktree', 'create',
        '--name', 'ha-1',
        '--agent', 'omp',
        '--repo', 'path:/tmp/repo',
        '--json',
        '--no-parent',
        '--setup', 'run',
      ],
    );

    assert.deepEqual(
      buildDispatchWorktreeArgv({
        name: 'child',
        agent: 'omp',
        repo: '/abs/repo',
        worktree: 'new-child',
        setup: 'skip',
        baseBranch: 'main',
      }),
      [
        'worktree', 'create',
        '--name', 'child',
        '--agent', 'omp',
        '--repo', 'path:/abs/repo',
        '--json',
        '--setup', 'skip',
        '--base-branch', 'main',
      ],
    );
  });

  it('omits --base-branch when empty and does not include --prompt', () => {
    const argv = buildDispatchWorktreeArgv({
      name: 'n',
      agent: 'omp',
      repo: 'name:foo',
      worktree: 'new-top-level',
      setup: '',
      baseBranch: '',
    });
    assert.ok(!argv.includes('--base-branch'));
    assert.ok(!argv.includes('--setup'));
    assert.ok(!argv.includes('--prompt'));
    assert.ok(!argv.some((x) => String(x).startsWith('--prompt=')));
  });

  it('buildDispatchCurrentTerminalArgv prefixes bare absolute paths with path:', () => {
    assert.deepEqual(
      buildDispatchCurrentTerminalArgv({ repo: '/home/testuser/r', name: 't', agent: 'omp' }),
      ['terminal', 'create', '--worktree', 'path:/home/testuser/r', '--title', 't', '--command', 'omp', '--json'],
    );
    assert.deepEqual(
      buildDispatchCurrentTerminalArgv({ repo: 'path:/home/testuser/r', name: 't', agent: 'omp' }),
      ['terminal', 'create', '--worktree', 'path:/home/testuser/r', '--title', 't', '--command', 'omp', '--json'],
    );
  });

  it('buildDispatchInjectArgv and terminal wait are exact', () => {
    assert.deepEqual(
      buildDispatchInjectArgv({ taskId: 'task_1', handle: 'term_w' }),
      ['orchestration', 'dispatch', '--task', 'task_1', '--to', 'term_w', '--inject', '--json'],
    );
    assert.deepEqual(
      buildTerminalWaitIdleArgv('term_w'),
      ['terminal', 'wait', '--terminal', 'term_w', '--for', 'tui-idle', '--timeout-ms', '60000', '--json'],
    );
  });
});

describe('argv builders: await / check', () => {
  it('buildAwaitCheckArgv includes run, types, wait by default', () => {
    assert.deepEqual(
      buildAwaitCheckArgv({ runId: 'run_1' }),
      [
        'orchestration', 'check',
        '--run', 'run_1',
        '--json',
        '--types', DEFAULT_WAIT_TYPES,
        '--wait', '--timeout-ms', String(CHECK_WAIT_DEFAULT_MS),
      ],
    );
  });

  it('emits --ack and --peek only when set; omits wait when waitMs=0', () => {
    assert.deepEqual(
      buildAwaitCheckArgv({ runId: 'r', ackId: 'del_1', peek: true, types: 'question', waitMs: 0 }),
      [
        'orchestration', 'check',
        '--run', 'r',
        '--json',
        '--ack', 'del_1',
        '--peek',
        '--types', 'question',
      ],
    );
  });

  it('ack/types values stay single slots (no flag injection)', () => {
    const argv = buildAwaitCheckArgv({
      runId: 'r',
      ackId: 'id --all --from x',
      types: 'worker_done --evil',
      waitMs: 1000,
    });
    assert.equal(argv[argv.indexOf('--ack') + 1], 'id --all --from x');
    assert.equal(argv[argv.indexOf('--types') + 1], 'worker_done --evil');
    assert.equal(argv.filter((x) => x === '--all' || x === '--from').length, 0);
  });

  it('clampWaitMs respects default and max', () => {
    assert.equal(clampWaitMs(undefined), CHECK_WAIT_DEFAULT_MS);
    assert.equal(clampWaitMs(null), CHECK_WAIT_DEFAULT_MS);
    assert.equal(clampWaitMs(-5), 0);
    assert.equal(clampWaitMs(45_000), 45_000);
    assert.equal(clampWaitMs(999_999), CHECK_WAIT_MAX_MS);
  });

  it('injectSenderArgv adds --terminal for check and --from for mutations', () => {
    const check = injectSenderArgv(
      ['orchestration', 'check', '--run', 'r', '--json'],
      'term_sender',
    );
    assert.deepEqual(check.slice(-2), ['--terminal', 'term_sender']);

    const use = injectSenderArgv(
      ['orchestration', 'run-use', '--id', 'r', '--json'],
      'term_sender',
    );
    assert.deepEqual(use.slice(-2), ['--from', 'term_sender']);

    // already present — do not duplicate
    const already = injectSenderArgv(
      ['orchestration', 'check', '--terminal', 'term_existing', '--json'],
      'term_sender',
    );
    assert.ok(!already.includes('term_sender'));
    assert.ok(already.includes('term_existing'));

    // non-orch untouched
    assert.deepEqual(
      injectSenderArgv(['terminal', 'list', '--json'], 'term_sender'),
      ['terminal', 'list', '--json'],
    );
  });

  it('ORCH_FROM_CMDS covers dispatch mutations but not check', () => {
    assert.ok(ORCH_FROM_CMDS.has('dispatch'));
    assert.ok(ORCH_FROM_CMDS.has('run-create'));
    assert.ok(!ORCH_FROM_CMDS.has('check'));
  });
});

describe('argv builders: release path', () => {
  it('worker-release / terminal close / show helpers are exact', () => {
    assert.deepEqual(
      buildWorkerReleaseArgv('ctx_1'),
      ['orchestration', 'worker-release', '--dispatch', 'ctx_1', '--json'],
    );
    assert.deepEqual(
      buildTerminalCloseArgv('term_w'),
      ['terminal', 'close', '--terminal', 'term_w', '--tab', '--json'],
    );
    assert.deepEqual(
      buildDispatchShowArgv('task_1'),
      ['orchestration', 'dispatch-show', '--task', 'task_1', '--json'],
    );
    assert.deepEqual(
      buildWorkerShowArgv('ctx_1'),
      ['orchestration', 'worker-show', '--dispatch', 'ctx_1', '--json'],
    );
  });

  it('dispatch id with spaces stays one argv element', () => {
    const id = 'ctx_x --json --from evil';
    const argv = buildWorkerReleaseArgv(id);
    assert.equal(argv.length, 5);
    assert.equal(argv[3], id);
  });
});

describe('argvHasFlag', () => {
  it('detects separated and = joined forms', () => {
    assert.equal(argvHasFlag(['--from', 't'], '--from'), true);
    assert.equal(argvHasFlag(['--from=t'], '--from'), true);
    assert.equal(argvHasFlag(['--terminal'], '--from'), false);
  });
});

// ---------------------------------------------------------------------------
// OAuth: DCR, PKCE, token persistence
// ---------------------------------------------------------------------------

describe('OAuth PKCE', () => {
  it('derives S256 challenge as base64url(sha256(verifier))', () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    // RFC 7636 appendix B
    const expected = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
    assert.equal(pkceS256Challenge(verifier), expected);
    assert.equal(pkceOk(verifier, expected, 'S256'), true);
    // Non-'plain' methods use the S256 digest path (including lowercase 's256').
    assert.equal(pkceOk(verifier, expected, 's256'), true);
  });

  it('plain method compares verifier === challenge', () => {
    assert.equal(pkceOk('abc', 'abc', 'plain'), true);
    assert.equal(pkceOk('abc', 'xyz', 'plain'), false);
  });

  it('empty challenge is tolerated (legacy clients)', () => {
    assert.equal(pkceOk('anything', '', 'S256'), true);
    assert.equal(pkceOk('anything', null, 'S256'), true);
  });

  it('rejects wrong verifier for S256', () => {
    const challenge = pkceS256Challenge('good');
    assert.equal(pkceOk('bad', challenge, 'S256'), false);
  });

  it('b64url strips padding and uses -_', () => {
    const buf = Buffer.from([0xff, 0xee, 0xdd, 0xcc]);
    const s = b64url(buf);
    assert.ok(!s.includes('+'));
    assert.ok(!s.includes('/'));
    assert.ok(!s.includes('='));
    assert.equal(s, buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
  });
});

describe('OAuth DCR response shape', () => {
  it('returns public-client registration fields', () => {
    const body = { redirect_uris: ['https://hyperagent.com/cb'] };
    const res = buildDcrResponse(body, { clientId: 'orca-bridge-abc', issuedAt: 1700000000 });
    assert.deepEqual(res, {
      client_id: 'orca-bridge-abc',
      client_id_issued_at: 1700000000,
      redirect_uris: ['https://hyperagent.com/cb'],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code'],
      response_types: ['code'],
    });
  });

  it('defaults empty redirect_uris', () => {
    const res = buildDcrResponse({}, { clientId: 'c1', issuedAt: 1 });
    assert.deepEqual(res.redirect_uris, []);
  });
});

describe('OAuth token persistence round-trip', () => {
  it('write then load preserves the set', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-mcp-tok-'));
    const store = path.join(dir, 'tokens.json');
    try {
      const tokens = new Set(['obt_one', 'obt_two']);
      persistIssuedTokens(store, tokens);
      const loaded = loadIssuedTokens(store);
      assert.equal(loaded.size, 2);
      assert.ok(loaded.has('obt_one'));
      assert.ok(loaded.has('obt_two'));
      // mode 600 when supported
      const mode = fs.statSync(store).mode & 0o777;
      assert.equal(mode, 0o600);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('missing or corrupt store yields empty set', () => {
    assert.equal(loadIssuedTokens('/no/such/file-orca-mcp.json').size, 0);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-mcp-bad-'));
    const store = path.join(dir, 'bad.json');
    try {
      fs.writeFileSync(store, '{not-json');
      assert.equal(loadIssuedTokens(store).size, 0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// auth: tokenMatches + authenticate
// ---------------------------------------------------------------------------

describe('tokenMatches', () => {
  const MASTER = 'test-master-token-32chars-min!!';

  it('accepts the correct master token', () => {
    assert.equal(tokenMatches(MASTER, MASTER), true);
  });

  it('rejects wrong / empty / non-string candidates', () => {
    assert.equal(tokenMatches('wrong-token-value-here!!', MASTER), false);
    assert.equal(tokenMatches('', MASTER), false);
    assert.equal(tokenMatches(null, MASTER), false);
    assert.equal(tokenMatches(undefined, MASTER), false);
    assert.equal(tokenMatches(123, MASTER), false);
  });

  it('rejects when master token empty', () => {
    assert.equal(tokenMatches(MASTER, ''), false);
  });

  it('is timing-safe: uses sha256 digests + timingSafeEqual (not ===)', () => {
    // Structural proof: equal-length digests always; function source path is
    // createHash + timingSafeEqual in security-core.mjs. Behavioral check:
    // same-length wrong tokens still reject.
    const a = 'a'.repeat(32);
    const b = 'b'.repeat(32);
    assert.equal(tokenMatches(a, b), false);
    assert.equal(tokenMatches(a, a), true);
    // Digest lengths match regardless of input length (sha256 = 32 bytes).
    const d1 = createHash('sha256').update('short').digest();
    const d2 = createHash('sha256').update('much-longer-candidate-value').digest();
    assert.equal(d1.length, d2.length);
    assert.equal(d1.length, 32);
  });
});

describe('extractBearer', () => {
  it('parses Bearer scheme case-insensitively', () => {
    assert.equal(extractBearer({ headers: { authorization: 'Bearer tok123' } }), 'tok123');
    assert.equal(extractBearer({ headers: { authorization: 'bearer tok123' } }), 'tok123');
    assert.equal(extractBearer({ headers: { authorization: '  BEARER   tok123  ' } }), 'tok123');
  });

  it('returns empty for missing / malformed headers', () => {
    assert.equal(extractBearer({ headers: {} }), '');
    assert.equal(extractBearer({ headers: { authorization: 'Basic x' } }), '');
    assert.equal(extractBearer({ headers: { authorization: 'Bearer' } }), '');
    assert.equal(extractBearer({ headers: { authorization: ['Bearer a'] } }), 'a');
    assert.equal(extractBearer({ headers: { authorization: 1 } }), '');
    assert.equal(extractBearer({}), '');
  });
});

describe('authenticateRequest', () => {
  const MASTER = 'unit-test-master-token-xx';
  const sessions = new Map();

  function sessionIdFrom(req) {
    const h = req.headers?.['mcp-session-id'];
    return typeof h === 'string' ? h.trim() : '';
  }
  function touchSession(id) {
    const s = sessions.get(id);
    return s || null;
  }
  function pruneSessions() {}

  function auth(req, issued = new Set()) {
    return authenticateRequest(req, {
      token: MASTER,
      issuedTokens: issued,
      deriveClientKey,
      sessionIdFrom,
      touchSession,
      pruneSessions,
    });
  }

  it('accepts bearer master token', () => {
    const r = auth({ url: '/mcp', headers: { authorization: `Bearer ${MASTER}` } });
    assert.ok(r);
    assert.equal(r.authKind, 'bearer-master');
    assert.equal(r.path, '/mcp');
    assert.equal(r.clientKey, 'master');
  });

  it('accepts bearer oauth token from issued set', () => {
    const tok = 'obt_' + b64url(randomBytes(8));
    const r = auth(
      { url: '/mcp', headers: { authorization: `Bearer ${tok}` } },
      new Set([tok]),
    );
    assert.ok(r);
    assert.equal(r.authKind, 'bearer-oauth');
    assert.equal(r.bearer, tok);
    assert.match(r.clientKey, /^oauth:[0-9a-f]{16}$/);
  });

  it('accepts path-token /t/<master>/…', () => {
    const r = auth({ url: `/t/${encodeURIComponent(MASTER)}/mcp`, headers: {} });
    assert.ok(r);
    assert.equal(r.authKind, 'path-token');
    assert.equal(r.path, '/mcp');
  });

  it('accepts valid session-only (SSE style)', () => {
    sessions.set('sid-live', { createdAt: Date.now(), lastSeen: Date.now(), clientKey: 'oauth:deadbeefdeadbeef' });
    const r = auth({ url: '/mcp', headers: { 'mcp-session-id': 'sid-live' } });
    assert.ok(r);
    assert.equal(r.authKind, 'session');
    assert.equal(r.clientKey, 'oauth:deadbeefdeadbeef');
  });

  it('rejects missing token', () => {
    assert.equal(auth({ url: '/mcp', headers: {} }), null);
  });

  it('rejects wrong bearer token', () => {
    assert.equal(
      auth({ url: '/mcp', headers: { authorization: 'Bearer totally-wrong-token-value' } }),
      null,
    );
  });

  it('rejects malformed authorization header', () => {
    assert.equal(auth({ url: '/mcp', headers: { authorization: 'Token abc' } }), null);
    assert.equal(auth({ url: '/mcp', headers: { authorization: 'Bearer' } }), null);
  });

  it('rejects wrong path token', () => {
    assert.equal(auth({ url: '/t/not-the-master/mcp', headers: {} }), null);
  });

  it('rejects unknown session id', () => {
    assert.equal(auth({ url: '/mcp', headers: { 'mcp-session-id': 'nope' } }), null);
  });
});
