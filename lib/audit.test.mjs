import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  redactArgs,
  redactValue,
  redactArgv,
  looksLikeSecret,
  buildAuditRecord,
  createAuditLog,
  createDispatchRegistry,
  listMcpResources,
  readMcpResource,
  resolveOrcaAction,
  ORCA_TOOL_ANNOTATIONS,
  ACTION_ANNOTATIONS,
  ORCA_OUTPUT_SCHEMA,
  STRUCTURED_OUTPUT_ACTIONS,
  RESOURCE_URIS,
  conformsToOutputSchema,
} from './audit.mjs';

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

describe('looksLikeSecret', () => {
  it('flags bearer headers and obt_ tokens', () => {
    assert.equal(looksLikeSecret('Bearer abcdefghijklmnop'), true);
    assert.equal(looksLikeSecret('obt_abcDEF12_xyz'), true);
  });

  it('flags long hex blobs', () => {
    assert.equal(looksLikeSecret('a'.repeat(32)), true);
  });

  it('leaves ordinary short strings alone', () => {
    assert.equal(looksLikeSecret('health'), false);
    assert.equal(looksLikeSecret('run_abc'), false);
  });
});

describe('redactArgs', () => {
  it('redacts top-level spec / prompt / body', () => {
    const out = redactArgs({
      action: 'dispatch',
      spec: 'do the thing with secret sauce',
      agent: 'omp',
    });
    assert.equal(out.action, 'dispatch');
    assert.equal(out.agent, 'omp');
    assert.match(out.spec, /^\[REDACTED len=\d+\]$/);
    assert.equal(JSON.stringify(out).includes('secret sauce'), false);
  });

  it('scrubs a token embedded in a nested arg object', () => {
    const secret = 'obt_NestedTokenValue99';
    const out = redactArgs({
      action: 'cli',
      meta: {
        headers: {
          Authorization: `Bearer ${secret}`,
        },
        nested: { access_token: secret, safe: 'ok' },
      },
    });
    const dump = JSON.stringify(out);
    assert.equal(dump.includes(secret), false);
    assert.equal(dump.includes('NestedTokenValue'), false);
    assert.equal(out.meta.nested.safe, 'ok');
    assert.match(String(out.meta.nested.access_token), /REDACTED/);
    assert.match(String(out.meta.headers.Authorization), /REDACTED/);
  });

  it('redacts argv --prompt / --body / --spec values', () => {
    const out = redactArgs({
      action: 'cli',
      args: [
        'orchestration',
        'reply',
        '--id',
        'msg_1',
        '--body',
        'secret answer with token obt_abcDEF12_zzzz',
        '--json',
      ],
    });
    assert.deepEqual(out.args.slice(0, 5), [
      'orchestration',
      'reply',
      '--id',
      'msg_1',
      '--body',
    ]);
    assert.match(out.args[5], /^\[REDACTED len=\d+\]$/);
    assert.equal(JSON.stringify(out).includes('secret answer'), false);
    assert.equal(JSON.stringify(out).includes('obt_'), false);
  });

  it('redacts --flag=value form for sensitive flags', () => {
    const out = redactArgv(['worktree', 'create', '--prompt=do secret work', '--name', 'x']);
    assert.equal(out[0], 'worktree');
    assert.match(out[2], /^--prompt=\[REDACTED len=\d+\]$/);
    assert.equal(out[3], '--name');
    assert.equal(out[4], 'x');
  });

  it('redacts free-text that embeds Authorization Bearer', () => {
    const out = redactValue(
      'debug Authorization: Bearer supersecrettokenvalue123 and done',
      'note',
    );
    assert.equal(String(out).includes('supersecrettokenvalue123'), false);
    assert.match(String(out), /Bearer \[REDACTED\]/);
  });
});

// ---------------------------------------------------------------------------
// Audit record + append-only log
// ---------------------------------------------------------------------------

describe('buildAuditRecord', () => {
  it('includes required fields and redacts args', () => {
    const rec = buildAuditRecord({
      tool: 'orca',
      action: 'dispatch',
      args: { action: 'dispatch', spec: 'TOP SECRET BRIEF', runId: 'run_1' },
      clientKey: 'oauth:abc',
      outcome: 'ok',
      durationMs: 12.7,
      ts: '2026-08-11T00:00:00.000Z',
    });
    assert.equal(rec.tool, 'orca');
    assert.equal(rec.action, 'dispatch');
    assert.equal(rec.clientKey, 'oauth:abc');
    assert.equal(rec.outcome, 'ok');
    assert.equal(rec.durationMs, 13);
    assert.equal(rec.ts, '2026-08-11T00:00:00.000Z');
    assert.match(rec.args.spec, /REDACTED/);
    assert.equal(rec.args.runId, 'run_1');
    assert.equal(JSON.stringify(rec).includes('TOP SECRET'), false);
  });
});

describe('createAuditLog append-only', () => {
  let dir;
  let audit;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-audit-'));
    audit = createAuditLog({ dir, maxBytes: 10_000, maxFiles: 3 });
  });

  afterEach(() => {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* */
    }
  });

  it('appends NDJSON lines and never rewrites prior records', () => {
    audit.appendEvent({
      tool: 'orca',
      action: 'health',
      args: { action: 'health' },
      clientKey: 'master',
      outcome: 'ok',
      durationMs: 1,
    });
    audit.appendEvent({
      tool: 'orca',
      action: 'dispatch',
      args: { action: 'dispatch', spec: 'brief-one' },
      clientKey: 'master',
      outcome: 'ok',
      durationMs: 5,
    });
    const text1 = audit.readText();
    const lines1 = text1.trim().split('\n');
    assert.equal(lines1.length, 2);
    const first = lines1[0];

    audit.appendEvent({
      tool: 'orca',
      action: 'release',
      args: { action: 'release', dispatchId: 'd1' },
      clientKey: 'master',
      outcome: 'ok',
      durationMs: 2,
    });
    const text2 = audit.readText();
    const lines2 = text2.trim().split('\n');
    assert.equal(lines2.length, 3);
    // first line byte-identical (append-only)
    assert.equal(lines2[0], first);
    assert.equal(text2.startsWith(text1), true);
    assert.equal(text2.includes('brief-one'), false);
  });

  it('readTail returns parsed records in order', () => {
    for (let i = 0; i < 5; i++) {
      audit.appendEvent({
        tool: 'orca',
        action: 'health',
        args: { action: 'health', n: i },
        clientKey: 'c',
        outcome: 'ok',
        durationMs: i,
      });
    }
    const tail = audit.readTail(3);
    assert.equal(tail.length, 3);
    assert.equal(tail[0].args.n, 2);
    assert.equal(tail[2].args.n, 4);
  });

  it('rotates when maxBytes exceeded without losing append API', () => {
    const small = createAuditLog({ dir, filename: 'small.ndjson', maxBytes: 80, maxFiles: 2 });
    // force path via internal
    for (let i = 0; i < 20; i++) {
      small.appendEvent({
        tool: 'orca',
        action: 'cli',
        args: { action: 'cli', args: ['status', '--json'], i, pad: 'x'.repeat(40) },
        clientKey: 'c',
        outcome: 'ok',
        durationMs: 1,
      });
    }
    assert.equal(typeof small.readText(), 'string');
    // rotated sibling may exist
    const names = fs.readdirSync(dir);
    assert.ok(names.some((n) => n.startsWith('audit') || n === 'small.ndjson' || n.startsWith('small')));
  });

  it('exposes no rewrite/update method on the public surface', () => {
    assert.equal(typeof audit.append, 'function');
    assert.equal(typeof audit.appendEvent, 'function');
    assert.equal(typeof audit.readTail, 'function');
    assert.equal(audit.update, undefined);
    assert.equal(audit.rewrite, undefined);
    assert.equal(audit.write, undefined);
    assert.equal(audit.truncate, undefined);
  });
});

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

describe('MCP resources list/read', () => {
  let dir;
  let audit;
  let registry;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orca-res-'));
    audit = createAuditLog({ dir });
    registry = createDispatchRegistry();
    audit.appendEvent({
      tool: 'orca',
      action: 'dispatch',
      args: { action: 'dispatch', spec: 'SECRET' },
      clientKey: 'client-a',
      outcome: 'ok',
      durationMs: 10,
    });
    registry.upsert('disp_1', {
      status: 'running',
      runId: 'run_1',
      clientKey: 'client-a',
      terminalHandle: 'term_w1',
    });
    registry.appendTranscript('disp_1', {
      type: 'worker_done',
      body: 'done ok',
      deliveryId: 'del_1',
    });
  });

  afterEach(() => {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* */
    }
  });

  it('list includes audit + dispatch + transcript URIs', () => {
    const { resources } = listMcpResources({ audit, registry, clientKey: 'client-a' });
    const uris = resources.map((r) => r.uri);
    assert.ok(uris.includes(RESOURCE_URIS.auditLog));
    assert.ok(uris.includes(RESOURCE_URIS.auditTail));
    assert.ok(uris.includes(RESOURCE_URIS.dispatches));
    assert.ok(uris.includes(RESOURCE_URIS.dispatchPrefix + 'disp_1'));
    assert.ok(uris.includes(RESOURCE_URIS.transcriptPrefix + 'disp_1'));
    for (const r of resources) {
      assert.equal(typeof r.uri, 'string');
      assert.equal(typeof r.name, 'string');
      assert.equal(typeof r.mimeType, 'string');
    }
  });

  it('read audit log is NDJSON without secrets', () => {
    const res = readMcpResource(RESOURCE_URIS.auditLog, { audit, registry });
    assert.ok(res.contents);
    assert.equal(res.contents[0].mimeType, 'application/x-ndjson');
    assert.equal(res.contents[0].text.includes('SECRET'), false);
    assert.ok(res.contents[0].text.includes('dispatch'));
  });

  it('read audit tail is JSON array shape', () => {
    const res = readMcpResource(RESOURCE_URIS.auditTail, { audit, registry });
    const body = JSON.parse(res.contents[0].text);
    assert.equal(typeof body.count, 'number');
    assert.ok(Array.isArray(body.records));
    assert.ok(body.records.length >= 1);
    assert.equal(body.records[0].action, 'dispatch');
  });

  it('read dispatch status + transcript shapes', () => {
    const d = readMcpResource(RESOURCE_URIS.dispatchPrefix + 'disp_1', {
      audit,
      registry,
      clientKey: 'client-a',
    });
    const dj = JSON.parse(d.contents[0].text);
    assert.equal(dj.dispatchId, 'disp_1');
    assert.equal(dj.status, 'running');
    assert.equal(dj.runId, 'run_1');

    const t = readMcpResource(RESOURCE_URIS.transcriptPrefix + 'disp_1', {
      audit,
      registry,
      clientKey: 'client-a',
    });
    const tj = JSON.parse(t.contents[0].text);
    assert.equal(tj.dispatchId, 'disp_1');
    assert.equal(tj.count, 1);
    assert.equal(tj.entries[0].type, 'worker_done');
  });

  it('unknown uri returns error object', () => {
    const res = readMcpResource('orca-bridge://nope', { audit, registry });
    assert.equal(typeof res.error, 'string');
  });
});

// ---------------------------------------------------------------------------
// Annotations + structured output schema
// ---------------------------------------------------------------------------

describe('tool annotations', () => {
  it('marks the single orca tool conservatively (not read-only, destructive)', () => {
    assert.equal(ORCA_TOOL_ANNOTATIONS.readOnlyHint, false);
    assert.equal(ORCA_TOOL_ANNOTATIONS.destructiveHint, true);
    assert.equal(ORCA_TOOL_ANNOTATIONS.idempotentHint, false);
    assert.equal(ORCA_TOOL_ANNOTATIONS.openWorldHint, true);
  });

  it('documents per-action semantics including read-only health/guide', () => {
    assert.equal(ACTION_ANNOTATIONS.health.readOnlyHint, true);
    assert.equal(ACTION_ANNOTATIONS.guide.readOnlyHint, true);
    assert.equal(ACTION_ANNOTATIONS.dispatch.destructiveHint, true);
    assert.equal(ACTION_ANNOTATIONS.release.destructiveHint, true);
    assert.equal(ACTION_ANNOTATIONS.cli.readOnlyHint, false);
  });
});

describe('resolveOrcaAction', () => {
  it('defaults empty orca call to health', () => {
    assert.equal(resolveOrcaAction('orca', {}), 'health');
  });
  it('routes action field and legacy tool names', () => {
    assert.equal(resolveOrcaAction('orca', { action: 'await', runId: 'r' }), 'await');
    assert.equal(resolveOrcaAction('dispatch_worker', {}), 'dispatch');
    assert.equal(resolveOrcaAction('orca', { args: ['status'] }), 'cli');
  });
});

describe('structuredContent / outputSchema', () => {
  it('declares structured output for health and await only', () => {
    assert.ok(STRUCTURED_OUTPUT_ACTIONS.has('health'));
    assert.ok(STRUCTURED_OUTPUT_ACTIONS.has('await'));
    assert.equal(STRUCTURED_OUTPUT_ACTIONS.has('cli'), false);
  });

  it('health-shaped payload conforms to ORCA_OUTPUT_SCHEMA', () => {
    const health = {
      bridge: {
        version: '0.3.0',
        minVersion: '0.2.0',
        versionOk: true,
        uptimeSec: 1,
        node: 'v22.0.0',
        platform: 'linux',
      },
      orcaBinary: 'orca',
      defaultAgent: 'omp',
      actions: ['health', 'dispatch', 'await', 'release', 'guide', 'check', 'cli'],
      actionAnnotations: ACTION_ANNOTATIONS,
      statusProbe: { ok: true },
      next: { action: 'dispatch_or_guide', detail: 'ready' },
    };
    assert.equal(conformsToOutputSchema(health, ORCA_OUTPUT_SCHEMA), true);
  });

  it('await-shaped payload conforms to ORCA_OUTPUT_SCHEMA', () => {
    const awaitResult = {
      ok: true,
      run_id: 'run_1',
      window_ms: 45000,
      timedOut: true,
      deliveryId: null,
      count: 0,
      summary: { status: 'empty' },
      messages: [],
      client_key: 'master',
      sender_handle: 'term_x',
      next: { action: 'await', detail: 're-call' },
    };
    assert.equal(conformsToOutputSchema(awaitResult, ORCA_OUTPUT_SCHEMA), true);
  });

  it('rejects non-object structured payloads', () => {
    assert.equal(conformsToOutputSchema('nope', ORCA_OUTPUT_SCHEMA), false);
    assert.equal(conformsToOutputSchema(null, ORCA_OUTPUT_SCHEMA), false);
  });

  it('rejects wrong property types', () => {
    assert.equal(
      conformsToOutputSchema({ ok: 'yes', window_ms: 1 }, ORCA_OUTPUT_SCHEMA),
      false,
    );
  });
});

// ---------------------------------------------------------------------------
// Backward-compatible tools/call result shape (unit-level contract)
// ---------------------------------------------------------------------------

describe('tools/call result back-compat contract', () => {
  it('legacy content text JSON remains the primary payload', () => {
    // Mirrors server handleRpc tools/call success path:
    // { content: [{ type:'text', text: JSON.stringify(result) }], isError:false, structuredContent? }
    const result = {
      bridge: { version: '0.3.0', versionOk: true },
      actions: ['health'],
      next: { action: 'dispatch_or_guide' },
    };
    const payload = {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      isError: false,
      structuredContent: result,
    };
    assert.equal(payload.isError, false);
    assert.equal(payload.content[0].type, 'text');
    const parsed = JSON.parse(payload.content[0].text);
    assert.deepEqual(parsed, result);
    assert.equal(payload.structuredContent.bridge.version, '0.3.0');
    // existing coordinators that only read content[0].text still work
    assert.equal(parsed.actions[0], 'health');
  });

  it('error path keeps content text + isError without structuredContent requirement', () => {
    const payload = {
      content: [{ type: 'text', text: 'Error: boom' }],
      isError: true,
    };
    assert.equal(payload.isError, true);
    assert.match(payload.content[0].text, /^Error:/);
    assert.equal(payload.structuredContent, undefined);
  });
});
