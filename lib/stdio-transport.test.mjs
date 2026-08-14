/**
 * stdio transport smoke tests.
 * Boots server.mjs --stdio, drives initialize + tools/list over NDJSON,
 * and asserts stdout is protocol-clean (no non-JSON-RPC lines).
 *
 * Runner: node --test (same harness as orch-isolation.test.mjs).
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.resolve(__dirname, '../server.mjs');
const TOKEN = 'stdio-test-token-0123456789abcdef'; // ≥16 chars
const PROTOCOL = '2025-11-25';

/**
 * Spawn orca-mcp --stdio and exchange NDJSON JSON-RPC messages.
 * Collects every stdout line; fails the test if any line is not parseable JSON-RPC.
 */
function startStdioClient(envExtra = {}) {
  const child = spawn(process.execPath, [SERVER, '--stdio'], {
    env: {
      ...process.env,
      ORCA_BRIDGE_TOKEN: TOKEN,
      // Mute access-log noise on stderr; keep protocol path real.
      ORCA_BRIDGE_DEBUG: '0',
      // Isolated in-process signer for tests (never production).
      ORCA_BRIDGE_STORE_SIGNER_KEY:
        envExtra.ORCA_BRIDGE_STORE_SIGNER_KEY ||
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      ...envExtra,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const stdoutLines = [];
  const stderrChunks = [];
  const pending = new Map(); // id -> { resolve, reject, timer }
  let nextId = 1;
  let closed = false;

  const rlOut = createInterface({ input: child.stdout, crlfDelay: Infinity });
  rlOut.on('line', (line) => {
    stdoutLines.push(line);
    let msg;
    try {
      msg = JSON.parse(line);
    } catch (e) {
      // Surface non-protocol stdout immediately — this is the classic stdio break.
      for (const [, p] of pending) {
        clearTimeout(p.timer);
        p.reject(new Error(`non-protocol stdout line: ${JSON.stringify(line)} (${e.message})`));
      }
      pending.clear();
      return;
    }
    if (msg && typeof msg === 'object' && msg.id != null && pending.has(msg.id)) {
      const p = pending.get(msg.id);
      pending.delete(msg.id);
      clearTimeout(p.timer);
      p.resolve(msg);
    }
  });

  child.stderr.on('data', (c) => stderrChunks.push(c));

  const exitPromise = new Promise((resolve) => {
    child.on('exit', (code, signal) => {
      closed = true;
      resolve({ code, signal });
    });
  });

  function request(method, params, { timeoutMs = 5_000 } = {}) {
    if (closed) return Promise.reject(new Error('child already exited'));
    const id = nextId++;
    const msg = { jsonrpc: '2.0', id, method, params };
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`timeout waiting for response to ${method} id=${id}`));
      }, timeoutMs);
      pending.set(id, { resolve, reject, timer });
      child.stdin.write(JSON.stringify(msg) + '\n');
    });
  }

  function notify(method, params = {}) {
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
  }

  async function close() {
    try {
      child.stdin.end();
    } catch { /* ignore */ }
    // Hard kill if graceful exit stalls (should not — stdin EOF triggers shutdown).
    const killer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* ignore */ }
    }, 3_000);
    const result = await exitPromise;
    clearTimeout(killer);
    rlOut.close();
    return result;
  }

  return {
    request,
    notify,
    close,
    stdoutLines,
    stderrText: () => Buffer.concat(stderrChunks).toString('utf8'),
    child,
  };
}

describe('stdio transport', () => {
  it('initialize + tools/list over NDJSON; stdout is protocol-clean', async () => {
    const client = startStdioClient();
    try {
      const init = await client.request('initialize', {
        protocolVersion: PROTOCOL,
        capabilities: {},
        clientInfo: { name: 'orca-mcp-stdio-test', version: '0.0.0' },
      });

      assert.equal(init.jsonrpc, '2.0');
      assert.ok(init.result, 'initialize must return result');
      assert.equal(init.error, undefined);
      assert.equal(init.result.protocolVersion, PROTOCOL);
      assert.equal(init.result.serverInfo?.name, 'orca-bridge');
      assert.ok(init.result.serverInfo?.version, 'serverInfo.version present');
      assert.ok(init.result.capabilities?.tools, 'tools capability present');

      // notifications/initialized → no response on the wire
      client.notify('notifications/initialized', {});

      const listed = await client.request('tools/list', {});
      assert.equal(listed.jsonrpc, '2.0');
      assert.ok(listed.result?.tools, 'tools/list returns tools');
      assert.ok(Array.isArray(listed.result.tools));
      assert.equal(listed.result.tools.length, 1);
      assert.equal(listed.result.tools[0].name, 'orca');

      const actions = listed.result.tools[0].inputSchema?.properties?.action;
      // Schema documents the supervised action surface; string match is enough.
      const actionBlob = JSON.stringify(actions || listed.result.tools[0]);
      for (const a of ['health', 'dispatch', 'await', 'release', 'guide', 'check', 'cli']) {
        assert.match(actionBlob, new RegExp(a), `tool schema mentions action ${a}`);
      }
    } finally {
      const { code } = await client.close();
      // Exit 0 on clean stdin EOF.
      assert.equal(code, 0, `stdio server exit code (stderr tail: ${client.stderrText().slice(-400)})`);
    }

    // Every stdout line must be valid JSON-RPC (object with jsonrpc: "2.0").
    assert.ok(client.stdoutLines.length >= 2, 'at least initialize + tools/list responses');
    for (const line of client.stdoutLines) {
      assert.doesNotMatch(line, /\n/, 'no embedded raw newlines in a framed line');
      const msg = JSON.parse(line);
      assert.equal(msg.jsonrpc, '2.0');
      assert.ok(
        Object.prototype.hasOwnProperty.call(msg, 'result')
          || Object.prototype.hasOwnProperty.call(msg, 'error')
          || typeof msg.method === 'string',
        `line is a JSON-RPC message: ${line.slice(0, 120)}`,
      );
    }

    // Startup banner must not leak to stdout — it goes to stderr via log().
    const stderr = client.stderrText();
    assert.match(stderr, /stdio mode/, 'startup log on stderr');
    assert.doesNotMatch(
      client.stdoutLines.join('\n'),
      /listening on|stdio mode|orca binary/,
      'no banner text on stdout',
    );
  });

  it('rejects missing ORCA_BRIDGE_TOKEN before speaking on stdout', async () => {
    const child = spawn(process.execPath, [SERVER, '--stdio'], {
      env: { ...process.env, ORCA_BRIDGE_TOKEN: '' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    const code = await new Promise((resolve) => child.on('exit', resolve));
    assert.notEqual(code, 0);
    assert.equal(stdout, '', 'FATAL path must not write to stdout');
    assert.match(stderr, /ORCA_BRIDGE_TOKEN/);
  });

  it('HTTP mode still binds without --stdio (default transport)', async () => {
    // Pick an ephemeral free port via PORT=0 is not supported by server (Number),
    // so use a high random port and skip if bind fails.
    const port = 19000 + Math.floor(Math.random() * 1000);
    const child = spawn(process.execPath, [SERVER, '--port', String(port)], {
      env: {
        ...process.env,
        ORCA_BRIDGE_TOKEN: TOKEN,
        ORCA_BRIDGE_DEBUG: '0',
        PORT: String(port),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });

    // Wait for listen banner (HTTP mode logs to stdout).
    const ready = await new Promise((resolve) => {
      const t = setTimeout(() => resolve(false), 4_000);
      const onData = () => {
        if (/listening on 127\.0\.0\.1:/.test(stdout)) {
          clearTimeout(t);
          resolve(true);
        }
      };
      child.stdout.on('data', onData);
      child.on('exit', () => {
        clearTimeout(t);
        resolve(false);
      });
    });

    try {
      assert.ok(ready, `HTTP server did not listen (stdout=${stdout} stderr=${stderr})`);
      const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TOKEN}`,
          accept: 'application/json',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: PROTOCOL,
            capabilities: {},
            clientInfo: { name: 'http-smoke', version: '0.0.0' },
          },
        }),
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.result?.protocolVersion, PROTOCOL);
      assert.equal(body.result?.serverInfo?.name, 'orca-bridge');

      const listRes = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TOKEN}`,
          accept: 'application/json',
          'mcp-session-id': res.headers.get('mcp-session-id') || '',
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
      });
      const listBody = await listRes.json();
      assert.equal(listBody.result?.tools?.[0]?.name, 'orca');
    } finally {
      child.kill('SIGTERM');
      await new Promise((r) => child.on('exit', r));
    }
  });
});
