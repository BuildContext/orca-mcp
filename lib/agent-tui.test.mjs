import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { looksLikeAgentTui, isTemplateWorkerDone } from './agent-tui.mjs';

describe('looksLikeAgentTui', () => {
  it('accepts a known agent title even when idle', () => {
    const r = looksLikeAgentTui({ title: 'Grok', preview: 'Turns: 0', turns: 0, toolCalls: 0 });
    assert.equal(r.ok, true);
  });

  it('accepts omp / Claude / Codex titles', () => {
    assert.equal(looksLikeAgentTui({ title: 'omp', busyHint: true }).ok, true);
    assert.equal(looksLikeAgentTui({ title: 'Claude', turns: 1 }).ok, true);
    assert.equal(looksLikeAgentTui({ title: 'Codex', toolCalls: 2 }).ok, true);
  });

  it('rejects a shell title', () => {
    assert.equal(looksLikeAgentTui({ title: 'bash', preview: '$ ' }).ok, false);
    assert.equal(looksLikeAgentTui({ title: 'zsh', preview: '% ' }).ok, false);
    assert.equal(looksLikeAgentTui({ title: 'sh' }).reason, 'shell_title');
  });

  it('rejects command-not-found for === / worker_done', () => {
    const r = looksLikeAgentTui({
      title: 'bash',
      preview: 'bash: ===: command not found\nbash: worker_done: command not found',
    });
    assert.equal(r.ok, false);
  });

  it('rejects wrapper seed-only screen that is not an agent', () => {
    const r = looksLikeAgentTui({
      title: 'orca-omp-as-worker.sh omp',
      preview: 'orca-omp-as-worker: capability pointer present for task task_1\n',
      turns: 0,
    });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'wrapper_seed_only');
  });

  it('rejects idle unknown title', () => {
    const r = looksLikeAgentTui({ title: 'term', preview: '', turns: 0 });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'not_agent');
  });
});

describe('isTemplateWorkerDone', () => {
  it('hits the live template subject/body/filesModified', () => {
    assert.equal(
      isTemplateWorkerDone({
        subject: '<short status>',
        body: '<3-sentence summary: what you did, what you found, what\'s left>',
        payload: { outcome: 'succeeded', filesModified: ['path/a', 'path/b'] },
      }),
      true,
    );
  });

  it('hits dummy filesModified even with a real subject', () => {
    assert.equal(
      isTemplateWorkerDone({
        subject: 'done',
        body: 'I really did the work and found nothing left.',
        filesModified: ['path/a', 'path/b'],
      }),
      true,
    );
  });

  it('hits empty or placeholder body even when outcome succeeded', () => {
    assert.equal(
      isTemplateWorkerDone({ subject: 'ok', body: '', payload: { outcome: 'succeeded' } }),
      true,
    );
    assert.equal(
      isTemplateWorkerDone({ subject: 'ok', body: 'TODO', payload: { outcome: 'succeeded' } }),
      true,
    );
  });

  it('accepts a real worker_done', () => {
    assert.equal(
      isTemplateWorkerDone({
        subject: 'isolation harden landed',
        body: 'Wrote gitdir guard and per-tree ACL. Tests pass. Ready to tag.',
        payload: { outcome: 'succeeded', filesModified: ['lib/gitdir-guard.mjs'] },
      }),
      false,
    );
  });
});
