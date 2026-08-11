#!/usr/bin/env node
/**
 * Generate / check coordinator-discipline doc regions from
 * lib/coordinator-doctrine.mjs.
 *
 *   node scripts/docs.mjs build   — write COORDINATOR.md + README.md regions
 *   node scripts/docs.mjs check   — exit 1 if committed docs drift from doctrine
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  applyGeneratedRegion,
  renderCoordinatorMarkdown,
  renderReadmeOrchestrationMarkdown,
} from '../lib/coordinator-doctrine.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const COORD_PATH = path.join(ROOT, 'COORDINATOR.md');
const README_PATH = path.join(ROOT, 'README.md');

function buildTargets() {
  const coordSrc = fs.existsSync(COORD_PATH) ? fs.readFileSync(COORD_PATH, 'utf8') : '';
  const readmeSrc = fs.readFileSync(README_PATH, 'utf8');

  const coordNext = applyGeneratedRegion(coordSrc, renderCoordinatorMarkdown(), {
    wholeFileIfMissing: true,
  });
  const readmeNext = applyGeneratedRegion(readmeSrc, renderReadmeOrchestrationMarkdown(), {
    wholeFileIfMissing: false,
  });

  return [
    { path: COORD_PATH, next: coordNext, label: 'COORDINATOR.md' },
    { path: README_PATH, next: readmeNext, label: 'README.md' },
  ];
}

function cmdBuild() {
  for (const t of buildTargets()) {
    fs.writeFileSync(t.path, t.next.endsWith('\n') ? t.next : `${t.next}\n`, 'utf8');
    console.log(`wrote ${t.label}`);
  }
}

function cmdCheck() {
  let drift = false;
  for (const t of buildTargets()) {
    const cur = fs.readFileSync(t.path, 'utf8');
    if (cur !== (t.next.endsWith('\n') ? t.next : `${t.next}\n`) && cur !== t.next) {
      // normalize trailing newline only
      const a = cur.replace(/\s+$/, '') + '\n';
      const b = t.next.replace(/\s+$/, '') + '\n';
      if (a !== b) {
        console.error(`docs drift: ${t.label} differs from lib/coordinator-doctrine.mjs`);
        drift = true;
      }
    }
  }
  if (drift) {
    console.error('Run: npm run docs:build');
    process.exit(1);
  }
  console.log('docs check ok');
}

const cmd = process.argv[2] || 'check';
if (cmd === 'build') cmdBuild();
else if (cmd === 'check') cmdCheck();
else {
  console.error(`usage: node scripts/docs.mjs build|check`);
  process.exit(2);
}
