#!/usr/bin/env node
/**
 * Zero-dep lint: parse every tracked .mjs file with node --check.
 * Intentionally narrow — no style rules, no reformat of server.mjs.
 */
import { execFileSync } from 'node:child_process';
import { readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.git') continue;
    const p = path.join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (name.endsWith('.mjs')) out.push(p);
  }
  return out;
}

const files = walk(root).sort();
let failed = 0;
for (const file of files) {
  const rel = path.relative(root, file);
  try {
    execFileSync(process.execPath, ['--check', file], { stdio: ['ignore', 'pipe', 'pipe'] });
    console.log(`ok  ${rel}`);
  } catch (e) {
    failed += 1;
    const err = (e.stderr || e.stdout || Buffer.from(String(e.message))).toString();
    console.error(`FAIL ${rel}`);
    console.error(err.trim());
  }
}

if (failed) {
  console.error(`\nlint: ${failed}/${files.length} file(s) failed syntax check`);
  process.exit(1);
}
console.log(`\nlint: ${files.length} file(s) ok`);
