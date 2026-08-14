#!/usr/bin/env node
/**
 * Operator one-shot: sign legacy unsigned ownership stores (pre-0.3.2).
 *
 *   node scripts/migrate-store-signatures.mjs [--dry-run] [--home DIR]
 *
 * Requires a reachable store signer:
 *   ORCA_BRIDGE_STORE_SIGNER_SOCKET  (production)
 *   ORCA_BRIDGE_STORE_SIGNER_KEY     (tests / isolated HOME only)
 *
 * Run as the BRIDGE uid, with the bridge STOPPED, AFTER the signer unit is up.
 * Does NOT weaken runtime load — unsigned remains rejected until this runs.
 *
 * C5: already-signed envelopes with bad/foreign signatures are refused (no
 * overwrite). Bare unsigned JSON is signed as-is — residual trust requires
 * bridge stopped (no concurrent attacker write race).
 */

import os from 'node:os';
import {
  resolveStoreSigner,
  DEFAULT_STORE_SIGNER_SOCKET,
} from '../lib/store-signer.mjs';
import {
  migrateUnsignedStores,
  resolveMigrateStorePaths,
} from '../lib/store-signature-migrate.mjs';

function printUsage(stream = console.error) {
  stream(
    [
      'Usage: node scripts/migrate-store-signatures.mjs [options]',
      '',
      'Sign legacy unsigned ownership stores so 0.3.2 load accepts them.',
      'Runtime still rejects unsigned — this is an explicit operator step.',
      '',
      'Options:',
      '  --dry-run          Report what would be signed; write nothing',
      '  --home <dir>       Override HOME (default: process HOME / os.homedir())',
      '  --audit-dir <dir>  Override ownership store dir (default: $ORCA_BRIDGE_AUDIT_DIR or <home>/.orca-bridge)',
      '  -h, --help         Show this help',
      '',
      'Env:',
      '  ORCA_BRIDGE_STORE_SIGNER_SOCKET  unix socket (required in production)',
      '  ORCA_BRIDGE_STORE_SIGNER_KEY     in-process key (tests only)',
      '  ORCA_BRIDGE_AUDIT_DIR            ownership store directory',
      '',
      'Exit codes:',
      '  0  success (including pure no-ops: missing/empty/already-signed)',
      '  1  signer unreachable, bad-signature refuse, or write/sign failure',
      '  2  usage error',
    ].join('\n'),
  );
}

function parseArgs(argv) {
  /** @type {{ dryRun: boolean, home?: string, auditDir?: string, help: boolean }} */
  const out = { dryRun: false, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--dry-run') {
      out.dryRun = true;
    } else if (a === '--home') {
      const v = argv[++i];
      if (!v || v.startsWith('-')) {
        throw new Error('--home requires a directory argument');
      }
      out.home = v;
    } else if (a === '--audit-dir') {
      const v = argv[++i];
      if (!v || v.startsWith('-')) {
        throw new Error('--audit-dir requires a directory argument');
      }
      out.auditDir = v;
    } else if (a === '-h' || a === '--help') {
      out.help = true;
    } else {
      throw new Error(`unknown argument: ${a}`);
    }
  }
  return out;
}

function formatFileLine(name, file) {
  const bits = [`${name}: ${file.action}`];
  if (file.path) bits.push(`path=${file.path}`);
  if (file.backupPath) bits.push(`backup=${file.backupPath}`);
  if (file.legacyUnsignedTrust) bits.push('legacy-unsigned-trust=true');
  if (file.reason) bits.push(`reason=${file.reason}`);
  if (file.error) bits.push(`error=${file.error}`);
  return bits.join('  ');
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error(`migrate-store-signatures: ${e.message}`);
    printUsage();
    process.exit(2);
  }

  if (args.help) {
    printUsage(console.log);
    process.exit(0);
  }

  const home = args.home || process.env.HOME || os.homedir();
  const auditDir = args.auditDir
    || (process.env.ORCA_BRIDGE_AUDIT_DIR || '').trim()
    || undefined;

  const signer = resolveStoreSigner(process.env);
  if (!signer) {
    const sockHint = process.env.ORCA_BRIDGE_STORE_SIGNER_SOCKET
      || DEFAULT_STORE_SIGNER_SOCKET;
    console.error(
      'migrate-store-signatures: refusing to run — no store signer configured.\n' +
        `  Set ORCA_BRIDGE_STORE_SIGNER_SOCKET (e.g. ${sockHint}) and ensure the\n` +
        '  orca-bridge-store-signer unit is running, or ORCA_BRIDGE_STORE_SIGNER_KEY\n' +
        '  for isolated-HOME tests only. Never silently no-op.',
    );
    process.exit(1);
  }

  const paths = resolveMigrateStorePaths({ home, auditDir });
  console.error(
    `migrate-store-signatures: home=${paths.home}` +
      (args.dryRun ? '  mode=dry-run' : '  mode=apply'),
  );
  console.error(`  pins:       ${paths.pinsPath}`);
  console.error(`  ownership:  ${paths.ownershipPath}`);
  if (signer.kind === 'socket') {
    console.error(`  signer:     socket ${signer.socketPath}`);
  } else {
    console.error(`  signer:     ${signer.kind || 'local'}`);
  }

  const result = await migrateUnsignedStores({
    home: paths.home,
    auditDir: paths.auditDir,
    signer,
    dryRun: args.dryRun,
  });

  console.log(formatFileLine('pins', result.files.pins));
  console.log(formatFileLine('ownership', result.files.ownership));

  if (!result.ok) {
    console.error(
      `migrate-store-signatures: FAILED — ${result.error || result.reason || 'see file actions above'}`,
    );
    if (result.reason === 'signer-unavailable' || /signer|unreachable|ECONNREFUSED|ENOENT|timeout/i.test(String(result.error || ''))) {
      console.error(
        '  Signer socket is not reachable. Start orca-bridge-store-signer.service first.\n' +
          '  Refusing to migrate (no silent no-op).',
      );
    }
    process.exit(1);
  }

  if (args.dryRun) {
    console.error('migrate-store-signatures: dry-run complete (no files written)');
  } else {
    console.error('migrate-store-signatures: ok');
  }
  process.exit(0);
}

main().catch((e) => {
  console.error(`migrate-store-signatures: ${e && e.stack ? e.stack : e}`);
  process.exit(1);
});
