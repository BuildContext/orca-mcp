#!/usr/bin/env node
/**
 * orca-bridge store-signer daemon (NAS-249 / NAS-253).
 *
 * Runs under a dedicated uid (see deploy/linux/orca-bridge-store-signer.service).
 * Holds the HMAC key and serves sign/verify on a unix socket that only the
 * bridge service group can open.
 *
 * Env:
 *   ORCA_BRIDGE_STORE_SIGNER_SOCKET  — listen path (default /run/orca-bridge/store-signer.sock)
 *   ORCA_BRIDGE_STORE_SIGNER_KEY_FILE — key file path (default /var/lib/orca-bridge-signer/hmac.key)
 *   ORCA_BRIDGE_STORE_SIGNER_KEY     — hex/raw key (test only; prefer key file in prod)
 *
 * Never print the key. Never accept connections' peer identity beyond what the
 * filesystem socket mode already enforces.
 */

import fs from 'node:fs';
import path from 'node:path';
import {
  DEFAULT_STORE_SIGNER_SOCKET,
  createSignerDaemon,
  generateSignerKeyHex,
  parseSignerKey,
} from '../lib/store-signer.mjs';

const socketPath = (process.env.ORCA_BRIDGE_STORE_SIGNER_SOCKET || '').trim()
  || DEFAULT_STORE_SIGNER_SOCKET;
const keyFile = (process.env.ORCA_BRIDGE_STORE_SIGNER_KEY_FILE || '').trim()
  || '/var/lib/orca-bridge-signer/hmac.key';

function loadOrCreateKey() {
  const envKey = (process.env.ORCA_BRIDGE_STORE_SIGNER_KEY || '').trim();
  if (envKey) {
    return parseSignerKey(envKey);
  }
  try {
    if (fs.existsSync(keyFile)) {
      const raw = fs.readFileSync(keyFile, 'utf8').trim();
      return parseSignerKey(raw);
    }
  } catch (e) {
    console.error(`store-signer: cannot read key file: ${e.message}`);
    process.exit(1);
  }
  // First boot: create key file 0600. Directory must already be owned by this uid.
  try {
    fs.mkdirSync(path.dirname(keyFile), { recursive: true, mode: 0o700 });
    const hex = generateSignerKeyHex();
    fs.writeFileSync(keyFile, `${hex}\n`, { mode: 0o600 });
    console.error(`store-signer: created new key file at ${keyFile}`);
    return parseSignerKey(hex);
  } catch (e) {
    console.error(`store-signer: cannot create key file: ${e.message}`);
    process.exit(1);
  }
}

const key = loadOrCreateKey();
const seqPath = (process.env.ORCA_BRIDGE_STORE_SIGNER_SEQ || '').trim()
  || path.join(path.dirname(keyFile), 'store-seq.json');
const { server } = createSignerDaemon({ key, socketPath, seqPath });

server.on('listening', () => {
  try {
    // Defense in depth if systemd socket activation is not used:
    // owner = this uid, group leave default, mode 0660 so only same-group peers connect.
    fs.chmodSync(socketPath, 0o660);
  } catch {
    // systemd-managed sockets may not allow chmod; unit file sets SocketMode=.
  }
  console.error(`store-signer: listening on ${socketPath}`);
});

server.on('error', (e) => {
  console.error(`store-signer: ${e.message}`);
  process.exit(1);
});

function shutdown(signal) {
  console.error(`store-signer: ${signal}, exiting`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
