# NAS-249 / NAS-253 — separate-uid store signer

**Branch:** `BuildContext/nas-249-253-ownership-signer`  
**Code SHA:** `95cfec3a9a9e25e709467cb3430672e56d7f36ef` (signer implementation)
**Docs tip:** this file is committed on the same branch after the code SHA; branch HEAD is the tip containing both code and this report.  
**Parent (pre-fix):** `5ab2488aa69230bdeafc9f1671b8ea4ccaa3a9f0`

## What shipped

| Piece | Path |
| --- | --- |
| HMAC + NDJSON socket client/daemon lib | `lib/store-signer.mjs` |
| Daemon entrypoint | `scripts/store-signer-daemon.mjs` |
| systemd unit (signer uid) | `deploy/linux/orca-bridge-store-signer.service` |
| Bridge unit joins signer group + socket env | `deploy/linux/orca-bridge.service` |
| Bridge load/persist wired to sign+verify | `server.mjs` |
| Forge-rejection tests (one per store) | `lib/store-signer.test.mjs` |

Algorithm: **HMAC-SHA256** (one-shot `createHmac` per call). Envelope:

```json
{ "v": 1, "alg": "hmac-sha256", "payload": <store>, "sig": "<base64url>" }
```

Stores signed on write, verified on read:

- `~/.orca-bridge-sender-pins.json` (NAS-253)
- `~/.orca-bridge/dispatch-ownership.json` (NAS-249)

Unsigned / malformed / foreign-key → **rejected** (zero hydrate), never warn-and-accept.  
Nothing is keyed on `runtimeId` — bindings survive bridge and runtime restarts.

## How the socket is closed off from the worker uid

1. **Dedicated uid** `orca-bridge-signer` runs the daemon and owns the key file  
   (`StateDirectory=orca-bridge-signer` mode `0700`, key `0600`).
2. **Socket path** `/run/orca-bridge/store-signer.sock` lives in  
   `RuntimeDirectory=orca-bridge` mode **`0750`**, group `orca-bridge-signer`.
3. **Socket mode `0660`**, owner = signer uid, group = `orca-bridge-signer`  
   (`ExecStartPost=chmod 0660` + `chgrp orca-bridge-signer`).
4. **Bridge unit only:** `SupplementaryGroups=orca-bridge-signer` so the bridge  
   process can open the socket. **Worker uids are not members of that group**,  
   so `connect(2)` fails with `EACCES` even if a worker knows the path.
5. Key never leaves the signer uid; workers under the bridge uid can rewrite  
   the JSON files but cannot produce a valid MAC.

Deploy of the unit on the live host is **out of scope** for this wave (code + unit only).

## Tests

### Parent sha must fail (mandatory evidence)

```text
PARENT_SHA=5ab2488aa69230bdeafc9f1671b8ea4ccaa3a9f0
```

1. New test file against parent tree (module absent):

```text
$ git archive HEAD | tar -x   # parent tree
$ cp <branch>/lib/store-signer.test.mjs lib/
$ node --test lib/store-signer.test.mjs
Error [ERR_MODULE_NOT_FOUND]: Cannot find module '.../lib/store-signer.mjs'
# tests 1
# pass 0
# fail 1
```

2. Behavioral: parent load path accepts forged unsigned JSON:

```text
parent_accepted_forged_pins= [{"clientKey":"oauth:attacker","handle":"term_stolen"}]
parent_accepted_forged_ownership= [{"dispatchId":"ctx_victim","clientKey":"oauth:attacker",...}]
PROOF: parent trusts unsigned stores (forgeries accepted).
```

### Post-fix suite

```text
$ npm test
# tests 457
# pass 457
# fail 0
```

Baseline was 441; +16 from `lib/store-signer.test.mjs` (includes one forge test per store).

## Env

| Variable | Role |
| --- | --- |
| `ORCA_BRIDGE_STORE_SIGNER_SOCKET` | Production: path to signer unix socket |
| `ORCA_BRIDGE_STORE_SIGNER_KEY` | Tests / isolated HOME only — in-process HMAC |
| `ORCA_BRIDGE_STORE_SIGNER_KEY_FILE` | Daemon key path (default under StateDirectory) |

Live contour was not touched (no bridge restart, no live `~/.orca-bridge*`).
