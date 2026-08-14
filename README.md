# orca-mcp

**External MCP server for [Orca](https://github.com/stablyai/orca)** — control worktrees, agent sessions, and orchestration from any MCP client (Claude Desktop, Cursor, VS Code, Hyperagent, custom agents, …).

Orca today is driven by its CLI. This project is a small, zero-dependency Node.js bridge that:

1. Speaks **MCP** over **stdio** (local desktop hosts) or **Streamable HTTP** (remote / multi-tenant)
2. Spawns **only** the `orca` binary (`execFile`, no shell)
3. Exposes a supervised **dispatch → await → release** workflow for multi-agent orchestration
4. Optionally proxies a local **Hindsight** MCP next to Orca

> Community stopgap for [stablyai/orca#13079](https://github.com/stablyai/orca/issues/13079)  
> (*“Expose Orca as an MCP server for session and workspace control”*).  
> When Orca ships a first-party `orca mcp`, this bridge remains useful as a remote / multi-tenant edge with OAuth.

**Protocol target:** MCP **2025-11-25** (stdio NDJSON + Streamable HTTP).  
**Roadmap:** migrate HTTP mode toward **2026-07-28** stateless HTTP when clients catch up.


**Tested on**

| Host | Orca surface | Notes |
| --- | --- | --- |
| **macOS** | GUI app + CLI | Full worktrees, iOS Simulator, LaunchAgent install |
| **Linux** | CLI-only (`orca-ide` / headless Cockpit) | systemd unit, no GUI; orchestration sender auto-pinned |

---

## Security warning

**This server is not a sandbox and not a security boundary.**

`orca-mcp` runs **with your OS user privileges**. An authenticated caller can:

- spawn **coding agents** and supervised workers on your machine
- drive **Orca terminals** (including raw `terminal send` under default config)
- reach the **host filesystem and network** indirectly through those agents and the Orca CLI
- execute anything the bridge OS user (and your `orca` / `orca-ide` binary) can already do

Defaults (toolsets stay open for trusted coordinators; CLI surface is exact-form locked):

| Control | Default |
| --- | --- |
| Capability toolsets (`status` / `dispatch` / `admin`) | **all enabled** |
| `ORCA_BRIDGE_CLI_HARDENING` exact-form allowlist on `action=cli` | **on** (NAS-227); set `0`/`false`/`off` for warn-only |
| OS / FS / network sandbox | **none** |
| Per-caller authz beyond possessing the token/session | **none** |

Always-on guardrails are narrow: HTTP binds **`127.0.0.1` only**, spawn is **`execFile` of the Orca binary only** (no shell), unsupervised `worktree create --agent --prompt` via raw `cli` is rejected, master-token compare is timing-safe, and the audit log redacts common secrets. That is **not** equivalent to “safe for untrusted users.”

### Shared or untrusted deployments — restrict toolsets

```bash
# Supervised coordinators only — drop raw admin CLI (terminal send, worktree rm, …):
export ORCA_BRIDGE_TOOLSETS=status,dispatch
# CLI exact-form allowlist is ON by default (NAS-227). Explicit off only for migration:
# export ORCA_BRIDGE_CLI_HARDENING=0

# Read-only observer (health / inventory / check):
node server.mjs --port 8787 --read-only
```

Also: put a long random `ORCA_BRIDGE_TOKEN` in a mode-`600` env file (never in git); prefer **OAuth** on HTTP so the master token is not stored in remote MCP client settings; use a **separate OAuth client per coordinator**; never hand the master path-token URL to someone you would not give a shell.

**Do not expose this bridge to callers you do not trust.** Full threat model, assets, and non-goals: [`docs/threat-model.md`](./docs/threat-model.md). Vulnerability reporting: [`SECURITY.md`](./SECURITY.md).

---

## Why this exists

MCP clients cannot natively control Orca. Shelling out to the CLI works only when the agent already has a shell on the Orca host. Remote coordinators (cloud agents, Hyperagent, another laptop) need a network-facing MCP endpoint with auth. Local desktop hosts need a stdio subprocess they can launch themselves.

`orca-mcp` runs **next to** Orca on the host:

```text
  Local host (Claude Desktop / Cursor / VS Code)
       │  stdio NDJSON (orca-mcp --stdio)
       ▼
  orca-mcp  ──execFile──►  orca CLI  ──►  Orca runtime

  Remote MCP client  ──HTTPS──►  Funnel / proxy  ──►  127.0.0.1:8787 (HTTP mode)
```


---

## Features

- **Two transports, one tool surface**
  - **stdio** (`orca-mcp --stdio`) — local hosts; env-based auth; stdout is JSON-RPC only
  - **Streamable HTTP** (default) — remote coordinators; OAuth + path-token; loopback bind
- **Single MCP tool `orca`** with `action`:
  - `health` — Orca reachability + bridge version
  - `dispatch` — create worktree / inject agent + auto `worker_done` contract
  - `await` — poll orchestration inbox (empty/timeout = re-call, not failure)
  - `release` — settle worker (safe against coordinator-sender close)
  - `guide` — coordinator discipline (also in [`COORDINATOR.md`](./COORDINATOR.md))
  - `check` / `cli` — lower-level inbox + raw CLI (with handoff guards)
- **Capability toolsets** (`status` / `dispatch` / `admin`) — opt-in restriction via env/flag; **default = all enabled**
- **OAuth 2.0 + PKCE** on HTTP (Dynamic Client Registration) so the master token never sits in the MCP client config
- **Path-token URLs** (`/t/<token>/mcp`) for curl / sandboxes
- **Per-OAuth-client sender isolation** — multiple coordinators on one bridge without fencing each other
- **Zero npm dependencies** — `node server.mjs` and done
- **Mac LaunchAgent** + **Linux systemd** deploy helpers under `deploy/`

Current bridge version: **0.3.0** (from `package.json`).

---

## Quick start

## Local install (stdio)

Desktop MCP hosts (Claude Desktop, Cursor, VS Code, Windsurf, Claude Code) launch the bridge as a **subprocess** and speak **newline-delimited JSON-RPC** on stdin/stdout. No browser OAuth — secrets come from the environment (MCP guidance for stdio servers).

**Published package:** pin the version with `npx -y orca-mcp@0.3.0`. Prefer the [container image](#container-ghcr) for long-lived or privileged hosts.

### Standard config (local checkout)

```json
{
  "mcpServers": {
    "orca": {
      "command": "node",
      "args": ["/absolute/path/to/orca-mcp/server.mjs", "--stdio"],
      "env": {
        "ORCA_BRIDGE_TOKEN": "<openssl rand -hex 32>",
        "ORCA_CLI_COMMAND": "orca"
      }
    }
  }
}
```

Clone first if needed:

```bash
git clone https://github.com/BuildContext/orca-mcp.git
# zero runtime dependencies — no npm install required to run
```

### Soon: npm package

After the first npm publish, the same host configs can switch to the registry package (pin the version; `@latest` is fine for throwaways only):

```json
{
  "mcpServers": {
    "orca": {
      "command": "npx",
      "args": ["-y", "orca-mcp@0.3.0", "--stdio"],
      "env": {
        "ORCA_BRIDGE_TOKEN": "<openssl rand -hex 32>",
        "ORCA_CLI_COMMAND": "orca"
      }
    }
  }
}
```

### Host matrix

<details>
<summary>Claude Desktop</summary>

Edit the desktop config and restart Claude Desktop:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Use the **Standard config (local checkout)** JSON above (`mcpServers.orca`).

</details>

<details>
<summary>Claude Code</summary>

```bash
# Local checkout (works today):
claude mcp add orca --env ORCA_BRIDGE_TOKEN=… -- node /absolute/path/to/orca-mcp/server.mjs --stdio

# After npm publish (pin the version):
claude mcp add orca --env ORCA_BRIDGE_TOKEN=… -- npx -y orca-mcp@0.3.0 --stdio
```

</details>

<details>
<summary>Cursor</summary>

**Cursor Settings → MCP → Add new MCP Server**, command type:

- Command: `node`
- Args: `/absolute/path/to/orca-mcp/server.mjs --stdio`
- Env: `ORCA_BRIDGE_TOKEN`, optional `ORCA_CLI_COMMAND`

Or merge the **Standard config (local checkout)** into Cursor’s MCP JSON. After npm publish you can switch to `npx` + `orca-mcp@0.3.0` as in the “Soon: npm package” example.

</details>

<details>
<summary>VS Code</summary>

```bash
# Local checkout (VS Code 1.102+ MCP support):
code --add-mcp '{"name":"orca","command":"node","args":["/absolute/path/to/orca-mcp/server.mjs","--stdio"],"env":{"ORCA_BRIDGE_TOKEN":"<token>"}}'

# After npm publish:
# code --add-mcp '{"name":"orca","command":"npx","args":["-y","orca-mcp@0.3.0","--stdio"],"env":{"ORCA_BRIDGE_TOKEN":"<token>"}}'
```

Or add the same object under `"mcp": { "servers": { … } }` in `.vscode/mcp.json` / user `settings.json` (see current VS Code MCP docs for the exact key — it has moved between preview builds).

</details>

<details>
<summary>Windsurf</summary>

Cascade → MCP servers → add a stdio server with the **Standard config** fields (`command` / `args` / `env`), or edit the Windsurf MCP config JSON equivalently.

</details>

### stdio auth (env only)

| Variable | Required | Purpose |
| --- | --- | --- |
| `ORCA_BRIDGE_TOKEN` | **yes** (≥16 chars) | Master token — proves the local host may drive the bridge (same secret HTTP mode uses) |
| `ORCA_CLI_COMMAND` | no | Override `orca` binary (Linux headless often `orca-ide`) |
| `ORCA_BRIDGE_DEFAULT_REPO` | no | Default `--repo` for `dispatch` |
| `ORCA_BRIDGE_DEFAULT_AGENT` | no | Default agent (default `omp`) |
| `ORCA_BRIDGE_SENDER_TERMINAL` / `ORCA_BRIDGE_FROM` | no | Pin orchestration sender handle |
| `ORCA_BRIDGE_SENDER_TITLE` | no | Title for auto-created coordinator tabs |
| `ORCA_BRIDGE_SENDER_SHARED` | no | `1` = single-tenant sender pin |
| `ORCA_BRIDGE_DEBUG` | no | `0` mutes access log (stderr in stdio mode) |
| `HINDSIGHT_URL` | no | Not used on the stdio path today (HTTP proxy only) |

**stdout is protocol-only.** All logs go to **stderr** in `--stdio` mode. Do not wrap the process with tools that print banners on stdout.

### stdio smoke

```bash
export ORCA_BRIDGE_TOKEN="$(openssl rand -hex 32)"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | node /absolute/path/to/orca-mcp/server.mjs --stdio
# Expect two JSON-RPC response lines on stdout (initialize + tools/list); banners on stderr only.
# After npm publish you can substitute: npx -y orca-mcp@0.3.0 --stdio
```

---

## Container (GHCR)

Docker's guidance for privileged MCP servers is **container over bare registry installs**. The published image runs as non-root UID 1001, bakes no secrets, and the same entrypoint supports HTTP and stdio.

```bash
# pin by semver
docker pull ghcr.io/buildcontext/orca-mcp:0.3.0

# stdio (local MCP host launches the container)
docker run --rm -i \
  -e ORCA_BRIDGE_TOKEN \
  -e ORCA_CLI_COMMAND=orca \
  ghcr.io/buildcontext/orca-mcp:0.3.0 --stdio

# HTTP on loopback (publish via Funnel / reverse proxy yourself)
docker run --rm \
  -e ORCA_BRIDGE_TOKEN \
  -e ORCA_BRIDGE_PUBLIC_ORIGIN=https://your-host.example.ts.net \
  -p 127.0.0.1:8787:8787 \
  ghcr.io/buildcontext/orca-mcp:0.3.0
```

After each release the image is also digest-pinned in the GitHub Release notes. Prefer the digest in production:

```bash
# example — replace with the digest from the release:
# docker pull ghcr.io/buildcontext/orca-mcp@sha256:<digest>
```

MCP Registry metadata lives in [`server.json`](./server.json) (`io.github.buildcontext/orca-mcp`).

---

## Remote install (Streamable HTTP)


### Prerequisites

- Node.js **≥ 18** (22 recommended)
- Orca installed and working on the same machine (`orca` or `orca-ide` on `PATH`)
- A secret master token (≥ 16 chars)

```bash
# From a git checkout (works today):
git clone https://github.com/BuildContext/orca-mcp.git
cd orca-mcp
export ORCA_BRIDGE_TOKEN="$(openssl rand -hex 32)"
echo "Save this token: $ORCA_BRIDGE_TOKEN"
export ORCA_BRIDGE_PUBLIC_ORIGIN="https://your-host.example.ts.net"   # optional; needed for OAuth URLs
node server.mjs --port 8787

# After npm publish (HTTP mode):
# npx -y orca-mcp@0.3.0 --port 8787
```

The server binds **127.0.0.1 only**. Publish it yourself:

```bash
# example: Tailscale Funnel
tailscale funnel --bg 8787
tailscale funnel status
```

### Register in an MCP client

**OAuth path (recommended)** — URL only, no token in settings:

```text
https://your-host.example.ts.net/mcp
```

The client discovers OAuth metadata, registers (DCR), opens a browser; you enter the master token once. Issued access tokens live in `~/.orca-bridge-tokens.json`.

**Direct path token** (debug / curl):

```text
https://your-host.example.ts.net/t/<ORCA_BRIDGE_TOKEN>/mcp
```

Hyperagent default redirect prefix is allowlisted (`https://hyperagent.com/`). For other clients set:

```bash
export ORCA_BRIDGE_REDIRECT_ALLOW="https://your-client.example/,https://hyperagent.com/"
```

### Smoke test

```bash
curl -sS -X POST "https://your-host.example.ts.net/t/$ORCA_BRIDGE_TOKEN/mcp" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"orca","arguments":{"action":"health"}}}'
```

Expect `statusProbe.ok: true` and a `bridge.version`.

---

<!-- BEGIN GENERATED: coordinator-discipline -->
## Supervised orchestration (for coordinators)

> **Generated** from `lib/coordinator-doctrine.mjs`. Edit the doctrine module, then run `npm run docs:build`.

Raw `worktree create --agent --prompt` is **rejected** (`forbidden_handoff`). Use the action API:

```text
dispatch → await(≤45s)×N [honor liveness] → worker_done → release(dispatchId, terminalHandle) → read-only
```

Runtime/version gates run **lazily** inside `dispatch` / `await` / `release` (self-diagnosing errors). `health` is optional compact diagnostics (`verbose:true` for the full dump).

| `await` summary.status | Meaning |
| --- | --- |
| empty / timeout (active\|idle) | Re-call `await` — normal early; watch `liveness` |
| empty + liveness=stalled | Stop-condition: peek → ping → release + report |
| question | Reply via `cli` → `orchestration reply`, then await + ack |
| escalation | Reply via `cli` → `orchestration reply` (dual-routes onto `dispatch:<id>`), then await + ack; prefer `ask` for back-and-forth |
| worker_done | `release` with `dispatchId` + worker `terminalHandle` |

Full discipline: tool description, `action=guide`, and [`COORDINATOR.md`](./COORDINATOR.md).

Example wave:

```jsonc
// 1. start work
{ "action": "dispatch", "spec": "…", "repo": "path:/path/to/repo", "agent": "omp" }

// 2. poll until worker_done (repeat; honor liveness on empty)
{ "action": "await", "runId": "<from dispatch>", "waitMs": 45000 }

// 3. cleanup
{ "action": "release", "dispatchId": "<…>", "terminalHandle": "<worker handle from dispatch>" }
```
<!-- END GENERATED: coordinator-discipline -->

---

## Environment

| Variable | Purpose |
| --- | --- |
| `ORCA_BRIDGE_TOKEN` | **Required** (both transports). Master token (≥16 chars) — stdio env auth; HTTP path-token + OAuth “password” |
| `ORCA_BRIDGE_PUBLIC_ORIGIN` | HTTP only. Public origin for OAuth URLs (Funnel / proxy host) |
| `ORCA_BRIDGE_REDIRECT_ALLOW` | HTTP only. Comma-separated allowed `redirect_uri` prefixes |
| `ORCA_CLI_COMMAND` | Override `orca` binary (Linux often `orca-ide`) |
| `ORCA_BRIDGE_DEFAULT_AGENT` | Default agent for `dispatch` (default `omp`) |
| `ORCA_BRIDGE_DEFAULT_REPO` | Default `--repo` (`path:…` / `name:…`) |
| `ORCA_BRIDGE_SENDER_TERMINAL` / `ORCA_BRIDGE_FROM` | Pin a live terminal as orchestration sender |
| `ORCA_BRIDGE_SENDER_TITLE` | Title for auto-created coordinator tabs |
| `ORCA_BRIDGE_SENDER_SHARED` | `1` = force all clients onto the env pin (disables multi-coordinator isolation) |
| `ORCA_BRIDGE_TOOLSETS` | Comma list of enabled tiers: `status`, `dispatch`, `admin` (default = **all three**) |
| `ORCA_BRIDGE_CLI_HARDENING` | Default **on** (exact-form allowlist). `0`/`false`/`off` = warn-only migration |
| `ORCA_BRIDGE_CLI_ADMIN` | `1` = union `admin` into enabled toolsets (compat with CLI allowlist admin; ignored under `--read-only`) |
| `ORCA_BRIDGE_DEBUG` | `0` mutes access log (stderr in `--stdio`, stdout in HTTP) |
| `HINDSIGHT_URL` | HTTP only. Optional Hindsight proxy target (default `http://127.0.0.1:8888`) |
| `PORT` / `--port` | HTTP only. Listen port (default `8787`) |
| `--read-only` | CLI flag equivalent to `ORCA_BRIDGE_TOOLSETS=status` (wins over the env var) |
| `--stdio` | CLI flag. Select stdio transport instead of Streamable HTTP |

State files (mode `600` where applicable) — all under the `HOME` of the account the
bridge runs as, and **all must be owned by that account** (see
[Linux deploy](#linux-cli-only--headless)):

- `~/.orca-bridge-tokens.json` — issued OAuth access tokens  
- `~/.orca-bridge-sender-pins.json` — durable per-client sender pins  
- `~/.orca-bridge/` (dir `700`) — audit log; override with `ORCA_BRIDGE_AUDIT_DIR`  

The bridge writes these ownership-preserving (a write performed as root keeps the file
with the account that owns the state) and logs a `WARN:` at boot for any state file it cannot read or write,
or that belongs to another account.

---

## Capability toolsets

The multiplexed `orca` tool is still one MCP name (no renames — agents keep working). Operators can restrict **which actions** an authenticated caller may invoke.

### Tiers

| Tier | Actions / surfaces |
| --- | --- |
| `status` | `health`, `guide`, `check`; read-only `cli` prefixes (`status`, `worktree list/show`, `terminal list/read`, `orchestration check/worker-show/worker-read/dispatch-show`, `skills get`) |
| `dispatch` | `dispatch`, `await`, `release`; `cli` → `orchestration reply`, `terminal close` |
| `admin` | Remaining raw `cli` (admin prefixes: `terminal send`, `worktree create/rm`, …) and any unlisted argv |

Mapping lives in one module: [`lib/toolsets.mjs`](./lib/toolsets.mjs) (`ACTION_TIERS` + `CLI_PREFIX_TIERS`).

### Config precedence

1. **`--read-only`** (process argv) → `{ status }` only  
2. **`ORCA_BRIDGE_TOOLSETS`** → exact set (e.g. `status,dispatch`)  
3. **Default** → `{ status, dispatch, admin }` (identical to the historical all-tiers-on behavior)

Compat: `ORCA_BRIDGE_CLI_ADMIN=1` **adds** `admin` to the enabled set when the env list omitted it. It does **not** override `--read-only`.

`ORCA_BRIDGE_CLI_HARDENING` enforces the exact-form allowlist on `action=cli` (default **on**, NAS-227). Set `0`/`false`/`off` for warn-don’t-block migration. The toolset `admin` bit unlocks admin forms under hardening — one admin concept, not two competing switches.

### Toolsets default open; CLI forms default locked (owner decision)

**All toolset tiers are ON unless you restrict them.** CLI exact-form allowlist is **ON** by default (NAS-227). Existing coordinators that only use doctrine forms need zero config; non-form argv requires `ORCA_BRIDGE_CLI_HARDENING=0` or an allowlist expansion.

When a tier is disabled, the bridge returns a structured error (not a bare string):

```json
{
  "ok": false,
  "error": "toolset_denied",
  "required_tier": "dispatch",
  "action": "dispatch",
  "enabled_toolsets": ["status"],
  "detail": "… Set ORCA_BRIDGE_TOOLSETS to include \"dispatch\" …",
  "enable_via": { "env": "ORCA_BRIDGE_TOOLSETS", "example": "status,dispatch", "read_only_flag": "--read-only" }
}
```

`action=health` always reports the active set under `toolsets` (when `status` is enabled — which it is in every supported config).

### Recommended hardened deploy (shared / untrusted)

```bash
# Supervised coordinators only — no raw admin cli:
export ORCA_BRIDGE_TOOLSETS=status,dispatch
# CLI exact-form allowlist is already ON by default (NAS-227).

# Read-only observer (health / inventory / check):
node server.mjs --port 8787 --read-only
# equivalent: ORCA_BRIDGE_TOOLSETS=status
```

> **SHOULD** set `ORCA_BRIDGE_TOOLSETS=status,dispatch` on any bridge reachable by more than a trusted coordinator. CLI hardening is already the default; toolset restriction is the remaining operator knob.

Both Streamable HTTP and `--stdio` resolve toolsets the same way: `createToolsetGate({ env: process.env, argv: process.argv })` at process start.

---

## Deploy

### macOS (GUI Orca)

Helpers under `deploy/macos/`:

```bash
export ORCA_BRIDGE_TOKEN=…          # or --seed-env-from-pid
export ORCA_BRIDGE_PUBLIC_ORIGIN=https://your-host.ts.net
export ORCA_BRIDGE_DURABLE_CHECKOUT="$(pwd)"   # where server.mjs lives
export ORCA_BRIDGE_NODE_BIN="$(command -v node)"

./deploy/macos/install-mac.sh
```

Installs a user LaunchAgent (`com.orca-mcp.bridge`), runtime dir `~/.orca-bridge/`, secrets in `~/.orca-bridge/env` (mode 600). Does **not** kill a process already holding `:8787` — cutover is a separate step.

### Linux (CLI-only / headless)

**The one rule:** root may install the *code*; the **service account owns the *state***.
The bridge keeps its OAuth tokens, sender pins and audit log in the `HOME` of the
account the unit runs as. Anything that writes those files while running as root —
`sudo node server.mjs`, a root-run upgrade or migration script — replaces them with
`root:0600` inodes, and the service account then loses both read and write on its own
state. Nothing crashes: the bridge answers normally, but tokens issued afterwards live
in memory only and the next restart drops every MCP client back to a fresh OAuth flow.
See [Troubleshooting: tokens do not survive restart](#troubleshooting-tokens-do-not-survive-restart).

Below, `orca` is the dedicated service account. Substitute your own.

#### 1. Service account

```bash
# Skip if the account already exists.
sudo useradd --system --create-home --shell /usr/sbin/nologin orca
```

#### 2. Install the code

Pick one. Both are fine; they differ only in *who owns the files on disk*.

**A. Checkout owned by the service account** (no registry, no root in the install step):

```bash
sudo install -d -o orca -g orca /opt/orca-mcp
sudo -u orca git clone https://github.com/BuildContext/orca-mcp.git /opt/orca-mcp
# zero runtime dependencies — nothing to npm install
```

`ExecStart=/usr/bin/node /opt/orca-mcp/server.mjs --port 8787`

**B. Global npm install** (root-owned binary, shared across accounts):

```bash
sudo npm i -g orca-mcp@0.3.0     # → /usr/lib/node_modules/orca-mcp, root:root
sudo -u orca orca-mcp --version  # prove the service account can execute it
```

`ExecStart=/usr/bin/orca-mcp --port 8787`

Root owning the *binary* is correct here — it is read-only, executable by everyone,
and no state lives next to it. What must **never** happen is running the bridge itself
(or a migration touching `~/.orca-bridge-*`) as root. `npm i -g` under `sudo` does not
create bridge state, so it is safe; `sudo orca-mcp --port 8787` is not.

> Do **not** `sudo npm i -g` into the *service account's* npm prefix, and do not run
> `npm i -g` as `orca` into a root-owned prefix. Either mixes owners inside one tree.

#### 3. Unit file

Copy `deploy/linux/orca-bridge.service` → `/etc/systemd/system/`, then edit:

| field | value |
|-------|-------|
| `User` / `Group` | the service account (`orca`) |
| `Environment=HOME=` | **that account's home** (`/home/orca`) — this is where state lands |
| `WorkingDirectory` | any directory the account can read |
| `EnvironmentFile` | the env file from step 4 |
| `ExecStart` | from step 2 (A or B) |

`HOME` must match `User`. If they disagree, the bridge writes its state into a home
directory belonging to someone else, and you get the same lockout by a different route.

#### 4. Secrets

Env file, mode `600`, owned by root or by the service account (systemd reads it before
dropping privileges; the bridge never writes to it):

```bash
ORCA_BRIDGE_TOKEN=…
ORCA_BRIDGE_PUBLIC_ORIGIN=https://your-host.ts.net
ORCA_CLI_COMMAND=orca-ide   # if that is your binary name
# recommended on shared hosts:
# ORCA_BRIDGE_TOOLSETS=status,dispatch
# CLI hardening is ON by default (NAS-227); set ORCA_BRIDGE_CLI_HARDENING=0 only for migration
```

#### 5. Start and verify ownership

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now orca-bridge.service
journalctl -u orca-bridge.service -n 50
```

After the first OAuth pairing, confirm the invariant — every path must be owned by the
service account, mode `600` (dir `700`):

```bash
sudo ls -l  /home/orca/.orca-bridge-tokens.json /home/orca/.orca-bridge-sender-pins.json
sudo ls -ld /home/orca/.orca-bridge
sudo find /home/orca -user root        # must print nothing
```

The bridge itself checks this at boot and logs a `WARN:` line per bad path, so
`journalctl -u orca-bridge.service | grep WARN` is the short version.

#### Upgrades

Upgrade the code however you installed it (`sudo -u orca git pull`, or
`sudo npm i -g orca-mcp@<version>`), then `sudo systemctl restart orca-bridge.service`.
Never point a root shell at `~/.orca-bridge-*`. If some script must, it has to restore
the previous owner afterwards (`chown --reference=` or a stat/chown pair) — the bridge
does this for its own writes, but it cannot fix a rewrite done behind its back.

Pairing survives a restart: `~/.orca-bridge-tokens.json` is re-read at boot, so no
client should have to re-authorize after an upgrade. If one does, the state files
changed owner — see the troubleshooting entry below.

`deploy/linux/run.sh` is an optional manual/watchdog launcher (systemd is the production
path); set `ORCA_BRIDGE_SERVER` to your `server.mjs`. Run it **as the service account** —
under `sudo` it produces exactly the root-owned state this section is about.

#### Troubleshooting: tokens do not survive restart

Symptom: the bridge is up and answering, but an MCP client that was already paired has
to run the OAuth flow again — and after the *next* restart, again. Journal shows
`WARN: cannot persist tokens: EACCES` or a boot `WARN:` about
`~/.orca-bridge-tokens.json`.

Cause: the token store is owned by another account (almost always `root`, from an
install/migration step run under `sudo`). Diagnose and fix:

```bash
sudo ls -l /home/orca/.orca-bridge-tokens.json     # owner is root → this is it
sudo chown orca:orca /home/orca/.orca-bridge-tokens.json
sudo chmod 600 /home/orca/.orca-bridge-tokens.json
sudo systemctl restart orca-bridge.service
```

Also check the sibling paths (`~/.orca-bridge-sender-pins.json`, `~/.orca-bridge/`);
the same step usually touched all of them. Ownership and mode are the only fix needed —
the file contents stay valid, so already-issued tokens keep working and clients paired
before the incident do not need to re-pair.

---

## Security model

Read the blunt [Security warning](#security-warning) first. Operational facts:

- **HTTP mode** listens on **127.0.0.1 only** — never open the port raw to the internet; terminate TLS at Funnel / reverse proxy.
- **stdio mode** is a local subprocess: auth is `ORCA_BRIDGE_TOKEN` from the host env / MCP client config (no OAuth browser flow). stdout carries **only** JSON-RPC; logs go to stderr.
- Auth: constant-time token compare (`tokenMatches`); OAuth access tokens (HTTP) are revocable (delete `~/.orca-bridge-tokens.json` + restart).
- Process spawn is **only** the Orca binary — no arbitrary shell through the bridge.
- Full CLI surface is powerful (`terminal send`, etc.). **Default toolsets leave admin forms available** for back-compat; restrict with `ORCA_BRIDGE_TOOLSETS` / `--read-only`. Exact-form CLI allowlist is **on** by default (see [Capability toolsets](#capability-toolsets)).
- Append-only **audit log** (redacted NDJSON under `ORCA_BRIDGE_AUDIT_DIR` or `~/.orca-bridge`) records tool calls for forensics — it is not an access-control layer.
- Rotate master token by setting a new `ORCA_BRIDGE_TOKEN`, restarting, and re-pairing clients.
- Threat model: [`docs/threat-model.md`](./docs/threat-model.md). Report vulnerabilities privately: [`SECURITY.md`](./SECURITY.md).


---

## Project layout

```text
server.mjs                     # MCP server: shared handlers + HTTP/stdio transports (zero deps)
server.json                    # MCP Registry metadata (io.github.buildcontext/orca-mcp)
Dockerfile / .dockerignore     # non-root image for GHCR (HTTP + --stdio)
lib/coordinator-doctrine.mjs   # canonical coordinator discipline (guide + docs)
lib/toolsets.mjs               # capability tiers + gate
lib/cli-policy.mjs             # action=cli allowlist policy
lib/security-core.mjs          # pure security helpers
lib/audit.mjs                  # annotations + audit resources
lib/state-ownership.mjs        # state-file ownership guards (root-safe writes, boot check)
lib/orch-isolation.mjs         # multi-coordinator isolation helpers + unit tests
lib/stdio-transport.test.mjs   # stdio + HTTP smoke (node --test)
scripts/docs.mjs               # npm run docs:build / docs:check
docs/design.md                 # why the bridge is shaped this way (sender pin, inject, OAuth)
docs/threat-model.md           # trust boundaries, threats, mitigations
SECURITY.md                    # private vulnerability reporting + scope
CONTRIBUTING.md                # dev setup, checks, doctrine edit rule
COORDINATOR.md                 # generated supervised-flow discipline (action=guide)
deploy/macos/                  # LaunchAgent installer (HTTP mode)
deploy/linux/                  # systemd unit + host scripts (HTTP mode)
.github/workflows/release.yml  # npm --provenance + GHCR on v* tags
```

Design rationale (sender pinning, inject recovery, envelope quirks, OAuth):
[`docs/design.md`](./docs/design.md). Threat model: [`docs/threat-model.md`](./docs/threat-model.md). Contributing: [`CONTRIBUTING.md`](./CONTRIBUTING.md).

```bash
npm test          # node --test lib/**/*.test.mjs
npm run lint      # syntax check all .mjs
npm run docs:check
```


---

## Relation to upstream Orca

| | This project | Hoped-for first-party (`orca mcp`) |
| --- | --- | --- |
| Transport | stdio (local) + Streamable HTTP + OAuth (remote) | Likely stdio for local agents |
| Protocol | MCP **2025-11-25** (roadmap: 2026-07-28 stateless HTTP) | TBD |
| Placement | External process next to Orca | Inside Orca / CLI |
| Scope today | Supervised orchestration + raw CLI passthrough | Session / workspace tools per #13079 |


If you maintain Orca: this repo is a working reference for tool shapes, headless sender pinning on CLI-only hosts, and multi-client isolation. Link from #13079 welcome.

---

## License

MIT — see [LICENSE](./LICENSE).

Orca is a product of [Stably](https://github.com/stablyai/orca); this project is an independent community bridge, not affiliated with or endorsed by Stably.
