# Bridge design rationale

Why `orca-mcp` is shaped the way it is. Operational knowledge that used to live
only as Russian comments in `server.mjs` lives here so new contributors can read
it without spelunking the source. Short pointer comments in the code still
point at the relevant section.

This is **not** a user guide (see [README.md](../README.md)) and **not** the
coordinator playbook (see [COORDINATOR.md](../COORDINATOR.md) / `action=guide`).
It is the *why* behind the hard edges.

---

## What this is

A minimal MCP server (Streamable HTTP, JSON-RPC 2.0) with **zero npm
dependencies**. It runs next to Orca on the host, listens on loopback only, and
is published outward through something like Tailscale Funnel. Hyperagent (and
other MCP clients) register it as a custom remote MCP.

Design constraints that do not move:

- **Zero deps** — `node server.mjs` is the whole runtime.
- **Spawn only the Orca binary** via `execFile` (no shell).
- **Auth** is Bearer token, path prefix `/t/<token>/…`, or a valid MCP session.
- **Bind 127.0.0.1 only** — TLS and exposure are the operator's problem
  (Funnel / reverse proxy), never raw port-forward of the bridge.

See the file header in `server.mjs` and the [README](../README.md) for env vars
and launch.

---

## Sender pinning

### The problem

Headless bridge hosts have no `ORCA_TERMINAL_HANDLE`. Orca ≤1.4.173 requires an
explicit sender terminal (`--from` / `check --terminal`) on orchestration
mutations. Early bridge versions either:

1. reused one env-pinned sender for every client, so two coordinators on one
   bridge fenced each other (`consumer_fenced`, stolen acks), or
2. re-discovered the sender by **tab title** each call — shell TUIs rewrite
   `--title` to things like `user@host: path`, so "re-discovery" created a
   **second** coordinator tab mid-wave and the next `task-create` fenced the
   first generation.

### The ladder (0.2.11 → 0.2.13)

| Version | Change |
| --- | --- |
| **0.2.11** | Per-OAuth-client durable sender terminal; orchestration mutations for one client are serialized through a per-client lock. |
| **0.2.12** | **Pin-by-handle**: once a client has a handle, revalidate that handle; never create a sibling while the pin lives. Titles are best-effort only when there is no live pin. |
| **0.2.13** | Persist pins in `~/.orca-bridge-sender-pins.json`. **Skip redundant `run-use`** when this pin is already bound to the same `runId` — `run-use` bumps `consumer_generation` and invalidates prior `deliveryId`s, which made `ack` fail with `consumer_fenced` even for a single coordinator. |

### Identity and isolation

- Client key = OAuth access token (hashed) or master/session identity
  (`deriveClientKey` in `lib/orch-isolation.mjs`).
- Each OAuth client gets its own sender title suffix so tabs are distinguishable.
- `ORCA_BRIDGE_SENDER_SHARED=1` forces every client onto the env pin — **single-tenant
  only**. Multi-coordinator deployments need **two OAuth tokens**, never the
  shared flag.
- `await` may return `foreign_messages`. Operators must neither release nor act
  on a foreign `dispatch_id`. `next.action` never targets another coordinator's
  worker. On release, pass the **worker** `terminal_handle` from the dispatch
  response, never the sender handle.

### Resolve order

`resolveSenderTerminal` trusts in this order:

1. cached / persisted pin (revalidate with `terminal show`)
2. env pin (`ORCA_BRIDGE_SENDER_TERMINAL` / `ORCA_BRIDGE_FROM`) when allowed
3. best-effort exact title match (only with no live pin)
4. create one durable coordinator shell tab for this client, then pin it

Never "adopt a random live terminal" — that was mechanism A of the
multi-coordinator regression.

Pure helpers and the serial lock live in `lib/orch-isolation.mjs`
(`senderPinPlan`, `shouldRunUseBeforeAwait`, `partitionMailbox`,
`releaseRefusesCoordinator`, `createSerialLockMap`).

---

## Inject recovery

### The failure mode

Supervised dispatch path:

```text
run-create → task-create → worktree/agent terminal →
  terminal wait tui-idle → orchestration dispatch --inject →
  terminal send --enter (submit the typed compose) →
  liveness probe → (optional) terminal send --text … --enter recovery
```

`orchestration dispatch --inject` **types** the brief into the TUI compose box
and has **no Enter affordance**. There is no `--submit` flag on any Orca
command. After `--inject` the bridge sends `terminal send --enter` to submit
the already-typed compose. When the bridge itself types text (idle recovery,
isolated preamble), submit is **target-dependent**: a shell target submits on
the first `--text … --enter`; a Grok TUI compose box needs that plus a
following empty `--enter` (verified live 2026-08-15). The extra send is
harmless when the first already submitted.

Some agents (notably Grok) accept `--inject` and still sit at **Turns:0 /
idle**. The dispatch envelope looks fine; the worker never starts work. Without
recovery the coordinator waits forever on `await`.

### What the bridge does

After `--inject`, the bridge sends `terminal send --enter` to submit the
already-typed compose. Then `ensureInjectLanded`:

1. Snapshots terminal preview/tail and decides "looks working" vs idle.
2. If idle, pushes the task text again via `terminal send --text … --enter`
   **plus** a following empty `--enter` (TUI draft buffer; shell already
   submitted on the first), with an explicit **inject-recovery** trailer that
   restates `task_id`, `dispatch_id`, and the `worker_done` contract. Use
   `--interrupt` on a stuck TUI.
3. Re-probes. Results surface on the dispatch response as
   `inject_recovered` / `inject_landed` so coordinators can see the fix fired.
   `injected` is whatever the runtime `--inject` envelope reported — the
   runtime cannot express Enter, so do not treat `injected:true` as "submitted".

Disable with `ORCA_BRIDGE_INJECT_RECOVERY=0`. Settle window:
`ORCA_BRIDGE_INJECT_SETTLE_MS` (default 10s).

### Release after inject-path `worker_done`

On the inject path the Dispatch is already **completed** when `worker_done`
arrives. `worker-release` often returns `dispatch_not_found` — that is
**expected**, not a failure. Cleanup is `terminal close --terminal <handle> --json`
(no `--tab`) using the **worker** handle from the dispatch response
(`mode=terminal-close`, `expected_for_inject_path: true`). `tab_not_found` and
`workspace_session_unavailable` are treated as already gone. Passing the
coordinator sender handle here would kill the pin — refused by
`releaseRefusesCoordinator`. Isolated commits are bridge-uid named-path
`commitNamedPaths` after a gitdir assert; uid 994 never commits.

---

## Envelope parsing quirks

Orca CLI with `--json` prints a JSON **envelope** on stdout. Reality is messier
than "one JSON object":

1. **Banner lines may precede the envelope.** `findEnvelopeBody` tries the whole
   trimmed stdout, then each line from the bottom up, and keeps the first
   parseable `{…}` object.
2. **The envelope beats the process exit code.** A CLI can exit non-zero while
   still returning a usable `ok: true` envelope (or the reverse). `describeRun`
   prefers envelope `ok` when present.
3. **Unreadable envelope + exit 0** falls back to trusting the exit code and
   returns `envelopeMissing: true` (broken transport, or a command that does
   not speak envelopes).
4. **Spawn failures** are distinct from CLI exit codes: `error.code` as a
   **string** (e.g. `ENOENT`) becomes `spawnError`; numeric codes stay as
   `exitCode`. `runOrca` never throws on non-zero exit — callers always get a
   structured result.

Contract adapted from Orca's own `orca_terminal.mjs` transport so the bridge
behaves like in-process tooling.

### Orca binary resolution

On Linux, bare `orca` is often the **GNOME screen reader**, not the IDE CLI.
Resolution order:

1. `ORCA_CLI_COMMAND` if set
2. else `orca-ide` on Linux, `orca` elsewhere

---

## OAuth and session auth

### Dual role

The bridge is its own **authorization server and resource server**. A human
enters the master token once on `/authorize` in a browser (not in the MCP
client settings form). Hyperagent receives a separate, revocable access token.
Issued tokens persist in `~/.orca-bridge-tokens.json` so a bridge restart does
not force re-pairing.

### Auth order for protected paths

`authenticate` accepts, in order:

1. **Bearer** master token or issued OAuth access token
2. **Path prefix** `/t/<master-token>/…` (curl / sandboxes)
3. **Valid `Mcp-Session-Id`** — required because Streamable HTTP clients on
   GET SSE often send only the session id and omit `Authorization`

### Sessions

After `initialize`, the client should send `Mcp-Session-Id` on every request.
A new session is created on each `initialize` if the client did not reuse an
old id. On GET SSE, if the client arrives with only Bearer, the bridge mints a
sid so subsequent POSTs with that header are recognized.

### Public origin and open-redirect

- `ORCA_BRIDGE_PUBLIC_ORIGIN` — public origin for OAuth discovery/endpoints
  (Funnel host). If unset, endpoints are built from the request `Host` /
  `X-Forwarded-*` headers.
- `ORCA_BRIDGE_REDIRECT_ALLOW` — comma-separated redirect URI prefixes after
  authorize (open-redirect protection). Default includes Hyperagent.

### Path-inserted well-known (RFC 8414 / 9728)

Clients probe both bare and **path-inserted** well-known URLs:

```text
/.well-known/oauth-authorization-server
/.well-known/oauth-authorization-server/<resource-path>
/.well-known/oauth-protected-resource/<resource-path>
```

Exact-match only broke registration of resources that live under a path
(e.g. `/hindsight/mcp/omp/`). Discovery handlers use **prefix** matching.
Protected-resource metadata must return a `resource` URL that **exactly
matches** what the client registered (`/mcp`, `/hindsight/mcp/omp/`, …) or
strict clients reject the metadata.

On 401, `WWW-Authenticate` points at path-inserted
`oauth-protected-resource` metadata for the requested resource so the MCP
client can start OAuth without prior config.

OAuth endpoints and discovery are handled **before** the token gate — they are
the auth mechanism itself. DCR (`/register`) accepts any public client.

---

## Streamable HTTP and SSE

- MCP over Streamable HTTP: POST for JSON-RPC; GET with
  `Accept: text/event-stream` opens an optional server→client SSE stream.
- First SSE bytes are a comment/padding line so reverse proxies flush headers
  before the first real event.
- Keepalive comments every `SSE_KEEPALIVE_MS` (15s).
- Hindsight proxy pipes upstream SSE through unchanged (no re-buffering of the
  event stream).
- Single-message SSE responses for JSON-RPC when the client asked for an event
  stream are spec-legal and end the stream after one `message` event.

---

## MCP tool surface

Hyperagent custom MCP historically exports **one** tool name from this server
(`mcp-orca__orca`). The whole control plane is multiplexed into the single tool
`orca` via the `action` field. Multi-name `tools/list` does not help HA clients.

Primary actions: `health`, `dispatch`, `await`, `release`, `guide`, plus lower
level `check` / `cli`. Capability tiers and the opt-in CLI allowlist are
documented in the README (capability toolsets / CLI allowlist).

---

## State file ownership

The bridge persists three things, all under the `HOME` of the account it runs as:
`~/.orca-bridge-tokens.json` (issued OAuth access tokens),
`~/.orca-bridge-sender-pins.json` (per-client sender pins) and `~/.orca-bridge/`
(audit log). There is no server-side database; this *is* the durable state.

### The failure mode (NAS-241)

A cutover script ran a token-store migration **as root**. It wrote correctly —
`mkstemp` + `chmod 0600` + `os.replace()` — but an atomic replace installs a *new
inode*, and the new inode is owned by whoever performed the write. The store became
`root:root 0600` while the unit runs as `orca`.

What makes this expensive is how quiet it is:

- The bridge starts fine. `readFileSync` throws, the catch swallows it, and the
  in-memory token set is simply empty.
- Clients re-run OAuth once and everything looks healthy again.
- `persistTokens` then fails with `EACCES` — a single `WARN` line — so the new token
  lives in memory only, and the next restart repeats the whole cycle.

Only an explicit permission check surfaced it. Ownership drift is therefore treated as
a first-class failure here, not as an operator mistake to document away.

### Guards

`lib/state-ownership.mjs` holds both, and both are inert in the normal non-root case:

1. **Ownership-preserving writes.** `writeFilePreservingOwner` stats the target first
   and decides who *should* own the result. A file owned by a normal account keeps that
   owner. A file that is missing — or already `root`-owned inside someone else's home,
   which is exactly what a migration's `os.replace()` leaves behind — is handed to the
   owner of the containing directory, i.e. the service account's HOME. So the guard
   both prevents the damage and repairs it on the next write, rather than cementing a
   root-owned store. A root-owned file in a root-owned home is left alone, and non-root
   writes chown nothing.
   A failed `chown` is reported, never thrown — the data is already on disk.

   Note the one case that is *not* a bug: a plain `writeFileSync` over an existing file
   truncates the inode in place and leaves its owner alone, even under root. The damage
   in NAS-241 came from the atomic replace, not from the write itself.
2. **Boot-time inspection.** `stateOwnershipWarnings` classifies every state path
   (missing / ok / foreign owner / unreadable / unwritable / loose mode) and the server
   logs one `WARN:` per unhealthy path at startup, each naming the `chown` that fixes
   it.

Neither guard can repair a rewrite performed behind the bridge's back while it is not
running — that is what the README's Linux install rules are for: root installs the
code, the service account owns the state.

---

## Related files

| Path | Role |
| --- | --- |
| `server.mjs` | HTTP/MCP server, dispatch/await/release, OAuth |
| `lib/orch-isolation.mjs` | Pure multi-coordinator isolation helpers |
| `lib/security-core.mjs` | Pure auth/CLI argv helpers (testable) |
| `lib/cli-policy.mjs` | Opt-in `action=cli` allowlist |
| `lib/toolsets.mjs` | Capability tiers status/dispatch/admin |
| `lib/state-ownership.mjs` | State-file ownership guards (root-safe writes, boot check) |
| `COORDINATOR.md` | Operator discipline (also `action=guide`) |
| `README.md` | Install, env, security model |
