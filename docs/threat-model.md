# Threat model

Honest scope for **orca-mcp** (bridge version documented against `main` / 0.2.13-era code). This is not a compliance artifact and not a promise of safety. It states what the process can do, who we trust, what we mitigate today, and what we deliberately do **not**.

Companion docs: [SECURITY.md](../SECURITY.md) (reporting), [README security warning](../README.md#security-warning), [design rationale](./design.md).

## One-line summary

Anyone who can authenticate to the bridge can drive Orca **as the bridge OS user** — create worktrees, inject coding agents, and (under default config) send raw CLI including `terminal send`. The bridge is a **privileged remote control surface**, not a sandbox.

## Trust boundaries

```text
                    ┌─────────────────────────────────────────┐
  MCP client        │  Trust boundary: auth to bridge         │
  (coordinator) ───►│  master token / OAuth token / path-token │
                    │  / live MCP session (HTTP)               │
                    └─────────────────┬───────────────────────┘
                                      │
                    ┌─────────────────▼───────────────────────┐
                    │  orca-mcp process (host user privileges) │
                    │  execFile(orca only) · audit log · pins  │
                    └─────────────────┬───────────────────────┘
                                      │
                    ┌─────────────────▼───────────────────────┐
                    │  Orca runtime · agent TUIs · worktrees   │
                    │  host filesystem & network as that user  │
                    └─────────────────────────────────────────┘
```

### HTTP (Streamable HTTP, default)

| Boundary | Reality in code |
| --- | --- |
| Network reachability | Server **`listen`s on `127.0.0.1` only**. Exposure is entirely the operator's reverse proxy / Tailscale Funnel / SSH tunnel. Raw internet bind is not offered. |
| Unauthenticated Internet | OAuth discovery + DCR + authorize endpoints are reachable without the master token (they *are* the auth mechanism). Protected MCP routes require auth. |
| Authenticated caller | Bearer master token, issued OAuth access token, path prefix `/t/<master-token>/…`, or a live `Mcp-Session-Id` after `initialize` (`authenticateRequest` in `lib/security-core.mjs`). |
| OAuth client vs master | OAuth access tokens are distinct, revocable (delete `~/.orca-bridge-tokens.json` + restart). Master token is the root secret (env + optional path-token URLs). |
| Multi-coordinator | Per-OAuth-client sender pins and mailbox partitioning (`lib/orch-isolation.mjs`). **Not** full IAM: same master path-token or shared OAuth token ⇒ shared power. `ORCA_BRIDGE_SENDER_SHARED=1` forces one sender pin (single-tenant). |

### stdio (`--stdio`)

| Boundary | Reality in code |
| --- | --- |
| Who can speak protocol | The **parent process** that spawned the bridge (desktop host, IDE, agent runtime). There is no browser OAuth on this path. |
| Auth | `ORCA_BRIDGE_TOKEN` must be present in the **process environment** at startup (≥16 chars) or the process exits before speaking on stdout. The local host is trusted to inject that env (MCP client config). |
| Inheritance | Full parent env, cwd conventions, and the same host user. A malicious or compromised MCP host that can launch the binary already has whatever it put in `env`. |
| stdout | JSON-RPC only; logs go to **stderr** (avoids desktop-host protocol corruption). |

### What sits outside the bridge

- The Orca binary and its own authz to the user's projects
- The MCP client / model (prompt injection against the *coordinator* is a client-side concern unless it produces a bridge control bypass)
- TLS, reverse-proxy auth, and network policy in front of loopback HTTP

## Assets

| Asset | Why it matters | Where it lives |
| --- | --- | --- |
| **Master token** (`ORCA_BRIDGE_TOKEN`) | Root credential for HTTP path-token + OAuth “password” + stdio startup gate | Process env; sometimes MCP client config files; path URLs if used |
| **Issued OAuth access tokens** | Equivalent to an authenticated HTTP caller until revoked | `~/.orca-bridge-tokens.json` (mode `600`) |
| **Sender pins** | Bind orchestration identity per client | `~/.orca-bridge-sender-pins.json` |
| **Audit log** | Forensics; must not re-emit secrets | `ORCA_BRIDGE_AUDIT_DIR` or `~/.orca-bridge` NDJSON (+ rotation) |
| **Worker transcripts / terminal output** | May contain source, secrets pasted into TUIs, prod data | Orca terminal buffers; tool results (truncated); in-memory dispatch registry for MCP resources |
| **Host filesystem & credentials** | Ultimate blast radius | Anything the bridge OS user can read/write, via agents or CLI |
| **Other users' terminals** | Cross-tab interference / injection | Orca terminal handles; especially dangerous with `terminal send` |

## Threats

### T1 — Token theft

**Vector:** Token in shell history, world-readable env files, screenshots, CI logs, MCP client config synced to a third party, path-token URL in proxy logs.  
**Impact:** Full bridge power as that principal.  
**Mitigations today:** Timing-safe compare (`tokenMatches`: SHA-256 digests + `timingSafeEqual`); OAuth so the master token need not live in remote client settings; token file mode `600`; audit redaction of token-like fields.  
**Not mitigated:** Endpoint compromise, malicious local reader of env, operator pasting path-token URLs into tickets.

### T2 — Authenticated but hostile coordinator

**Vector:** Stolen OAuth token, malicious remote agent, insider.  
**Impact:** Under **default** config: `dispatch` agents, raw `cli`, worktree create/rm, `terminal send` — i.e. intentional product capabilities → host-level impact.  
**Mitigations today:** Opt-in `ORCA_BRIDGE_TOOLSETS` / `--read-only`; opt-in `ORCA_BRIDGE_CLI_HARDENING=1`; always-on forbidden handoff on raw CLI; per-client sender isolation for separate OAuth clients; audit log.  
**Not mitigated:** “Auth means trusted.” There is **no** per-caller authorization beyond possessing a valid token/session. Hostile-but-authenticated is a deploy problem (don't hand tokens to untrusted parties; turn hardening on).

### T3 — Prompt injection → `cli` argv

**Vector:** Untrusted content in a worker or coordinator context eventually causes `action=cli` with dangerous argv (or tricks a model into calling admin surfaces).  
**Impact:** Depends on toolsets + CLI hardening. With defaults, nearly full Orca CLI surface.  
**Mitigations today:** Always-on reject of unsupervised `worktree create --agent/--prompt` handoff (`isForbiddenHandoffArgv`); supervised `dispatch` path only for agent start; optional deny-by-default allowlist; tool annotations mark `cli`/`dispatch` destructive.  
**Not mitigated:** Model obedience. Hardening knobs are **off** unless set. Injection that stays within allowlisted prefixes still runs those prefixes.

### T4 — Malicious MCP client / confused deputy

**Vector:** User attaches a hostile MCP client config; or a page/tool drives a local client; historical ecosystem failures (see below).  
**Impact:** Whatever the client can invoke after auth — on stdio, launching the host with the token in env is already game over for that user.  
**Mitigations today:** Explicit token requirement; HTTP loopback default; destructive tool annotations; stdio stdout discipline.  
**Not mitigated:** Running the bridge under a highly privileged account; placing the master token in every untrusted client.

### T5 — Log / resource exfiltration

**Vector:** Reader with host FS access or MCP `resources/read` on audit URIs pulls sensitive tool arguments.  
**Impact:** Spec/prompt/token leakage.  
**Mitigations today:** Append-only NDJSON audit with key/argv redaction (`lib/audit.mjs`); sensitive key regex; length-preserving `[REDACTED len=N]` forms.  
**Not mitigated:** Redaction is heuristic (false negatives possible on novel secret shapes). Terminal transcripts and live tool responses may still carry secrets the model or CLI printed.

### T6 — `terminal send` cross-tab risk

**Vector:** Authenticated caller (or inject-recovery path) sends keystrokes to a terminal handle that is not the intended worker — another user's tab, the coordinator tab, a production shell.  
**Impact:** Command injection into an interactive session.  
**Mitigations today:** `terminal send` is an **admin**-tier CLI prefix; release refuses coordinator handles (`releaseRefusesCoordinator`); multi-coord mailbox partitioning; doctrine tells coordinators to use worker handles from dispatch.  
**Not mitigated:** Under default toolsets, admin is enabled — any authenticated caller may raw-CLI `terminal send` if they can name a handle. Handle confidentiality is weak (list/read surfaces exist on status tier).

### T7 — Ecosystem MCP incident classes (context)

These are **not** bugs in orca-mcp's tree; they shape how operators should think about MCP edges:

| Incident | Class | Lesson for this bridge |
| --- | --- | --- |
| [CVE-2025-6514](https://github.com/advisories/GHSA-6xpm-ggf7-wc3p) (mcp-remote) | Client-side RCE when connecting to a malicious remote MCP / OAuth metadata | Treat remote MCP endpoints as hostile; prefer HTTPS and trusted hosts; this bridge's HTTP side is a powerful server — do not expose it without auth path you understand |
| [CVE-2025-49596](https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g) (MCP Inspector) | Unauthenticated local debug proxy → RCE | Local “dev” listeners that spawn tools are high value; this bridge binds HTTP to loopback and requires a token, but **stdio inherits the parent** — don't debug with production tokens in casual configs |

MCP security guidance (official best practices and the above advisories) converges on: **least privilege for tokens, no ambient trust of tool output, don't expose debug control planes, assume prompts are adversarial.**

## Mitigated today (code-backed)

| Control | Default | Module / behavior |
| --- | --- | --- |
| Forbidden unsupervised handoff | **Always on** | `isForbiddenHandoffArgv` / cli-policy deny `forbidden_handoff` |
| Spawn surface | **Always** Orca binary only | `execFile`, no shell |
| HTTP bind | **Always** `127.0.0.1` | `server.listen(PORT, '127.0.0.1')` |
| Master token compare | **Always** timing-safe | `tokenMatches` |
| Audit log | **On** (dir configurable) | Redacted append-only NDJSON + MCP resources |
| OAuth + PKCE (HTTP) | Available | Master token stays out of remote client settings when OAuth is used |
| Per-OAuth-client sender isolation | On (unless shared pin) | `lib/orch-isolation.mjs` |
| CLI allowlist | **Opt-in** | `ORCA_BRIDGE_CLI_HARDENING=1` |
| Capability toolsets | **Opt-in restrict** | `ORCA_BRIDGE_TOOLSETS`, `--read-only`; default = all tiers |

## Explicitly NOT mitigated

- **No OS sandbox** (no container, seccomp, or FS jail imposed by the bridge)
- **Permissive defaults** — admin toolset on; CLI hardening off
- **No per-caller authorization** beyond “has a valid token/session”
- **No guarantee** that agent-driven file writes, network calls, or git pushes are blocked
- **No multi-tenant hard isolation** on shared master path-token or `ORCA_BRIDGE_SENDER_SHARED=1`
- **No prevention** of authenticated `terminal send` to an arbitrary handle when admin is enabled
- **No formal verification** that redaction catches every secret shape

## Recommended posture by deploy

| Deploy | Posture |
| --- | --- |
| Single operator, local stdio, trusted desktop host | Defaults acceptable; still use a long random `ORCA_BRIDGE_TOKEN`; don't reuse production tokens in throwaway configs |
| Remote HTTP, trusted coordinators only | Funnel/proxy to loopback; OAuth; `ORCA_BRIDGE_TOOLSETS=status,dispatch`; `ORCA_BRIDGE_CLI_HARDENING=1`; separate OAuth client per coordinator |
| Shared host / semi-trusted callers | Above + consider `--read-only` observers on a second process; never share master path-token URLs; monitor audit log; run as a dedicated low-privilege OS user if operationally possible |
| Untrusted callers | **Do not deploy.** This is the wrong tool. |

## Related code map

| Path | Role |
| --- | --- |
| `lib/security-core.mjs` | Handoff gate, `tokenMatches`, `authenticateRequest`, argv builders |
| `lib/cli-policy.mjs` | Opt-in allowlist; permissive default + warnings |
| `lib/toolsets.mjs` | status / dispatch / admin tiers |
| `lib/audit.mjs` | Redaction + append-only log + annotations |
| `lib/orch-isolation.mjs` | Multi-coordinator pins, mailbox partition, release guard |
| `server.mjs` | Transports, `execFile`, listen address, wiring |

## Document maintenance

When changing auth, toolsets, CLI policy, audit redaction, or bind/spawn behavior, update this file in the **same PR** and add/adjust tests under `lib/*.test.mjs`. Security claims in README / SECURITY.md must remain true of the code — if the code is weaker, fix the claim, not the other way around.
