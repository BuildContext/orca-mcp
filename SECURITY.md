# Security Policy

`orca-mcp` is an **RCE-class bridge**: authenticated callers drive the host's Orca CLI, spawn agent terminals, and can reach the host filesystem with the privileges of the bridge process. It is **not a sandbox** and **not a security boundary** by default. Read the blunt framing in the [README security warning](./README.md#security-warning) and the full [threat model](./docs/threat-model.md) before deploying.

## Reporting a vulnerability

**Please report security issues privately.** Do not open a public GitHub issue for vulnerabilities.

### Preferred: GitHub Security Advisories

Use GitHub's private vulnerability reporting for this repository:

**https://github.com/BuildContext/orca-mcp/security/advisories/new**

(Repository → **Security** → **Advisories** → **Report a vulnerability**, or the direct link above.)

Include, when you can:

- Affected version / commit (e.g. tag or `git rev-parse HEAD`)
- Transport mode (`--stdio` vs Streamable HTTP) and rough deploy shape (loopback only, Funnel, reverse proxy)
- Steps to reproduce and expected vs actual behavior
- Impact assessment (who can trigger it, what they gain)
- Whether you have a suggested fix or regression test

### Alternative

If GitHub private reporting is unavailable, open a **minimal** public issue titled `security: private contact requested` with **no exploit details**, and we will switch to a private channel.

## Response SLA

This is a small community project, not an enterprise product. Honest targets:

| Step | Target |
| --- | --- |
| Acknowledge receipt | within **7 days** |
| Initial severity / scope assessment | within **14 days** of acknowledgement |
| Fix or mitigation guidance for confirmed in-scope issues | **best effort**; severity and maintainer availability drive the calendar |

We do **not** promise 24-hour enterprise response, bug bounties, or fixed patch SLAs. Critical issues still get priority over feature work.

## Safe harbour

We will not pursue legal action against good-faith security research that:

- Avoids privacy violations, destruction of data, and disruption of production systems you do not own
- Does not exploit a finding beyond what is needed to demonstrate impact
- Reports findings privately through the channel above before public disclosure
- Gives us a reasonable window to mitigate before coordinated disclosure (we aim to work with you on timing)

Automated mass scanning, social engineering of maintainers, or attacking third-party infrastructure is out of bounds.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest published release on the default branch / npm (when published) | Yes — security fixes land here first |
| Development commits on `main` | Best effort |
| Older release tags | No guarantee of backports; upgrade when possible |

Until the package is published to npm (tracked separately), treat the tip of `main` as the supported line.

## In scope

We want private reports for issues such as:

- **Authentication bypass** — reaching tool actions without a valid master token, issued OAuth access token, path-token URL, or live MCP session (HTTP), or without the configured env token gate (stdio startup)
- **Broken access control between callers** — e.g. one OAuth client reliably acting on another client's dispatches/terminals beyond documented shared-token / `ORCA_BRIDGE_SENDER_SHARED` behavior
- **Bypass of always-on controls** — especially the forbidden handoff gate (`worktree create` + agent + prompt via raw `action=cli`)
- **Bypass of opt-in hardening when enabled** — `ORCA_BRIDGE_CLI_HARDENING=1` allowlist, `ORCA_BRIDGE_TOOLSETS` / `--read-only` tier gates
- **Secret leakage** — master/OAuth tokens or other secrets written to the audit log, access log, or tool results in ways that defeat documented redaction
- **Transport / session confusion** — e.g. stdio protocol smuggling onto stdout, HTTP request smuggling that skips the auth gate, open redirect beyond `ORCA_BRIDGE_REDIRECT_ALLOW`
- **Supply-chain / install integrity** issues in this repository's published artifacts (when publishing exists)

## Out of scope

The following are **not** vulnerabilities in this project:

- **An authenticated caller doing what the tool is designed to do.** With a valid token (or equivalent auth), `dispatch`, `cli`, worktree/terminal operations, and agent control are the product. That includes spawning agents, writing files via those agents, and running Orca CLI that the host user can already run.
- **Default-permissive configuration.** By design, toolsets default to `{status,dispatch,admin}` and CLI hardening is off unless `ORCA_BRIDGE_CLI_HARDENING=1`. Operators who leave defaults on a shared host have chosen a trusted-coordinator deploy.
- **Lack of OS sandboxing.** The bridge does not isolate filesystem, network, or process namespace. It runs as the host user (or service user) and inherits that user's powers.
- **Compromise of the host user account, MCP client, or Orca binary** outside the bridge — stolen laptop, malicious local process reading `ORCA_BRIDGE_TOKEN` from the environment, compromised `orca`/`orca-ide` binary.
- **Social engineering / prompt injection against a model** that an *already authenticated* coordinator chooses to trust, except where you can show a **bridge bug** that bypasses a documented control (e.g. handoff gate bypass).
- **Denial of service** via large payloads, many dispatches, or hanging `await` windows without a clear auth bypass or data break.
- **Issues only in third-party MCP clients, proxies, or inspectors** (for example historical classes like mcp-remote [CVE-2025-6514](https://github.com/advisories/GHSA-6xpm-ggf7-wc3p) or MCP Inspector [CVE-2025-49596](https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g)) unless this repo ships a vulnerable integration path of its own.
- **Missing enterprise features** (SSO, per-tool IAM, network policies, multi-tenant hard isolation beyond documented OAuth client sender pins).

## Hardening knobs (not defaults)

Defaults are permissive so existing coordinators keep working. For shared or less-trusted deployments, operators should restrict explicitly:

```bash
export ORCA_BRIDGE_TOOLSETS=status,dispatch   # drop raw admin cli
export ORCA_BRIDGE_CLI_HARDENING=1            # deny-by-default allowlist on action=cli
# observer only:
# node server.mjs --port 8787 --read-only
```

Always-on regardless of those knobs: forbidden unsupervised handoff via raw CLI, loopback HTTP bind (`127.0.0.1`), spawn of **only** the Orca binary via `execFile` (no shell), timing-safe master-token compare, and redacted append-only audit logging.

Details: [docs/threat-model.md](./docs/threat-model.md), [README](./README.md#security-warning), [docs/design.md](./docs/design.md).
