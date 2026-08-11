# Contributing to orca-mcp

Thanks for helping improve the bridge. This repo is a **zero-dependency** Node.js MCP server (`server.mjs` + `lib/`). Small, testable modules and honest docs beat clever abstraction.

## Prerequisites

- **Node.js ≥ 18** (22 recommended)
- `git`
- Orca CLI on `PATH` only if you are doing live integration checks (`orca` / `orca-ide`). Unit tests under `lib/**/*.test.mjs` do **not** require a running Orca.

## Setup

```bash
git clone https://github.com/BuildContext/orca-mcp.git
cd orca-mcp
# no npm install required for runtime — zero dependencies
# optional: copy env template for manual server runs
cp .env.example /path/to/secure/env   # chmod 600; never commit real tokens
```

Run the HTTP server locally:

```bash
export ORCA_BRIDGE_TOKEN="$(openssl rand -hex 32)"
npm start
# → node server.mjs --port 8787  (binds 127.0.0.1)
```

stdio mode:

```bash
export ORCA_BRIDGE_TOKEN="$(openssl rand -hex 32)"
npm run start:stdio
```

## Checks you must run

Before opening a PR:

```bash
npm test            # node --test lib/**/*.test.mjs
npm run lint        # syntax check all .mjs (scripts/lint.mjs)
npm run docs:check  # generated README/COORDINATOR regions match doctrine
```

All three should be green. CI expects the same trio.

### Docs generation

Coordinator discipline text is **generated** from a single source:

| Source of truth | Generated consumers |
| --- | --- |
| `lib/coordinator-doctrine.mjs` | Marked regions in `README.md`, body of `COORDINATOR.md`, and the live `action=guide` / tool description strings |

Rules:

1. **Edit `lib/coordinator-doctrine.mjs`**, then run `npm run docs:build`.
2. **Never hand-edit** content between:

   ```html
   <!-- BEGIN GENERATED: coordinator-discipline -->
   …
   <!-- END GENERATED: coordinator-discipline -->
   ```

   in `README.md`, or the generated body of `COORDINATOR.md`.
3. Hand-written README sections (install, security warning, env tables outside the marker, etc.) are fine — keep them outside the generated markers.
4. `npm run docs:check` fails the PR if generated output drifts.

Security and threat-model docs (`SECURITY.md`, `docs/threat-model.md`, README security warning) are **hand-maintained**. Keep them truthful against the code (see below).

## Project layout (where to change what)

| Path | Touch when… |
| --- | --- |
| `server.mjs` | HTTP/stdio transports, wiring, OAuth routes, dispatch/await/release orchestration |
| `lib/security-core.mjs` | Auth helpers, handoff gate, pure argv builders |
| `lib/cli-policy.mjs` | `action=cli` allowlist / hardening |
| `lib/toolsets.mjs` | status/dispatch/admin capability tiers |
| `lib/audit.mjs` | Redaction, audit NDJSON, MCP annotations/resources |
| `lib/orch-isolation.mjs` | Multi-coordinator sender pins / mailbox partition |
| `lib/coordinator-doctrine.mjs` | Guide + generated doc prose |
| `docs/design.md` | Why the bridge is shaped this way |
| `docs/threat-model.md` | Trust boundaries, threats, mitigations |
| `SECURITY.md` | Vulnerability reporting policy |
| `deploy/` | LaunchAgent / systemd helpers |

Prefer extracting pure helpers into `lib/` with unit tests over growing inseparable logic in `server.mjs`.

## PR norms

- **One concern per PR** when practical; link the related issue/ticket when one exists.
- Describe **behavior change** and **risk** in the PR body (especially anything auth-, spawn-, or CLI-related).
- Do not bump version / tag / publish unless that is the ticket. `package.json` `"private": true` stays until the publish track says otherwise.
- Do not commit secrets, real `ORCA_BRIDGE_TOKEN` values, or live paths with credentials.
- Match existing style: ESM (`.mjs`), no new runtime npm dependencies unless there is a strong, discussed reason (project norm is **zero** runtime deps).

### Security-critical changes

Changes that touch any of the following **must** ship with tests under `lib/*.test.mjs` (or extend an existing suite):

- Authentication / token compare / session or path-token handling
- Handoff gate (`isForbiddenHandoffArgv` and callers)
- CLI allowlist or toolset gates
- Audit redaction
- Bind address, `execFile` spawn surface, or stdio stdout/stderr split
- Multi-coordinator isolation (pins, mailbox partition, release guards)

Also update **docs in the same PR** when behavior operators rely on changes:

- `docs/threat-model.md` and/or `SECURITY.md` in-scope/out-of-scope text
- README security warning / hardening examples
- `docs/design.md` if you change a “why” invariant

**Honesty rule:** every security claim in docs must be true of the code you merge. If the implementation is weaker than the docs, fix the docs (or the code) before merge — do not paper over gaps.

See [SECURITY.md](./SECURITY.md) for how to report vulnerabilities (private advisory, not a public exploit issue).

## Suggested test approach

```bash
# focused
node --test lib/security-core.test.mjs
node --test lib/cli-policy.test.mjs lib/toolsets.test.mjs
node --test lib/audit.test.mjs

# full
npm test
```

Tests should lock **observable contracts** (deny/allow decisions, redaction output shapes, resolve precedence), not incidental formatting.

## Code of conduct (short)

Be respectful. Assume good faith. No harassment. Security research: follow [SECURITY.md](./SECURITY.md) safe harbour and private reporting.

## License

By contributing, you agree your contributions are licensed under the MIT License in [`LICENSE`](./LICENSE).
