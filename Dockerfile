# orca-mcp — preferred runtime for privileged bridges (over bare npx).
# No secrets are baked in; pass ORCA_BRIDGE_TOKEN (and friends) at run time.

FROM node:22-alpine

LABEL org.opencontainers.image.source="https://github.com/BuildContext/orca-mcp" \
      org.opencontainers.image.description="External MCP server for Orca worktrees/sessions/orchestration" \
      org.opencontainers.image.licenses="MIT" \
      io.modelcontextprotocol.server.name="io.github.buildcontext/orca-mcp"

WORKDIR /app

# Copy only what the runtime needs (mirrors package.json "files").
COPY package.json ./
COPY server.mjs ./
COPY lib/ ./lib/
COPY scripts/ ./scripts/
COPY docs/ ./docs/
COPY deploy/ ./deploy/
COPY COORDINATOR.md LICENSE README.md SECURITY.md CONTRIBUTING.md server.json ./

# Non-root runtime user.
RUN addgroup -g 1001 -S orca \
  && adduser -u 1001 -S orca -G orca \
  && chown -R orca:orca /app

USER orca

# HTTP default; override with `--stdio` for local MCP hosts.
ENV NODE_ENV=production \
    PORT=8787

EXPOSE 8787

# ENTRYPOINT is the bridge; CMD is the default HTTP listen args.
# Examples (tag = package version). CLI exact-form hardening is ON by default (NAS-227).
#   docker run --rm -e ORCA_BRIDGE_TOKEN=… -p 8787:8787 ghcr.io/buildcontext/orca-mcp:0.3.5
#   docker run --rm -i -e ORCA_BRIDGE_TOKEN=… ghcr.io/buildcontext/orca-mcp:0.3.5 --stdio
ENTRYPOINT ["node", "server.mjs"]
CMD ["--port", "8787"]
