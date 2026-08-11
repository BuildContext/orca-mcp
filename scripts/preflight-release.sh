#!/usr/bin/env bash
# Pre-flight checks before tagging a release (vX.Y.Z).
# Does NOT publish, tag, or push. Safe to re-run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; RESET=$'\033[0m'
pass() { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
warn() { printf '  %s⚠%s %s\n' "$YELLOW" "$RESET" "$1"; }
fail() { printf '  %s✗%s %s\n' "$RED" "$RESET" "$1"; FAILED=1; }
FAILED=0

VERSION="$(node -p 'require("./package.json").version')"
TAG="v${VERSION}"
NAME="$(node -p 'require("./package.json").name')"

printf '\n%sRelease preflight%s  %s@%s  (tag %s)\n\n' "$DIM" "$RESET" "$NAME" "$VERSION" "$TAG"

# ── package metadata ──────────────────────────────────────────────────────
node <<'NODE' || FAILED=1
const fs = require('fs');
const p = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const s = JSON.parse(fs.readFileSync('server.json', 'utf8'));
const fails = [];
if (p.private === true) fails.push('package.json has "private": true (blocks npm publish)');
if (p.name !== 'orca-mcp') fails.push(`unexpected name: ${p.name}`);
if (!p.license) fails.push('missing license');
if (!p.publishConfig || p.publishConfig.access !== 'public') {
  fails.push('publishConfig.access should be "public"');
}
if (p.version !== s.version) fails.push(`package.json ${p.version} != server.json ${s.version}`);
const npm = (s.packages || []).find((x) => x.registryType === 'npm');
const oci = (s.packages || []).find((x) => x.registryType === 'oci');
if (npm && npm.version !== p.version) fails.push(`server.json npm version ${npm.version}`);
if (npm && npm.identifier !== p.name) fails.push(`server.json npm identifier ${npm.identifier}`);
if (oci && !String(oci.identifier).endsWith(':' + p.version)) {
  fails.push(`server.json oci identifier ${oci.identifier} (expected :${p.version})`);
}
if (fails.length) {
  for (const f of fails) console.error('  ✗ ' + f);
  process.exit(1);
}
console.log('  ✓ package metadata + server.json versions aligned');
NODE

# ── quality gates (same as CI / prepack) ──────────────────────────────────
if npm test >/tmp/orca-preflight-test.log 2>&1; then
  pass "npm test ($(tail -5 /tmp/orca-preflight-test.log | grep -E '^# tests' || echo ok))"
else
  fail "npm test failed — see /tmp/orca-preflight-test.log"
fi

if npm run lint >/tmp/orca-preflight-lint.log 2>&1; then
  pass "npm run lint"
else
  fail "npm run lint failed — see /tmp/orca-preflight-lint.log"
fi

if npm run docs:check >/tmp/orca-preflight-docs.log 2>&1; then
  pass "npm run docs:check"
else
  fail "npm run docs:check failed — see /tmp/orca-preflight-docs.log"
fi

# ── pack dry-run (content hygiene) ────────────────────────────────────────
# prepack already runs test+lint+docs; dry-run re-runs them — acceptable.
if npm pack --dry-run >/tmp/orca-preflight-pack.log 2>&1; then
  if grep -E '\.env($|\.)|node_modules|\.orca-bridge|id_rsa|\.pem($|\.)' /tmp/orca-preflight-pack.log; then
    fail "npm pack listing contains forbidden paths"
  else
    files=$(grep -cE 'npm notice [0-9]' /tmp/orca-preflight-pack.log || true)
    pass "npm pack --dry-run (no forbidden paths)"
  fi
else
  fail "npm pack --dry-run failed — see /tmp/orca-preflight-pack.log"
fi

# ── scrub (host-local / private markers) ──────────────────────────────────
SCRUB_RE='REDACTED_PRIVATE_PATTERN'
if git grep -nI -E "$SCRUB_RE" -- . ':(exclude)scripts/preflight-release.sh' >/tmp/orca-preflight-scrub.txt 2>/dev/null; then
  fail "scrub hits in tree:"
  sed 's/^/    /' /tmp/orca-preflight-scrub.txt || true
else
  pass "scrub-grep clean (host paths / private markers)"
fi

# ── git / remote ──────────────────────────────────────────────────────────
if git rev-parse --abbrev-ref HEAD | grep -qx main; then
  pass "on main"
else
  warn "not on main (current: $(git rev-parse --abbrev-ref HEAD)) — tag from default branch tip"
fi

if git status --porcelain | grep -q .; then
  fail "working tree dirty — commit or stash before tagging"
else
  pass "working tree clean"
fi

if git rev-parse "$TAG" >/dev/null 2>&1; then
  fail "tag $TAG already exists locally"
else
  pass "tag $TAG not present locally"
fi

if git ls-remote --tags origin "refs/tags/${TAG}" 2>/dev/null | grep -q .; then
  fail "tag $TAG already exists on origin"
else
  pass "tag $TAG not present on origin"
fi

# ── npm registry name free / owned ────────────────────────────────────────
HTTP=$(curl -s -o /tmp/orca-preflight-npm.json -w '%{http_code}' "https://registry.npmjs.org/${NAME}" || echo 000)
if [[ "$HTTP" == "404" ]]; then
  pass "npm name '${NAME}' free (first publish will claim it)"
elif [[ "$HTTP" == "200" ]]; then
  REMOTE_VER=$(node -p 'JSON.parse(require("fs").readFileSync("/tmp/orca-preflight-npm.json","utf8"))["dist-tags"]?.latest || "?"' 2>/dev/null || echo '?')
  if node -e "const a=process.argv[1],b=process.argv[2];const pa=a.split('.').map(Number),pb=b.split('.').map(Number);for(let i=0;i<3;i++){if((pa[i]||0)>(pb[i]||0))process.exit(0);if((pa[i]||0)<(pb[i]||0))process.exit(1)}" "$VERSION" "$REMOTE_VER" 2>/dev/null; then
    pass "npm ${NAME}@${REMOTE_VER} exists; local ${VERSION} is newer/ok for publish"
  elif [[ "$VERSION" == "$REMOTE_VER" ]]; then
    fail "npm already has ${NAME}@${VERSION} — bump version before re-tagging"
  else
    warn "npm has ${NAME}@${REMOTE_VER}; local is ${VERSION} — confirm you intend this version"
  fi
else
  warn "could not query registry.npmjs.org (HTTP $HTTP)"
fi

# ── GitHub secrets + repo visibility ──────────────────────────────────────
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  if gh secret list -R BuildContext/orca-mcp 2>/dev/null | grep -q '^NPM_TOKEN'; then
    pass "GitHub secret NPM_TOKEN is set on BuildContext/orca-mcp"
  else
    fail "GitHub secret NPM_TOKEN missing on BuildContext/orca-mcp"
  fi
  VIS=$(gh api repos/BuildContext/orca-mcp --jq .visibility 2>/dev/null || echo unknown)
  if [[ "$VIS" == "public" ]]; then
    pass "GitHub repo is public"
  else
    warn "GitHub repo visibility is '${VIS}' — make public before OSS consumers can clone (npm/GHCR can still publish)"
  fi
  if gh api "users/BuildContext/packages/container/orca-mcp" >/dev/null 2>&1; then
    pass "GHCR package buildcontext/orca-mcp already exists"
  else
    pass "GHCR package not yet created (first release.yml run will create it via GITHUB_TOKEN)"
  fi
else
  warn "gh not ready — skipped secret/visibility checks"
fi

# ── optional docker ───────────────────────────────────────────────────────
# Prefer direct docker; fall back to `sg docker` when the process lacks the
# group (common after usermod until re-login). Durable membership: usermod -aG docker.
_docker() {
  if docker info >/dev/null 2>&1; then
    docker "$@"
  elif command -v sg >/dev/null 2>&1 && sg docker -c 'docker info' >/dev/null 2>&1; then
    # Quote args for the nested shell.
    local q=() a
    for a in "$@"; do q+=("$(printf '%q' "$a")"); done
    sg docker -c "docker ${q[*]}"
  else
    return 127
  fi
}

if _docker info >/dev/null 2>&1; then
  if _docker build -t "orca-mcp-preflight:${VERSION}" . >/tmp/orca-preflight-docker.log 2>&1; then
    pass "docker build ok (local tag orca-mcp-preflight:${VERSION})"
  else
    fail "docker build failed — see /tmp/orca-preflight-docker.log"
  fi
else
  warn "docker unavailable or no permission (sock) — skip image build; GHCR job will build in Actions"
  note "  fix: sudo usermod -aG docker \"\$USER\" && newgrp docker   # or: sg docker -c 'docker …'"
fi

printf '\n'
if [[ "$FAILED" -ne 0 ]]; then
  printf '%sPreflight FAILED%s — fix the items above before tagging.\n\n' "$RED" "$RESET"
  exit 1
fi

printf '%sPreflight OK%s — ready to release %s\n\n' "$GREEN" "$RESET" "$TAG"
printf 'Next (human / intentional publish):\n'
printf '  1. Make repo public (if still private):\n'
printf '       gh repo edit BuildContext/orca-mcp --visibility public\n'
printf '  2. Ensure main is the commit you want (already pushed).\n'
printf '  3. Tag and push (triggers release.yml → npm + GHCR + GitHub Release):\n'
printf '       git checkout main && git pull --ff-only\n'
printf '       git tag -a %s -m "orca-mcp %s"\n' "$TAG" "$VERSION"
printf '       git push origin %s\n' "$TAG"
printf '  4. Watch: gh run watch -R BuildContext/orca-mcp\n'
printf '  5. Verify:\n'
printf '       npm view orca-mcp version\n'
printf '       docker pull ghcr.io/buildcontext/orca-mcp:%s\n\n' "$VERSION"
exit 0
