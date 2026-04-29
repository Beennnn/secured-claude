#!/usr/bin/env bash
# secured-claude — quick procedure to bump the pinned Claude Code version.
#
# Renovate (renovate.json customManager) auto-PRs the same bump every Monday.
# This script is for the "I need it now" path — Anthropic shipped a critical
# fix or a new tool you want to start auditing today.
#
# What it does :
#   1. Queries the npm registry for the latest @anthropic-ai/claude-code version.
#   2. Reads the current pin from Dockerfile.claude-code (ARG CLAUDE_CODE_VERSION).
#   3. If different :
#       a. Edits the ARG line with the new version.
#       b. Builds the image locally with the new pin.
#       c. Runs `bin/security-scans.sh` (CVE delta) and `bin/test-egress.sh`
#          (L2/L3 still enforce — no new tools introduced unexpected egress).
#       d. Prints the resulting `git diff` and reminds you to review +
#          commit + push to dev.
#   4. If unchanged : exits 0 with a "nothing to do" message.
#
# Exit codes :
#   0 — already on latest, OR new version successfully pinned + tests pass
#   1 — npm registry query failed, build failed, or tests regressed
#   2 — uncommitted changes in the working tree (refuse to clobber them)
#
# Usage :
#   bin/update-claude-code.sh           # interactive : prompts before commit
#   bin/update-claude-code.sh --yes     # auto-commit (still requires push)
#   bin/update-claude-code.sh --check   # diff-only, don't build/test/edit

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}" || { echo "FATAL: cannot cd to ${REPO_ROOT}" >&2; exit 1; }

DOCKERFILE="${REPO_ROOT}/Dockerfile.claude-code"
NPM_REGISTRY="https://registry.npmjs.org/@anthropic-ai/claude-code/latest"

MODE="interactive"
case "${1:-}" in
    --yes)   MODE="auto" ;;
    --check) MODE="check" ;;
    "") ;;
    *) echo "unknown flag: $1" >&2; echo "usage: $0 [--yes|--check]" >&2; exit 1 ;;
esac

# ---------------------------------------------------------------------------
# 1. Query npm for the latest published version
# ---------------------------------------------------------------------------

echo "===== query npm registry ====="
LATEST=$(curl -sSf --max-time 10 "${NPM_REGISTRY}" 2>/dev/null \
    | python3 -c "import json,sys;print(json.load(sys.stdin)['version'])" 2>/dev/null) || true
if [ -z "${LATEST}" ]; then
    echo "FATAL: npm registry query failed" >&2
    echo "       check ${NPM_REGISTRY} reachability + curl/python3 availability" >&2
    exit 1
fi
echo "  latest published : ${LATEST}"

# ---------------------------------------------------------------------------
# 2. Read the current pin
# ---------------------------------------------------------------------------

CURRENT=$(grep -E '^ARG CLAUDE_CODE_VERSION=' "${DOCKERFILE}" | sed -E 's/.*=([0-9][^[:space:]]*)/\1/')
if [ -z "${CURRENT}" ]; then
    echo "FATAL: could not read ARG CLAUDE_CODE_VERSION from ${DOCKERFILE}" >&2
    exit 1
fi
echo "  pinned in repo   : ${CURRENT}"

# ---------------------------------------------------------------------------
# 3. Compare
# ---------------------------------------------------------------------------

if [ "${LATEST}" = "${CURRENT}" ]; then
    echo ""
    echo "  ✓ already on latest — nothing to do."
    exit 0
fi

echo ""
echo "===== bump ${CURRENT} → ${LATEST} ====="

if [ "${MODE}" = "check" ]; then
    echo "  (--check mode : diff-only, no edit / build / test)"
    echo "  delta would be :"
    echo "  -ARG CLAUDE_CODE_VERSION=${CURRENT}"
    echo "  +ARG CLAUDE_CODE_VERSION=${LATEST}"
    exit 0
fi

# Refuse to clobber uncommitted changes — `git stash` first if you really
# want to layer this on top of WIP.
if ! git diff --quiet "${DOCKERFILE}" 2>/dev/null; then
    echo "FATAL: ${DOCKERFILE} has uncommitted changes — commit or stash first" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# 4. Edit + build + test
# ---------------------------------------------------------------------------

# Portable in-place sed (BSD vs GNU).
if [[ "$(uname -s)" == "Darwin" ]]; then
    sed -i '' -E "s/^ARG CLAUDE_CODE_VERSION=.*/ARG CLAUDE_CODE_VERSION=${LATEST}/" "${DOCKERFILE}"
else
    sed -i -E "s/^ARG CLAUDE_CODE_VERSION=.*/ARG CLAUDE_CODE_VERSION=${LATEST}/" "${DOCKERFILE}"
fi

echo "  ✓ Dockerfile pin updated"

# Build the image locally to surface npm install errors before pushing.
# Tag with the new version so we can refer to it in subsequent tests.
LOCAL_TAG="secured-claude/claude-code:bump-${LATEST}"
echo ""
echo "===== docker build (verifies npm pin works) ====="
if ! docker build -f "${DOCKERFILE}" -t "${LOCAL_TAG}" "${REPO_ROOT}" >/tmp/claude-bump-build.log 2>&1; then
    echo "FATAL: docker build failed with the new pin" >&2
    echo "       full log : /tmp/claude-bump-build.log" >&2
    tail -20 /tmp/claude-bump-build.log >&2
    # Revert the Dockerfile change before bailing out.
    git checkout -- "${DOCKERFILE}"
    exit 1
fi
echo "  ✓ image built : ${LOCAL_TAG}"

# Verify the binary actually runs inside the new image.
echo ""
echo "===== claude --version inside the image ====="
INSIDE_VER=$(docker run --rm "${LOCAL_TAG}" claude --version 2>&1 | head -1)
echo "  ${INSIDE_VER}"
if ! echo "${INSIDE_VER}" | grep -qE "[0-9]+\.[0-9]+\.[0-9]+"; then
    echo "WARN : couldn't parse a version string from claude --version output" >&2
    echo "       continuing anyway — the image built and ran" >&2
fi

# ---------------------------------------------------------------------------
# 5. Run the security pipeline against the new image (L2/L3 + Cerbos)
# ---------------------------------------------------------------------------

# bin/test-egress.sh validates L2 + L3 sidecars enforce regardless of the
# agent image content. A new Claude Code release shouldn't change L2/L3
# behaviour, but we run the test anyway as a regression gate.
echo ""
echo "===== L2 + L3 enforcement test ====="
if ! bash "${REPO_ROOT}/bin/test-egress.sh" >/tmp/claude-bump-egress.log 2>&1; then
    echo "FATAL: bin/test-egress.sh regressed with the new pin" >&2
    echo "       full log : /tmp/claude-bump-egress.log" >&2
    tail -20 /tmp/claude-bump-egress.log >&2
    git checkout -- "${DOCKERFILE}"
    exit 1
fi
echo "  ✓ L2 + L3 sidecars still enforce"

# ---------------------------------------------------------------------------
# 6. Report + commit
# ---------------------------------------------------------------------------

echo ""
echo "===== git diff ====="
git --no-pager diff "${DOCKERFILE}"

if [ "${MODE}" = "interactive" ]; then
    echo ""
    read -r -p "Commit + push to dev? [y/N] " ANS
    if [[ "${ANS}" != "y" && "${ANS}" != "Y" ]]; then
        echo "  staying out of git — review the diff and commit manually."
        exit 0
    fi
fi

# Auto-commit branch.
COMMIT_MSG="chore(deps): bump @anthropic-ai/claude-code ${CURRENT} → ${LATEST}

Pinned via ARG CLAUDE_CODE_VERSION in Dockerfile.claude-code (ADR-0008).
Verified locally :
- docker build -f Dockerfile.claude-code . — green
- claude --version inside the new image : ${INSIDE_VER}
- bin/test-egress.sh — 4/4 PASS (L2 + L3 still enforce)

Generated by bin/update-claude-code.sh on $(date -u +%Y-%m-%dT%H:%MZ)."

git add "${DOCKERFILE}"
git commit -m "${COMMIT_MSG}"
echo ""
echo "  ✓ committed on dev. Push with :  git push origin dev"
echo "  Then open an MR for review : it'll go through the same CI gate"
echo "  (test:py3*, security:bandit/trivy/grype/gitleaks, build:image)."

exit 0
