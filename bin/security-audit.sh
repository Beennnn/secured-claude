#!/usr/bin/env bash
# secured-claude — end-to-end security audit demonstration.
#
# Boots a real Cerbos PDP container, runs the 26-scenario red-team +
# happy-path battery against it, writes a Markdown report, and exits
# non-zero if any red-team scenario was approved (= adversary won).
#
# Used :
#   * Locally — bin/security-audit.sh before tagging a release
#   * In CI — security:full-audit job (per .gitlab-ci/security.yml)
#   * As a release gate — exit 1 ⇒ no tag

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}" || { echo "FATAL: cannot cd to ${REPO_ROOT}" >&2; exit 1; }

CERBOS_IMAGE="cerbos/cerbos:0.42.0"
CERBOS_PORT="${CERBOS_PORT:-3592}"
CERBOS_NAME="secured-claude-audit-cerbos"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT_DIR="${REPORT_DIR:-${REPO_ROOT}/audit-reports}"
REPORT_PATH="${REPORT_DIR}/audit-${TS}.md"
mkdir -p "${REPORT_DIR}"

# shellcheck disable=SC2329  # invoked by `trap cleanup EXIT`, not statically detectable
cleanup() {
    if docker ps -a --format '{{.Names}}' | grep -q "^${CERBOS_NAME}$"; then
        docker rm -f "${CERBOS_NAME}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "===== boot Cerbos PDP ====="
docker run -d --rm \
    --name "${CERBOS_NAME}" \
    -p "127.0.0.1:${CERBOS_PORT}:3592" \
    -v "${REPO_ROOT}/policies:/policies:ro" \
    -v "${REPO_ROOT}/cerbos/config.yaml:/etc/cerbos/config.yaml:ro" \
    "${CERBOS_IMAGE}" \
    server --config=/etc/cerbos/config.yaml >/dev/null

# Poll until the HTTP API answers /api/_status
echo "===== wait for Cerbos to be healthy ====="
ready=0
for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${CERBOS_PORT}/_cerbos/health" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
if [ "${ready}" -ne 1 ]; then
    echo "FATAL: Cerbos PDP did not become healthy in 30s" >&2
    docker logs "${CERBOS_NAME}" >&2 || true
    exit 1
fi

echo "===== run audit-demo ====="
if ! uv run python -m secured_claude.audit_demo \
        --cerbos-url "http://127.0.0.1:${CERBOS_PORT}" \
        --report "${REPORT_PATH}"; then
    echo ""
    echo "===== AUDIT FAILED — see ${REPORT_PATH} ====="
    exit 1
fi

echo ""
echo "===== AUDIT PASSED — ${REPORT_PATH} ====="
exit 0
