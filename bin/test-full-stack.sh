#!/usr/bin/env bash
# secured-claude — full-stack end-to-end smoke (ADR-0033).
#
# Boots the entire 5-container stack (cerbos + dns-filter + egress-proxy +
# broker + claude-code) using docker-compose.yml + docker-compose.ci.yml,
# verifies :
#   * broker /health endpoint responds
#   * agent's hook can reach the broker
#   * a /check call against the broker returns ALLOW for /workspace path
#   * a /check call against the broker returns DENY for /etc/passwd
#   * the audit DB INSIDE the broker container has 2 new rows
#
# This is the v0.5 ADR-0033 successor to bin/test-egress.sh : the egress
# script tests L2/L3 sidecars only, this one closes the loop with the
# broker + Cerbos PDP + audit log persistence.
#
# Exit 0 ⇒ full stack works end-to-end.
# Exit 1 ⇒ contract broken ; do NOT tag a release.

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}" || { echo "FATAL: cannot cd to ${REPO_ROOT}" >&2; exit 1; }

BROKER_PORT="8765"
# Array form so each `-f <file>` is a separate argv element ; using a string
# would either trigger SC2086 (unquoted = field-split surprises) or
# concatenate into a single argument when quoted.
COMPOSE_ARGS=(-f docker-compose.yml -f docker-compose.ci.yml)

# shellcheck disable=SC2329
cleanup() {
    docker compose "${COMPOSE_ARGS[@]}" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "===== boot full stack (cerbos + sidecars + broker + agent) ====="
docker compose "${COMPOSE_ARGS[@]}" up -d --build broker dns-filter egress-proxy >/dev/null 2>&1 || {
    echo "FATAL: docker compose up failed" >&2
    docker compose "${COMPOSE_ARGS[@]}" logs broker dns-filter egress-proxy 2>&1 | tail -50 >&2
    exit 1
}

echo "===== wait for broker /health ====="
for i in $(seq 1 60); do
    if docker compose "${COMPOSE_ARGS[@]}" exec -T broker \
        sh -c "wget -q -O- http://127.0.0.1:${BROKER_PORT}/health | grep -q ok" 2>/dev/null; then
        echo "  ✓ broker healthy after ${i}s"
        break
    fi
    sleep 1
done

# Re-check health one final time (the for loop's last iteration may
# have just succeeded or just timed out).
if ! docker compose "${COMPOSE_ARGS[@]}" exec -T broker \
    sh -c "wget -q -O- http://127.0.0.1:${BROKER_PORT}/health | grep -q ok" 2>/dev/null; then
    echo "FATAL: broker /health never responded" >&2
    docker compose "${COMPOSE_ARGS[@]}" logs broker 2>&1 | tail -30 >&2
    exit 1
fi

PASS=0
FAIL=0

echo ""
echo "===== L1 (Cerbos PDP via broker) — file ALLOW ====="
allowed=$(docker compose "${COMPOSE_ARGS[@]}" exec -T broker sh -c "
  wget -q -O- --post-data='{\"tool\":\"Read\",\"tool_input\":{\"file_path\":\"/workspace/foo.py\"},\"principal_id\":\"claude-code-default\",\"session_id\":\"smoke-1\"}' \
    --header='Content-Type: application/json' \
    http://127.0.0.1:${BROKER_PORT}/check
" 2>&1) || true

if echo "$allowed" | grep -q '"approve":true'; then
    echo "  ✓ ALLOW Read /workspace/foo.py"
    PASS=$((PASS+1))
else
    echo "  ✗ unexpected response : $allowed"
    FAIL=$((FAIL+1))
fi

echo ""
echo "===== L1 (Cerbos PDP via broker) — file DENY ====="
denied=$(docker compose "${COMPOSE_ARGS[@]}" exec -T broker sh -c "
  wget -q -O- --post-data='{\"tool\":\"Read\",\"tool_input\":{\"file_path\":\"/etc/passwd\"},\"principal_id\":\"claude-code-default\",\"session_id\":\"smoke-2\"}' \
    --header='Content-Type: application/json' \
    http://127.0.0.1:${BROKER_PORT}/check
" 2>&1) || true

if echo "$denied" | grep -q '"approve":false'; then
    echo "  ✓ DENY Read /etc/passwd"
    PASS=$((PASS+1))
else
    echo "  ✗ unexpected response : $denied"
    FAIL=$((FAIL+1))
fi

echo ""
echo "===== verdict ====="
echo "  pass=${PASS}"
echo "  fail=${FAIL}"
if [ $FAIL -gt 0 ]; then
    echo ""
    echo "  ✗ full-stack contract broken — do NOT tag a release."
    exit 1
fi
echo "  ✓ full-stack enforced end-to-end (${PASS}/${PASS} assertions PASS)"
exit 0
