#!/usr/bin/env bash
# secured-claude — L2 (egress proxy) + L3 (DNS allowlist) end-to-end test.
#
# Boots the dns-filter + egress-proxy sidecars from docker-compose.yml,
# then asserts :
#   * Allowed domain (api.anthropic.com) — proxy passes through ; DNS resolves.
#   * Denied domain (evil.com) — proxy returns 403 ; DNS returns REFUSED.
#
# Exit 0 ⇒ both layers enforce as designed (ADR-0019 + ADR-0020).
# Exit 1 ⇒ the contract broke ; do NOT tag a release.
#
# Used :
#   * Locally — bin/test-egress.sh before tagging a release
#   * In CI (future v0.3) — security:l2-l3-enforcement job
#   * As a release gate — exit 1 ⇒ no tag

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}" || { echo "FATAL: cannot cd to ${REPO_ROOT}" >&2; exit 1; }

EGRESS_IP="172.30.42.4"
DNS_IP="172.30.42.3"
CURL_IMAGE="alpine:3.20"

# shellcheck disable=SC2329
cleanup() {
    docker compose down >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "===== boot dns-filter + egress-proxy ====="
docker compose up -d dns-filter egress-proxy >/dev/null 2>&1 || {
    echo "FATAL: docker compose up failed" >&2
    docker compose logs dns-filter egress-proxy 2>&1 | tail -30 >&2
    exit 1
}

# Wait for both healthchecks to pass — up to 60 s.
echo "===== wait for healthy ====="
for i in $(seq 1 60); do
    dns_h=$(docker inspect --format '{{.State.Health.Status}}' secured-claude-dns 2>/dev/null || echo "starting")
    egress_h=$(docker inspect --format '{{.State.Health.Status}}' secured-claude-egress 2>/dev/null || echo "starting")
    if [ "$dns_h" = "healthy" ] && [ "$egress_h" = "healthy" ]; then
        echo "  ✓ both healthy after ${i}s"
        break
    fi
    sleep 1
done
if [ "$dns_h" != "healthy" ] || [ "$egress_h" != "healthy" ]; then
    echo "FATAL: containers not healthy (dns=$dns_h egress=$egress_h)" >&2
    exit 1
fi

PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# L3 — DNS allowlist
# ---------------------------------------------------------------------------

echo ""
echo "===== L3 DNS allowlist ====="

# DNS allowed : api.anthropic.com → resolves
allowed_rc=$(docker run --rm --network secured-claude-net "${CURL_IMAGE}" \
    sh -c "nslookup api.anthropic.com ${DNS_IP} >/dev/null 2>&1" 2>/dev/null && echo 0 || echo 1)
if [ "$allowed_rc" = "0" ]; then
    echo "  ✓ DNS-ALLOW api.anthropic.com — resolves"
    PASS=$((PASS+1))
else
    echo "  ✗ DNS-ALLOW api.anthropic.com — UNEXPECTED FAIL"
    FAIL=$((FAIL+1))
fi

# DNS denied : evil.com → REFUSED (nslookup output contains "REFUSED")
denied_out=$(docker run --rm --network secured-claude-net "${CURL_IMAGE}" \
    sh -c "nslookup evil.com ${DNS_IP} 2>&1" 2>/dev/null)
if echo "$denied_out" | grep -q "REFUSED"; then
    echo "  ✓ DNS-DENY  evil.com — REFUSED"
    PASS=$((PASS+1))
else
    echo "  ✗ DNS-DENY  evil.com — DID NOT RETURN REFUSED"
    echo "     output : ${denied_out}"
    FAIL=$((FAIL+1))
fi

# ---------------------------------------------------------------------------
# L2 — HTTP egress proxy (CONNECT allowlist)
# ---------------------------------------------------------------------------

echo ""
echo "===== L2 egress allowlist ====="

# Egress allowed : api.anthropic.com — CONNECT tunnel succeeds (any HTTP code, even 405)
allowed_http=$(docker run --rm --network secured-claude-net "${CURL_IMAGE}" \
    sh -c "apk add --no-cache curl >/dev/null 2>&1 && \
           curl -sS --max-time 8 -o /dev/null -w '%{http_code}' \
             -x http://${EGRESS_IP}:3128 \
             https://api.anthropic.com/v1/messages 2>/dev/null || echo 000" 2>/dev/null)
if [ "$allowed_http" != "000" ] && [ "$allowed_http" != "" ]; then
    echo "  ✓ EGRESS-ALLOW api.anthropic.com — http_code=${allowed_http} (tunnel succeeded)"
    PASS=$((PASS+1))
else
    echo "  ✗ EGRESS-ALLOW api.anthropic.com — tunnel failed (got ${allowed_http})"
    FAIL=$((FAIL+1))
fi

# Egress denied : evil.com — proxy returns 403 (curl exit 56 "CONNECT tunnel failed")
denied_curl_rc=$(docker run --rm --network secured-claude-net "${CURL_IMAGE}" \
    sh -c "apk add --no-cache curl >/dev/null 2>&1 && \
           curl -sS --max-time 6 -o /dev/null \
             -x http://${EGRESS_IP}:3128 \
             https://evil.com 2>&1; echo \$?" 2>/dev/null | tail -1)
# curl exit codes : 56 = CONNECT tunnel failed (expected) ; 0 = passthrough (BAD)
if [ "$denied_curl_rc" = "56" ] || [ "$denied_curl_rc" = "22" ]; then
    echo "  ✓ EGRESS-DENY  evil.com — proxy refused (curl rc=${denied_curl_rc})"
    PASS=$((PASS+1))
else
    echo "  ✗ EGRESS-DENY  evil.com — UNEXPECTED rc=${denied_curl_rc} (proxy may have allowed)"
    FAIL=$((FAIL+1))
fi

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

echo ""
echo "===== verdict ====="
echo "  pass=${PASS}"
echo "  fail=${FAIL}"
if [ $FAIL -gt 0 ]; then
    echo ""
    echo "  ✗ L2 / L3 contract broken — do NOT tag a release."
    echo "  Re-run individual tests against ${EGRESS_IP}:3128 / ${DNS_IP} to debug."
    exit 1
fi
echo "  ✓ L2 + L3 enforced end-to-end (4/4 assertions PASS)"
echo ""
echo "Reproduces ADR-0019 (egress proxy) + ADR-0020 (DNS allowlist) on every"
echo "release. Tag is safe to push."
exit 0
