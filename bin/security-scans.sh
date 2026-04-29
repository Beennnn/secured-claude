#!/usr/bin/env bash
# secured-claude — security scan harness.
#
# Runs every static / supply-chain scan we declare in `docs/security/security-
# evidence.md` and prints a green-or-red summary. Suitable for :
#
#   * Local dev — `bin/security-scans.sh` before opening an MR
#   * CI — invoked by the `security` stage of the GitLab pipeline (ADR-0014)
#   * Release gate — invoked before tagging vX.Y.Z (ADR-0014, ADR-0017)
#
# A non-zero exit means at least one scan failed ; the release MUST NOT ship.
#
# Optional env vars :
#   STRICT=1                  fail on any LOW finding too (default: HIGH/CRITICAL)
#   SCAN_REPORTS_DIR=path     directory for JSON/SPDX outputs (default: ./audit-reports/scans-<ts>)

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}" || { echo "FATAL: cannot cd to ${REPO_ROOT}" >&2; exit 1; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
REPORTS_DIR="${SCAN_REPORTS_DIR:-${REPO_ROOT}/audit-reports/scans-${TS}}"
mkdir -p "${REPORTS_DIR}"

STRICT="${STRICT:-0}"
SEVERITY_GATE="HIGH,CRITICAL"
[[ "${STRICT}" == "1" ]] && SEVERITY_GATE="LOW,MEDIUM,HIGH,CRITICAL"

# Track each scan's outcome so we can fail at the end with a summary instead
# of bailing on the first failure (we want all evidence on every run).
OK=()
FAIL=()
SKIP=()

run_scan() {
    local name="$1" ; shift
    local cmd="$*"
    echo ""
    echo "===== ${name} ====="
    if eval "${cmd}"; then
        OK+=("${name}")
        echo "[ ok ] ${name}"
    else
        FAIL+=("${name}")
        echo "[fail] ${name}"
    fi
}

skip_scan() {
    local name="$1" ; shift
    local reason="$*"
    echo ""
    echo "===== ${name} ====="
    echo "[skip] ${name} — ${reason}"
    SKIP+=("${name}")
}

# ---------------------------------------------------------------------------
# Layer 1: Python static analysis (lint + type + security smell)
# ---------------------------------------------------------------------------

if command -v uv >/dev/null 2>&1; then
    run_scan "ruff (lint+security S rules)" \
        "uv run ruff check src/ tests/ 2>&1 | tee '${REPORTS_DIR}/ruff.txt'"
    run_scan "ruff format --check" \
        "uv run ruff format --check src/ tests/ 2>&1 | tee '${REPORTS_DIR}/ruff-format.txt'"
    run_scan "mypy --strict" \
        "uv run mypy src/ 2>&1 | tee '${REPORTS_DIR}/mypy.txt'"
    run_scan "bandit (B404/B603 skipped — see ADR-0017)" \
        "uv run bandit -r src/ -c pyproject.toml -f json -o '${REPORTS_DIR}/bandit.json' --quiet 2>&1"
    run_scan "pip-audit (Python deps CVE)" \
        "uv run pip-audit --skip-editable 2>&1 | tee '${REPORTS_DIR}/pip-audit.txt'"
else
    skip_scan "ruff/mypy/bandit/pip-audit" "uv not found on PATH"
fi

# ---------------------------------------------------------------------------
# Layer 2: Repo-level secret + leak scan
# ---------------------------------------------------------------------------

if command -v gitleaks >/dev/null 2>&1; then
    run_scan "gitleaks (secret scan)" \
        "gitleaks detect --source . --no-git --redact -r '${REPORTS_DIR}/gitleaks.json' 2>&1"
else
    skip_scan "gitleaks" "not installed (brew install gitleaks)"
fi

# ---------------------------------------------------------------------------
# Layer 3: Container & supply-chain scanners
# ---------------------------------------------------------------------------

if command -v trivy >/dev/null 2>&1; then
    run_scan "trivy fs (deps + secrets + config)" \
        "trivy fs --scanners vuln,secret,config --severity '${SEVERITY_GATE}' --exit-code 1 --quiet . 2>&1 | tee '${REPORTS_DIR}/trivy.txt'"
else
    skip_scan "trivy" "not installed (brew install trivy)"
fi

if command -v grype >/dev/null 2>&1; then
    run_scan "grype dir (deps CVE cross-check)" \
        "grype dir:. --fail-on high --quiet 2>&1 | tee '${REPORTS_DIR}/grype.txt'"
else
    skip_scan "grype" "not installed (brew install grype)"
fi

# ---------------------------------------------------------------------------
# Layer 4: Dockerfile + shell hygiene
# ---------------------------------------------------------------------------

if command -v docker >/dev/null 2>&1; then
    run_scan "hadolint (Dockerfile lint)" \
        "docker run --rm -i hadolint/hadolint < Dockerfile.claude-code 2>&1 | tee '${REPORTS_DIR}/hadolint.txt'"
else
    skip_scan "hadolint" "docker not on PATH"
fi

if command -v shellcheck >/dev/null 2>&1; then
    run_scan "shellcheck (POSIX shell)" \
        "shellcheck docker/entrypoint.sh bin/*.sh 2>&1 | tee '${REPORTS_DIR}/shellcheck.txt'"
else
    skip_scan "shellcheck" "not installed (brew install shellcheck)"
fi

# ---------------------------------------------------------------------------
# Layer 5: Cerbos policy compile (the L1 of defense-in-depth)
# ---------------------------------------------------------------------------

if command -v docker >/dev/null 2>&1; then
    run_scan "cerbos compile (PDP policy validation)" \
        "docker run --rm -v '${REPO_ROOT}/policies:/policies:ro' cerbos/cerbos:0.42.0 compile /policies 2>&1 | tee '${REPORTS_DIR}/cerbos-compile.txt'"
fi

# ---------------------------------------------------------------------------
# Layer 6: SBOM generation (artifact)
# ---------------------------------------------------------------------------

if command -v syft >/dev/null 2>&1; then
    run_scan "syft SBOM (SPDX)" \
        "syft scan dir:. -o spdx-json='${REPORTS_DIR}/sbom.spdx.json' --quiet 2>&1"
else
    skip_scan "syft" "not installed (brew install syft)"
fi

# ---------------------------------------------------------------------------
# Layer 7: Test suite + coverage gate
# ---------------------------------------------------------------------------

if command -v uv >/dev/null 2>&1; then
    run_scan "pytest + coverage (gate ≥ 90%)" \
        "uv run pytest tests/ --cov=src/secured_claude --cov-report=term --cov-report=xml:'${REPORTS_DIR}/coverage.xml' 2>&1 | tee '${REPORTS_DIR}/pytest.txt'"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "====================================================================="
echo " Security scan summary — ${TS}"
echo "====================================================================="
echo " ${#OK[@]} ok   : ${OK[*]+${OK[*]}}"
echo " ${#FAIL[@]} fail : ${FAIL[*]+${FAIL[*]}}"
echo " ${#SKIP[@]} skip : ${SKIP[*]+${SKIP[*]}}"
echo ""
echo " Reports in : ${REPORTS_DIR}"
echo "====================================================================="

if [[ "${#FAIL[@]}" -gt 0 ]]; then
    exit 1
fi
exit 0
