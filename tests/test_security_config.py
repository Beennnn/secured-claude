"""Tests that the project's security configuration is in effect.

These tests don't run scanners — they verify that the *configuration* a
scanner depends on is present and correct. The scanners themselves run in CI
and `bin/security-scans.sh` per ADR-0017.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_pyproject() -> dict:
    """Read and parse pyproject.toml at the repo root."""
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as f:
        return tomllib.load(f)


def test_pyproject_exists() -> None:
    assert (PROJECT_ROOT / "pyproject.toml").exists()


def test_ruff_select_includes_security_S_rules() -> None:
    """Ruff must include the S (flake8-bandit) rule set as our primary security lint."""
    cfg = _load_pyproject()
    select = cfg["tool"]["ruff"]["lint"]["select"]
    assert "S" in select, f"ruff lint.select must include 'S' for security rules, got {select}"


def test_ruff_does_not_ignore_S603() -> None:
    """S603 (subprocess shell=False + argv list) must remain enforced — see ADR-0017."""
    cfg = _load_pyproject()
    ignore = cfg["tool"]["ruff"]["lint"].get("ignore", [])
    assert "S603" not in ignore, "S603 must remain enforced per ADR-0017"


def test_mypy_strict_mode_on() -> None:
    cfg = _load_pyproject()
    mypy = cfg["tool"]["mypy"]
    assert mypy.get("strict") is True
    assert mypy.get("disallow_untyped_defs") is True


def test_coverage_fail_under_at_least_90() -> None:
    cfg = _load_pyproject()
    fail_under = cfg["tool"]["coverage"]["report"]["fail_under"]
    assert fail_under >= 90, f"coverage gate must be ≥ 90, got {fail_under}"


def test_coverage_branch_enabled() -> None:
    cfg = _load_pyproject()
    branch = cfg["tool"]["coverage"]["run"]["branch"]
    assert branch is True, "coverage must include branch coverage for meaningful security tests"


def test_bandit_only_skips_documented_rules() -> None:
    """bandit may only skip rules whose rationale is documented in ADR-0017."""
    cfg = _load_pyproject()
    skips = cfg["tool"]["bandit"].get("skips", [])
    documented_skips = {"B404", "B603"}
    extra = set(skips) - documented_skips
    assert not extra, (
        f"bandit skips must be documented in ADR-0017 ; un-documented skip(s) : {extra}. "
        "Either add an ADR entry justifying the skip or remove it."
    )


def test_pyproject_python_version_pin() -> None:
    """Project must require Python ≥ 3.11 (security baseline ; older Pythons are EOL)."""
    cfg = _load_pyproject()
    requires = cfg["project"]["requires-python"]
    assert any(requires.startswith(prefix) for prefix in (">=3.11", ">=3.12", ">=3.13"))


def test_security_scans_script_is_executable() -> None:
    """The bin/security-scans.sh entrypoint must be present and executable."""
    script = PROJECT_ROOT / "bin" / "security-scans.sh"
    assert script.exists(), "bin/security-scans.sh missing — see ADR-0017"
    if sys.platform != "win32":
        assert script.stat().st_mode & 0o111, "bin/security-scans.sh must be executable"


def test_adr_0017_present() -> None:
    """ADR-0017 must exist and reference all 7 pipeline layers."""
    adr = PROJECT_ROOT / "docs" / "adr" / "0017-security-testing-evidence-pipeline.md"
    assert adr.exists()
    text = adr.read_text(encoding="utf-8")
    # The 7 layer headings should appear in some form
    for keyword in ("ruff", "mypy", "bandit", "pip-audit", "gitleaks", "trivy", "cerbos"):
        assert keyword in text.lower(), f"ADR-0017 must reference scanner '{keyword}'"


def test_security_evidence_doc_present() -> None:
    """docs/security/security-evidence.md must exist and reference latest run."""
    doc = PROJECT_ROOT / "docs" / "security" / "security-evidence.md"
    assert doc.exists()
    text = doc.read_text(encoding="utf-8")
    assert "Latest run" in text
    assert "verdict" in text.lower()
