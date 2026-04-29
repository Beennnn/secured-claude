"""Tests for the audit-demo scenario battery (no real Cerbos required).

We mock CerbosClient.check so we can verify :
  * The scenario set covers every threat class
  * The report renders correctly for both PASS and FAIL outcomes
  * The runner returns exit 0 when expectations match, 1 otherwise

The HTTP-level integration tests (real Cerbos PDP container) live in
`bin/security-audit.sh` which boots Cerbos and runs the same scenarios.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from secured_claude import audit_demo
from secured_claude.cerbos_client import CheckResult


def _make_oracle(predict: dict[str, str]) -> MagicMock:
    """Mock CerbosClient that returns ALLOW/DENY based on the oracle map.

    `predict` maps Scenario.label substrings to "ALLOW" or "DENY". Any label
    not matched defaults to DENY (closed-surface).
    """
    client = MagicMock()

    def fake_check(**kwargs: Any) -> CheckResult:
        label = kwargs.get("resource_id", "")
        # Defaults to DENY ; ALLOW only if any predict key is in the resource_id
        decision = "DENY"
        for key, want in predict.items():
            if key in str(label) or key in str(kwargs.get("resource_attr", {})):
                decision = want
                break
        allow = decision == "ALLOW"
        return CheckResult(
            allow=allow,
            reason=f"effect=EFFECT_{'ALLOW' if allow else 'DENY'} (mocked)",
            duration_ms=2,
            raw={},
        )

    client.check.side_effect = fake_check
    return client


def test_scenarios_cover_every_threat_class() -> None:
    """Every STRIDE-aligned class must have ≥ 1 scenario."""
    classes = {s.threat_class for s in audit_demo.SCENARIOS}
    expected = {
        "FS exfil",
        "FS inject",
        "Shell RCE",
        "Net exfil",
        "MCP abuse",
        "Path traversal",
        "Happy path",
    }
    assert expected.issubset(classes), f"missing: {expected - classes}"


def test_at_least_one_red_team_per_class() -> None:
    """Every red-team class (not Happy path) must have ≥ 1 scenario expecting DENY."""
    by_class: dict[str, list[audit_demo.Scenario]] = {}
    for s in audit_demo.SCENARIOS:
        by_class.setdefault(s.threat_class, []).append(s)
    for cls, items in by_class.items():
        if cls == "Happy path":
            continue
        denies = [s for s in items if s.expected_decision == "DENY"]
        assert denies, f"red-team class {cls!r} has no DENY scenario"


def test_happy_paths_present() -> None:
    """Happy-path scenarios prevent over-blocking ; ≥ 4 expected ALLOW."""
    happy = [s for s in audit_demo.SCENARIOS if s.threat_class == "Happy path"]
    allows = [s for s in happy if s.expected_decision == "ALLOW"]
    assert len(allows) >= 4


def test_demo_passes_when_oracle_matches_expectations() -> None:
    """When the mock denies red-team and allows happy-path, all scenarios pass."""
    # Predict ALLOW only for /workspace/ paths (happy paths) and dev commands
    client = _make_oracle(
        {
            "/workspace/src/foo.py": "ALLOW",
            "/workspace/bar.py": "ALLOW",
            "/workspace/baz.py": "ALLOW",
            "git status --short": "ALLOW",
            "npm install": "ALLOW",
            "uv sync": "ALLOW",
            "python -m pytest tests/": "ALLOW",
        }
    )
    report = audit_demo.run_demo(client)
    assert report.all_passed
    assert report.passed_count == report.total
    assert report.failed_count == 0


def test_demo_fails_when_red_team_passes() -> None:
    """If Cerbos mistakenly approves a red-team scenario, the demo fails."""
    # Allow EVERYTHING — every red-team scenario will mistakenly pass = bad
    client = MagicMock()
    client.check.return_value = CheckResult(
        allow=True, reason="effect=EFFECT_ALLOW (mocked)", duration_ms=1, raw={}
    )
    report = audit_demo.run_demo(client)
    assert not report.all_passed
    # Every red-team should fail (because all are ALLOWed when they should be DENY)
    failures = [r for r in report.results if not r.passed]
    assert all(r.scenario.expected_decision == "DENY" for r in failures)


def test_render_markdown_for_passing_run() -> None:
    """Markdown output contains the verdict and per-scenario rows."""

    # Use the same oracle logic as test_main_returns_0_when_all_pass to ensure
    # all 26 scenarios match expectations.
    def oracle_check(**kwargs: Any) -> CheckResult:
        rid = str(kwargs.get("resource_id", ""))
        attr = kwargs.get("resource_attr", {})
        allow = ("/workspace/" in rid and ".env" not in rid and "../" not in rid) or attr.get(
            "cmd_first_word"
        ) in {"git", "npm", "uv", "python", "python3"}
        return CheckResult(
            allow=allow,
            reason=f"effect=EFFECT_{'ALLOW' if allow else 'DENY'}",
            duration_ms=2,
            raw={},
        )

    client = MagicMock()
    client.check.side_effect = oracle_check
    report = audit_demo.run_demo(client)
    md = audit_demo.render_markdown(report)
    assert "Security audit demonstration" in md
    assert "PASS" in md
    assert "R1.1" in md  # scenario IDs surface in the table
    assert "H1.1" in md


def test_render_markdown_for_failing_run_has_failures_section() -> None:
    client = MagicMock()
    client.check.return_value = CheckResult(
        allow=True, reason="effect=EFFECT_ALLOW", duration_ms=1, raw={}
    )
    report = audit_demo.run_demo(client)
    md = audit_demo.render_markdown(report)
    assert "FAIL" in md
    assert "## Failures" in md
    assert "R1.1" in md  # at least one red-team scenario in the failures list


def test_main_returns_0_when_all_pass(monkeypatch, tmp_path) -> None:
    """The CLI entrypoint exits 0 on full pass, writes a report file."""

    # Build an oracle that satisfies every expected_decision in SCENARIOS
    def oracle_check(**kwargs: Any) -> CheckResult:
        rid = str(kwargs.get("resource_id", ""))
        attr = kwargs.get("resource_attr", {})
        # Default DENY, then ALLOW for the known happy paths
        allow = ("/workspace/" in rid and ".env" not in rid and "../" not in rid) or attr.get(
            "cmd_first_word"
        ) in {"git", "npm", "uv", "python", "python3"}
        return CheckResult(
            allow=allow,
            reason=f"effect=EFFECT_{'ALLOW' if allow else 'DENY'}",
            duration_ms=2,
            raw={},
        )

    fake_client = MagicMock()
    fake_client.check.side_effect = oracle_check
    monkeypatch.setattr("secured_claude.audit_demo.CerbosClient", lambda **kw: fake_client)

    report_path = tmp_path / "report.md"
    rc = audit_demo.main(["--report", str(report_path), "--cerbos-url", "http://test"])
    assert rc == 0
    assert report_path.exists()
    content = report_path.read_text()
    assert "PASS" in content


def test_main_returns_1_when_any_red_team_passes(monkeypatch, tmp_path) -> None:
    fake_client = MagicMock()
    fake_client.check.return_value = CheckResult(
        allow=True, reason="all-allow", duration_ms=1, raw={}
    )
    monkeypatch.setattr("secured_claude.audit_demo.CerbosClient", lambda **kw: fake_client)

    report_path = tmp_path / "fail.md"
    rc = audit_demo.main(["--report", str(report_path)])
    assert rc == 1
    assert "FAIL" in report_path.read_text()
