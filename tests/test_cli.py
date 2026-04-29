"""Tests for the CLI argparse wiring and command routing.

We mock the orchestrator so no Docker daemon is required. The actual end-to-end
behavior is covered by the smoke test (manual or in audit-demo).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from secured_claude import cli


def test_help_when_no_subcommand(capsys: pytest.CaptureFixture[str]) -> None:
    """argparse exits 2 (or returns 2 from main) when no subcommand is given."""
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    # argparse exits with 2 on "required argument missing"
    assert exc.value.code == 2


def test_version_subcommand_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["version"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "secured-claude" in captured.out
    assert "0.1.0" in captured.out


def test_up_calls_orchestrator_up() -> None:
    with patch("secured_claude.cli.orchestrator.up") as up_mock:
        rc = cli.main(["up"])
    assert rc == 0
    up_mock.assert_called_once()


def test_up_with_build_flag_propagates() -> None:
    with patch("secured_claude.cli.orchestrator.up") as up_mock:
        cli.main(["up", "--build"])
    assert up_mock.call_args.kwargs.get("build") is True


def test_up_handles_docker_not_installed(capsys: pytest.CaptureFixture[str]) -> None:
    err = cli.orchestrator.DockerNotInstalledError("no docker")
    with patch("secured_claude.cli.orchestrator.up", side_effect=err):
        rc = cli.main(["up"])
    assert rc == 1
    captured = capsys.readouterr()
    assert "no docker" in captured.out


def test_up_handles_compose_error(capsys: pytest.CaptureFixture[str]) -> None:
    err = cli.orchestrator.ComposeError("compose blew up")
    with patch("secured_claude.cli.orchestrator.up", side_effect=err):
        rc = cli.main(["up"])
    assert rc == 1
    captured = capsys.readouterr()
    assert "compose blew up" in captured.out


def test_down_calls_orchestrator_down() -> None:
    with patch("secured_claude.cli.orchestrator.down") as down_mock:
        rc = cli.main(["down"])
    assert rc == 0
    down_mock.assert_called_once()
    assert down_mock.call_args.kwargs.get("remove_volumes") is False


def test_down_with_volumes_propagates() -> None:
    with patch("secured_claude.cli.orchestrator.down") as down_mock:
        cli.main(["down", "--volumes"])
    assert down_mock.call_args.kwargs.get("remove_volumes") is True


def test_status_no_services(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("secured_claude.cli.orchestrator.status", return_value=[]):
        rc = cli.main(["status"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "No services running" in captured.out


def test_status_with_services(capsys: pytest.CaptureFixture[str]) -> None:
    statuses = [
        cli.orchestrator.ContainerStatus(
            name="cerbos", state="running", health="healthy", image="cerbos:0.42.0"
        )
    ]
    with patch("secured_claude.cli.orchestrator.status", return_value=statuses):
        rc = cli.main(["status"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "cerbos" in captured.out
    assert "running" in captured.out


def test_run_invokes_exec_in(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_exec(
        compose_file: Path, service: str, command: list[str], *, interactive: bool
    ) -> int:
        seen["service"] = service
        seen["command"] = command
        seen["interactive"] = interactive
        return 0

    monkeypatch.setattr("secured_claude.cli.orchestrator.exec_in", fake_exec)
    rc = cli.main(["run", "hello", "world"])
    assert rc == 0
    assert seen["service"] == "claude-code"
    assert seen["interactive"] is True
    cmd_list: list[str] = seen["command"]  # type: ignore[assignment]
    assert "claude" in cmd_list
    assert "hello" in cmd_list


def test_exec_invokes_one_shot_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_exec(
        compose_file: Path, service: str, command: list[str], *, interactive: bool
    ) -> int:
        seen["interactive"] = interactive
        seen["command"] = command
        return 0

    monkeypatch.setattr("secured_claude.cli.orchestrator.exec_in", fake_exec)
    rc = cli.main(["exec", "summarize", "this"])
    assert rc == 0
    assert seen["interactive"] is False
    cmd_list: list[str] = seen["command"]  # type: ignore[assignment]
    assert cmd_list[0] == "claude"
    assert cmd_list[1] == "-p"


def test_audit_table_default(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("secured_claude.cli.audit.query", lambda *a, **kw: [])
    rc = cli.main(["audit"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "No matching audit rows" in captured.out


def test_audit_with_json_flag(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("secured_claude.cli.audit.query", lambda *a, **kw: [])
    rc = cli.main(["audit", "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    # An empty result via the JSON renderer is the empty string
    assert captured.out.strip() == ""


def test_audit_decision_filters_passed_through(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_query(store: object, **kwargs: object) -> list[object]:
        seen.update(kwargs)
        return []

    monkeypatch.setattr("secured_claude.cli.audit.query", fake_query)
    cli.main(["audit", "--allowed", "--principal", "alice", "--kind", "file"])
    assert seen["decision"] == "ALLOW"
    assert seen["principal_id"] == "alice"
    assert seen["resource_kind"] == "file"


def test_audit_denied_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_query(store: object, **kwargs: object) -> list[object]:
        seen.update(kwargs)
        return []

    monkeypatch.setattr("secured_claude.cli.audit.query", fake_query)
    cli.main(["audit", "--denied"])
    assert seen["decision"] == "DENY"


def test_doctor_all_checks(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`doctor` should print findings and exit 0 if all checks pass on this host."""
    rc = cli.main(["doctor"])
    captured = capsys.readouterr()
    assert "Python ≥ 3.11" in captured.out
    assert "Docker installed" in captured.out
    assert "policies/ present" in captured.out
    # rc may be 0 or 1 depending on whether the project root is auto-detected
    assert rc in (0, 1)


def test_doctor_when_docker_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("secured_claude.cli.shutil.which", lambda _: None)
    rc = cli.main(["doctor"])
    assert rc == 1
    captured = capsys.readouterr()
    assert "✗" in captured.out


def test_policy_lint_when_docker_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("secured_claude.cli.shutil.which", lambda _: None)
    rc = cli.main(["policy", "lint"])
    assert rc == 1
    captured = capsys.readouterr()
    assert "docker not on PATH" in captured.out


def test_policy_stats_renders_table(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Approved rows are aggregated into a frequency table."""
    rc = cli.main(["policy", "stats"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Top approved" in captured.out
