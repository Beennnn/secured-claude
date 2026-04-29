"""Tests for the docker-compose orchestrator wrapper.

We don't actually start containers in the unit tests — we mock the
`subprocess.run` call and assert the right CLI invocation is built. End-to-end
tests with a real Docker daemon live in the audit-demo / smoke-test layer.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from secured_claude import orchestrator


@pytest.fixture
def compose_file(tmp_path: Path) -> Path:
    """A throwaway compose file path — content doesn't matter for these mocks."""
    p = tmp_path / "docker-compose.yml"
    p.write_text("services: {}\n")
    return p


def _ok_proc(stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def test_docker_not_installed_raises(monkeypatch: pytest.MonkeyPatch, compose_file: Path) -> None:
    monkeypatch.setattr("secured_claude.orchestrator.shutil.which", lambda _: None)
    with pytest.raises(orchestrator.DockerNotInstalledError):
        orchestrator.up(compose_file)


def test_up_invokes_docker_compose_up_d(compose_file: Path) -> None:
    with patch.object(orchestrator.subprocess, "run") as run:
        run.return_value = _ok_proc()
        orchestrator.up(compose_file, detach=True, build=False)
    args = run.call_args.args[0]
    assert "compose" in args
    assert "up" in args
    assert "-d" in args
    assert "--build" not in args


def test_up_with_build_flag(compose_file: Path) -> None:
    with patch.object(orchestrator.subprocess, "run") as run:
        run.return_value = _ok_proc()
        orchestrator.up(compose_file, detach=True, build=True)
    assert "--build" in run.call_args.args[0]


def test_down_invokes_docker_compose_down(compose_file: Path) -> None:
    with patch.object(orchestrator.subprocess, "run") as run:
        run.return_value = _ok_proc()
        orchestrator.down(compose_file)
    args = run.call_args.args[0]
    assert "down" in args
    assert "-v" not in args


def test_down_with_remove_volumes(compose_file: Path) -> None:
    with patch.object(orchestrator.subprocess, "run") as run:
        run.return_value = _ok_proc()
        orchestrator.down(compose_file, remove_volumes=True)
    assert "-v" in run.call_args.args[0]


def test_pull_invokes_docker_compose_pull(compose_file: Path) -> None:
    with patch.object(orchestrator.subprocess, "run") as run:
        run.return_value = _ok_proc()
        orchestrator.pull(compose_file)
    assert "pull" in run.call_args.args[0]


def test_build_invokes_docker_compose_build(compose_file: Path) -> None:
    with patch.object(orchestrator.subprocess, "run") as run:
        run.return_value = _ok_proc()
        orchestrator.build(compose_file)
    assert "build" in run.call_args.args[0]


def test_status_parses_ndjson_compose_v2_format(compose_file: Path) -> None:
    """Compose v2 emits one JSON object per line."""
    ndjson = "\n".join(
        [
            json.dumps(
                {
                    "Name": "secured-claude-cerbos",
                    "State": "running",
                    "Health": "healthy",
                    "Image": "cerbos/cerbos:0.42.0",
                }
            ),
            json.dumps(
                {
                    "Name": "secured-claude-agent",
                    "State": "running",
                    "Health": None,
                    "Image": "secured-claude/claude-code:0.1.0",
                }
            ),
        ]
    )
    with patch.object(orchestrator.subprocess, "run") as run:
        run.return_value = _ok_proc(stdout=ndjson)
        statuses = orchestrator.status(compose_file)
    assert len(statuses) == 2
    assert statuses[0].name == "secured-claude-cerbos"
    assert statuses[0].state == "running"
    assert statuses[0].health == "healthy"
    assert statuses[1].health is None


def test_status_parses_legacy_array_compose_v1_format(compose_file: Path) -> None:
    """Older compose v1 emits a single JSON array."""
    payload = json.dumps([{"Name": "a", "State": "running", "Image": "x:1"}])
    with patch.object(orchestrator.subprocess, "run") as run:
        run.return_value = _ok_proc(stdout=payload)
        statuses = orchestrator.status(compose_file)
    assert len(statuses) == 1
    assert statuses[0].name == "a"


def test_status_empty_output_returns_empty_list(compose_file: Path) -> None:
    with patch.object(orchestrator.subprocess, "run") as run:
        run.return_value = _ok_proc(stdout="")
        statuses = orchestrator.status(compose_file)
    assert statuses == []


def test_compose_error_includes_stdout_stderr(compose_file: Path) -> None:
    """When capture=True and exit != 0, the wrapper raises ComposeError with the captured output."""
    err = subprocess.CalledProcessError(
        returncode=1, cmd=["docker", "compose"], output="some stdout", stderr="some stderr"
    )
    with patch.object(orchestrator.subprocess, "run", side_effect=err):
        with pytest.raises(orchestrator.ComposeError, match="some stderr"):
            orchestrator.status(compose_file)


def test_exec_in_with_tty_returns_inner_exit_code(compose_file: Path) -> None:
    fake_proc = MagicMock(returncode=42)
    with patch.object(orchestrator.subprocess, "run", return_value=fake_proc) as run:
        rc = orchestrator.exec_in(
            compose_file, service="claude-code", command=["claude"], interactive=True
        )
    assert rc == 42
    args = run.call_args.args[0]
    assert "exec" in args
    assert "-i" in args
    assert "-t" in args
    assert "claude-code" in args


def test_exec_in_non_interactive_omits_tty_flags(compose_file: Path) -> None:
    fake_proc = MagicMock(returncode=0)
    with patch.object(orchestrator.subprocess, "run", return_value=fake_proc) as run:
        orchestrator.exec_in(compose_file, service="x", command=["echo"], interactive=False)
    args = run.call_args.args[0]
    assert "-i" not in args
    assert "-t" not in args
