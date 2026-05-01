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


@pytest.fixture(autouse=True)
def _fake_docker_on_path(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    """Pretend docker is on PATH so unit tests don't depend on the CI image
    having it. The single test that exercises the absence is
    `test_docker_not_installed_raises`, which monkeypatches shutil.which itself
    after this autouse fixture installs the default fake — its later patch wins.
    """
    if request.node.name == "test_docker_not_installed_raises":
        return
    monkeypatch.setattr("secured_claude.orchestrator.shutil.which", lambda _name: "/usr/bin/docker")


def _ok_proc(stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def test_docker_not_installed_raises(monkeypatch: pytest.MonkeyPatch, compose_file: Path) -> None:
    monkeypatch.setattr("secured_claude.orchestrator.shutil.which", lambda _: None)
    with pytest.raises(orchestrator.DockerNotInstalledError):
        orchestrator.up(compose_file)


def test_up_invokes_docker_compose_up_d(compose_file: Path) -> None:
    with (
        patch.object(orchestrator.subprocess, "run") as run,
        patch.object(orchestrator, "start_broker"),
    ):
        run.return_value = _ok_proc()
        orchestrator.up(compose_file, detach=True, build=False)
    args = run.call_args.args[0]
    assert "compose" in args
    assert "up" in args
    assert "-d" in args
    assert "--build" not in args


def test_up_with_build_flag(compose_file: Path) -> None:
    with (
        patch.object(orchestrator.subprocess, "run") as run,
        patch.object(orchestrator, "start_broker"),
    ):
        run.return_value = _ok_proc()
        orchestrator.up(compose_file, detach=True, build=True)
    assert "--build" in run.call_args.args[0]


def test_up_starts_broker(compose_file: Path) -> None:
    """ADR-TBD : `up` forks the host-side broker as a background process."""
    with (
        patch.object(orchestrator.subprocess, "run") as run,
        patch.object(orchestrator, "start_broker") as start_broker,
    ):
        run.return_value = _ok_proc()
        orchestrator.up(compose_file)
    start_broker.assert_called_once()


def test_down_invokes_docker_compose_down(compose_file: Path) -> None:
    with (
        patch.object(orchestrator.subprocess, "run") as run,
        patch.object(orchestrator, "stop_broker"),
    ):
        run.return_value = _ok_proc()
        orchestrator.down(compose_file)
    args = run.call_args.args[0]
    assert "down" in args
    assert "-v" not in args


def test_down_stops_broker(compose_file: Path) -> None:
    """`down` stops the broker BEFORE the containers (fail-closed semantics)."""
    with (
        patch.object(orchestrator.subprocess, "run") as run,
        patch.object(orchestrator, "stop_broker") as stop_broker,
    ):
        run.return_value = _ok_proc()
        orchestrator.down(compose_file)
    stop_broker.assert_called_once()


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


# ────────────────────────────────────────────────────────────────────
# Host-side broker lifecycle
# ────────────────────────────────────────────────────────────────────


def test_broker_pid_alive_returns_none_when_no_pidfile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(orchestrator, "_BROKER_PIDFILE", tmp_path / "broker.pid")
    assert orchestrator._broker_pid_alive() is None


def test_broker_pid_alive_cleans_stale_pidfile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Pidfile pointing at a dead PID is detected + cleaned."""
    pidfile = tmp_path / "broker.pid"
    pidfile.write_text("999999")  # almost certainly dead
    monkeypatch.setattr(orchestrator, "_BROKER_PIDFILE", pidfile)
    assert orchestrator._broker_pid_alive() is None
    assert not pidfile.exists()


def test_broker_pid_alive_returns_pid_for_running_process(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Our own PID is alive ; the helper returns it without crashing."""
    import os

    pidfile = tmp_path / "broker.pid"
    pidfile.write_text(str(os.getpid()))
    monkeypatch.setattr(orchestrator, "_BROKER_PIDFILE", pidfile)
    assert orchestrator._broker_pid_alive() == os.getpid()


def test_start_broker_idempotent_when_already_running(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """If pidfile points to a live broker, start_broker returns its PID
    without spawning a duplicate."""
    import os

    pidfile = tmp_path / "broker.pid"
    pidfile.write_text(str(os.getpid()))
    monkeypatch.setattr(orchestrator, "_BROKER_PIDFILE", pidfile)
    spawned = []
    monkeypatch.setattr(
        orchestrator.subprocess,
        "Popen",
        lambda *a, **kw: spawned.append(1) or (_ for _ in ()).throw(AssertionError("spawned!")),
    )
    pid = orchestrator.start_broker()
    assert pid == os.getpid()
    assert spawned == []


def test_stop_broker_returns_false_when_no_broker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(orchestrator, "_BROKER_PIDFILE", tmp_path / "broker.pid")
    assert orchestrator.stop_broker() is False


def test_broker_status_reports_not_running_when_no_pid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(orchestrator, "_BROKER_PIDFILE", tmp_path / "broker.pid")
    s = orchestrator.broker_status()
    assert s.name == "secured-claude-broker"
    assert "not running" in s.state


def test_broker_status_reports_running_when_alive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import os

    pidfile = tmp_path / "broker.pid"
    pidfile.write_text(str(os.getpid()))
    monkeypatch.setattr(orchestrator, "_BROKER_PIDFILE", pidfile)
    monkeypatch.setattr(orchestrator, "_broker_reachable", lambda: False)
    s = orchestrator.broker_status()
    assert "running" in s.state
    assert str(os.getpid()) in s.state
    assert s.health == "unreachable"


def test_start_broker_spawns_uvicorn_and_writes_pidfile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When no broker is running, start_broker spawns uvicorn + records the PID."""
    pidfile = tmp_path / "broker.pid"
    monkeypatch.setattr(orchestrator, "_BROKER_PIDFILE", pidfile)
    monkeypatch.setattr(orchestrator, "_data_dir", lambda: tmp_path)

    fake_proc = MagicMock(pid=99999)
    fake_popen = MagicMock(return_value=fake_proc)
    monkeypatch.setattr(orchestrator.subprocess, "Popen", fake_popen)
    # Skip the urlopen health-poll loop — return a successful response immediately
    fake_resp = MagicMock(
        __enter__=lambda s: MagicMock(status=200),
        __exit__=lambda *a: None,
    )
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **kw: fake_resp)

    pid = orchestrator.start_broker()
    assert pid == 99999
    assert pidfile.read_text().strip() == "99999"
    assert fake_popen.called
    args = fake_popen.call_args.args[0]
    assert "uvicorn" in args
    assert "secured_claude.gateway:make_app" in args


def test_stop_broker_sends_sigterm(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """stop_broker reads the pidfile + sends SIGTERM."""
    import os

    pidfile = tmp_path / "broker.pid"
    pidfile.write_text(str(os.getpid()))
    monkeypatch.setattr(orchestrator, "_BROKER_PIDFILE", pidfile)

    sent_signals: list[tuple[int, int]] = []
    monkeypatch.setattr(orchestrator._os, "kill", lambda pid, sig: sent_signals.append((pid, sig)))

    assert orchestrator.stop_broker() is True
    # Two kill calls : one is signal-0 (existence check), one is SIGTERM
    sigs_sent = [sig for _pid, sig in sent_signals]
    assert orchestrator._signal.SIGTERM in sigs_sent
    assert not pidfile.exists()


def test_broker_reachable_false_when_health_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_broker_reachable() catches URLError + returns False (used by status)."""
    import urllib.error

    def raise_urlerror(*args: object, **kwargs: object) -> None:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", raise_urlerror)
    assert orchestrator._broker_reachable() is False
