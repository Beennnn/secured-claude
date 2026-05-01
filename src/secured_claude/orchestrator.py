"""Docker lifecycle orchestrator (ADR-0005, ADR-0006, ADR-0007).

Wraps `docker compose` for cross-platform container lifecycle. We use the
docker-compose CLI rather than the Docker SDK directly because :

- `compose` handles networks, named volumes, env_file, depends_on, healthchecks
  in one config (docker-compose.yml). Re-implementing that on top of the SDK
  would be reinventing compose.
- `docker compose` ships with Docker Desktop (Mac/Win) and `docker-compose-
  plugin` is the standard on Linux ; same UX on the three OSes.
- Failure modes are the user's familiar `docker compose` errors, not opaque
  Python exceptions.

We keep the surface small : up / down / status / pull / build / exec.
"""

from __future__ import annotations

import json
import os as _os
import shutil
import signal as _signal
import subprocess
import sys as _sys
import time as _time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secured_claude._paths import data_dir as _data_dir


@dataclass(frozen=True)
class ContainerStatus:
    """Status of one container in the compose project."""

    name: str
    state: str
    health: str | None
    image: str


class DockerNotInstalledError(RuntimeError):
    """Raised when the `docker` CLI is not on PATH."""


class ComposeError(RuntimeError):
    """Raised when a `docker compose` invocation fails."""


def _docker_bin() -> str:
    path = shutil.which("docker")
    if path is None:
        raise DockerNotInstalledError(
            "`docker` CLI not found on PATH. Install Docker Desktop (Mac/Win) "
            "or Docker Engine (Linux), then re-run."
        )
    return path


def _run_compose(
    compose_file: Path,
    args: list[str],
    *,
    capture: bool = False,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[Any]:
    """Run `docker compose -f <file> <args>` and return the completed process.

    Raises ComposeError on non-zero exit when capture=True (so we can include
    the captured output). When capture=False, output goes straight to the
    user's terminal so they see progress on `pull` / `build`.
    """
    cmd = [_docker_bin(), "compose", "-f", str(compose_file), *args]
    if capture:
        try:
            return subprocess.run(  # noqa: S603 — argv list, shell=False, controlled inputs
                cmd,
                check=True,
                capture_output=True,
                text=True,
                cwd=cwd,
            )
        except subprocess.CalledProcessError as e:
            raise ComposeError(
                f"docker compose {' '.join(args)} failed (exit {e.returncode})\n"
                f"stdout:\n{e.stdout}\nstderr:\n{e.stderr}"
            ) from e
    return subprocess.run(  # noqa: S603 — argv list, shell=False, controlled inputs
        cmd, check=True, cwd=cwd
    )


def up(compose_file: Path, *, detach: bool = True, build: bool = False) -> None:
    """Bring up the secured-claude services (cerbos + claude-code)."""
    args = ["up"]
    if detach:
        args.append("-d")
    if build:
        args.append("--build")
    _run_compose(compose_file, args)
    # Auto-start the host-side broker (TASKS.md item shipped post-v0.8.0).
    # Without this, the agent's PreToolUse hook POSTs to a dead 127.0.0.1:8765
    # and every tool call fails closed (ADR-0009 deny-on-broker-unreachable).
    start_broker()


def down(compose_file: Path, *, remove_volumes: bool = False) -> None:
    """Stop and remove the secured-claude containers and network.

    By default named volumes (audit DB, claude state) are PRESERVED so the
    audit log survives a `down`/`up` cycle. Pass remove_volumes=True only
    when the user explicitly asks for a hard reset.
    """
    # Stop the broker BEFORE the containers — the hook in the agent might
    # still emit a /check on shutdown ; tearing the broker first guarantees
    # those fail-closed (DENY) instead of going through.
    stop_broker()
    args = ["down"]
    if remove_volumes:
        args.append("-v")
    _run_compose(compose_file, args)


# ────────────────────────────────────────────────────────────────────
# Host-side broker lifecycle
# ────────────────────────────────────────────────────────────────────
#
# The broker (FastAPI on 127.0.0.1:8765) runs OUTSIDE compose by design
# (ADR-0006 — host-side trust boundary). Until v0.8.x we expected the
# user to start uvicorn manually ; that was a real DX gap discovered
# during the v0.8.0 redaction smoke. Now `up` forks the broker as a
# background process and `down` stops it. The PID file lets `status`
# report broker health and prevents double-start.

_BROKER_PIDFILE = _data_dir() / "broker.pid"
_BROKER_HOST = _os.environ.get("SECURED_CLAUDE_BROKER_HOST", "127.0.0.1")
_BROKER_PORT = int(_os.environ.get("SECURED_CLAUDE_BROKER_PORT", "8765"))


def _broker_pid_alive() -> int | None:
    """Return the broker PID if a live process is running, else None.

    Reads the pidfile + verifies the PID is alive AND was launched by us
    (the comm name contains 'uvicorn' or 'python'). Stale pidfiles from a
    crashed broker are cleaned up.
    """
    if not _BROKER_PIDFILE.exists():
        return None
    try:
        pid = int(_BROKER_PIDFILE.read_text().strip())
    except (ValueError, OSError):
        _BROKER_PIDFILE.unlink(missing_ok=True)
        return None
    try:
        _os.kill(pid, 0)  # signal 0 = check existence without sending a signal
    except (ProcessLookupError, PermissionError):
        _BROKER_PIDFILE.unlink(missing_ok=True)
        return None
    return pid


def start_broker() -> int:
    """Fork a uvicorn process serving secured_claude.gateway:make_app.

    Idempotent : if a live broker PID is recorded in the pidfile, returns
    that PID without spawning a duplicate. Returns the PID of the running
    broker (existing or freshly-forked).

    The broker logs to ``data_dir()/broker.log``. The pidfile lives at
    ``data_dir()/broker.pid``. Both paths are XDG / Application Support
    cross-platform per `_paths.data_dir()`.
    """
    existing = _broker_pid_alive()
    if existing is not None:
        return existing

    log_path = _data_dir() / "broker.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fd = open(log_path, "ab")

    cmd = [
        _sys.executable,
        "-m",
        "uvicorn",
        "secured_claude.gateway:make_app",
        "--factory",
        "--host",
        _BROKER_HOST,
        "--port",
        str(_BROKER_PORT),
    ]
    proc = subprocess.Popen(  # noqa: S603 — argv list, shell=False
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=log_fd,
        stderr=subprocess.STDOUT,
        start_new_session=True,  # detach from this process group ; survives parent exit
        env=_os.environ.copy(),
    )
    _BROKER_PIDFILE.write_text(str(proc.pid))

    # Wait briefly for /health to come up before returning so callers get
    # a fully-functional broker. ~1.5 s budget : if uvicorn fails to bind
    # (port already in use, etc.) we prefer to surface that synchronously.
    import urllib.error
    import urllib.request

    deadline = _time.monotonic() + 1.5
    health_url = f"http://{_BROKER_HOST}:{_BROKER_PORT}/health"
    while _time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(health_url, timeout=0.3) as resp:  # nosec B310
                if resp.status == 200:
                    return proc.pid
        except (urllib.error.URLError, OSError):
            _time.sleep(0.1)
    # Health didn't come up in time — return the PID anyway. Caller can
    # check broker_status() to confirm.
    return proc.pid


def stop_broker() -> bool:
    """Send SIGTERM to the broker process recorded in the pidfile.

    Returns True if a process was signalled, False if no live broker was
    found. Cleans up the pidfile either way.
    """
    pid = _broker_pid_alive()
    if pid is None:
        return False
    try:
        _os.kill(pid, _signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    _BROKER_PIDFILE.unlink(missing_ok=True)
    return True


def broker_status() -> ContainerStatus:
    """Return a synthetic ContainerStatus for the broker — fits in the
    same table that `status` renders for the docker services."""
    pid = _broker_pid_alive()
    if pid is None:
        return ContainerStatus(
            name="secured-claude-broker",
            state="not running",
            health=None,
            image="(host process)",
        )
    return ContainerStatus(
        name="secured-claude-broker",
        state=f"running (pid {pid})",
        health="reachable" if _broker_reachable() else "unreachable",
        image="(host process)",
    )


def _broker_reachable() -> bool:
    """True if a /health request to the broker returns 200."""
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(  # nosec B310
            f"http://{_BROKER_HOST}:{_BROKER_PORT}/health", timeout=0.5
        ) as resp:
            return bool(resp.status == 200)
    except (urllib.error.URLError, OSError):
        return False


def pull(compose_file: Path) -> None:
    """Pull all upstream images (Cerbos, Node base) — used by `secured-claude doctor`."""
    _run_compose(compose_file, ["pull"])


def build(compose_file: Path) -> None:
    """Build the Claude Code image locally."""
    _run_compose(compose_file, ["build"])


def status(compose_file: Path) -> list[ContainerStatus]:
    """Return the state of each compose service.

    Uses `docker compose ps --format json` which returns one JSON object per
    line (NDJSON). Each entry has a `Name`, `State`, `Health`, `Image`.
    """
    proc = _run_compose(compose_file, ["ps", "--format", "json"], capture=True)
    out = proc.stdout.strip()
    if not out:
        return []
    statuses: list[ContainerStatus] = []
    # Compose v2 emits one JSON object per line ; older v1 emits a single array.
    first_char = out.lstrip()[:1]
    raw_entries: list[dict[str, str]] = (
        json.loads(out)
        if first_char == "["
        else [json.loads(line) for line in out.splitlines() if line.strip()]
    )
    for entry in raw_entries:
        statuses.append(
            ContainerStatus(
                name=str(entry.get("Name", entry.get("Service", "?"))),
                state=str(entry.get("State", "unknown")),
                health=entry.get("Health") or None,
                image=str(entry.get("Image", "?")),
            )
        )
    return statuses


def exec_in(
    compose_file: Path,
    service: str,
    command: list[str],
    *,
    interactive: bool = True,
) -> int:
    """Run a command inside a running container, optionally with TTY for interactive use.

    Returns the exit code from the inner command (so `secured-claude run` can
    forward it back to the caller).
    """
    args = ["exec"]
    if interactive:
        args.extend(["-i", "-t"])
    args.append(service)
    args.extend(command)
    proc = subprocess.run(  # noqa: S603 — argv list, shell=False
        [_docker_bin(), "compose", "-f", str(compose_file), *args],
        check=False,
    )
    return proc.returncode


__all__ = [
    "ComposeError",
    "ContainerStatus",
    "DockerNotInstalledError",
    "broker_status",
    "build",
    "down",
    "exec_in",
    "pull",
    "start_broker",
    "status",
    "stop_broker",
    "up",
]
