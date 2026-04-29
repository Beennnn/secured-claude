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
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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


def down(compose_file: Path, *, remove_volumes: bool = False) -> None:
    """Stop and remove the secured-claude containers and network.

    By default named volumes (audit DB, claude state) are PRESERVED so the
    audit log survives a `down`/`up` cycle. Pass remove_volumes=True only
    when the user explicitly asks for a hard reset.
    """
    args = ["down"]
    if remove_volumes:
        args.append("-v")
    _run_compose(compose_file, args)


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
    "build",
    "down",
    "exec_in",
    "pull",
    "status",
    "up",
]
