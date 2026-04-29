"""Top-level CLI for secured-claude.

Subcommands :

  up / down / status      — Docker lifecycle (Cerbos + Claude Code containers)
  run / exec              — interactive / one-shot Claude Code session
  audit                   — query the SQLite audit log (filters, JSON export)
  doctor                  — validate prerequisites end-to-end
  policy lint|stats       — Cerbos policy validation, frequency stats
  version                 — print package version
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from secured_claude import __version__, audit, orchestrator
from secured_claude.store import Store


def _project_root() -> Path:
    """Resolve the project root that contains docker-compose.yml.

    Resolution order :
      1. SECURED_CLAUDE_ROOT env var (explicit override)
      2. CWD if it contains docker-compose.yml
      3. Walk parents from this file's location, stopping at the first
         dir containing docker-compose.yml
      4. Fall back to CWD even if compose isn't there (let the error surface
         when actually used)
    """
    env = os.environ.get("SECURED_CLAUDE_ROOT")
    if env:
        return Path(env).resolve()

    cwd = Path.cwd()
    if (cwd / "docker-compose.yml").exists():
        return cwd

    here = Path(__file__).resolve().parent
    for parent in (here, *here.parents):
        if (parent / "docker-compose.yml").exists():
            return parent

    return cwd


def _compose_file() -> Path:
    return _project_root() / "docker-compose.yml"


def cmd_version(args: argparse.Namespace) -> int:
    print(f"secured-claude {__version__}")
    return 0


def cmd_up(args: argparse.Namespace) -> int:
    console = Console()
    console.print("[cyan]Starting secured-claude services…[/cyan]")
    try:
        orchestrator.up(_compose_file(), detach=True, build=args.build)
    except orchestrator.DockerNotInstalledError as e:
        console.print(f"[red]error:[/red] {e}")
        return 1
    except orchestrator.ComposeError as e:
        console.print(f"[red]error:[/red] {e}")
        return 1
    console.print(
        "[green]✓[/green] services up. Run `secured-claude run` to start a Claude Code session."
    )
    return 0


def cmd_down(args: argparse.Namespace) -> int:
    console = Console()
    console.print("[cyan]Stopping secured-claude services…[/cyan]")
    try:
        orchestrator.down(_compose_file(), remove_volumes=args.volumes)
    except (orchestrator.DockerNotInstalledError, orchestrator.ComposeError) as e:
        console.print(f"[red]error:[/red] {e}")
        return 1
    console.print("[green]✓[/green] services down (audit DB preserved).")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    console = Console()
    try:
        statuses = orchestrator.status(_compose_file())
    except (orchestrator.DockerNotInstalledError, orchestrator.ComposeError) as e:
        console.print(f"[red]error:[/red] {e}")
        return 1

    if not statuses:
        console.print("[yellow]No services running.[/yellow] Use `secured-claude up` to start.")
        return 0

    table = Table(title="secured-claude services", header_style="bold magenta")
    table.add_column("name")
    table.add_column("state")
    table.add_column("health")
    table.add_column("image")
    for s in statuses:
        state_styled = (
            f"[green]{s.state}[/green]" if s.state == "running" else f"[yellow]{s.state}[/yellow]"
        )
        table.add_row(s.name, state_styled, s.health or "-", s.image)
    console.print(table)

    store = Store()
    console.print(f"\n[dim]Audit DB :[/dim] {store.path} ({store.count()} row(s))")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Attach an interactive Claude Code session inside the running container."""
    cmd = ["claude"]
    if args.prompt:
        cmd.extend(args.prompt)
    return orchestrator.exec_in(
        _compose_file(),
        service="claude-code",
        command=cmd,
        interactive=True,
    )


def cmd_exec(args: argparse.Namespace) -> int:
    """Run a one-shot Claude Code session (non-interactive)."""
    cmd = ["claude", "-p", " ".join(args.prompt) if args.prompt else ""]
    return orchestrator.exec_in(
        _compose_file(),
        service="claude-code",
        command=cmd,
        interactive=False,
    )


def cmd_audit(args: argparse.Namespace) -> int:
    store = Store()
    rows = audit.query(
        store,
        decision="ALLOW" if args.allowed else ("DENY" if args.denied else None),
        principal_id=args.principal,
        resource_kind=args.kind,
        action=args.action,
        since=args.since,
        limit=args.limit,
    )
    if args.json:
        print(audit.render_json(rows))
    else:
        audit.render_table(rows)
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Validate the install end-to-end : Python, Docker, images, policies, paths."""
    console = Console()
    findings: list[tuple[str, bool, str]] = []

    findings.append(
        ("Python ≥ 3.11", sys.version_info >= (3, 11), f"running {sys.version.split()[0]}")
    )
    findings.append(
        (
            "Docker installed",
            shutil.which("docker") is not None,
            shutil.which("docker") or "not on PATH",
        )
    )

    compose = _compose_file()
    findings.append(("docker-compose.yml present", compose.exists(), str(compose)))

    policies = _project_root() / "policies"
    findings.append(("policies/ present", policies.exists() and policies.is_dir(), str(policies)))

    store = Store()
    findings.append(("audit DB writable", store.path.exists(), str(store.path)))

    table = Table(title="secured-claude doctor", header_style="bold magenta")
    table.add_column("check")
    table.add_column("ok", justify="center")
    table.add_column("detail", overflow="fold")
    for name, ok, detail in findings:
        table.add_row(name, "[green]✓[/green]" if ok else "[red]✗[/red]", detail)
    console.print(table)

    all_ok = all(ok for _, ok, _ in findings)
    if all_ok:
        console.print(Panel.fit("[green]All checks passed[/green]", title="status"))
        return 0
    console.print(Panel.fit("[red]Some checks failed[/red] — see detail above", title="status"))
    return 1


def cmd_policy_lint(args: argparse.Namespace) -> int:
    """Run `cerbos compile` in a temporary container against the policies dir."""
    docker = shutil.which("docker")
    if docker is None:
        Console().print("[red]error:[/red] docker not on PATH")
        return 1
    policies = _project_root() / "policies"
    if not policies.is_dir():
        Console().print(f"[red]error:[/red] {policies} not found")
        return 1
    import subprocess

    proc = subprocess.run(  # noqa: S603 — argv list, shell=False
        [
            docker,
            "run",
            "--rm",
            "-v",
            f"{policies}:/policies:ro",
            "cerbos/cerbos:0.42.0",
            "compile",
            "/policies",
        ],
        check=False,
    )
    return proc.returncode


def cmd_policy_stats(args: argparse.Namespace) -> int:
    """Show the most-frequently approved (resource_kind, action) tuples."""
    store = Store()
    rows = store.query(decision="ALLOW", limit=100000)
    counts: dict[tuple[str, str], int] = {}
    for r in rows:
        counts[(r.resource_kind, r.action)] = counts.get((r.resource_kind, r.action), 0) + 1

    table = Table(
        title=(
            "Top approved (resource_kind, action) tuples — promotion candidates for static policies"
        ),
        header_style="bold magenta",
    )
    table.add_column("kind")
    table.add_column("action")
    table.add_column("count", justify="right")
    for (kind, action), n in sorted(counts.items(), key=lambda kv: -kv[1])[:30]:
        table.add_row(kind, action, str(n))
    Console().print(table)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secured-claude",
        description="Claude Code wrapper, secured by design — every tool call gated by Cerbos PDP.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("version", help="print package version").set_defaults(func=cmd_version)

    p_up = sub.add_parser("up", help="start cerbos + claude-code containers")
    p_up.add_argument("--build", action="store_true", help="rebuild images before starting")
    p_up.set_defaults(func=cmd_up)

    p_down = sub.add_parser("down", help="stop containers (audit DB preserved)")
    p_down.add_argument(
        "--volumes", action="store_true", help="ALSO remove named volumes (destructive)"
    )
    p_down.set_defaults(func=cmd_down)

    sub.add_parser("status", help="show service health").set_defaults(func=cmd_status)

    p_run = sub.add_parser("run", help="interactive Claude Code session")
    p_run.add_argument("prompt", nargs="*", help="initial prompt (optional)")
    p_run.set_defaults(func=cmd_run)

    p_exec = sub.add_parser("exec", help="one-shot Claude Code session")
    p_exec.add_argument("prompt", nargs="*", help="prompt to send")
    p_exec.set_defaults(func=cmd_exec)

    p_audit = sub.add_parser("audit", help="query the SQLite audit log")
    p_audit.add_argument("--allowed", action="store_true", help="only ALLOW decisions")
    p_audit.add_argument("--denied", action="store_true", help="only DENY decisions")
    p_audit.add_argument("--principal", help="filter by principal_id")
    p_audit.add_argument("--kind", help="filter by resource_kind (file|command|url|mcp_tool|...)")
    p_audit.add_argument(
        "--action", help="filter by action (read|write|edit|execute|fetch|invoke|...)"
    )
    p_audit.add_argument("--since", help="ISO 8601 lower bound on ts")
    p_audit.add_argument("--limit", type=int, default=100, help="max rows (default 100)")
    p_audit.add_argument("--json", action="store_true", help="emit JSONL instead of a table")
    p_audit.set_defaults(func=cmd_audit)

    sub.add_parser("doctor", help="validate prerequisites").set_defaults(func=cmd_doctor)

    p_policy = sub.add_parser("policy", help="policy operations")
    psub = p_policy.add_subparsers(dest="policy_cmd", required=True)
    psub.add_parser("lint", help="run `cerbos compile` against policies/").set_defaults(
        func=cmd_policy_lint
    )
    psub.add_parser("stats", help="top-N approved (resource_kind, action) tuples").set_defaults(
        func=cmd_policy_stats
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 2
    rv = func(args)
    return int(rv) if rv is not None else 0


if __name__ == "__main__":
    raise SystemExit(main())
