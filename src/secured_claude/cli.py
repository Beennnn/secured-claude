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

from secured_claude import __version__, audit, audit_demo, orchestrator
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

    # Show the host-side broker alongside container services so the user
    # gets a single coherent picture (TASKS.md item shipped post-v0.8.0).
    broker = orchestrator.broker_status()

    if not statuses and "not running" in broker.state:
        console.print("[yellow]No services running.[/yellow] Use `secured-claude up` to start.")
        return 0

    table = Table(title="secured-claude services", header_style="bold magenta")
    table.add_column("name")
    table.add_column("state")
    table.add_column("health")
    table.add_column("image")
    for s in [*statuses, broker]:
        state_styled = (
            f"[green]{s.state}[/green]"
            if s.state == "running" or "running" in s.state
            else f"[yellow]{s.state}[/yellow]"
        )
        table.add_row(s.name, state_styled, s.health or "-", s.image)
    console.print(table)

    store = Store()
    console.print(f"\n[dim]Audit DB :[/dim] {store.path} ({store.count()} row(s))")
    return 0


def _principal_env(args: argparse.Namespace) -> dict[str, str] | None:
    """Build the env override dict for a `run`/`exec` session.

    Returns ``{"SECURED_CLAUDE_PRINCIPAL": <id>}`` when --principal is set,
    else ``None`` (so the agent container's baked default applies).
    """
    principal = getattr(args, "principal", None)
    return {"SECURED_CLAUDE_PRINCIPAL": principal} if principal else None


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
        env=_principal_env(args),
    )


def cmd_exec(args: argparse.Namespace) -> int:
    """Run a one-shot Claude Code session (non-interactive)."""
    cmd = ["claude", "-p", " ".join(args.prompt) if args.prompt else ""]
    return orchestrator.exec_in(
        _compose_file(),
        service="claude-code",
        command=cmd,
        interactive=False,
        env=_principal_env(args),
    )


def cmd_audit(args: argparse.Namespace) -> int:
    store = Store()
    try:
        rows = audit.query(
            store,
            decision="ALLOW" if args.allowed else ("DENY" if args.denied else None),
            principal_id=args.principal,
            resource_kind=args.kind,
            action=args.action,
            since=args.since,
            limit=args.limit,
        )
    except ValueError as e:
        Console().print(f"[red]error:[/red] {e}")
        return 2
    if args.json:
        print(audit.render_json(rows))
    else:
        audit.render_table(rows)
    return 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    """Walk the SQLite hash chain and report the first detected break.

    Exit codes :
      0 — chain intact
      1 — chain broken (tampered or rows removed) ; report shows where
      2 — DB unreadable / no chain to verify
    """
    console = Console()
    store = Store()
    n = store.count()
    if n == 0:
        console.print("[yellow]audit DB is empty — nothing to verify[/yellow]")
        return 0
    console.print(f"Verifying {n} row(s) in {store.path}...")
    break_found = store.verify_chain()
    if break_found is None:
        console.print(f"[green]✓ chain intact across {n} row(s)[/green]")
        return 0
    console.print(f"[red]✗ chain broken at row #{break_found.row_id}[/red] (ts={break_found.ts})")
    console.print(f"  reason  : {break_found.reason}")
    console.print(f"  expected: {break_found.expected_hash}")
    console.print(f"  actual  : {break_found.actual_hash}")
    return 1


def cmd_audit_anchor(args: argparse.Namespace) -> int:
    """Emit an external hash anchor for the current audit log (ADR-0029).

    Writes a JSON document committing to the latest row_hash + row_id + ts
    of the audit DB. The operator stores this externally (S3 with object
    lock, public timestamp authority, signed by their GPG key, etc.) and
    later compares against the local chain via `audit-verify-anchor`.

    A successful tamper of the local SQLite file (e.g. `rm approvals.db`)
    produces a chain that no longer ends with the anchored hash — detectable
    against any externally-stored copy.

    Exit codes :
      0 — anchor emitted
      1 — empty audit DB / no chain to anchor
    """
    import json
    from datetime import UTC, datetime

    from secured_claude import __version__

    console = Console()
    store = Store()
    n = store.count()
    if n == 0:
        console.print("[yellow]audit DB is empty — nothing to anchor[/yellow]")
        return 1
    rows = store.query(limit=1)
    last = rows[0]
    if last.row_hash is None:
        console.print(
            "[red]✗ latest row has no row_hash[/red] (pre-v0.3 row ; ADR-0024 chain not started)"
        )
        return 1
    anchor = {
        "anchor_format_version": "1.0",
        "anchored_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "secured_claude_version": __version__,
        "audit_db_path": str(store.path),
        "row_count": n,
        "last_row_id": last.id,
        "last_row_ts": last.ts,
        "last_row_hash": last.row_hash,
        "verification": (
            "Run `secured-claude audit-verify-anchor <this-file>` against the same DB "
            "later — exit 0 if the chain still ends with last_row_hash, exit 1 if "
            "tampering occurred between anchor and verify."
        ),
    }
    output = args.output or "-"
    payload = json.dumps(anchor, indent=2, ensure_ascii=False)
    if output == "-":
        print(payload)
    else:
        Path(output).write_text(payload + "\n", encoding="utf-8")
        console.print(f"[green]✓ anchor written to {output}[/green]")
        console.print(f"  last_row_id   : {last.id}")
        console.print(f"  last_row_hash : {last.row_hash}")
    return 0


def cmd_audit_verify_anchor(args: argparse.Namespace) -> int:
    """Verify the current audit DB still ends with the anchor's last_row_hash.

    Exit codes :
      0 — anchor matches the current chain (or the chain extends past it
          cleanly — anchor is a snapshot, the chain can grow forward)
      1 — anchor mismatch (tampering between anchor and verify)
      2 — anchor file unreadable or malformed
    """
    import json

    console = Console()
    try:
        anchor = json.loads(Path(args.anchor_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        console.print(f"[red]✗ cannot read anchor file: {e}[/red]")
        return 2
    expected_id = int(anchor["last_row_id"])
    expected_hash = str(anchor["last_row_hash"])
    store = Store()
    # Look up the row at expected_id and compare its row_hash
    rows = store.query(limit=10000)  # query is descending
    target = next((r for r in rows if r.id == expected_id), None)
    if target is None:
        console.print(
            f"[red]✗ anchored row #{expected_id} not in current DB[/red] "
            "(rows were removed, or DB was reset)"
        )
        return 1
    if target.row_hash != expected_hash:
        console.print(
            f"[red]✗ row #{expected_id} hash mismatch[/red]\n"
            f"  anchor : {expected_hash}\n"
            f"  actual : {target.row_hash}"
        )
        return 1
    # Also walk the full chain forward to ensure no break above the anchor.
    break_found = store.verify_chain()
    if break_found is not None:
        console.print(
            f"[red]✗ chain broken at row #{break_found.row_id}[/red] "
            f"(after the anchor at row #{expected_id} ; tampering happened later)"
        )
        return 1
    console.print(
        f"[green]✓ anchor matches[/green] — row #{expected_id} hash "
        f"{expected_hash[:16]}… is intact, full chain verified up to row "
        f"#{store.count()}"
    )
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


def _audit_demo_args(a: argparse.Namespace) -> list[str]:
    """Forward parsed args to audit_demo.main(argv)."""
    argv: list[str] = ["--cerbos-url", a.cerbos_url]
    if a.report:
        argv += ["--report", str(a.report)]
    if a.json:
        argv += ["--json"]
    return argv


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


def cmd_principal_validate(args: argparse.Namespace) -> int:
    """Validate config/principals.yaml schema (ADR-0031).

    Loads the principal directory + walks each entry, reporting any whose
    `roles` isn't a list-of-strings or `attributes` isn't a dict. Catches
    typos like `atributes:` (missing 't') or `role:` (singular) that would
    otherwise silently fall back to the default principal.

    Exit codes :
      0 — file valid, all entries well-formed (or file missing — fallback OK)
      1 — at least one entry malformed (file path + key + reason in stdout)
      2 — file unreadable / not YAML
    """
    import os
    from pathlib import Path

    import yaml

    console = Console()
    path_arg = args.path or os.environ.get("SECURED_CLAUDE_PRINCIPALS")
    path = Path(path_arg) if path_arg else Path("config/principals.yaml")
    if not path.exists():
        msg = (
            f"[yellow]principals file {path} not found — "
            "broker uses single-default fallback[/yellow]"
        )
        console.print(msg)
        return 0
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        console.print(f"[red]✗ {path} is malformed YAML: {e}[/red]")
        return 2
    if not isinstance(data, dict):
        console.print(
            f"[red]✗ {path} top-level must be a YAML mapping (got {type(data).__name__})[/red]"
        )
        return 1
    raw = data.get("principals")
    if not isinstance(raw, dict):
        console.print(
            f"[red]✗ {path} missing or malformed `principals:` key[/red] "
            "— broker would use single-default fallback"
        )
        return 1
    issues: list[str] = []
    for pid, entry in raw.items():
        if not isinstance(entry, dict):
            issues.append(f"  • {pid!r}: entry must be a mapping (got {type(entry).__name__})")
            continue
        roles = entry.get("roles")
        attributes = entry.get("attributes")
        if not isinstance(roles, list):
            issues.append(
                f"  • {pid!r}.roles: must be a list of strings "
                f"(got {type(roles).__name__ if roles is not None else 'missing'})"
            )
        elif not all(isinstance(r, str) for r in roles):
            issues.append(f"  • {pid!r}.roles: every element must be a string")
        if attributes is not None and not isinstance(attributes, dict):
            issues.append(
                f"  • {pid!r}.attributes: must be a mapping (got {type(attributes).__name__})"
            )
        # Catch common typos : `role:` singular, `atributes:` (missing t),
        # `attribute:` (missing s) — they wouldn't fail the type checks
        # above because they're entirely separate keys, but they leak the
        # operator's intent.
        for typo in ("role", "atribute", "atributes", "attribute"):
            if typo in entry:
                issues.append(
                    f"  • {pid!r}: unknown key {typo!r} — did you mean "
                    f"{'roles' if typo == 'role' else 'attributes'}?"
                )
    if issues:
        console.print(f"[red]✗ {path} has {len(issues)} validation issue(s):[/red]")
        for issue in issues:
            console.print(issue)
        return 1
    n = len(raw)
    console.print(f"[green]✓ {path} valid — {n} principal(s) defined[/green]")
    for pid, entry in raw.items():
        roles_summary = "+".join(entry.get("roles") or [])
        attrs_summary = ", ".join(f"{k}={v}" for k, v in (entry.get("attributes") or {}).items())
        # `print` not console.print to bypass Rich's [...] markup parsing —
        # the role list contains literal square brackets that Rich would
        # otherwise consume as style tags.
        print(f"  {pid}: roles=[{roles_summary}] attrs={{{attrs_summary}}}")
    return 0


def cmd_principal_list(args: argparse.Namespace) -> int:
    """List principals defined in config/principals.yaml (ADR-0047).

    Lighter than `principal validate` — emits a Rich table without the
    schema-check chatter, so operators can pick a `--principal` for
    `run` / `exec` at a glance.

    Exit codes :
      0 — file readable + at least one principal defined (or empty file
          with the implicit single-default fallback noted)
      2 — file unreadable / not YAML
    """
    import os

    import yaml

    console = Console()
    path_arg = args.path or os.environ.get("SECURED_CLAUDE_PRINCIPALS")
    path = Path(path_arg) if path_arg else Path("config/principals.yaml")
    if not path.exists():
        console.print(
            f"[yellow]principals file {path} not found — "
            "broker uses single-default fallback (`claude-code-default`)[/yellow]"
        )
        return 0
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        console.print(f"[red]✗ {path} is malformed YAML: {e}[/red]")
        return 2
    raw = (data or {}).get("principals") if isinstance(data, dict) else None
    if not isinstance(raw, dict):
        console.print(f"[yellow]{path} has no `principals:` mapping[/yellow]")
        return 0
    table = Table(title=f"principals ({len(raw)}) — from {path}", header_style="bold magenta")
    table.add_column("principal_id")
    table.add_column("roles")
    table.add_column("attributes")
    for pid, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        roles = "+".join(entry.get("roles") or [])
        attrs = ", ".join(f"{k}={v}" for k, v in (entry.get("attributes") or {}).items())
        table.add_row(pid, roles, attrs)
    console.print(table)
    console.print(
        "\n[dim]Use one with `secured-claude run --principal <principal_id>` "
        "(or `exec --principal ...`).[/dim]"
    )
    return 0


def cmd_policy_template(args: argparse.Namespace) -> int:
    """Scaffold a starter policies/ tree from a profile template.

    Profiles available :
      * developer-default — workspace RW + standard dev shell allowlist
        + curated network/MCP allowlists. Mirrors the project's baseline
        policies/ ; useful for new repos getting started with secured-claude.
      * enterprise-strict — read-only filesystem, no shell, no WebFetch,
        no MCP. Compliance-bound posture for inspection-only deployments.

    Refuses to overwrite existing files unless --force is passed. Reports
    each file written + a final hint to run `secured-claude policy lint`
    to validate the result.
    """
    import shutil
    from importlib import resources

    console = Console()
    profile = args.profile
    output_dir = Path(args.output)

    template_files = resources.files("secured_claude.policy_templates").joinpath(profile)
    if not template_files.is_dir():
        console.print(f"[red]error:[/red] template directory missing for profile {profile!r}")
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    skipped: list[str] = []
    for entry in template_files.iterdir():
        if not entry.name.endswith(".yaml"):
            continue
        target = output_dir / entry.name
        if target.exists() and not args.force:
            skipped.append(entry.name)
            continue
        with resources.as_file(entry) as src_path:
            shutil.copyfile(src_path, target)
        written.append(entry.name)

    if written:
        console.print(f"[green]wrote[/green] {len(written)} policy files to {output_dir}/")
        for name in written:
            console.print(f"  · {name}")
    if skipped:
        console.print(
            f"[yellow]skipped[/yellow] {len(skipped)} (already exist, use --force to overwrite):"
        )
        for name in skipped:
            console.print(f"  · {name}")
    if not written and not skipped:
        console.print(f"[yellow]no .yaml files found in template {profile!r}[/yellow]")
        return 1

    if written:
        console.print(
            f"\nNext : [bold]secured-claude policy lint[/bold] "
            f"to validate, then commit {output_dir}/ to your repo."
        )
    return 0


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
    p_run.add_argument(
        "--principal",
        help=(
            "principal_id for this session (overrides the container default). "
            "Must exist in config/principals.yaml ; see "
            "`secured-claude principal list`."
        ),
    )
    p_run.set_defaults(func=cmd_run)

    p_exec = sub.add_parser("exec", help="one-shot Claude Code session")
    p_exec.add_argument("prompt", nargs="*", help="prompt to send")
    p_exec.add_argument(
        "--principal",
        help=(
            "principal_id for this session (overrides the container default). "
            "Must exist in config/principals.yaml ; see "
            "`secured-claude principal list`."
        ),
    )
    p_exec.set_defaults(func=cmd_exec)

    p_audit = sub.add_parser("audit", help="query the SQLite audit log")
    p_audit.add_argument("--allowed", action="store_true", help="only ALLOW decisions")
    p_audit.add_argument("--denied", action="store_true", help="only DENY decisions")
    p_audit.add_argument("--principal", help="filter by principal_id")
    p_audit.add_argument("--kind", help="filter by resource_kind (file|command|url|mcp_tool|...)")
    p_audit.add_argument(
        "--action", help="filter by action (read|write|edit|execute|fetch|invoke|...)"
    )
    p_audit.add_argument(
        "--since",
        help=(
            "lower bound on ts ; accepts a relative duration "
            "('30s', '5m', '2h', '1d', '1w') or an ISO 8601 timestamp"
        ),
    )
    p_audit.add_argument("--limit", type=int, default=100, help="max rows (default 100)")
    p_audit.add_argument("--json", action="store_true", help="emit JSONL instead of a table")
    p_audit.set_defaults(func=cmd_audit)

    p_audit_verify = sub.add_parser(
        "audit-verify",
        help="walk the audit-log hash chain ; exit 1 if tampered (ADR-0024)",
    )
    p_audit_verify.set_defaults(func=cmd_audit_verify)

    p_audit_anchor = sub.add_parser(
        "audit-anchor",
        help="emit an external anchor for the audit log (ADR-0029) ; commit "
        "to latest row hash so post-tamper deletion is detectable",
    )
    p_audit_anchor.add_argument(
        "--output",
        "-o",
        default=None,
        help="path to write the anchor JSON (default : stdout)",
    )
    p_audit_anchor.set_defaults(func=cmd_audit_anchor)

    p_audit_verify_anchor = sub.add_parser(
        "audit-verify-anchor",
        help="check the current audit DB chain still matches the anchor file (ADR-0029)",
    )
    p_audit_verify_anchor.add_argument("anchor_path", help="path to the anchor JSON")
    p_audit_verify_anchor.set_defaults(func=cmd_audit_verify_anchor)

    sub.add_parser("doctor", help="validate prerequisites").set_defaults(func=cmd_doctor)

    p_demo = sub.add_parser(
        "audit-demo",
        help="run the red-team scenario battery against the live policy stack",
    )
    p_demo.add_argument("--cerbos-url", default="http://127.0.0.1:3592")
    p_demo.add_argument("--report", type=Path, help="markdown report path")
    p_demo.add_argument("--json", action="store_true")
    p_demo.set_defaults(func=lambda a: audit_demo.main(_audit_demo_args(a)))

    p_policy = sub.add_parser("policy", help="policy operations")
    psub = p_policy.add_subparsers(dest="policy_cmd", required=True)
    psub.add_parser("lint", help="run `cerbos compile` against policies/").set_defaults(
        func=cmd_policy_lint
    )
    psub.add_parser("stats", help="top-N approved (resource_kind, action) tuples").set_defaults(
        func=cmd_policy_stats
    )
    p_policy_template = psub.add_parser(
        "template",
        help=(
            "scaffold a starter policies/ tree from a profile "
            "(developer-default | enterprise-strict)"
        ),
    )
    p_policy_template.add_argument(
        "profile",
        choices=["developer-default", "enterprise-strict"],
        help="policy profile to scaffold",
    )
    p_policy_template.add_argument(
        "--output",
        default="policies",
        help="target directory (default : ./policies)",
    )
    p_policy_template.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing files (default : skip files that already exist)",
    )
    p_policy_template.set_defaults(func=cmd_policy_template)

    p_principal = sub.add_parser(
        "principal",
        help="principal directory operations (ADR-0027 / ADR-0031)",
    )
    pripsub = p_principal.add_subparsers(dest="principal_cmd", required=True)
    p_principal_validate = pripsub.add_parser(
        "validate",
        help="validate config/principals.yaml schema (catches typos, missing fields)",
    )
    p_principal_validate.add_argument(
        "--path",
        default=None,
        help=(
            "path to principals.yaml "
            "(default : SECURED_CLAUDE_PRINCIPALS env or config/principals.yaml)"
        ),
    )
    p_principal_validate.set_defaults(func=cmd_principal_validate)

    p_principal_list = pripsub.add_parser(
        "list",
        help="list principals from config/principals.yaml (use one with `run --principal <id>`)",
    )
    p_principal_list.add_argument(
        "--path",
        default=None,
        help=(
            "path to principals.yaml "
            "(default : SECURED_CLAUDE_PRINCIPALS env or config/principals.yaml)"
        ),
    )
    p_principal_list.set_defaults(func=cmd_principal_list)

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
