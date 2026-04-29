"""Audit subcommand — render the SQLite approvals log to the user's terminal.

Reads from `Store` (read-only access) and pretty-prints rows with the `rich`
library. Supports filtering by decision / principal / resource_kind / action /
since, and JSON export for SIEM-style downstream pipelines.
"""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.table import Table

from secured_claude.store import Approval, Store


def render_table(rows: list[Approval], console: Console | None = None) -> None:
    """Render approvals as a Rich table to stdout."""
    cons = console or Console()
    if not rows:
        cons.print("[yellow]No matching audit rows.[/yellow]")
        return

    table = Table(
        title=f"secured-claude audit log — {len(rows)} row(s)",
        show_lines=False,
        header_style="bold magenta",
    )
    table.add_column("ts (UTC)", style="dim", no_wrap=True)
    table.add_column("decision", justify="center")
    table.add_column("kind")
    table.add_column("action")
    table.add_column("resource", overflow="fold", max_width=60)
    table.add_column("ms", justify="right", style="dim")

    for r in rows:
        decision_styled = "[green]ALLOW[/green]" if r.decision == "ALLOW" else "[red]DENY[/red]"
        table.add_row(
            r.ts,
            decision_styled,
            r.resource_kind,
            r.action,
            r.resource_id,
            str(r.duration_ms) if r.duration_ms is not None else "-",
        )
    cons.print(table)


def render_json(rows: list[Approval]) -> str:
    """Serialize approvals to one JSON object per line (SIEM-friendly)."""
    out_lines: list[str] = []
    for r in rows:
        record: dict[str, Any] = {
            "id": r.id,
            "ts": r.ts,
            "session_id": r.session_id,
            "principal_id": r.principal_id,
            "principal_roles": r.principal_roles,
            "resource_kind": r.resource_kind,
            "resource_id": r.resource_id,
            "action": r.action,
            "decision": r.decision,
            "args_json": r.args_json,
            "cerbos_reason": r.cerbos_reason,
            "duration_ms": r.duration_ms,
        }
        out_lines.append(json.dumps(record, ensure_ascii=False))
    return "\n".join(out_lines)


def query(
    store: Store,
    *,
    decision: str | None = None,
    principal_id: str | None = None,
    resource_kind: str | None = None,
    action: str | None = None,
    since: str | None = None,
    limit: int = 100,
) -> list[Approval]:
    """Thin wrapper around Store.query for the CLI subcommand."""
    return store.query(
        decision=decision,
        principal_id=principal_id,
        resource_kind=resource_kind,
        action=action,
        since=since,
        limit=limit,
    )


__all__ = ["query", "render_json", "render_table"]
