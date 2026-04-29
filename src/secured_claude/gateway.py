"""FastAPI gateway — receives PreToolUse hook intents, queries Cerbos, logs to SQLite.

Implements ADR-0001 (Cerbos PDP), ADR-0002 (hook interception), ADR-0004
(append-only audit log), ADR-0009 (fail-closed).
"""

from __future__ import annotations

import logging
import os
import urllib.parse
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from secured_claude import __version__
from secured_claude.cerbos_client import CerbosClient, CheckResult
from secured_claude.store import Store

log = logging.getLogger(__name__)


class CheckRequest(BaseModel):
    tool: str
    tool_input: dict[str, Any] = Field(default_factory=dict)
    principal_id: str = "claude-code-default"
    session_id: str = "unknown-session"


class CheckResponse(BaseModel):
    approve: bool
    reason: str
    decision_id: int


def map_tool_to_resource(
    tool: str, tool_input: dict[str, Any]
) -> tuple[str, str, str, dict[str, Any]]:
    """Map a Claude Code tool call to a Cerbos resource (kind, id, action, attr)."""
    tool_lower = tool.lower()

    if tool_lower == "read":
        path = str(tool_input.get("file_path") or tool_input.get("path") or "")
        return ("file", path, "read", {"path": path})

    if tool_lower == "write":
        path = str(tool_input.get("file_path") or tool_input.get("path") or "")
        content = tool_input.get("content", "")
        size = len(content) if isinstance(content, str) else 0
        return ("file", path, "write", {"path": path, "size": size})

    if tool_lower in ("edit", "multiedit"):
        path = str(tool_input.get("file_path") or tool_input.get("path") or "")
        return ("file", path, "edit", {"path": path})

    if tool_lower == "bash":
        full = str(tool_input.get("command", ""))
        first_word = full.strip().split(maxsplit=1)[0] if full.strip() else ""
        return (
            "command",
            full[:200],
            "execute",
            {"cmd_first_word": first_word, "full_cmd": full},
        )

    if tool_lower == "webfetch":
        url = str(tool_input.get("url", ""))
        parsed = urllib.parse.urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return (
            "url",
            url[:300],
            "fetch",
            {
                "host": parsed.hostname or "",
                "scheme": parsed.scheme or "",
                "port": port,
                "method": str(tool_input.get("method", "GET")),
                "url_full": url,
            },
        )

    if tool_lower == "websearch":
        query = str(tool_input.get("query", ""))
        return ("web_search", query[:300], "query", {"query_text": query})

    if tool.startswith("mcp__"):
        parts = tool.split("__", 2)
        server = parts[1] if len(parts) >= 2 else ""
        mcp_tool = parts[2] if len(parts) >= 3 else ""
        return (
            "mcp_tool",
            f"{server}/{mcp_tool}",
            "invoke",
            {"server": server, "tool": mcp_tool, "input": tool_input},
        )

    return ("unknown_tool", tool, "invoke", {"tool": tool, "input": tool_input})


def make_app(
    cerbos: CerbosClient | None = None,
    store: Store | None = None,
) -> FastAPI:
    """Build the FastAPI app. Test code injects mocks via `cerbos` and `store`."""
    cerbos_client = cerbos or CerbosClient(
        base_url=os.environ.get("CERBOS_URL", "http://127.0.0.1:3592")
    )
    audit_store = store or Store()

    app = FastAPI(title="secured-claude broker", version=__version__)

    @app.post("/check", response_model=CheckResponse)
    def check(req: CheckRequest) -> CheckResponse:
        kind, rid, action, attr = map_tool_to_resource(req.tool, req.tool_input)
        try:
            result: CheckResult = cerbos_client.check(
                principal_id=req.principal_id,
                principal_roles=["agent", "claude_agent"],
                principal_attr={"trust_level": 0},
                resource_kind=kind,
                resource_id=rid,
                resource_attr=attr,
                actions=[action],
            )
            allow = result.allow
            reason = result.reason
            duration_ms = result.duration_ms
        except Exception as e:
            log.exception("Cerbos call failed")
            allow = False
            reason = f"cerbos PDP unavailable: {type(e).__name__}: {e}"
            duration_ms = 0

        decision = "ALLOW" if allow else "DENY"
        decision_id = audit_store.insert(
            session_id=req.session_id,
            principal_id=req.principal_id,
            principal_roles=["agent", "claude_agent"],
            resource_kind=kind,
            resource_id=rid,
            action=action,
            decision=decision,
            args=req.tool_input,
            cerbos_reason=reason,
            duration_ms=duration_ms,
        )
        return CheckResponse(approve=allow, reason=reason, decision_id=decision_id)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "approvals_count": audit_store.count()}

    return app


__all__ = ["CheckRequest", "CheckResponse", "make_app", "map_tool_to_resource"]
