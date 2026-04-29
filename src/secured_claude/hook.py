#!/usr/bin/env python3
"""PreToolUse hook for Claude Code (ADR-0002, ADR-0009).

Runs INSIDE the agent container. Reads the tool intent JSON from stdin,
POSTs to the host broker gateway, writes a `permissionDecision` JSON to
stdout. Fails closed (DENY) on any error per ADR-0009.

This file is also installed into the container image as the binary
`secured-claude-hook` via the pyproject.toml `project.scripts` entry.
The shebang above is essential when invoked as a Claude Code hook : the
hook system runs the file directly (no `python` prefix), so without the
shebang bash would parse it as shell and fail.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import requests

DEFAULT_BROKER = "http://host.docker.internal:8765"


def _emit_decision(decision: str, reason: str, exit_code: int) -> None:
    """Write the permissionDecision JSON to stdout per Claude Code hook spec."""
    payload = {
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }
    sys.stdout.write(json.dumps(payload))
    sys.stdout.write("\n")
    sys.stdout.flush()
    sys.exit(exit_code)


def main() -> None:
    broker_base = os.environ.get("SECURED_CLAUDE_BROKER", DEFAULT_BROKER).rstrip("/")
    broker_url = f"{broker_base}/check"
    timeout_s = float(os.environ.get("SECURED_CLAUDE_TIMEOUT", "2.0"))
    principal_id = os.environ.get("SECURED_CLAUDE_PRINCIPAL", "claude-code-default")

    raw = sys.stdin.read()
    try:
        data: dict[str, Any] = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as e:
        _emit_decision("deny", f"hook: invalid stdin JSON: {e}", 2)
        return

    tool = str(data.get("tool_name") or data.get("tool") or "unknown")
    tool_input = data.get("tool_input") or data.get("input") or {}
    session_id = str(data.get("session_id", "unknown-session"))

    body = {
        "tool": tool,
        "tool_input": tool_input,
        "principal_id": principal_id,
        "session_id": session_id,
    }

    try:
        resp = requests.post(broker_url, json=body, timeout=timeout_s)
        resp.raise_for_status()
        result = resp.json()
    except (requests.RequestException, ValueError) as e:
        _emit_decision(
            "deny",
            f"secured-claude broker unavailable: {type(e).__name__}: {e}",
            2,
        )
        return

    if result.get("approve"):
        _emit_decision("allow", str(result.get("reason", "")), 0)
    else:
        _emit_decision(
            "deny",
            str(result.get("reason", "denied by policy")),
            2,
        )


if __name__ == "__main__":
    main()
