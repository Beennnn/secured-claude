"""Tests for the hook script's stdin/stdout JSON contract (ADR-0002, ADR-0009)."""

from __future__ import annotations

import json
import subprocess
import sys


def test_hook_emits_deny_when_broker_unreachable() -> None:
    """Hook fails closed when the broker URL is unreachable (ADR-0009)."""
    proc = subprocess.run(
        [sys.executable, "-m", "secured_claude.hook"],
        input=json.dumps(
            {
                "tool_name": "Read",
                "tool_input": {"file_path": "/workspace/foo.py"},
                "session_id": "test-session",
            }
        ),
        capture_output=True,
        text=True,
        timeout=10,
        env={
            "SECURED_CLAUDE_BROKER": "http://127.0.0.1:1",
            "SECURED_CLAUDE_TIMEOUT": "0.5",
            "PATH": "/usr/bin:/bin:/usr/local/bin",
        },
        check=False,
    )
    assert proc.returncode == 2, (
        f"hook should exit 2 on broker unreachable, got {proc.returncode}\nstderr={proc.stderr}"
    )
    out_line = proc.stdout.strip().split("\n")[-1]
    out = json.loads(out_line)
    assert out["permissionDecision"] == "deny"
    assert "broker unavailable" in out["permissionDecisionReason"]


def test_hook_emits_deny_on_invalid_stdin() -> None:
    """Hook DENY on malformed stdin JSON."""
    proc = subprocess.run(
        [sys.executable, "-m", "secured_claude.hook"],
        input="not-valid-json{",
        capture_output=True,
        text=True,
        timeout=10,
        env={
            "SECURED_CLAUDE_BROKER": "http://127.0.0.1:1",
            "PATH": "/usr/bin:/bin:/usr/local/bin",
        },
        check=False,
    )
    assert proc.returncode == 2
    out = json.loads(proc.stdout.strip().split("\n")[-1])
    assert out["permissionDecision"] == "deny"
    assert "invalid stdin JSON" in out["permissionDecisionReason"]
