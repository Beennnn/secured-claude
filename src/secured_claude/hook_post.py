#!/usr/bin/env python3
"""PostToolUse hook for Read results — secret redaction (ADR-0046).

Runs INSIDE the agent container after a Read tool call. Reads the
tool-result JSON from stdin, POSTs the file CONTENT to the host
broker's `/transform` route with action=redact, and outputs the
redacted content as a `decision: block` with the redacted text as
`reason` — Claude Code surfaces the reason to the LLM as if it was
the tool result, so the LLM sees redacted secrets instead of raw ones.

Activation : when SECURED_CLAUDE_REDACT_LEVEL is unset / off in the
broker, the broker /transform route returns the input unchanged ;
the hook becomes a no-op pass-through. Operators opt in by setting
SECURED_CLAUDE_REDACT_LEVEL=secrets before `secured-claude up`.

Fail-open semantics (deliberate, see ADR-0046 § "Failure modes") :
if the broker is unreachable or returns an error, the hook exits
cleanly without blocking. The PreToolUse hook (ADR-0009) already
fails CLOSED on broker-unavailable, so an attacker can't bypass
policy by killing the broker — but for redaction, blocking the
Read entirely on broker-down would degrade UX without security
benefit (the secret never left the broker because there's no broker
to send to).
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import requests

DEFAULT_BROKER = "http://host.docker.internal:8765"


def main() -> None:
    broker_base = os.environ.get("SECURED_CLAUDE_BROKER", DEFAULT_BROKER).rstrip("/")
    transform_url = f"{broker_base}/transform"
    timeout_s = float(os.environ.get("SECURED_CLAUDE_TIMEOUT", "2.0"))

    raw = sys.stdin.read()
    try:
        data: dict[str, Any] = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        # Malformed input ; pass through (not our place to decide).
        sys.exit(0)

    tool_name = str(data.get("tool_name", ""))
    if tool_name != "Read":
        # We only redact Read results in v0.8.0. Other tools pass through.
        sys.exit(0)

    session_id = str(data.get("session_id", "unknown-session"))
    tool_response = data.get("tool_response", "")

    # tool_response shape varies : sometimes a string (file content),
    # sometimes a dict (with a "content" or "text" field). Cover both.
    if isinstance(tool_response, dict):
        content = (
            tool_response.get("content")
            or tool_response.get("text")
            or tool_response.get("output")
            or ""
        )
    else:
        content = str(tool_response)

    if not content:
        sys.exit(0)

    try:
        resp = requests.post(
            transform_url,
            json={"action": "redact", "content": content, "session_id": session_id},
            timeout=timeout_s,
        )
        resp.raise_for_status()
        result = resp.json()
    except (requests.RequestException, ValueError):
        # Broker unreachable / bad response — fail-open per docstring.
        sys.exit(0)

    redacted = result.get("content", content)
    matches = result.get("matches_fired", [])

    if not matches:
        # No secrets detected — nothing to do, pass the original content
        # through unchanged.
        sys.exit(0)

    # Output the redacted content as a `block` decision so Claude Code
    # surfaces the redacted text to the LLM in place of the raw
    # tool_response. Matches list goes into the reason for visibility.
    summary = (
        f"[secured-claude redacted {len(matches)} secret(s) "
        f"({', '.join(sorted(set(matches)))}) before they reached the LLM]\n"
    )
    print(
        json.dumps(
            {
                "decision": "block",
                "reason": summary + redacted,
            }
        )
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
