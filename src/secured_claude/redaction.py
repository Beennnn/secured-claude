"""On-the-fly secret redaction for tool outputs (ADR-0046).

The PreToolUse hook + Cerbos PDP gate INTENT — they catch
`Read /etc/passwd` before it executes. They do NOT catch the case where
the agent legitimately reads `/workspace/.env` (workspace path, ALLOWed
by policy) and the file CONTENT contains a secret that then ships to
the LLM verbatim. That's a content-level exfiltration vector that the
v0.7.x design left open ; this module closes it.

Posture (v0.8.0 baseline) :

  * `RedactionEngine` scans tool-output content for secrets matching
    a curated subset of gitleaks-style patterns (AWS / GitHub / GitLab /
    Stripe / Slack tokens, JWTs, generic-api-key heuristic, private-key
    PEM markers, DB connection strings).
  * Matches are replaced with opaque placeholders : `<<SECRET:uuid>>`.
  * The placeholder→value map is held in memory, keyed by session_id.
    Never persisted to disk ; broker restart = mapping lost = next
    redact-restore round just generates fresh placeholders.
  * `restore()` substitutes placeholders back. Used by the broker
    when the LLM later needs the actual secret value (e.g. a Bash
    command that legitimately passes a credential to a CLI).

What this DOES NOT catch (documented honest limits) :

  * Custom-format secrets : a token like `mycorp-secret-7a2b...` won't
    match any pattern. v0.8.x adds an `aggressive` mode for files
    explicitly marked as sensitive.
  * Inferred-from-context secrets : an env var line `AWS_KEY=<<SECRET:abc>>`
    leaks the *kind* of secret (the variable name) even if not the
    value. Consider that "metadata leak" out of scope.
  * Adversarial Bash : if the LLM tries `base64 -d <<<<<SECRET:abc>>>`
    or other transformation, the literal substitution doesn't apply —
    the broker rejects Bash commands containing placeholders that
    aren't whole-word arguments.

Activation : `SECURED_CLAUDE_REDACT_LEVEL` env :
  * `off` (default) — pre-v0.8 behaviour, no redaction.
  * `secrets` — patterns below applied to all PostToolUse Read results.
  * `aggressive` — reserved for v0.8.x ; same as `secrets` for now.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
from dataclasses import dataclass

from secured_claude import metrics

log = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────
# Curated pattern library
# ────────────────────────────────────────────────────────────────────
#
# Each entry : (rule_id, regex). The rule_id appears in audit logs +
# prom counter labels so operators can see which pattern fired.
#
# Patterns are conservative — they target high-confidence formats that
# rarely produce false positives. Generic heuristics (e.g. "any base64
# string > 32 chars") are deliberately excluded ; they'd flag normal
# source code.

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # AWS — strict format from AWS docs
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # AWS secret key — 40 chars base64-safe alphabet (heuristic — only
    # match in the context of AWS env-style assignments to limit false
    # positives in source code).
    (
        "aws-secret-key",
        re.compile(r"(?i)aws[_\-]?secret[_\-]?(access[_\-]?)?key[\s:='\"]+([A-Za-z0-9/+=]{40})\b"),
    ),
    # GitHub PAT formats (classic + fine-grained)
    ("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github-fine-grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("github-oauth", re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("github-server-token", re.compile(r"\bghs_[A-Za-z0-9]{36}\b")),
    # GitLab PAT
    ("gitlab-pat", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b")),
    # Slack
    ("slack-bot-token", re.compile(r"\bxoxb-[A-Za-z0-9\-]{20,}\b")),
    ("slack-user-token", re.compile(r"\bxoxp-[A-Za-z0-9\-]{20,}\b")),
    # Stripe
    ("stripe-live-secret", re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b")),
    ("stripe-test-secret", re.compile(r"\bsk_test_[A-Za-z0-9]{24,}\b")),
    # Anthropic API key (sk-ant-...)
    ("anthropic-api-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b")),
    # OpenAI key
    ("openai-api-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b")),
    # Generic JWT (3 base64url segments separated by dots — ~standard)
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ),
    # Private key PEM markers (covers RSA / EC / OpenSSH / PGP)
    (
        "pem-private-key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    ),
    # DB connection strings with embedded credentials
    (
        "db-conn-string",
        re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^\s]+"),
    ),
    # Generic api_key=... assignment (last in priority — broader match)
    (
        "generic-api-key",
        re.compile(
            r"(?i)\b(?:api[_\-]?key|access[_\-]?token|auth[_\-]?token)[\s:='\"]+([A-Za-z0-9_\-]{20,})\b"
        ),
    ),
]


@dataclass
class RedactionResult:
    content: str
    matches: list[str]  # rule_ids that fired (multiset for counting)
    mapping: dict[str, str]  # placeholder → original secret


class RedactionEngine:
    """Scans content for known secret formats, replaces with placeholders.

    Stateful : holds a `dict[session_id, dict[placeholder, secret]]` so
    later `restore()` calls can substitute back. State lives in memory
    only ; broker restart = state lost = LLM gets fresh placeholders
    on the next interaction.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, dict[str, str]] = {}

    def _make_placeholder(self) -> str:
        # 16 hex chars = 64 bits of entropy ; collision-safe at any
        # realistic per-session secret count.
        return f"<<SECRET:{secrets.token_hex(8)}>>"

    def redact(self, content: str, session_id: str) -> RedactionResult:
        """Replace every secret match with a placeholder.

        Returns the redacted content + the list of rule_ids that fired
        (for logging + Prometheus counters) + the new mapping additions.
        """
        if not content:
            return RedactionResult(content=content, matches=[], mapping={})
        session_map = self._sessions.setdefault(session_id, {})
        new_mapping: dict[str, str] = {}
        matches_fired: list[str] = []
        result = content
        for rule_id, pattern in _PATTERNS:

            def _replace(match: re.Match[str], rid: str = rule_id) -> str:
                # Avoid double-redacting : if the matched string is itself
                # a placeholder (recursive case), pass through.
                if match.group(0).startswith("<<SECRET:"):
                    return match.group(0)
                placeholder = self._make_placeholder()
                session_map[placeholder] = match.group(0)
                new_mapping[placeholder] = match.group(0)
                matches_fired.append(rid)
                return placeholder

            result = pattern.sub(_replace, result)
        if matches_fired:
            log.info(
                "redaction : session=%s rules_fired=%s n=%d",
                session_id,
                sorted(set(matches_fired)),
                len(matches_fired),
            )
            for rule in matches_fired:
                metrics.REDACTION_MATCHES_TOTAL.labels(rule=rule).inc()
        return RedactionResult(content=result, matches=matches_fired, mapping=new_mapping)

    def restore(self, content: str, session_id: str) -> str:
        """Substitute every placeholder for this session back to its secret.

        Placeholders not in the session map (e.g. forged by the LLM,
        or from a previous broker process) are left untouched — the
        caller (broker /check route) decides whether such a leftover
        placeholder is grounds to DENY the tool call.
        """
        session_map = self._sessions.get(session_id)
        if not session_map:
            return content
        for placeholder, secret in session_map.items():
            content = content.replace(placeholder, secret)
        return content

    def has_unresolved_placeholder(self, content: str, session_id: str) -> bool:
        """True if `content` mentions a placeholder NOT in the session map.

        Used by the broker to refuse Bash / Write commands that reference
        placeholders we can't resolve (forged or expired). Refusing is
        safer than passing the literal `<<SECRET:abc>>` to the shell.
        """
        unknown_pattern = re.compile(r"<<SECRET:[a-f0-9]{16}>>")
        session_map = self._sessions.get(session_id, {})
        for match in unknown_pattern.finditer(content):
            if match.group(0) not in session_map:
                return True
        return False

    def session_count(self, session_id: str) -> int:
        """How many placeholders are currently live for this session."""
        return len(self._sessions.get(session_id, {}))


def make_engine() -> RedactionEngine | None:
    """Factory : returns an engine if SECURED_CLAUDE_REDACT_LEVEL activates it.

    `off` (default) → None ; broker uses no redaction (pre-v0.8 behaviour).
    `secrets` / `aggressive` → engine instance (aggressive == secrets in v0.8.0 ;
    additional patterns reserved for v0.8.x per ADR-0046).
    """
    level = os.environ.get("SECURED_CLAUDE_REDACT_LEVEL", "off").strip().lower()
    if level in ("secrets", "aggressive"):
        return RedactionEngine()
    return None


__all__ = ["RedactionEngine", "RedactionResult", "make_engine"]
