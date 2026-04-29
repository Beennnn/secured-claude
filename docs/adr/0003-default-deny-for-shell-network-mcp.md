# ADR-0003: Default-deny for shell, network, and MCP

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

## Context

When defining Cerbos policies for a Claude Code agent, we have a choice for each resource kind :

- **Allow-list** : everything is denied unless explicitly listed as allowed.
- **Deny-list** : everything is allowed unless explicitly listed as denied.

For an enterprise security posture, allow-list is the default best practice ([OWASP A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/), [NIST SP 800-53 AC-3](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1.1&number=AC-3)). Deny-list is whack-a-mole : every new attack vector requires a new entry.

But allow-list has a friction cost : a developer using a tool we didn't pre-approve hits a wall, has to add it to the allowlist, restart, retry. We must minimize false-positives without weakening security.

## Decision

For the high-risk resource kinds, the policy default is **DENY** :

- **`command`** (Bash) — DENY by default ; ALLOW only commands whose `first_word` is in the allowlist (`{ls, cat, grep, find, head, tail, wc, git, npm, uv, pip, python, python3, node, mvn, ./mvnw, docker, kubectl, echo, date, pwd, which, cd}`) AND whose full string does not match the deny-pattern list (`rm -rf /`, `curl ... | sh`, `sudo`, `chmod 777`, fork bombs, etc.).
- **`url`** (WebFetch) — DENY by default ; ALLOW only when `host` ∈ allowlist (GitHub, npm, PyPI, anthropic.com, docs.claude.com, etc.).
- **`mcp_tool`** (MCP server invocations) — DENY by default ; ALLOW only when `server` is explicitly listed in `policies/mcp.yaml`.

For lower-risk, **fenced ALLOW** is acceptable :

- **`file`** (Read/Write/Edit) — ALLOW for paths under `/workspace/`, DENY for the deny-pattern list (`.ssh/`, `.aws/`, `.gnupg/`, `password`, `secret`, `.env`, `id_rsa`, etc.). Outside `/workspace/`, DENY by default.

## Consequences

### Positive

- **Closed surface** — adding a new MCP server, a new domain, a new shell command is an explicit policy edit (PR + review by sec). No silent expansion.
- **Easier review** — security can read `policies/shell.yaml` and see the full list of executables Claude is permitted to invoke. No need to enumerate "what's denied" (infinite).
- **Defense against unknown attacks** — a new clever Bash trick that wasn't in our deny list still fails the allow check (it must match an allowed first_word AND not match deny patterns).
- **Aligns with established standards** — OWASP A01, NIST AC-3, CIS Control 4 (Secure Configuration), MITRE ATT&CK M1038 (Execution Prevention).

### Negative

- **Friction when an unlisted command is needed** — example : developer wants to run `ruff check`, but `ruff` not in allowlist. Resolution : edit `policies/shell.yaml`, PR, merge. This is a feature, not a bug — it forces explicit consideration. Mitigated by : (a) the default allowlist is generous for normal dev work (git, npm, uv, pip, mvn, etc.), (b) ALLOW additions are low-risk PRs to review.
- **Allowlist maintenance** — over time the list grows. Mitigated by : (a) `secured-claude policy stats` shows usage frequency so we can prune unused entries, (b) v0.2+ "policy generation" feature suggests bulk additions from the audit log.
- **Risk of allow-list creep** — every PR that adds a command is one more thing trusted. Mitigated by : (a) ADR-style review for any policy change (justification for why this command is safe), (b) defense-in-depth — even an allowed command is bounded by L2 (network), L3 (FS), L4 (container hardening).

### Neutral

- We accept that the broker is in the critical path of every tool call. Allowlist evaluation is O(1) (`set` membership) ; per-rule regex matches are O(n_patterns) but small.

## Alternatives considered

- **Deny-list everything** — simpler initial config, much weaker. New attack vectors require updating the policy AFTER the attack is known. Rejected — explicitly the OWASP A01 anti-pattern.
- **Mixed default per resource kind, allow for files** — accepted (see decision : `file` is fenced-ALLOW under `/workspace/`).
- **Per-principal default** (e.g. trusted_agent has wider allowlist) — useful pattern via Cerbos derived roles, planned for v0.2+ when multi-principal arrives. v0.1 single principal makes this unnecessary.
- **Time-of-day or geo-based conditions** — out of scope for v0.1 ; could be added via Cerbos CEL conditions in v0.2 if requested.

## References

- OWASP Top 10 2021, A01 Broken Access Control — https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- NIST SP 800-53 AC-3 (Access Enforcement) — https://csrc.nist.gov/Projects/risk-management/sp800-53-controls
- CIS Controls v8 — Control 4 (Secure Configuration of Enterprise Assets and Software)
- MITRE ATT&CK M1038 (Execution Prevention) — https://attack.mitre.org/mitigations/M1038/
- Policy files implementing this : [`policies/shell.yaml`](../../policies/shell.yaml), [`policies/network.yaml`](../../policies/network.yaml), [`policies/mcp.yaml`](../../policies/mcp.yaml), [`policies/filesystem.yaml`](../../policies/filesystem.yaml)
- Test verifying default-deny : [`tests/test_audit_demo.py`](../../tests/test_audit_demo.py) (R5 — un-allowlisted MCP DENY)
- Related ADRs : [0001](0001-cerbos-as-policy-decision-point.md), [0012](0012-defense-in-depth-layers.md)
