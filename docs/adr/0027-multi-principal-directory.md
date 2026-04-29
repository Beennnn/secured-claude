# 27. Multi-principal directory (`config/principals.yaml`)

Date: 2026-04-29
Status: Accepted

## Context

`policies/derived_roles.yaml` (v0.1) already defined three roles :

- `claude_agent` — base agent (parent: `agent`)
- `trusted_agent` — derived when `request.principal.attr.trust_level >= 1`
- `auditor` — derived when `request.principal.attr.scope == "audit-only"`

But the broker hardcoded a single principal :

```python
principal_id=req.principal_id,           # variable
principal_roles=["agent", "claude_agent"],  # hardcoded
principal_attr={"trust_level": 0},       # hardcoded
```

The `derived_roles.yaml` definitions for `trusted_agent` and `auditor` could **never activate** because no caller could ever pass `trust_level: 1` or `scope: "audit-only"`. The multi-principal story was theatre.

The reviewer flagged it as a v0.3 known limitation : "Multi-principal Cerbos roles defined but broker hardcodes single principal". This ADR closes that gap.

## Decision

Introduce a **principal directory** at `config/principals.yaml` mapping each `principal_id` to its `roles` + `attributes`. The broker loads it at startup and uses it to populate the `principal_roles` + `principal_attr` for every Cerbos `CheckResources` call.

### `config/principals.yaml`

```yaml
principals:
  claude-code-default:
    roles: [agent]
    attributes:
      trust_level: 0

  claude-code-trusted:
    roles: [agent]
    attributes:
      trust_level: 1

  audit-only:
    roles: [agent]
    attributes:
      scope: "audit-only"
      trust_level: 0
```

The default principal (`claude-code-default`) preserves v0.1+v0.2 behaviour exactly — same roles, same attrs. Existing deployments keep working without change.

### Gateway loading

`load_principals(path: Path | None = None) → dict[str, dict[str, Any]]` :

- Reads `config/principals.yaml` (overridable via `SECURED_CLAUDE_PRINCIPALS` env).
- Returns `{principal_id → {roles, attributes}}` mapping.
- **Best-effort** : missing file or malformed YAML returns the single-default-principal fallback (matches pre-v0.3.1 hardcoded behaviour). Never fail-closed at startup over the principals file.
- Always includes `claude-code-default` in the result, even if the YAML omits it. Defensive ; ensures the default remains addressable.

`make_app(..., principals=None)` accepts an injected directory for tests. Production code uses `load_principals()` defaults.

### Lookup at request time

```python
principal_entry = principal_directory.get(req.principal_id) or _DEFAULT_PRINCIPAL
roles = list(principal_entry.get("roles") or ["agent"])
principal_attr = dict(principal_entry.get("attributes") or {})
```

Unknown `principal_id` → minimal default. The principal_id itself is **still passed to Cerbos and persisted in the audit log**, so the unknown principal is traceable. Fail-open here is safe because :

1. Roles fall back to `["agent"]` (minimum trust)
2. Attrs fall back to `{"trust_level": 0}` (no `trusted_agent` activation)
3. The Cerbos policies still gate every action (no policy exception for unknown principals).

### Operational model

To create a new principal :

1. Add an entry to `config/principals.yaml` under `principals:`.
2. Set the env in the agent container : `SECURED_CLAUDE_PRINCIPAL=<new-id>`.
3. The hook reads the env, sends it on each `/check`, broker resolves to the new roles/attrs, Cerbos evaluates with the new attribute set.

The audit log shows the principal_id on each row, so a "this Bash was approved as `claude-code-trusted`" lookup is one SQL query.

## Consequences

**Positive** :
- The multi-principal story is real now — `trusted_agent` and `auditor` derived roles can actually activate end-to-end.
- Operators can grant elevated trust to a specific session (e.g. "this batch job runs `claude-code-trusted` because it goes through manual review") without changing global policies.
- Unknown principal_ids are logged but treated as default — minimum-surprise behaviour for callers that don't read this ADR.
- 6 new tests cover : default attrs, trusted attrs, auditor scope, unknown fallback, YAML loading, missing-file fallback. Total 123 tests up from 117.
- Pure additive — no breaking change. v0.2.x deployments without `config/principals.yaml` keep working.

**Negative** :
- The principals file is now a security-relevant config that needs review on every change. Mitigated by it being checked into git + reviewed in PRs.
- A typo in the YAML (`atributes` vs `attributes`) silently falls back to default, which the operator might not notice. v0.4 ticket : add a `secured-claude principal validate` CLI subcommand that lints the file.

**Neutral** :
- The hook's request payload is unchanged — still just `{tool, tool_input, principal_id, session_id}`. Roles/attrs resolution is broker-side, not in the request schema.

## Alternatives considered

- **Pass roles + attrs in the request payload** — flexibility but trust-bypass risk : the agent (which is what the policy gate is meant to constrain) would self-declare its trust level. Rejected.
- **Convention-based principal_id parsing** (e.g. `claude-code-trust-1` → trust_level=1) — works but invents a serialization format that re-encodes what the YAML directory already does cleanly. Rejected.
- **External identity provider** (Auth0, Keycloak) — overkill for v0.3.1. v0.5 ticket if enterprise demand emerges.

## Verification

Tests in `tests/test_gateway.py` :

- `test_default_principal_uses_minimal_attrs` — claude-code-default → `roles=[agent]`, `trust_level=0`
- `test_trusted_principal_passes_higher_trust_level` — claude-code-trusted → `trust_level=1` reaches Cerbos
- `test_audit_only_principal_passes_scope` — audit-only → `scope=audit-only` reaches Cerbos
- `test_unknown_principal_falls_back_to_default_attrs` — unknown id → minimal default, principal_id preserved
- `test_load_principals_from_yaml` — direct loader test
- `test_load_principals_missing_file_returns_default` — missing file → fallback

End-to-end (manual) :

```
$ SECURED_CLAUDE_PRINCIPAL=claude-code-trusted secured-claude run "..."
$ secured-claude audit --principal claude-code-trusted | head -5
# rows show principal_id=claude-code-trusted, principal_roles=["agent"]
```

## References

- [`policies/derived_roles.yaml`](../../policies/derived_roles.yaml) — the Cerbos derived-role definitions this ADR finally activates
- [ADR-0001](0001-cerbos-as-policy-decision-point.md) — Cerbos PDP rationale
- [ADR-0009](0009-hook-fails-closed.md) — fail-closed contract (we still honour it on Cerbos calls ; only principal-loading is fail-open)
- v0.5 ticket : `secured-claude principal validate` lint CLI
- v0.5 ticket : external IdP integration (Auth0, OIDC)
