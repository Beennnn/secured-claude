# 31. `secured-claude principal validate` lint CLI

Date: 2026-04-29
Status: Accepted

## Context

[ADR-0027](0027-multi-principal-directory.md) introduced `config/principals.yaml` as the per-principal roles + attributes directory. The broker's `load_principals()` is fail-open by design : a malformed entry, missing key, or wrong type silently falls back to the single-default principal. That's the right runtime behaviour (the broker shouldn't refuse to start over a typo) but it means the operator only finds out their YAML is broken when they notice their `claude-code-trusted` session is actually running with `trust_level: 0` — invisible until they audit the broker logs or the audit DB.

Common typos the loader silently absorbs :

- `role: [agent]` (singular) — the loader's `entry.get("roles")` returns None, falls back to default.
- `atributes: {trust_level: 1}` (missing 't') — same path, same silent fallback.
- `roles: "agent"` (string instead of list) — type check fails, entry skipped.
- `attributes: 42` (int instead of dict) — same.

A reviewer flagged this as a "v0.4+ ticket : add a `secured-claude principal validate` CLI subcommand that lints the file."

## Decision

Add `secured-claude principal validate [--path PATH]` as a CLI subcommand. Walks the principals YAML, reports each malformed entry with the specific issue, and returns a non-zero exit code so CI / pre-commit hooks can gate on it.

### Validation rules

For each `principal_id → entry` :

1. `entry` must be a YAML mapping (not a list, not a scalar).
2. `roles` must be a list of strings.
3. `attributes` if present must be a mapping.
4. **Typo guard** — explicit error if any of these singular / mistyped keys appears :
   - `role` (singular) → "did you mean `roles`?"
   - `atribute`, `atributes`, `attribute` → "did you mean `attributes`?"

The typo guard catches the most common operator errors in real review feedback. It's not exhaustive ; we don't try to be a full schema validator. But it covers the cases that have been silently absorbed in our own ADR-0027 + production rollouts.

### Output

```
$ secured-claude principal validate
✓ config/principals.yaml valid — 3 principal(s) defined
  claude-code-default: roles=[agent] attrs={trust_level=0}
  claude-code-trusted: roles=[agent] attrs={trust_level=1}
  audit-only: roles=[agent] attrs={scope=audit-only, trust_level=0}
```

Failure :

```
$ secured-claude principal validate --path /tmp/bad.yaml
✗ /tmp/bad.yaml has 5 validation issue(s):
  • 'bad-typo'.roles: must be a list of strings (got missing)
  • 'bad-typo': unknown key 'role' — did you mean roles?
  • 'bad-typo': unknown key 'atributes' — did you mean attributes?
  • 'bad-types'.roles: must be a list of strings (got str)
  • 'bad-types'.attributes: must be a mapping (got int)
$ echo $?
1
```

### Exit codes

- `0` — file valid, all entries well-formed (or file missing — fallback OK)
- `1` — at least one entry malformed
- `2` — file unreadable / not YAML

### Path resolution

Same as the broker's `load_principals()` :

1. `--path` arg if provided.
2. `SECURED_CLAUDE_PRINCIPALS` env var.
3. `config/principals.yaml` (relative to CWD).

Missing file returns 0 with a `yellow` info message — the broker would use the single-default fallback in this case, which is intentional, not an error.

## Consequences

**Positive** :
- Operators catch typos at edit-time instead of next-Cerbos-eval-time.
- The command is wireable into pre-commit hooks (`secured-claude principal validate || exit 1`).
- 5 new tests cover happy-path, typo-detection, type-mismatch, missing-file (returns 0), malformed YAML (returns 2). 137 tests total.
- Doesn't change runtime behaviour — the broker's fail-open `load_principals` stays as-is per ADR-0027.

**Negative** :
- Two parsers now exist for the same file (`load_principals` runtime + `cmd_principal_validate` lint). They could drift. Mitigated by sharing the YAML structure expectations + the validation tests.
- The typo guard is heuristic ; it won't catch every typo (e.g. `roless`, `attribut`). Operators get strong signals on the common mistakes ; weirder typos still fall through to fail-open. Acceptable.

**Neutral** :
- Pure additive CLI ; no broker / hook / agent changes.

## Alternatives considered

- **Schema validation via `jsonschema`** — full schema-driven, catches every typo. Adds a new dependency + a schema file to maintain. Rejected for v0.5 ; the typo-guard heuristic is simpler. If the directory grows past 5-6 keys, revisit.
- **Make `load_principals` fail-CLOSED on invalid entries** — rejected per ADR-0027's "broker should never fail-closed at startup over a non-critical config". Lint catches the issue before runtime.
- **Skip and document** — what v0.3.1 did. Reviewer flagged. Closed in v0.5.

## Verification

Tests in `tests/test_cli.py` :

- `test_principal_validate_reports_valid_file` — happy path, exit 0.
- `test_principal_validate_catches_typo_in_key` — `role` + `atributes` → exit 1.
- `test_principal_validate_catches_wrong_types` — `roles: "string"` + `attributes: 42` → exit 1.
- `test_principal_validate_missing_file_returns_0` — missing file is OK.
- `test_principal_validate_malformed_yaml_returns_2` — invalid YAML → exit 2.

End-to-end :

```
$ uv run secured-claude principal validate
✓ config/principals.yaml valid — 3 principal(s) defined
$ echo $?
0
```

## References

- [ADR-0027](0027-multi-principal-directory.md) — principals directory ; this ADR's runtime complement
- [ADR-0009](0009-hook-fails-closed.md) — fail-closed at the broker layer (runtime calls), but the principals file is a separate fail-open by design
