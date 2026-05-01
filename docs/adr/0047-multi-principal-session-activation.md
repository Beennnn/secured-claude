# 0047 — Multi-principal session activation

**Status** — Accepted (v0.9.0).

## Context

[ADR-0027](0027-multi-principal-directory.md) shipped the principal
**directory** : a YAML file (`config/principals.yaml`) mapping
`principal_id` → `roles` + `attributes`, resolved by the broker at
`/check` time and used by Cerbos derived roles
(`policies/derived_roles.yaml`) to elevate or constrain access. The
broker has consumed this directory since v0.3.1 ; the
`policies/derived_roles.yaml` already defines `trusted_agent` (gated on
`trust_level >= 1`) and `auditor` (gated on `scope == "audit-only"`).

The gap up to v0.8.x was on the **agent side** : the
`SECURED_CLAUDE_PRINCIPAL` env var was set ONCE at container boot
(via `docker-compose.yml`'s `environment:` block, default
`claude-code-default`). Switching principal required a container
restart — which closes session state, breaks the audit log
correlation by `session_id`, and is operationally awkward for an
operator who wants to demo "the same agent acting under role X then
role Y".

The `auditor` derived role had a `# Reserved for future v0.2`
comment. v0.3.1 wired the directory ; v0.9.0 closes the loop by
making the principal **session-bound** — chosen at `run`/`exec`
time rather than at container boot.

## Decision

Add a `--principal <principal_id>` flag to `secured-claude run` and
`secured-claude exec`. When set, the CLI :

1. Builds an env override dict `{"SECURED_CLAUDE_PRINCIPAL": <id>}`
2. Passes it through `orchestrator.exec_in(..., env=...)`
3. Which renders to `docker compose exec -e SECURED_CLAUDE_PRINCIPAL=<id>
   claude-code claude ...`

The agent container is unchanged — `claude` inherits the env, the
hook reads it (`os.getenv("SECURED_CLAUDE_PRINCIPAL", "claude-code-default")`),
the POST to `/check` carries the chosen principal_id, the broker
resolves it via the directory, Cerbos evaluates, the audit row
stores the resolved roles.

A new `secured-claude principal list` subcommand emits a Rich table
of available principal_ids so operators can discover what they can
pass to `--principal` without reading YAML.

## Consequences

**Positive** :

- The `auditor` and `trusted_agent` roles defined in
  `policies/derived_roles.yaml` since v0.1 are FINALLY usable
  end-to-end without code changes. The principal directory's
  attributes (`trust_level`, `scope`) actually steer Cerbos
  decisions per-session.
- `session_id` correlation in the audit log is preserved across
  principal switches (the container stays up ; only the env on
  the inner exec changes).
- Demo flow becomes trivial : `secured-claude run --principal
  claude-code-trusted` vs `secured-claude run --principal
  audit-only` shows the same agent under two trust levels in the
  same minute, with two distinguishable audit-row trails.
- Backward-compatible : without `--principal`, the agent's baked
  default applies (matches v0.8.x behaviour).

**Negative** :

- An operator with shell access to the host can choose any
  principal_id at `run` time. This is FINE for the single-user
  dev tool framing (the host operator IS the trust root — see
  ADR-0006 host-side broker). For a future multi-tenant SaaS
  framing, a JWT-bound `principal_id` (already supported via
  ADR-0038) would override the env-var choice and prevent
  unilateral elevation.
- A typo in `--principal` falls back to the directory's default
  fallback path (`claude-code-default`), which may surprise the
  operator. Mitigation : `secured-claude principal list` surfaces
  the catalogue ; the broker's existing principal-resolution
  metric counts unknown-principal lookups as cache misses
  (Prometheus counter `secured_claude_principal_resolution_total{
  result="unknown"}`).

**Neutral** :

- No new attack surface : the env override is on the `docker
  compose exec` argv, NOT on the long-running agent container's
  environment block. A previously-launched session that didn't
  pass `--principal` keeps its baked default. Sibling sessions
  with different principals are independent.

## Alternatives

**(a) JWT-only multi-principal — defer the env-var path** : require
the operator to mint a JWT with `sub: <principal_id>` and pass it
via `SECURED_CLAUDE_BEARER`. Rejected for v0.9.0 : the JWT path
requires an OIDC discovery URL (ADR-0038), a JWKS, and a key-pair
the operator owns — that's a real onboarding cost for a feature
that should "just work" on a fresh install. The env-var path
covers the common single-host case. The JWT path remains AVAILABLE
for the rare multi-tenant deployment that needs it (ADR-0041
multi-issuer ALLOWLIST + ADR-0044 per-issuer config still apply
on top).

**(b) Per-container principal (one container per principal_id)** :
boot N agent containers with `SECURED_CLAUDE_PRINCIPAL` baked.
Rejected : N × (image pull, network attach, dns/egress sidecars,
healthchecks) for a feature that's per-session. The host's `up`
already takes 10 s ; multiplying by 3 for trusted+default+auditor
is ergonomic suicide.

**(c) Configure principal at `up` time only (status quo)** :
deferring the activation. Rejected : the entire point of
ADR-0027's directory is operator-time choice ; if the principal
must be set at install time, the directory is a YAML file with one
useful entry, not a directory.

## Verification (passed v0.9.0 dev pipeline)

Live E2E smoke :

```bash
secured-claude up
echo "v0.9 multi-principal smoke" > workspace/v09-test.txt

# Force the trusted principal on this session
docker exec -e SECURED_CLAUDE_PRINCIPAL=claude-code-trusted secured-claude-agent \
  claude -p "read /workspace/v09-test.txt and summarise"

# Audit row carries the resolved principal_id + roles :
sqlite3 ~/Library/Application\ Support/secured-claude/approvals.db \
  "select ts, decision, principal_id, principal_roles
   from approvals order by id desc limit 1"
# 2026-05-01T12:24:43.569+00:00|ALLOW|claude-code-trusted|["agent","claude_agent"]|/workspace/v09-test.txt
```

Without `--principal`, the audit row would carry
`claude-code-default` (the container's baked env default). Same
session_id correlation either way ; only the principal field
differs — exactly the targeted axis.

Tests added in v0.9.0 :

- `tests/test_orchestrator.py::test_exec_in_threads_env_overrides_via_dash_e`
- `tests/test_orchestrator.py::test_exec_in_no_env_means_no_dash_e_flags`
- `tests/test_orchestrator.py::test_exec_in_empty_env_dict_means_no_dash_e_flags`
- `tests/test_cli.py::test_run_with_principal_flag_threads_env`
- `tests/test_cli.py::test_exec_with_principal_flag_threads_env`
- `tests/test_cli.py::test_principal_list_table_has_principals`
- `tests/test_cli.py::test_principal_list_missing_file_falls_back`
- `tests/test_cli.py::test_principal_list_malformed_yaml_returns_2`

Total : 321 tests pass (was 313 in v0.8.4 ; +8 new).
