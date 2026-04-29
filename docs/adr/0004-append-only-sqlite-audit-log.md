# ADR-0004: Append-only SQLite audit log

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

## Context

Every tool intent — approved or denied — must be recorded in a way that :

- **Survives restarts** of the broker (durable storage).
- **Cannot be tampered with** by approved actions inside the agent container.
- **Is queryable** for audit, compliance, and the `secured-claude audit` CLI.
- **Is portable across Mac / Linux / Windows** (cross-platform constraint).
- **Has near-zero operational overhead** (no separate database server to manage).
- **Can grow into a SIEM feed** for v0.2+.

The audit log is the single source of truth for retrospective security review, EU AI Act Art. 12 compliance, and the "evolving allowlist" of approved tuples that justifies our threat model.

## Decision

We use **SQLite** (Python stdlib `sqlite3`) as the audit store. The single file `approvals.db` lives in the cross-platform OS data directory ([ADR-0007](0007-cross-platform-via-docker-sdk.md), `_paths.py`). The schema is **append-only** — the broker code only ever issues `INSERT`, never `UPDATE` or `DELETE` :

```sql
CREATE TABLE approvals (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL,                          -- ISO 8601 UTC
    session_id      TEXT NOT NULL,
    principal_id    TEXT NOT NULL,
    principal_roles TEXT NOT NULL,                          -- JSON array
    resource_kind   TEXT NOT NULL,                          -- file|command|url|mcp_tool|...
    resource_id     TEXT NOT NULL,                          -- path / cmd / url / tool name
    action          TEXT NOT NULL,                          -- read|write|execute|fetch|invoke|...
    decision        TEXT NOT NULL CHECK(decision IN ('ALLOW','DENY')),
    args_json       TEXT,
    cerbos_reason   TEXT,
    duration_ms     INTEGER
);
CREATE INDEX idx_approvals_principal ON approvals(principal_id);
CREATE INDEX idx_approvals_resource_action ON approvals(resource_kind, action);
CREATE INDEX idx_approvals_ts ON approvals(ts);
```

A SQL trigger refuses `UPDATE` and `DELETE` :

```sql
CREATE TRIGGER approvals_no_update BEFORE UPDATE ON approvals
  BEGIN SELECT RAISE(ABORT, 'append-only: UPDATE forbidden'); END;
CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals
  BEGIN SELECT RAISE(ABORT, 'append-only: DELETE forbidden'); END;
```

(The trigger is defense-in-depth — the broker code wouldn't issue UPDATE/DELETE anyway, but a coding mistake or future feature that tries to "compact" the log will fail loud.)

The DB file mode is `0o600` (owner read/write only).

## Consequences

### Positive

- **Zero-config** — no database server, no migrations to manage, ships in the Python wheel automatically (`sqlite3` is stdlib).
- **Durable** — SQLite WAL mode survives broker crashes.
- **Queryable** — `secured-claude audit --denied --since 1d` works out of the box. Standard SQL means any analyst with `sqlite3 approvals.db` can investigate.
- **Append-only enforced at two levels** — broker code (no UPDATE/DELETE in the codebase) + DB trigger.
- **Cross-platform** — SQLite is supported on Mac / Linux / Windows identically.
- **Integration-ready** — exporting to JSON Lines for SIEM (Splunk, Datadog, Elastic) is `secured-claude audit --json`.
- **Compliance** — supports EU AI Act Art. 12 (record-keeping for high-risk AI), NIST CIS Control 8 (Audit Log Management), and SOC 2 CC7.2 (system monitoring).

### Negative

- **Single-file = single point of corruption** — if `approvals.db` is deleted, history is lost. Mitigated by : (a) optional periodic backup via `secured-claude audit --backup`, (b) v0.2 SIEM export gives a second copy.
- **Concurrent writes** — SQLite serializes writes. With our load (~1 write per tool call, ~10s of QPS at peak), this is fine. If we ever need higher throughput, switch to PostgreSQL (and write a migration ADR).
- **No cryptographic chain (Merkle / hash-chain) yet** — a sufficiently determined adversary with file write access could in principle replay the DB. Mitigated by : (a) DB file permissions, (b) the agent container has no host filesystem access (L3), (c) v0.2 will add hash-chained entries (each row's hash includes the previous row's, so retroactive editing breaks the chain).
- **Args may contain sensitive data** — file paths, command lines, URLs may include secrets the user typed (e.g. `Bash "kubectl --token=xyz get pods"`). Mitigated by : (a) `args_json` redaction patterns for known token formats, (b) DB file mode 0o600.

### Neutral

- The DB grows linearly with usage. Empirically : ~1 KB per row, so ~1 GB per million tool calls. For v0.1 we accept this ; v0.2 may add a rotation policy (archive rows older than N days).

## Alternatives considered

- **Plain JSONL append file** — even simpler, but : no transactions (tool call could die mid-write leaving partial JSON), no efficient queries (need to grep through history), no schema evolution support. Rejected.
- **Plain CSV** — same problems as JSONL, plus quoting ambiguity for paths with commas.
- **PostgreSQL** — overkill for v0.1 ; adds a dependency that defeats "single binary install". Reasonable for a multi-host enterprise deployment in v0.3+.
- **syslog / journald** — OS-dependent, not cross-platform, awkward to query.
- **Cerbos audit log only** (Cerbos can write its own audit) — yes, we'll *also* enable Cerbos audit (`audit.enabled: true` in the Cerbos config), but it lives inside the Cerbos container and is harder to query / export. Our SQLite is the *primary* audit, Cerbos's is a redundant secondary trail.
- **Append-only object storage (S3 with object-lock)** — ideal for tamper-evidence in production, but requires cloud setup. Out of scope v0.1 ; planned v0.3+ as a SIEM target.
- **Hash-chained Merkle tree** in v0.1 — adds complexity without immediate user value. Tracked as v0.2 enhancement.

## References

- SQLite WAL mode — https://sqlite.org/wal.html
- EU AI Act Art. 12 (Record-keeping) — https://artificialintelligenceact.eu/the-act/
- NIST CIS Control 8 (Audit Log Management) — https://www.cisecurity.org/controls/v8
- SOC 2 CC7.2 — system monitoring requirements
- Implementation : [`src/secured_claude/store.py`](../../src/secured_claude/store.py)
- Tests : [`tests/test_store.py`](../../tests/test_store.py) — verifies trigger blocks UPDATE/DELETE
- Related ADRs : [0007](0007-cross-platform-via-docker-sdk.md) (cross-platform paths), [0011](0011-no-secret-baked-in-image.md) (no secrets in args), [0006](0006-host-side-broker.md) (broker location)
