# 24. Hash-chain audit log (tamper-evident)

Date: 2026-04-29
Status: Accepted

## Context

[ADR-0004](0004-append-only-sqlite-audit-log.md) establishes the audit log as INSERT-only via SQLite triggers that ABORT on UPDATE/DELETE. The contract is "no row, once written, can be modified or removed through the application's SQL surface."

A reviewer pointed out the gap :

> "L'audit n'est pas tamper-proof : suppression du fichier SQLite possible hors application. Le README le reconnaît."

This is correct. The triggers protect against tampering through the application's connection. But the SQLite database file itself (`approvals.db` on the host) is just a file — anyone with filesystem access to the host (the user who runs `secured-claude` ; root ; another process running under the same UID) can :

- `rm approvals.db` — the next INSERT silently creates a new, empty database.
- Open the file with `sqlite3 approvals.db` directly and `DROP TRIGGER` then `UPDATE`/`DELETE` rows.
- Edit the binary file at byte level with a hex editor.

The triggers don't prevent any of these. The append-only contract holds *through the application's connection*, not against an attacker with file-level access.

The honest improvement isn't to make the file un-deletable (impossible without OS-level immutable-bit + SELinux + ...). It's to make tampering **detectable**. Once detected, the audit log loses integrity for the affected rows but the *fact* of tampering is preserved as evidence.

## Decision

Implement a per-row **SHA-256 hash chain** over the `approvals` table :

```
row_hash = SHA-256(prev_hash + ":" + canonical_json(row_content))
prev_hash = (previous row's row_hash)   for row 2+
prev_hash = "0000…0000" (64 hex zeros)  for the first row (genesis sentinel)
```

`canonical_json(row_content)` serializes the row's deterministic fields (`ts`, `session_id`, `principal_id`, `principal_roles`, `resource_kind`, `resource_id`, `action`, `decision`, `args_json`, `cerbos_reason`, `duration_ms`) with `sort_keys=True, separators=(",", ":"), ensure_ascii=True`. Excludes `id` (assigned by AUTOINCREMENT after INSERT) and the hash columns themselves.

### Schema additions

Two TEXT columns added to `approvals` :

- `prev_hash` — the previous row's `row_hash` (or genesis sentinel for row 1).
- `row_hash` — SHA-256 of `prev_hash || ":" || canonical_payload`.

ALTER TABLE migration in `Store._init_schema` runs idempotently — fresh installs get the columns from the `CREATE TABLE`, pre-v0.3 databases get them via ALTER. Pre-existing rows have NULL hashes ; the chain restarts at the first row inserted by v0.3+.

### Verification

`Store.verify_chain()` walks the table forward (id ASC) and recomputes each row's `row_hash`. On the first mismatch, returns a `ChainBreak(row_id, ts, expected_hash, actual_hash, reason)`. On clean traversal, returns `None`.

Two break reasons are distinguished :

- **prev_hash mismatch** — this row's `prev_hash` doesn't match the previous row's `row_hash`. The previous row was tampered with or removed. (Most common with `DELETE WHERE id=N` after dropping the trigger : row N+1 still references row N's old hash, but row N is gone or modified.)
- **row_hash mismatch** — this row's `row_hash` doesn't match the recomputed value from `prev_hash || canonical_payload`. The row's content was modified after INSERT.

Pre-v0.3 rows (NULL hash columns) are skipped.

### CLI surface

`secured-claude audit-verify` runs `verify_chain()` and exits :

- `0` — chain intact across all chained rows
- `1` — break detected, full report on stdout (row id, ts, expected vs actual hash, reason)
- `2` — DB unreadable / no chain to verify

## Consequences

**Positive** :
- Audit log is now **tamper-evident** (not tamper-proof — that's an OS-level concern).
- A compliance auditor can run `secured-claude audit-verify` as part of the routine evidence pull and either confirm the log's integrity or surface the exact row where it broke.
- The chain extends across application restarts (the `prev_hash` of the first row of each session is the `row_hash` of the last row of the previous session, persisted in the DB).
- Combined with the SQL triggers (no-UPDATE / no-DELETE), an attacker now needs to (a) escalate to filesystem access AND (b) rewrite the chain post-tampering AND (c) preserve the GENESIS link for it to look intact. That's significantly harder than the v0.2 contract.
- Implementation is single-file, stdlib-only (`hashlib.sha256`, no new deps).

**Negative** :
- Each INSERT now does one extra SQL roundtrip (read previous row's hash) and one SHA-256 computation. Microsecond-scale ; imperceptible at the broker's request rate.
- Migration of pre-v0.3 databases creates a "hash-less" prefix. Pre-existing rows can't be retroactively chained without altering them, which the trigger refuses. Acceptable — the chain establishes integrity for v0.3+ activity, the v0.2 prefix retains its v0.2 contract (append-only via trigger).
- The chain doesn't survive `rm approvals.db`. After deletion, the next INSERT creates a fresh genesis chain. `secured-claude audit-verify` would still pass, but a forensic investigator would notice the suspicious "starts at id=1 with genesis prev_hash" right next to a recent `ts` — a smoking gun. v0.3+ ticket : optionally export the latest `row_hash` to an external WORM store (cloud bucket with object-lock, GitLab CI artefact, …) so the deleted-and-recreated case is also detectable.

**Neutral** :
- No code change at the gateway / hook layer. The chain is internal to `Store`.

## Alternatives considered

- **SQLite trigger-side hashing** — register a custom SQL function `sha256(...)` via `sqlite3.create_function`, compute the hash inside an `AFTER INSERT` trigger. Cleaner in theory (the application can't forget to call it) but adds startup complexity (every connection must register the function) and conflates schema with crypto. Python-side at INSERT keeps the responsibility in one place. Rejected.
- **Merkle tree instead of linear chain** — overkill for our access pattern (we read sequentially in `audit-verify` ; we don't need O(log n) per-row proofs). Rejected for v0.3 ; revisitable if multi-broker / federated audit is added.
- **External hash anchor** (write the latest `row_hash` periodically to an external service like AWS QLDB or a public hash-anchor blockchain) — would close the `rm approvals.db` gap. Out of scope for v0.3 ; flagged as v0.4+ candidate.
- **Skip the chain ; document as known limitation** — the v0.2 status quo. Reviewer flagged as insufficient. Rejected.

## Verification

Unit tests in `tests/test_store.py` :

- `test_first_row_links_to_genesis` — first INSERT's `prev_hash` equals `GENESIS_PREV_HASH` (64 hex zeros).
- `test_subsequent_rows_link_to_previous` — each row's `prev_hash` equals the previous row's `row_hash`.
- `test_verify_chain_returns_none_when_intact` — clean DB → `verify_chain()` returns None.
- `test_verify_chain_detects_row_content_tampering` — drop trigger, UPDATE row 2's content, `verify_chain()` returns `ChainBreak(row_id=2, reason="row_hash mismatch...")`.
- `test_verify_chain_detects_prev_hash_tampering` — drop trigger, UPDATE row 2's `prev_hash`, `verify_chain()` returns `ChainBreak(row_id=2, reason contains "mismatch")`.
- `test_verify_chain_handles_pre_v03_rows` — NULL-hash rows are skipped ; the chain restarts at the first hashed row.

End-to-end CLI verification :

```
$ secured-claude audit-verify
Verifying 1247 row(s) in /Users/.../approvals.db...
✓ chain intact across 1247 row(s)

$ # tamper externally...
$ secured-claude audit-verify
Verifying 1247 row(s) in /Users/.../approvals.db...
✗ chain broken at row #842 (ts=2026-04-15T11:32:08.219+00:00)
  reason  : row_hash mismatch — row content was modified after INSERT
  expected: a3f2...
  actual  : 91ea...
```

## References

- [ADR-0004](0004-append-only-sqlite-audit-log.md) — append-only SQL contract that this ADR extends with tamper-evidence
- [ADR-0022](0022-intent-layer-vs-confinement-layers.md) — defense-in-depth contract ; the audit log is part of L1's evidence trail
- Git's content-addressable storage uses the same chained-hash idea (each commit references its parent's hash).
- Reviewer feedback that triggered this ADR : "Points faibles restants" critique 2026-04-29
