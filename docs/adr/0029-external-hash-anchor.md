# 29. External hash anchor for the audit log

Date: 2026-04-29
Status: Accepted

## Context

[ADR-0024](0024-hash-chain-audit-log.md) made the audit log **tamper-evident** : a SHA-256 chain over every row means modifying or removing a row breaks the chain on the next `audit-verify`. But the file itself is still deletable — `rm approvals.db` followed by a fresh start produces a chain that begins at id=1 with the genesis sentinel, ts=very-recent. A forensic investigator would notice, but `audit-verify` itself returns 0 because the (post-deletion) chain is locally intact.

The reviewer flagged this as a residual gap : "`rm approvals.db` is still possible from outside the application." ADR-0024 acknowledged it explicitly :

> "A `rm approvals.db` attack still succeeds (the file IS deletable from outside the application), but the next legitimate INSERT after a tamper has no valid `prev_hash` to build on — the resulting chain is detectably broken on the next `audit verify`."

The next-INSERT detection only works if the operator runs a fresh check after legitimate activity has resumed AND has memory of what the previous tip should be. Without an external commitment, an attacker can `rm approvals.db ; secured-claude run "..."` and produce a fresh-but-clean-looking chain.

## Decision

Add **external hash anchoring** : a CLI command emits a JSON document committing to the latest `row_hash` + `row_id` + `ts` at a point in time. The operator stores this externally (S3 with object-lock, public timestamp authority, signed by their GPG key, …) and later compares against the local chain.

A `rm approvals.db` followed by replay produces a chain whose latest row at `row_id == anchor.last_row_id` has a different `row_hash` than the anchor — detectable.

### Two CLI subcommands

```
secured-claude audit-anchor [--output PATH]
```

Reads the latest row from the audit DB, emits this JSON to stdout (or `--output` path) :

```json
{
  "anchor_format_version": "1.0",
  "anchored_at": "2026-04-29T20:00:00+00:00",
  "secured_claude_version": "0.4.0",
  "audit_db_path": "/Users/.../approvals.db",
  "row_count": 1247,
  "last_row_id": 1247,
  "last_row_ts": "2026-04-29T19:58:32.491+00:00",
  "last_row_hash": "a3f2…64-hex",
  "verification": "Run `secured-claude audit-verify-anchor <this-file>` …"
}
```

```
secured-claude audit-verify-anchor <path>
```

Loads the anchor JSON, looks up `row_id == anchor.last_row_id` in the local DB, compares its `row_hash` to `anchor.last_row_hash`, then walks the full chain forward to ensure no break above the anchor. Exit codes :

- `0` — anchor matches + chain forward intact
- `1` — anchor row missing, hash mismatch, or chain broken
- `2` — anchor file unreadable / malformed JSON

### What the anchor proves

- **Anchor matches → no tampering BETWEEN anchor and verify.** Both the anchored row and every row past it are byte-for-byte what the operator committed to.
- **Anchor mismatch (row hash differs)** → the row was modified post-anchor.
- **Anchor row missing** → `rm approvals.db` happened (the row never existed in this DB) OR a partial reset.
- **Chain break above anchor** → tampering on a row created after the anchor.

The anchor does **not** prove anything about the truth of the audited events themselves — Cerbos still gates intent, the SQL trigger still blocks UPDATE/DELETE through the application. The anchor closes the residual "file-level tampering after-the-fact" gap.

### What we deliberately don't do in v0.4

- **No automatic anchor signing.** `secured-claude audit-anchor` emits plain JSON. The operator decides how to make the anchor immutable :
  - GPG-sign it (`gpg --sign anchor.json`) — pure file-based.
  - RFC 3161 timestamp it (`openssl ts -query`) against a free TSA (FreeTSA, DigiCert).
  - Push to Sigstore Rekor (cosign sign-blob) — keyless OIDC.
  - Store in S3 with object-lock — write-once-read-many semantics.
  - Push to git (a public anchor branch in a separate repo) — anyone can verify the anchor existed at commit-time.
  None of these are baked-in : they depend on the operator's threat model + existing infra. The CLI provides the raw anchor ; the integration is BYO.

- **No automatic anchor on every insert.** Anchoring on every row would slow the broker by an order of magnitude (network call + signing) and concentrate trust in whatever signing oracle we pick. The operator anchors at meaningful checkpoints (daily, after a release, before a security incident review).

## Consequences

**Positive** :
- Closes the residual `rm approvals.db` gap from ADR-0024 — operators now have a way to PROVE post-deletion / replay.
- The anchor is plain JSON, integratable with any signing / timestamping / append-only-store of the operator's choosing. No vendor lock-in.
- 5 new tests in `tests/test_cli.py` cover the happy path + tampered-chain detection + missing-anchor-file. Total now 132 tests (was 127).

**Negative** :
- Manual workflow : operators need to actually run `audit-anchor` periodically. A forgotten anchor doesn't catch tampering. v0.4.1 ticket : optional auto-anchor cron / launchd template.
- An attacker who controls the file system AND the anchor storage can rewrite both. The anchor's value relies on the storage being adversary-resistant — that's the operator's threat-model call.

**Neutral** :
- No code change to the broker / hook. Pure additive CLI.
- No new dependencies — uses stdlib `json` + the existing `Store.query`.

## Alternatives considered

- **Append-only sign-on-every-insert** — every audit row triggers a Rekor / TSA call. Latency-prohibitive (10-100x current broker overhead), single-point-of-trust on the signing oracle. Rejected.
- **Internal Merkle tree** — would prove the chain ordering more compactly but doesn't address the file-deletion case (the tree lives in the same SQLite file). Rejected for v0.4 ; revisitable if we ever need O(log n) per-row proofs.
- **Skip and document as known limitation** — the v0.3 status quo. Closed in v0.4.

## Verification

Tests in `tests/test_cli.py` :

- `test_audit_anchor_writes_json_to_file` — anchor output schema.
- `test_audit_anchor_empty_db_exits_1` — empty DB rejection.
- `test_audit_verify_anchor_succeeds_on_intact_chain` — happy path.
- `test_audit_verify_anchor_detects_tampered_chain` — drops trigger, modifies a row, verify-anchor exits 1.
- `test_audit_verify_anchor_unreadable_file_exits_2` — missing anchor file → exit 2.

End-to-end manual :

```bash
$ secured-claude audit-anchor --output anchor-2026-04-29.json
$ # → operator stores anchor-2026-04-29.json externally.
$ # 1 day later, suspect tampering :
$ secured-claude audit-verify-anchor anchor-2026-04-29.json
✓ anchor matches — row #1247 hash a3f2... is intact, full chain verified up to row #1389
```

## References

- [ADR-0024](0024-hash-chain-audit-log.md) — hash chain (the in-DB integrity contract this ADR's external anchor extends)
- [ADR-0004](0004-append-only-sqlite-audit-log.md) — append-only contract (in-application)
- RFC 3161 (TSA) : https://datatracker.ietf.org/doc/html/rfc3161
- Sigstore Rekor : https://docs.sigstore.dev/logging/overview/
- v0.4.1 ticket : optional auto-anchor cron / launchd template
