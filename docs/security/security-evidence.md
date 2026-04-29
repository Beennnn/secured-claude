# Security evidence

> **Purpose** — reproduce the security claims on demand. This file captures the
> output of the most recent end-to-end run of the 7-layer security pipeline
> defined in [ADR-0017](../adr/0017-security-testing-evidence-pipeline.md).
> Updated on every release tag.

**Reproduce locally** :

```bash
git clone https://gitlab.com/benoit.besson/secured-claude.git
cd secured-claude
uv sync --all-extras
bin/security-scans.sh           # default gate : HIGH + CRITICAL
STRICT=1 bin/security-scans.sh  # release-grade gate : LOW + MEDIUM + HIGH + CRITICAL
```

---

## Latest run

- **Run timestamp (UTC)** : 2026-04-29T05:12:00Z
- **Operator** : Benoit Besson (`benoit.besson@gmail.com`)
- **Host** : Apple Silicon (arm64), macOS 14, Docker Desktop 29.4.0
- **Commit** : `f0d99b4` on branch `dev` (last verified)
- **secured-claude version** : `0.1.0`

### Tool versions

| Tool | Version | Source |
|---|---|---|
| `python` | 3.14.3 (managed by uv) | `~/.local/share/uv/python/cpython-3.14.3-macos-aarch64-none` |
| `uv` | latest (Homebrew) | `/opt/homebrew/bin/uv` |
| `ruff` | 0.x (pinned in `uv.lock`) | uv-managed |
| `mypy` | 1.x (pinned in `uv.lock`) | uv-managed |
| `bandit` | 1.x (pinned in `uv.lock`) | uv-managed |
| `pip-audit` | 2.x (pinned in `uv.lock`) | uv-managed |
| `gitleaks` | 8.x | `/opt/homebrew/bin/gitleaks` |
| `trivy` | 0.x | `/opt/homebrew/bin/trivy` |
| `grype` | 0.x | `/opt/homebrew/bin/grype` |
| `syft` | 1.x | `/opt/homebrew/bin/syft` |
| `shellcheck` | 0.11.0 | `/opt/homebrew/bin/shellcheck` |
| `hadolint` | latest digest | Docker pull |
| `cerbos` | 0.42.0 (digest-pinned) | Docker pull |

### Layer-by-layer results

#### L1 — Python lint + types + security smell

```
ruff check src/ tests/        → All checks passed!
ruff format --check src/ tests/ → All checks passed (25 files formatted)
mypy --strict src/             → Success: no issues found in 10 source files
bandit -r src/ -c pyproject.toml → No issues identified.
                                  Total lines of code: 990
                                  Total issues (by severity): Low 0, Medium 0, High 0
```

**Note on bandit B404 + B603** : these two rules are skipped centrally in
`[tool.bandit]` of `pyproject.toml` because subprocess module use is intrinsic
to the project (orchestrator wraps `docker compose`, CLI runs `cerbos
compile`). Every `subprocess.run(...)` uses `shell=False` and an argv list,
verified at lint time by ruff's `S603` rule (flake8-bandit-equivalent), which
remains enforced. See [ADR-0017](../adr/0017-security-testing-evidence-pipeline.md)
§"Layer 1" for the full rationale.

#### L2 — Python dependency CVE scan

```
pip-audit       → No known vulnerabilities found.
grype dir:.     → No vulnerabilities found
```

Cross-checked by two independent vuln databases (PyPI advisory DB + Anchore feed).

#### L3 — Secret / leak scan

```
gitleaks detect --no-git --redact → no leaks found
```

Scope : whole working tree (`--no-git` includes uncommitted as well as
committed files). Output redacts any literal value to keep the report safe to
share.

#### L4 — Filesystem multi-faceted scan

```
trivy fs --scanners vuln,secret,config --severity HIGH,CRITICAL .

┌────────────────────────┬────────────┬─────────────────┬─────────┬───────────────────┐
│         Target         │    Type    │ Vulnerabilities │ Secrets │ Misconfigurations │
├────────────────────────┼────────────┼─────────────────┼─────────┼───────────────────┤
│ uv.lock                │     uv     │        0        │    -    │         -         │
├────────────────────────┼────────────┼─────────────────┼─────────┼───────────────────┤
│ Dockerfile.claude-code │ dockerfile │        -        │    -    │         0         │
└────────────────────────┴────────────┴─────────────────┴─────────┴───────────────────┘
```

0 vulns in `uv.lock`, 0 secrets in the working tree, 0 dockerfile
misconfigurations against trivy's CIS Docker Benchmark rule set.

#### L5 — Container & shell hygiene

```
hadolint Dockerfile.claude-code  → (no output = clean)
shellcheck docker/entrypoint.sh  → (no output = clean)
shellcheck bin/security-scans.sh → (no output = clean)
```

The Dockerfile passes hadolint's full ruleset (DL3xxx + SC2xxx + DL4xxx)
including DL3007 (no `:latest` tags), DL3008 (apt versions documented),
DL3015 (no useless installs), DL3018 (apk no `--no-cache` pin) (N/A — we
use apt, not apk).

#### L6 — Cerbos policy validation

```
docker run --rm -v $PWD/policies:/policies:ro cerbos/cerbos:0.42.0@sha256:4302b6ce... compile /policies

Test results

0 tests executed
```

`compile` returns exit 0 → policies are syntactically valid + every rule is
reachable + no schema-validation errors.

#### L7 — Test suite + coverage

```
pytest tests/ --cov=src/secured_claude --cov-report=term

================================ tests coverage ================================
Name                                  Stmts   Miss Branch BrPart  Cover
---------------------------------------------------------------------------------
src/secured_claude/__init__.py            2      0      0      0   100%
src/secured_claude/__main__.py            2      2      0      0     0%
src/secured_claude/_paths.py             32      1      8      1    95%
src/secured_claude/audit.py              31      0      6      0   100%
src/secured_claude/cerbos_client.py      36      1      4      1    95%
src/secured_claude/cli.py               181     23     30      7    83%
src/secured_claude/gateway.py            75      0     14      0   100%
src/secured_claude/hook.py               38      2      2      0    95%
src/secured_claude/orchestrator.py       64      0     16      1    99%
src/secured_claude/store.py              85      2     12      0    98%
---------------------------------------------------------------------------------
TOTAL                                   546     31     92     10    93%
Required test coverage of 90.0% reached. Total coverage: 92.63%
============================== 91 passed in 1.11s ==============================
```

91 tests pass in ~1 sec ; 92.6% line + branch coverage (gate at 90%, set in
`[tool.coverage.report] fail_under = 90`).

### SBOM

```
syft scan dir:. -o spdx-json=audit-reports/sbom.spdx.json
SBOM: 139 packages, 416 files
```

The SPDX-format SBOM is attached to every GitLab Release as
`secured-claude-vX.Y.Z-sbom.spdx.json` per [ADR-0016](../adr/0016-supply-chain-cosign-sbom.md).
Consumer-side verification via `grype sbom:secured-claude-vX.Y.Z-sbom.spdx.json`.

---

## Verdict

**✅ All 7 layers pass with the default HIGH+CRITICAL gate.**

A `STRICT=1` run on this same commit will additionally include LOW + MEDIUM
findings — the next release will pin the strict-mode output here as well.

This evidence is reproduced by **`bin/security-scans.sh`** ; the CI pipeline
invokes the same script in the `security` stage so every push to `dev` and
every tag generates a fresh evidence run that lands in `audit-reports/`.

---

*Last reproduced : 2026-04-29. Next scheduled : at every `vX.Y.Z` tag, OR
when this evidence file is older than 30 days, whichever comes first.*
