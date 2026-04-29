# ADR-0017: Security testing & evidence pipeline

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

## Context

Claiming "secured by design" without **reproducible evidence** lands in the same trash bin as "compliant" stickers : not falsifiable. A security reviewer's first question is "show me the scan output" ; the answer cannot be "trust the README", it must be "run `bin/security-scans.sh` ; here's the latest run from the CI pipeline."

We need a fixed list of **scanners**, **gates**, and **artifacts** so that every release ships with the same, comparable evidence. Drift in the scanner set or in the severity gate makes historical comparison impossible.

## Decision

We adopt a **7-layer security testing pipeline**, runnable both locally (`bin/security-scans.sh`) and in CI (the `security` stage of `.gitlab-ci.yml` per ADR-0014). Each layer has a defined scanner, severity gate, and produces a named artifact in `audit-reports/scans-<ISO_TIMESTAMP>/`.

| # | Layer | Scanner | Gate | Artifact |
|---|---|---|---|---|
| 1 | Lint + security smell (Python) | `ruff` (incl. `S` rules — flake8-bandit subset), `mypy --strict`, `bandit` | All clean. `B404` + `B603` skipped centrally with rationale (subprocess use is intrinsic, ruff `S603` already enforces shell=False + argv list — see `[tool.bandit]` in `pyproject.toml`) | `ruff.txt`, `mypy.txt`, `bandit.json` |
| 2 | Python dep CVE | `pip-audit` (PyPI advisory DB), `grype dir:.` (Anchore DB cross-check) | 0 known-vuln deps | `pip-audit.txt`, `grype.txt` |
| 3 | Secret / leak scan | `gitleaks detect --no-git --redact` | 0 leaks | `gitleaks.json` |
| 4 | Filesystem (multi-faceted) | `trivy fs --scanners vuln,secret,config` | 0 HIGH or CRITICAL ; 0 secrets ; 0 dockerfile misconfig | `trivy.txt` |
| 5 | Container hygiene | `hadolint` on `Dockerfile.claude-code`, `shellcheck` on `docker/entrypoint.sh` + `bin/*.sh` | 0 errors / warnings | `hadolint.txt`, `shellcheck.txt` |
| 6 | Policy validation | `cerbos compile policies/` in pinned `cerbos/cerbos:0.42.0` container | 0 syntax errors, 0 unreachable rules | `cerbos-compile.txt` |
| 7 | Test suite + coverage | `pytest` + branch coverage | ≥ 90% (`fail_under = 90` in `pyproject.toml`), all tests pass | `pytest.txt`, `coverage.xml` |

A separate stream produces a **Software Bill of Materials** (SBOM) :

| Artifact stream | Tool | Format | Purpose |
|---|---|---|---|
| SBOM | `syft scan dir:. -o spdx-json` | SPDX 2.3 JSON | OWASP A08, supply-chain provenance, attached to every GitLab Release per ADR-0016 |

### Strict mode

`STRICT=1 bin/security-scans.sh` widens every gate to include `LOW,MEDIUM` severity findings. Used :

- Locally before each release tag
- On `dev` once a week (Renovate co-occurrence)
- On any CHANGELOG entry that contains `security:` or `BREAKING CHANGE`

### Where evidence lives

- **`docs/security/security-evidence.md`** — captures the output of the latest known-good run, with date stamp and tool versions. Updated each time we tag a release.
- **`audit-reports/scans-<ts>/`** — ephemeral per-run artifacts, NOT committed (in `.gitignore`).
- **GitLab Release page** — for each `vX.Y.Z`, attaches the SBOM (`*.spdx.json`), the coverage report (`coverage.xml`), and a summary of the security stage's exit status.

### What we do NOT do (yet)

- We do not run **DAST** (dynamic application security testing) like ZAP — there's no long-lived HTTP server in our threat model (the FastAPI gateway binds 127.0.0.1 and is short-lived per session).
- We do not run **IaC scan** like `tfsec` / `checkov` — no Terraform shipped in v0.1. If v0.3 ships a Helm chart, we add `kubesec` and `kubeaudit` then.
- We do not run **fuzz testing** beyond the policy-fuzz harness (`bin/policy-fuzz.sh`, see audit-demo). General-purpose Python fuzzers like `atheris` / `hypothesis` may follow in v0.2 if a high-value target appears.
- We do not run **mutation testing** (e.g. `mutmut`) — coverage already at 92%+ ; mutmut for very-specific high-value modules tracked v0.2.

## Consequences

### Positive

- **Reproducible by anyone** — the security reviewer can replicate the entire suite with `bin/security-scans.sh` ; CI runs the same. No "works on my laptop" surprise.
- **Single source of truth for tooling versions** — the script prints them so the date-stamped report records what the scan was run *against*. Re-runnable retrospectively.
- **Evidence is a first-class artifact** — `docs/security/security-evidence.md` AND release assets, not mealy-mouthed README claims.
- **Maps to standards directly** — each layer corresponds to an OWASP A0X and/or NIST SSDF practice ; controls-matrix.md cross-references.
- **CI gate is non-skippable** — per ADR-0014, the `security` stage must pass before `publish` ; per CLAUDE.md global, no `allow_failure: true` shields.
- **Strict mode for releases** — daily noise stays at HIGH/CRITICAL, but release gating widens to LOW/MEDIUM so we never ship with uncategorized debt.

### Negative

- **Tool inflation** — 8 scanners is a lot to keep updated. Mitigated by Renovate auto-bumping image digests and pinning each tool's version (e.g. `aquasec/trivy:0.69.3`, `cerbos/cerbos:0.42.0`) per ADR-0008.
- **CI runtime** — the `security` stage takes ~3-5 minutes on a `macbook-local` runner. Acceptable ; jobs run in parallel within the stage.
- **False positive curation** — bandit B404/B603 skipped centrally with rationale. Each new scanner brings its own noise ; we document each suppression in `pyproject.toml` (or scanner-specific config) WITH a reason.
- **No coverage of binary-level supply chain** — we trust npm + Debian apt + PyPI repositories themselves. Mitigated by digest pinning (ADR-0008) + cosign signing OUR images (ADR-0016).

### Neutral

- We accept that scan output reading is a human task ; the goal isn't 100% automation, it's **evidence** that humans can verify in minutes instead of hours.

## Alternatives considered

- **Sonarqube / SonarCloud** — broader breadth (Java, JS, Python, Go) but : (a) requires hosted infra or a self-hosted Sonar server, (b) findings overlap heavily with bandit / ruff for our Python-only project, (c) free-tier cap on private projects. Tracked v0.2+ if multi-language work emerges.
- **Snyk** — commercial, paid for private repos, vendor lock-in. Free tier limits. We use OSS equivalents (pip-audit, grype, trivy) that cover the same ground.
- **Semgrep / Semgrep Pro** — interesting custom-rule language. We considered it for v0.1 but the bandit + ruff combo already catches the obvious patterns, and adding a 4th Python scanner (after ruff S, mypy, bandit) is diminishing returns for a v0.1 codebase. Tracked v0.2.
- **Skip CI gating, only manual scan** — disqualified ; "trust us" is exactly the anti-pattern this ADR exists to prevent.
- **Single mega-scanner** (e.g. only Snyk or only Sonar) — single point of failure for evidence. Defense-in-depth via 3 vuln scanners (`pip-audit` + `grype` + `trivy`) means a CVE missed by one is likely caught by another.

## References

- OWASP Top 10 2021 — https://owasp.org/Top10/
- NIST SP 800-218 (SSDF) v1.1 — https://csrc.nist.gov/Projects/ssdf
- bandit — https://github.com/PyCQA/bandit
- pip-audit — https://github.com/pypa/pip-audit
- grype — https://github.com/anchore/grype
- syft — https://github.com/anchore/syft
- trivy — https://github.com/aquasecurity/trivy
- gitleaks — https://github.com/gitleaks/gitleaks
- hadolint — https://github.com/hadolint/hadolint
- shellcheck — https://www.shellcheck.net/
- Cerbos compile — https://docs.cerbos.dev/cerbos/latest/cli/cerbos.html#compile
- Sigstore SLSA — https://slsa.dev/spec/v1.0/
- Implementation : [`bin/security-scans.sh`](../../bin/security-scans.sh), [`pyproject.toml`](../../pyproject.toml) (`[tool.bandit]`, `[tool.coverage.report]`, `[tool.ruff]`, `[tool.mypy]`)
- Latest run output : [`docs/security/security-evidence.md`](../security/security-evidence.md)
- Related ADRs : [0008](0008-pin-upstream-images-and-deps.md) (pinning), [0014](0014-gitlab-ci-pipeline-6-stages.md) (CI gate), [0016](0016-supply-chain-cosign-sbom.md) (cosign + SBOM)
