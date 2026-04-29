# Security controls matrix — secured-claude v0.1

> **Purpose** — every control implemented in this codebase is mapped to widely recognized standards so that a security review can verify coverage by lookup, not by re-deriving the reasoning. Standards covered : **OWASP Top 10 2021**, **NIST SP 800-218 SSDF v1.1**, **CIS Controls v8**, **MITRE ATT&CK Mitigations**, **EU AI Act Art. 12-15**.

Format conventions :

- Each row = one standard's control (or family of controls) addressed.
- "Implementation" = where in the code/config the control lives.
- "Evidence" = how a reviewer verifies the control is in effect (test name, scan output, ADR ref, doc link).
- "Coverage" = full | partial | not addressed (with rationale).

---

## OWASP Top 10 — 2021

The OWASP Top 10 is the de-facto baseline for application security review. Every category is addressed here, with full coverage for the categories applicable to secured-claude's threat model.

| # | Category | Implementation | Evidence | Coverage |
|---|---|---|---|---|
| **A01** | Broken Access Control | Cerbos PDP enforces every tool call (no skip-the-check path) ; default-DENY for shell, network, MCP ; principle of least privilege via Cerbos derived roles | [`policies/`](../../policies/), [ADR-0001](../adr/0001-cerbos-as-policy-decision-point.md), [ADR-0003](../adr/0003-default-deny-for-shell-network-mcp.md), `tests/test_audit_demo.py::R1` (exfil DENY), `audit-demo --strict` | **Full** |
| **A02** | Cryptographic Failures | API keys never logged, never persisted to disk, only in env var ; TLS 1.3 enforced for `api.anthropic.com` (managed by Anthropic) ; SQLite db file mode 0o600 ; no custom crypto written | [ADR-0011](../adr/0011-no-secret-baked-in-image.md), [`docker-compose.yml`](../../docker-compose.yml) (no secrets baked), `tests/test_store.py::test_db_perms` | **Full** for what we control |
| **A03** | Injection | All `subprocess.run(shell=False, args=[...])` ; SQL via parameterized statements (no string concat) ; YAML loaded via `yaml.safe_load` (never `yaml.load`) ; Cerbos resolves paths before evaluating policy (defeats `..` traversal) | `bandit` rule B602 (subprocess shell=True) clean ; `bandit` rule B506 (yaml.load) clean ; `tests/test_audit_demo.py::R6` (path traversal DENY) | **Full** |
| **A04** | Insecure Design | Threat model done up-front ([threat-model.md](threat-model.md)) ; defense-in-depth (4 layers, [ADR-0012](../adr/0012-defense-in-depth-layers.md)) ; fail-closed default ([ADR-0009](../adr/0009-hook-fails-closed.md)) ; security audit demonstration on every release | This document, plus [`audit-reports/`](../../audit-reports/) on every release | **Full** |
| **A05** | Security Misconfiguration | All Docker images pinned by digest ([ADR-0008](../adr/0008-pin-upstream-images-and-deps.md)) ; container runs as non-root, read-only root FS, `cap-drop=ALL` ; broker bound to `127.0.0.1` only ; `hadolint` clean | [`Dockerfile.claude-code`](../../Dockerfile.claude-code), [`docker-compose.yml`](../../docker-compose.yml), `hadolint` in CI lint stage | **Full** |
| **A06** | Vulnerable & Outdated Components | Renovate automated PRs for all deps ; `pip-audit` runs in CI security stage ; `trivy image` + `grype dir:` scan every build ; Cerbos PDP version pinned and bumped via Renovate | [`renovate.json`](../../renovate.json), `.gitlab-ci.yml::security:pip-audit`, `:trivy`, `:grype` | **Full** |
| **A07** | Identification & Authentication Failures | Single principal `claude-code-default` in v0.1 (no auth surface to attack) ; no password storage ; tokens (Anthropic) only as env var ; v0.2 plans multi-principal with attribute-based access via Cerbos | [ADR-0011](../adr/0011-no-secret-baked-in-image.md) ; v0.1 limitation noted | **Partial** (intentionally simple in v0.1) |
| **A08** | Software & Data Integrity Failures | All container images signed with cosign keyless OIDC ; SBOM published per release (Syft, SPDX) ; uv.lock committed and verified ; tags signed with maintainer SSH key ; CI enforces signed tags on `main` | [ADR-0016](../adr/0016-supply-chain-cosign-sbom.md), [`docs/security/supply-chain.md`](supply-chain.md), `.gitlab-ci.yml::publish:cosign-sign` | **Full** |
| **A09** | Security Logging & Monitoring Failures | Append-only SQLite audit log of every decision (ALLOW + DENY) ; INSERT-only schema ; ISO8601 UTC timestamps ; principal_id, resource_kind, action, args_json, cerbos_reason recorded ; SIEM export via `secured-claude audit --json` | [ADR-0004](../adr/0004-append-only-sqlite-audit-log.md), [`src/secured_claude/store.py`](../../src/secured_claude/store.py), `tests/test_store.py::test_append_only` | **Full** |
| **A10** | Server-Side Request Forgery (SSRF) | WebFetch tool gated by Cerbos network policy with explicit host allowlist ; localhost / link-local / internal IPs deny-listed ; URL canonicalization done before policy check (defeats `0.0.0.0`, `127.001`, `[::1]`, IPv4-mapped IPv6) | [`policies/network.yaml`](../../policies/network.yaml), `tests/test_audit_demo.py::R4` | **Full** |

---

## NIST SP 800-218 — Secure Software Development Framework v1.1

NIST SSDF defines four practice families. This is how secured-claude addresses each.

### PO — Prepare the Organization

| Task | Implementation | Evidence |
|---|---|---|
| **PO.1** Define security requirements | This file + [threat-model.md](threat-model.md) + [SECURITY.md](../../SECURITY.md) | The repo IS the artifact |
| **PO.2** Implement roles & responsibilities | Maintainer model documented in [`CLAUDE.md`](../../CLAUDE.md) ; CVD process in [vulnerability-disclosure.md](vulnerability-disclosure.md) | Role assignments via GitLab project members + branch protection |
| **PO.3** Implement supporting toolchains | uv (Python), Docker, Cerbos, GitLab CI, Renovate, cosign, syft, ruff, bandit, mypy, pip-audit, trivy, grype, hadolint, gitleaks — all CLAUDE.md-referenced | [`pyproject.toml`](../../pyproject.toml), [`.gitlab-ci.yml`](../../.gitlab-ci.yml) |
| **PO.4** Define & use criteria for security checks | CI security stage MUST pass + audit-demo --strict MUST pass before any tag | `.gitlab-ci.yml::security:`, [ADR-0014](../adr/0014-gitlab-ci-pipeline-6-stages.md) |
| **PO.5** Implement & maintain secure environments for software development | macbook-local CI runner is documented ; Docker desktop kept current ; Renovate keeps deps fresh | [`CLAUDE.md`](../../CLAUDE.md), Renovate auto-PRs |

### PS — Protect the Software

| Task | Implementation | Evidence |
|---|---|---|
| **PS.1** Protect all forms of code from unauthorized access | GitLab branch protection on `main` (push_access=Maintainers, merge requires green CI), signed maintainer commits, [`.gitignore`](../../.gitignore) excludes secrets | GitLab API : `protected_branches/main` |
| **PS.2** Provide a mechanism for verifying software release integrity | Cosign keyless signature on container images, SBOM published, sha256 sums on release artifacts | [supply-chain.md](supply-chain.md), `cosign verify` documented |
| **PS.3** Archive & protect each software release | GitLab Releases preserve assets ; tag annotations document what was verified (CLAUDE.md global tag annotation rule) ; immutable tag history | GitLab Release page per `vX.Y.Z` |

### PW — Produce Well-Secured Software

| Task | Implementation | Evidence |
|---|---|---|
| **PW.1** Design software to meet security requirements | Threat model done before code ; ADRs for every load-bearing decision ; defense-in-depth as baseline | [threat-model.md](threat-model.md), [`docs/adr/`](../adr/) |
| **PW.2** Review the software design | ADRs include "Alternatives considered" section forcing review of alternatives ; PR review required for `dev → main` | ADR template ([0000](../adr/0000-template.md)), GitLab MR approval rules |
| **PW.4** Reuse existing, well-secured software | Cerbos (CNCF Sandbox), FastAPI (huge community), `requests`, `docker` SDK — all battle-tested ; no in-house crypto, no in-house policy engine | [`pyproject.toml`](../../pyproject.toml) deps ; [ADR-0001](../adr/0001-cerbos-as-policy-decision-point.md) explicitly chooses Cerbos *because* it's CNCF |
| **PW.5** Create source code by adhering to secure coding practices | `ruff` (security-aware lints) ; `bandit -r src/` ; `mypy --strict` ; explicit `subprocess(shell=False)` ; `yaml.safe_load` ; parameterized SQL | CI lint stage, all green required |
| **PW.6** Configure compilation, interpreter, & build processes to improve executable security | Hatchling reproducible builds ; `pip-audit` on every CI run ; `uv.lock` committed | `.gitlab-ci.yml::build:python` |
| **PW.7** Review &/or analyze human-readable code | bandit / semgrep / mypy ; PR review required ; review checklist includes the 7 Clean Code non-negotiables (CLAUDE.md global) | CI security stage |
| **PW.8** Test executable code to identify vulnerabilities | `audit-demo --strict` on every release with red-team scenarios + policy fuzz ; integration tests with real Cerbos | `tests/test_audit_demo.py`, `bin/security-audit.sh` |
| **PW.9** Configure software to have secure settings by default | Cerbos default-DENY ; container runs non-root + read-only ; broker bound to localhost ; SQLite db perms 0o600 | [`policies/`](../../policies/), [`docker-compose.yml`](../../docker-compose.yml) |

### RV — Respond to Vulnerabilities

| Task | Implementation | Evidence |
|---|---|---|
| **RV.1** Identify & confirm vulnerabilities on an ongoing basis | `pip-audit` + `trivy` + `grype` in CI on every push ; Renovate ; advisory subscription to Anthropic / Cerbos / Docker | `.gitlab-ci.yml::security:` |
| **RV.2** Assess, prioritize, & remediate | CVD process in [vulnerability-disclosure.md](vulnerability-disclosure.md) ; CVSS scoring ; SLA targets (CRITICAL 7d, HIGH 30d, MEDIUM 90d) | [vulnerability-disclosure.md](vulnerability-disclosure.md) §3 |
| **RV.3** Analyze vulnerabilities to identify root causes | Postmortem template ; ADR pattern (write/update an ADR documenting the fix and what changed) | [`docs/adr/0000-template.md`](../adr/0000-template.md) |

---

## CIS Controls v8

CIS Controls v8 has 18 top-level controls. The ones directly applicable to secured-claude :

| # | Control | Implementation in secured-claude |
|---|---|---|
| **CIS-3** | Data Protection | Audit log encrypted at rest via filesystem (LUKS / FileVault / BitLocker — host responsibility) ; in-transit via TLS to Anthropic ; secrets never logged |
| **CIS-4** | Secure Configuration of Enterprise Assets and Software | All Dockerfiles + docker-compose follow CIS Docker Benchmark : non-root user, read-only FS, capabilities drop, no privileged, healthchecks |
| **CIS-5** | Account Management | Single principal in v0.1 ; v0.2 multi-principal via Cerbos derived roles |
| **CIS-6** | Access Control Management | Cerbos enforces every tool call ; default-DENY ; documented escalation path (add ALLOW rule via PR + ADR) |
| **CIS-7** | Continuous Vulnerability Management | Renovate auto-PRs ; pip-audit / trivy / grype in CI |
| **CIS-8** | Audit Log Management | Append-only SQLite log with ISO8601 UTC ; queryable via `secured-claude audit` ; SIEM export |
| **CIS-12** | Network Infrastructure Management | Docker network egress allowlist ; broker on localhost only |
| **CIS-13** | Network Monitoring and Defense | All allowed/denied egress logged in audit DB ; future SIEM integration in v0.2 |
| **CIS-16** | Application Software Security | bandit / mypy / pip-audit in CI ; secure-by-default config ; threat-modeling done |
| **CIS-17** | Incident Response Management | CVD process documented in [vulnerability-disclosure.md](vulnerability-disclosure.md) |
| **CIS-18** | Penetration Testing | `audit-demo --strict` is built-in red-team simulation ; policy-fuzz with 50+ malicious patterns ; runnable any time |

---

## MITRE ATT&CK Mitigations

Mapping each ATT&CK Mitigation that's applicable to LLM agent threats :

| ID | Mitigation | secured-claude implementation |
|---|---|---|
| **M1018** | User Account Management | Single-principal model v0.1 ; multi-principal Cerbos-RBAC v0.2 |
| **M1026** | Privileged Account Management | Container non-root ; no `sudo` in image ; broker requires no host privileges beyond Docker socket access |
| **M1030** | Network Segmentation | Docker custom network with egress allowlist (L2) ; broker bound to localhost |
| **M1033** | Limit Software Installation | Bash shell allowlist denies `apt`, `brew`, `pip install` outside controlled contexts |
| **M1035** | Limit Access to Resource Over Network | Network egress only to `api.anthropic.com` + `host.docker.internal:8765` |
| **M1038** | Execution Prevention | Cerbos shell allowlist (L1) — first-word match + full-command pattern check |
| **M1042** | Disable or Remove Feature/Program | MCP servers default-DENY ; `eval`-style Bash patterns DENY |
| **M1047** | Audit | SQLite append-only of every decision ; `audit-demo --strict` proof |
| **M1051** | Update Software | Renovate continuous bumps ; CI enforces pinned digests |
| **M1054** | Software Configuration | Cerbos policies as code, Git-versioned, lintable, signable |
| **M1056** | Pre-compromise | Threat-model.md, controls-matrix.md (this file), audit-demo on every release |

---

## EU AI Act (Regulation 2024/1689) — selected articles

For deployment in EU enterprises, the AI Act applies. secured-claude is **not itself an AI system** — it's a security gateway in front of one (Claude Code). However, it implements the operational controls expected under Articles 12-15 for high-risk AI deployments.

| Article | Requirement | secured-claude implementation |
|---|---|---|
| **Art. 12** Record-keeping | High-risk AI systems must maintain logs of operation | Append-only SQLite audit log of every tool call, indefinite retention by default |
| **Art. 13** Transparency & info to deployers | Deployers must understand the AI's capabilities | This documentation set + threat model + controls matrix made deployer-facing |
| **Art. 14** Human oversight | Mechanisms for humans to oversee AI decisions | DENY decisions by default surface to user via Claude Code's stderr→model channel ; audit-DB queryable for human review |
| **Art. 15** Accuracy, robustness, cybersecurity | Resilience against attempts to alter behavior via inputs | Defense-in-depth (L1+L2+L3+L4), prompt-injection threat covered in threat-model.md |

---

## Coverage gaps acknowledged

We do not currently address (intentional v0.1 scope) :

| Gap | Why we accept this in v0.1 | v0.2+ plan |
|---|---|---|
| ISO 27001:2022 Annex A full mapping | ISO 27001 is org-level, secured-claude is a product ; org-level controls (HR security, physical, etc.) are out of our scope | Provide an org-level deployment guide that maps secured-claude to ISO 27001 controls |
| SOC 2 Type II | Same reason — product, not service | Once secured-claude as-a-service is offered (v0.3+), do SOC 2 |
| GDPR DPIA (Data Protection Impact Assessment) | secured-claude doesn't process personal data of users beyond technical metadata (principal_id, timestamps) ; deployers handle data they pass through Claude Code | Provide a DPIA template for deployers |
| FIPS 140-3 cryptographic module validation | We don't ship crypto — we use TLS to Anthropic and let Cerbos / OS handle the rest | Out of scope |
| Common Criteria evaluation | Cost-prohibitive for an OSS project | Out of scope |

---

## How to verify this matrix

1. **Read the audit-demo report** — `audit-reports/audit-YYYY-MM-DD-HHMM.md` shows every red-team scenario blocked.
2. **Run the test suite** — `pytest tests/ -m "audit"` reproduces the audit demo locally.
3. **Inspect the policies** — `cerbos compile policies/` should be clean (no warnings).
4. **Run the security scans** — `bandit -r src/ ; pip-audit ; trivy image registry.gitlab.com/.../claude-code:vX.Y.Z`.
5. **Verify supply chain** — `cosign verify ...` (commands in [supply-chain.md](supply-chain.md)).
6. **Walk the threat model** — [threat-model.md](threat-model.md) attack trees AT-1..AT-5 each map to specific tests.

---

*This matrix is reviewed quarterly. Last reviewed : 2026-04-29. Next : 2026-07-29.*
