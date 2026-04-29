```
███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗██████╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗
███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ██║  ██║
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██║  ██║
███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗██████╔╝
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝
            ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗
           ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝
           ██║     ██║     ███████║██║   ██║██║  ██║█████╗
           ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝
           ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗
            ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
```

<p align="center"><b>The comfort of Claude Code, secured by design.</b></p>

<p align="center">
  <a href="https://gitlab.com/benoit.besson/secured-claude/-/pipelines"><img src="https://gitlab.com/benoit.besson/secured-claude/badges/main/pipeline.svg" alt="pipeline"></a>
  <a href="docs/SECURITY.md"><img src="https://img.shields.io/badge/security--audit-pass-brightgreen" alt="security audit"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="license"></a>
  <a href="pyproject.toml"><img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="python"></a>
  <a href="https://cerbos.dev"><img src="https://img.shields.io/badge/policy--engine-cerbos-ff6b35" alt="cerbos"></a>
  <a href="https://docker.com"><img src="https://img.shields.io/badge/runtime-docker-2496ed" alt="docker"></a>
  <a href="https://www.anthropic.com/claude-code"><img src="https://img.shields.io/badge/agent-claude--code-c8b3a8" alt="claude-code"></a>
</p>

---

## Status — verify in 60 seconds

**v0.2.0** — every claim below is backed by an artifact you can re-run yourself.
**Don't trust the README, run the verifications.**

```bash
git clone https://gitlab.com/benoit.besson/secured-claude.git
cd secured-claude
uv sync --all-extras

# 1. Static gates (~20 s warm) — runs the same 13-layer pipeline as CI
bash bin/security-scans.sh
#   → ruff/mypy/bandit clean ; pip-audit/grype/trivy 0 CVE ;
#     gitleaks 0 ; hadolint/shellcheck/cerbos compile clean ;
#     pytest 111/111, coverage 92.6 % ; SBOM 139 packages.

# 2. Live policy gate (~30 s) — boots a real Cerbos PDP and replays
#    19 red-team + 7 happy-path scenarios end-to-end :
bash bin/security-audit.sh
#   → Verdict ✅ PASS (26/26) — every red-team DENY, every happy-path ALLOW.

# 3. Last green CI pipeline on macbook-local runner :
#    https://gitlab.com/benoit.besson/secured-claude/-/pipelines/2487406196
#    14/14 jobs across lint / test / security / build, ~9 min wall.

# 4. Runtime end-to-end (needs ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN) :
secured-claude up
docker exec secured-claude-agent claude -p "Read /etc/passwd"
#   → claude attempts the Read tool, the PreToolUse hook posts to the
#     broker, Cerbos returns DENY, claude responds gracefully :
#     "A hook in your Claude Code configuration is blocking the Read
#      tool from accessing /etc/passwd ..."
secured-claude audit --denied
#   → the DENY decision is visible in the SQLite audit log,
#     5 ms duration, with cerbos_reason captured.
```

### What is real now (v0.2.0)

| Claim | Where | How to check |
|---|---|---|
| Cerbos PDP gating every tool call | `policies/*.yaml`, `src/secured_claude/cerbos_client.py`, `src/secured_claude/gateway.py` | `bin/security-audit.sh` (26/26) |
| FastAPI broker on host:8765 | `src/secured_claude/gateway.py` (75 lines, 100 % covered) | `tests/test_gateway.py` (8 tests) |
| Append-only SQLite audit | `src/secured_claude/store.py` (85 lines, 98 % covered) | `tests/test_store.py` includes UPDATE/DELETE refused by trigger |
| Claude Code container hardened | `Dockerfile.claude-code` + `docker-compose.yml` (non-root UID 1001, read-only cerbos rootfs, cap_drop ALL, healthcheck) | `secured-claude doctor`, `secured-claude up` |
| 21 ADRs justifying every decision | `docs/adr/0000-template.md` + `0001..0021-*.md` | `ls docs/adr/` |
| GitLab CI green on macbook-local runner | `.gitlab-ci.yml` + `.gitlab-ci/{lint,test,security,build,publish,release}.yml` | [pipeline #2487406196](https://gitlab.com/benoit.besson/secured-claude/-/pipelines/2487406196) |
| 7-layer security pipeline | `bin/security-scans.sh` + `pyproject.toml [tool.bandit]` | `bash bin/security-scans.sh` |
| SBOM (SPDX 2.3) per release | `.gitlab-ci/security.yml::security:sbom` | release artifact `sbom.spdx.json` |

### What is configured but NOT yet enforced — be explicit

A senior security reviewer should read this table before trusting any
"defense-in-depth" claim. v0.2.x ships **L1 + L2 + L3-DNS enforced**
(L2 closed via tinyproxy egress sidecar in [ADR-0019](docs/adr/0019-l2-egress-proxy-tinyproxy.md),
DNS leak closed via dnsmasq in [ADR-0020](docs/adr/0020-l3-dns-allowlist-dnsmasq.md)).
The remaining gaps below are documented ahead of being live.

| Item | v0.2 reality | When it goes live |
|---|---|---|
| **Audit log tamper-evidence at FS layer** | **v0.3 closes this** ([ADR-0024](docs/adr/0024-hash-chain-audit-log.md)) — SHA-256 chain over each row (`prev_hash`, `row_hash` columns) ; `secured-claude audit-verify` walks the chain and exits non-zero on the first detected break. `rm approvals.db` followed by re-creation is still possible but produces a chain that starts at id=1 with genesis prev_hash next to a recent ts — a forensic smoking gun. External hash anchor (QLDB / blockchain) tracked v0.4+. | Done in v0.3 — `secured-claude audit-verify` |
| **Multi-principal Cerbos roles** | `derived_roles.yaml` defines them ; broker hardcodes single principal `claude-code-default` | v0.3 |
| **Runtime smoke in CI** (real claude binary call) | Recipe exists (`secured-claude up && claude -p ...`), runs locally pre-tag ; not yet a CI job | v0.3 — uses a test API key in a GitLab CI variable |
| **read_only on egress-proxy / dns-filter sidecars** | **v0.3 closes this** ([ADR-0025](docs/adr/0025-pre-built-sidecar-images.md)) — dedicated `Dockerfile.dns-filter` + `Dockerfile.egress-proxy`, packages baked in, no apk-install-at-boot. `read_only: true` is back ; verified by `docker inspect ... ReadonlyRootfs=true`. Cosign signing of the sidecar images deferred to v0.3.1. | Done in v0.3 (image-level) ; v0.3.1 (cosign-signed) |
| **Multi-arch image (linux/arm64 native)** | Kaniko `--customPlatform=linux/amd64` produces an amd64-deterministic image regardless of the runner's native arch (arm64 macbook-local in v0.2). amd64 users get a native binary ; arm64 users (Apple Silicon, AWS Graviton) fall back to QEMU emulation under Docker Desktop / containerd `binfmt_misc`. v0.1.8 shipped arm64-only by mistake — this is the v0.2 fix. | v0.3 — true multi-arch manifest list (two parallel Kaniko jobs + `crane index append`) |
| **Hook coverage of every Claude Code tool** | `matcher: "*"` in PreToolUse hooks every tool we know about (Read/Write/Edit/Bash/WebFetch/WebSearch/MCP/Task). Anthropic adds tools faster than we audit ; **a new tool shipping in a future Claude Code release would default to ALLOW until we map it**. Mitigated by the broker's `unknown_tool` catch-all (kind=`unknown_tool` action=`invoke`) which has no policy rule → DENY by Cerbos default ; verified by `tests/test_gateway.py::test_map_unknown_tool_falls_back`. | Continuous — Renovate bumps Claude Code, audit-demo adds scenarios per new tool |

### What we explicitly DON'T claim to defend against

- Kernel CVEs / 0-days — Linux namespace isolation is the v0.1 boundary ; gVisor or Firecracker tracked v0.3+
- Side-channel attacks (Spectre/Meltdown class)
- Physical adversary at the developer machine
- Compromise of `cerbos/cerbos` upstream image — mitigated by digest pinning ; residual risk acknowledged

### Honest scoring : 1 intent layer + 3 confinement layers (v0.2)

Per [ADR-0022](docs/adr/0022-intent-layer-vs-confinement-layers.md) — only L1 understands the agent's intent. L2/L3/L4 are confinement layers that bound the blast radius if L1 is bypassed but don't replace L1's semantic decisions.

| Role | Layer | Designed | Enforced in v0.2 | Tested in v0.2 |
|---|---|---|---|---|
| **Intent** | **L1 — PreToolUse hook + Cerbos PDP** ([0001](docs/adr/0001-cerbos-as-policy-decision-point.md), [0002](docs/adr/0002-pretooluse-hook-as-interception-point.md)) | Yes | Yes | `bin/security-audit.sh` → 26/26 PASS + runtime smoke transcript |
| **Confinement** | **L2 — Network egress allowlist** ([ADR-0019](docs/adr/0019-l2-egress-proxy-tinyproxy.md)) | Yes | **Yes** — tinyproxy `FilterDefaultDeny` ; CONNECT to non-allowlisted host returns 403 | End-to-end : `curl -x http://172.30.42.4:3128 https://evil.com` → `CONNECT tunnel failed, response 403` (proof in ADR-0019) |
| **Confinement** | **L3 — DNS allowlist** ([ADR-0020](docs/adr/0020-l3-dns-allowlist-dnsmasq.md)) | Yes | **Yes** — dnsmasq `no-resolv` ; `nslookup evil.com` → REFUSED | End-to-end : `nslookup evil.com 172.30.42.3` → `REFUSED` (proof in ADR-0020) |
| **Confinement** | **L3 — Filesystem confinement** | Yes | Yes — only `/workspace` mounted RW from host | Inferred ; no explicit test that `/Users/<me>/.ssh` is unreachable |
| **Confinement** | **L4 — Container hardening** | Yes | Yes for the agent : non-root + cap_drop ALL + seccomp default + read-only rootfs + cgroup `mem_limit: 4g` ; sidecars partial (read_only deferred — see "configured but NOT yet enforced" above) | Inferred ; no explicit test (`docker inspect` would prove flags are set) |

Reading : v0.2 holds **L1 (intent) + L2 (egress confinement) + L3 (DNS + FS confinement) + partial L4 (container hardening)**. Per
[ADR-0022](docs/adr/0022-intent-layer-vs-confinement-layers.md), only L1
sees the agent's intent — it decides "this Read of `/etc/passwd` is
denied because the path matches a deny-list pattern." L2/L3/L4 are
**confinement layers** : they don't understand intent, but they bound
the blast radius if L1 is bypassed (a compromised Claude Code binary
can only reach `api.anthropic.com` via L2, can only resolve
`*.anthropic.com` via L3-DNS, can only read paths mounted into the
container via L3-FS, and runs without privileges via L4). Compromise
of L1 is therefore *bounded*, not *catastrophic* — but L2/L3/L4 don't
*replace* L1's semantic decisions. The remaining v0.3 gaps
(FS-tamper-evident audit log, multi-principal, runtime-smoke-in-CI,
read_only on sidecars) are documented above.

Full honest limits in [`SECURITY.md` §"Out-of-scope"](SECURITY.md#out-of-scope-honest-limits) and the residual-risks table in [`docs/security/threat-model.md` §7](docs/security/threat-model.md).

---

> **What this project demonstrates mastery of**
>
> - 🔒 **Sécurité** — defense-in-depth : **1 intent layer + 3 confinement layers** ([ADR-0022](docs/adr/0022-intent-layer-vs-confinement-layers.md)). L1 (PreToolUse hook + Cerbos PDP) is the semantic gate that understands the agent's *intent* and decides on policy. L2 (tinyproxy egress allowlist), L3 (dnsmasq DNS allowlist + workspace-only FS mount), and L4 (cap_drop + read_only + seccomp + cgroups) bound the blast radius if L1 is bypassed.
> - 🤖 **IA** — Claude Code wrapped in a policy-gated container, every tool call (Read / Write / Edit / Bash / WebFetch / MCP / Task) intercepted via the native PreToolUse hook.
> - 🏛 **Architecture** — Hexagonal-lite Python broker (host) + Cerbos PDP (container) + Claude Code CLI (container) ; clear trust boundary between intent (LLM) and execution (broker).
> - ✅ **Qualité** — 16 ADRs covering every security and operational decision ; security audit demonstration with 6 red-team scenarios + 2 happy-paths + policy fuzz + 8 static scans, run on every release.
> - 🔄 **CI/CD** — GitLab CI 6 stages (lint / test / security / build / publish / release), audit-demo strict gate on releases, cosign keyless signing + Syft SBOM for supply-chain provenance.
> - ☁️ **Infrastructure** — Cross-platform install (Mac / Linux / Windows) via pipx + GitLab Package Registry ; Docker images pinned by digest ; offline bundle for air-gapped enterprise deploys.
> - 🛠 **DevX** — `secured-claude` CLI feels like `claude` (TTY preserved) ; `audit` subcommand surfaces the evolving allowlist ; `doctor` validates the install end-to-end.

---

## Verify the artifacts (no clone needed — ADR-0023)

Every released `vX.Y.Z` carries 6 asset links on its [GitLab Release page](https://gitlab.com/benoit.besson/secured-claude/-/releases). Skip the source ; download the proof :

```bash
TAG=v0.2.1   # or whichever tag you want to audit
BASE=https://gitlab.com/benoit.besson/secured-claude

# 1. SBOM (SPDX 2.3) — what's in the image
curl -fsSL "$BASE/-/jobs/artifacts/$TAG/raw/sbom.spdx.json?job=security:sbom" \
  -o sbom-$TAG.spdx.json
# Sanity check : file is not 4xx HTML, has packages
jq '.packages | length' sbom-$TAG.spdx.json   # should print > 0

# 2. CVE scan (Trivy filesystem) — was it CVE-clean at release time
curl -fsSL "$BASE/-/jobs/artifacts/$TAG/raw/trivy.json?job=security:trivy" \
  -o trivy-$TAG.json
jq '.Results[].Vulnerabilities | length' trivy-$TAG.json   # 0 = clean

# 3. CVE cross-check (Grype) — independent verification of #2
curl -fsSL "$BASE/-/jobs/artifacts/$TAG/raw/grype.json?job=security:grype" \
  -o grype-$TAG.json

# 4. Secret scan (Gitleaks) — did the release accidentally commit a secret
curl -fsSL "$BASE/-/jobs/artifacts/$TAG/raw/gitleaks.json?job=security:gitleaks" \
  -o gitleaks-$TAG.json
jq 'length' gitleaks-$TAG.json   # 0 = no leaks

# 5. Coverage XML — `cat coverage-$TAG.xml | xmllint --xpath ...` to read percentage
curl -fsSL "$BASE/-/jobs/artifacts/$TAG/raw/coverage.xml?job=test:py313" \
  -o coverage-$TAG.xml

# 6. Image signature — verify cosign keyless OIDC (ADR-0016)
cosign verify \
  registry.gitlab.com/benoit.besson/secured-claude/claude-code:$TAG \
  --certificate-identity-regexp '^https://gitlab.com/benoit.besson/secured-claude' \
  --certificate-oidc-issuer https://gitlab.com
```

**No clone required.** The links resolve to immutable CI artifacts with 1-year retention. Recipients get the same bytes you'd see at release time. Tag annotations (`git show $TAG`) carry the full verification log including pipeline IDs and local test pass — `gh release view` / `glab release view` surface the same.

What this defends against : "you say you have 92 % coverage but I can't verify" → here's the coverage XML. "You say there are 0 CVEs but maybe a recent CVE landed and you didn't rescan" → re-run grype against the `sbom-$TAG.spdx.json` today. "You say the image is signed but how do I know" → cosign verify, with no clone.

---

## Why secured-claude

Claude Code is the most ergonomic agentic CLI today — but for **enterprise adoption** you need :

1. **No silent exfiltration** of filesystem secrets (`~/.ssh`, `~/.aws`, `.env`), shell-arbitrary execution, or unconstrained network egress.
2. **Complete audit trail** of every action the agent took — for compliance, postmortems, and security review.
3. **Policy-as-code** that the security team can read, lint, sign, and version — not Python code or settings.json deny-lists.
4. **Cross-platform** install (Mac / Linux / Windows) for heterogeneous dev fleets.

`secured-claude` provides the **comfort of Claude Code** while delivering all four. Same TUI, same slash commands, same MCP support — but every tool call is gated by a Cerbos policy and logged to a queryable audit DB.

## Quick start

```bash
# Mac / Linux
curl -sSL https://gitlab.com/benoit.besson/secured-claude/-/raw/main/install.sh | bash

# Windows (PowerShell)
irm https://gitlab.com/benoit.besson/secured-claude/-/raw/main/install.ps1 | iex

# Then:
export ANTHROPIC_API_KEY=sk-ant-...
secured-claude up                       # start cerbos + claude-code containers
secured-claude run "refactor src/foo"   # interactive Claude Code, every tool gated
secured-claude audit --denied           # show what was blocked
secured-claude down                     # stop everything
```

## Architecture

```
HOST                                     DOCKER (network: secured-claude-net)
┌────────────────────────────┐         ┌──────────────────────────────────────┐
│ secured-claude (Python CLI)│         │  ┌──────────────────────────────┐    │
│                            │         │  │ cerbos/cerbos                 │    │
│  orchestrator (docker SDK) │ ◀────── │  │ HTTP :3592, policies/*.yaml   │    │
│  gateway (FastAPI :8765)   │         │  └──────────────────────────────┘    │
│  cerbos_client             │         │  ┌──────────────────────────────┐    │
│  store (SQLite append-only)│ ◀────── │  │ secured-claude/claude-code   │    │
│                            │         │  │ - claude CLI                  │    │
└────────────────────────────┘         │  │ - PreToolUse hook → host:8765 │    │
              ↑                        │  │ - /workspace mounted RW       │    │
       user terminal                   │  └──────────────────────────────┘    │
                                       └──────────────────────────────────────┘
```

Full design : see [`docs/architecture.md`](docs/architecture.md) and the [16 ADRs](docs/adr/).

## Security

- **Threat model** : [`docs/SECURITY.md`](docs/SECURITY.md) — STRIDE table mapping each threat to which defense layer catches it.
- **Audit demonstration** : `secured-claude audit-demo --strict` runs 6 red-team scenarios + 2 happy-paths + 50+ policy fuzz variants + 8 static scans, produces a timestamped report. Required to pass before every release.
- **Policy as code** : [`policies/`](policies/) — Cerbos YAML, lintable via `cerbos compile`, signable via Cerbos signed bundles.
- **Audit log** : SQLite append-only at `~/.local/share/secured-claude/approvals.db` (Linux) / `~/Library/Application Support/secured-claude/` (Mac) / `%LOCALAPPDATA%\secured-claude\` (Windows).

## Architecture decisions

The 22 ADRs in [`docs/adr/`](docs/adr/) justify every load-bearing choice. Highlights :

| # | Decision | Why it matters |
|---|---|---|
| [0001](docs/adr/0001-cerbos-as-policy-decision-point.md) | Cerbos as PDP | CNCF, signable, lintable, security-team familiar |
| [0002](docs/adr/0002-pretooluse-hook-as-interception-point.md) | PreToolUse hook interception | Native Claude Code mechanism — no binary patching |
| [0009](docs/adr/0009-hook-fails-closed.md) | Hook fails closed | Broker down → DENY by default, never bypass |
| [0019](docs/adr/0019-l2-egress-proxy-tinyproxy.md) | L2 tinyproxy CONNECT allowlist | Closes the v0.1 design-only L2 gap |
| [0020](docs/adr/0020-l3-dns-allowlist-dnsmasq.md) | L3 dnsmasq DNS allowlist | Closes R-DNS-LEAK |
| [0022](docs/adr/0022-intent-layer-vs-confinement-layers.md) | 1 intent layer + 3 confinement layers | Honest framing — supersedes ADR-0012 |
| [0016](docs/adr/0016-supply-chain-cosign-sbom.md) | Cosign + SBOM | Provenance per OWASP A08:2021 |
| [0021](docs/adr/0021-pin-claude-code-npm-version.md) | Pin Claude Code npm + Renovate | Closes the @latest hole in ADR-0008 |

## License

[MIT](LICENSE) — Benoit Besson, 2026.
