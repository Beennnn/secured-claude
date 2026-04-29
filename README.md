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
  <a href="https://gitlab.com/secured-claude/secured-claude/-/pipelines"><img src="https://gitlab.com/secured-claude/secured-claude/badges/main/pipeline.svg" alt="pipeline"></a>
  <a href="docs/SECURITY.md"><img src="https://img.shields.io/badge/security--audit-pass-brightgreen" alt="security audit"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="license"></a>
  <a href="pyproject.toml"><img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="python"></a>
  <a href="https://cerbos.dev"><img src="https://img.shields.io/badge/policy--engine-cerbos-ff6b35" alt="cerbos"></a>
  <a href="https://docker.com"><img src="https://img.shields.io/badge/runtime-docker-2496ed" alt="docker"></a>
  <a href="https://www.anthropic.com/claude-code"><img src="https://img.shields.io/badge/agent-claude--code-c8b3a8" alt="claude-code"></a>
</p>

---

## Status — verify in 60 seconds

**v0.1.1** — every claim below is backed by an artifact you can re-run yourself.
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

### What is real now (v0.1.1)

| Claim | Where | How to check |
|---|---|---|
| Cerbos PDP gating every tool call | `policies/*.yaml`, `src/secured_claude/cerbos_client.py`, `src/secured_claude/gateway.py` | `bin/security-audit.sh` (26/26) |
| FastAPI broker on host:8765 | `src/secured_claude/gateway.py` (75 lines, 100 % covered) | `tests/test_gateway.py` (8 tests) |
| Append-only SQLite audit | `src/secured_claude/store.py` (85 lines, 98 % covered) | `tests/test_store.py` includes UPDATE/DELETE refused by trigger |
| Claude Code container hardened | `Dockerfile.claude-code` + `docker-compose.yml` (non-root UID 1001, read-only cerbos rootfs, cap_drop ALL, healthcheck) | `secured-claude doctor`, `secured-claude up` |
| 17 ADRs justifying every decision | `docs/adr/0000-template.md` + `0001..0017-*.md` | `ls docs/adr/` |
| GitLab CI green on macbook-local runner | `.gitlab-ci.yml` + `.gitlab-ci/{lint,test,security,build,publish,release}.yml` | [pipeline #2487406196](https://gitlab.com/benoit.besson/secured-claude/-/pipelines/2487406196) |
| 7-layer security pipeline | `bin/security-scans.sh` + `pyproject.toml [tool.bandit]` | `bash bin/security-scans.sh` |
| SBOM (SPDX 2.3) per release | `.gitlab-ci/security.yml::security:sbom` | release artifact `sbom.spdx.json` |

### What is configured but NOT yet enforced — be explicit

A senior security reviewer should read this table before trusting any
"defense-in-depth" claim. v0.1.x ships a credible **prototype** with a
working policy gate ; **L2 (network egress allowlist) is designed but
NOT enforced at the kernel level**, and a few other items are documented
ahead of being live.

| Item | v0.1 reality | When it goes live |
|---|---|---|
| **L2 — Network egress allowlist** | The `secured-claude-net` Docker bridge currently allows all egress. ADR-0010 specifies iptables (Linux) / sidecar HTTP proxy (cross-platform) ; **neither is implemented yet**. The hook (L1) is the only thing today preventing `WebFetch evil.com` ; a malicious post-install script in an approved `npm install` would not be blocked at the network layer. | v0.2 — sidecar HTTP allowlisting proxy + DNS filter |
| **Cosign keyless OIDC signature** on container image | Pipeline job exists (`publish:cosign-sign`) ; v0.1.1 release pipeline failed at `build:image` (buildx daemon access on Mac runner) so cosign was skipped. The wheel IS in GitLab Package Registry but the image is not signed yet. | v0.1.2 — `build:image` simplified to single-arch + `docker build` ; cosign chain re-validates on next tag |
| **GitLab Release with auto-attached SBOM + wheel + sig** | `release:gitlab` job exists ; same skip as above on v0.1.1 | v0.1.2 |
| **Audit log tamper-evidence at FS layer** | App + SQLite trigger refuse `UPDATE`/`DELETE` on `approvals` (tested). But a `rm approvals.db` from another process succeeds — the log is not tamper-EVIDENT, just append-only at the SQL boundary. | v0.2 — hash-chain entries (each row's hash includes previous), optional SIEM JSONL forward |
| **Multi-principal Cerbos roles** | `derived_roles.yaml` defines them ; broker hardcodes single principal `claude-code-default` | v0.2 |
| **DNS allowlist** (mitigates R-DNS-LEAK residual risk) | Documented in threat-model.md ; not implemented | v0.2 |
| **Runtime smoke in CI** (real claude binary call) | Recipe exists (`secured-claude up && claude -p ...`), runs locally pre-tag ; not yet a CI job | v0.2 — uses a test API key in a GitLab CI variable |
| **Hook coverage of every Claude Code tool** | `matcher: "*"` in PreToolUse hooks every tool we know about (Read/Write/Edit/Bash/WebFetch/WebSearch/MCP/Task). Anthropic adds tools faster than we audit ; **a new tool shipping in a future Claude Code release would default to ALLOW until we map it**. Mitigated by the broker's `unknown_tool` catch-all (kind=`unknown_tool` action=`invoke`) which has no policy rule → DENY by Cerbos default ; verified by `tests/test_gateway.py::test_map_unknown_tool_falls_back`. | Continuous — Renovate bumps Claude Code, audit-demo adds scenarios per new tool |

### What we explicitly DON'T claim to defend against

- Kernel CVEs / 0-days — Linux namespace isolation is the v0.1 boundary ; gVisor or Firecracker tracked v0.3+
- Side-channel attacks (Spectre/Meltdown class)
- Physical adversary at the developer machine
- Compromise of `cerbos/cerbos` upstream image — mitigated by digest pinning ; residual risk acknowledged

### Honest scoring of "defense-in-depth" in v0.1

| Layer | Designed | Enforced in v0.1 | Tested in v0.1 |
|---|---|---|---|
| **L1 — PreToolUse hook + Cerbos PDP** | Yes | Yes | `bin/security-audit.sh` → 26/26 PASS + runtime smoke transcript |
| **L2 — Network egress allowlist** | Yes (ADR-0010) | **No** — bridge network allows all egress | n/a |
| **L3 — Filesystem confinement** | Yes | Yes — only `/workspace` mounted RW from host | Inferred ; no explicit test that `/Users/<me>/.ssh` is unreachable |
| **L4 — Container hardening** | Yes | Partial — non-root + cap_drop ALL + seccomp default + read-only rootfs (cerbos AND claude-code as of v0.1.2) ; cgroup `mem_limit: 4g` | Inferred ; no explicit test (`docker inspect` would prove flags are set) |

Reading : v0.1 holds **L1 + partial L3/L4**. L2 is design-only. The
"4 independent layers, each independently sufficient" framing in
[ADR-0012](docs/adr/0012-defense-in-depth-layers.md) describes the
**target architecture** ; v0.1 is the L1-load-bearing baseline. This is
why the project tags v0.1.x not v1.0.0.

Full honest limits in [`SECURITY.md` §"Out-of-scope"](SECURITY.md#out-of-scope-honest-limits) and the residual-risks table in [`docs/security/threat-model.md` §7](docs/security/threat-model.md).

---

> **What this project demonstrates mastery of**
>
> - 🔒 **Sécurité** — defense-in-depth 4 couches (PreToolUse hook + Cerbos policy + Docker network egress allowlist + container FS confinement). Each layer is independently sufficient against its threat class.
> - 🤖 **IA** — Claude Code wrapped in a policy-gated container, every tool call (Read / Write / Edit / Bash / WebFetch / MCP / Task) intercepted via the native PreToolUse hook.
> - 🏛 **Architecture** — Hexagonal-lite Python broker (host) + Cerbos PDP (container) + Claude Code CLI (container) ; clear trust boundary between intent (LLM) and execution (broker).
> - ✅ **Qualité** — 16 ADRs covering every security and operational decision ; security audit demonstration with 6 red-team scenarios + 2 happy-paths + policy fuzz + 8 static scans, run on every release.
> - 🔄 **CI/CD** — GitLab CI 6 stages (lint / test / security / build / publish / release), audit-demo strict gate on releases, cosign keyless signing + Syft SBOM for supply-chain provenance.
> - ☁️ **Infrastructure** — Cross-platform install (Mac / Linux / Windows) via pipx + GitLab Package Registry ; Docker images pinned by digest ; offline bundle for air-gapped enterprise deploys.
> - 🛠 **DevX** — `secured-claude` CLI feels like `claude` (TTY preserved) ; `audit` subcommand surfaces the evolving allowlist ; `doctor` validates the install end-to-end.

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
curl -sSL https://gitlab.com/secured-claude/secured-claude/-/raw/main/install.sh | bash

# Windows (PowerShell)
irm https://gitlab.com/secured-claude/secured-claude/-/raw/main/install.ps1 | iex

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

The 16 ADRs in [`docs/adr/`](docs/adr/) justify every load-bearing choice. Highlights :

| # | Decision | Why it matters |
|---|---|---|
| [0001](docs/adr/0001-cerbos-as-policy-decision-point.md) | Cerbos as PDP | CNCF, signable, lintable, security-team familiar |
| [0002](docs/adr/0002-pretooluse-hook-as-interception-point.md) | PreToolUse hook interception | Native Claude Code mechanism — no binary patching |
| [0009](docs/adr/0009-hook-fails-closed.md) | Hook fails closed | Broker down → DENY by default, never bypass |
| [0010](docs/adr/0010-network-egress-filter-allowlist.md) | Docker network egress allowlist | Defense-in-depth — survives hook bypass |
| [0012](docs/adr/0012-defense-in-depth-layers.md) | 4 independent security layers | NIST SP 800-160 V1 §3.4 |
| [0016](docs/adr/0016-supply-chain-cosign-sbom.md) | Cosign + SBOM | Provenance per OWASP A08:2021 |

## License

[MIT](LICENSE) — Benoit Besson, 2026.
