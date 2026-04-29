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
