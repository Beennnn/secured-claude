# secured-claude — project-specific instructions for Claude

This file is loaded automatically by any Claude Code session opening this repo.
Global rules live in `~/.claude/CLAUDE.md` ; this file holds **project-specific** context only.

## What this project is

A wrapper around Claude Code that gates every tool call through a Cerbos policy decision point and persists every approval in an append-only SQLite audit log. Designed for **enterprise** adoption — see `README.md` and `docs/adr/` for the full justification.

## Architecture in one paragraph

A host-side Python CLI (`secured-claude`) spins up two Docker containers : Cerbos (PDP, port 3592) and a Claude Code container (Node.js + `@anthropic-ai/claude-code`). The Claude Code container has a `PreToolUse` hook installed that POSTs every tool intent to a host-side FastAPI gateway (port 8765). The gateway translates to a Cerbos `CheckResources` request, logs the decision to SQLite, and returns ALLOW/DENY. Defense-in-depth : 4 independent layers (hook + Cerbos + Docker network egress allowlist + container FS confinement).

## Build / test / lint commands

```bash
# Setup
uv sync --all-extras

# Lint
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
uv run mypy src/

# Test
uv run pytest tests/ -m "not audit"            # fast unit tests
uv run pytest tests/ -m "audit"                # slow security audit demonstration
uv run pytest --cov=src/secured_claude         # with coverage

# Security
uv run bandit -r src/
uv run pip-audit

# Cerbos policy lint
docker run --rm -v $PWD/policies:/policies cerbos/cerbos:0.42.0 compile /policies

# End-to-end (requires Docker + ANTHROPIC_API_KEY)
uv run secured-claude up
uv run secured-claude run "ls /workspace"
uv run secured-claude audit
uv run secured-claude down
```

## Hard rules for this repo

- **No bare `latest` tags** — every Docker image pinned by digest. CLAUDE.md global "pin everything" rule applies in full.
- **No secret in the image** — `ANTHROPIC_API_KEY` only as runtime env. Never `COPY .env`, never `ARG SECRET`.
- **Default-deny in policies** — adding ALLOW rules requires an ADR or comment explaining why the new resource/action is safe.
- **Hook fails closed** (ADR-0009) — if the broker is unreachable, the hook returns DENY. Never the opposite.
- **Append-only audit log** — never expose UPDATE or DELETE on the `approvals` table. SQLite trigger enforces it.
- **Cross-platform** — `pathlib.Path` everywhere, `subprocess.run(shell=False)` everywhere, no `/`-hardcoded paths outside the container.
- **ADR for every load-bearing decision** — if a reviewer asks "why this and not X?", the answer must be `docs/adr/NNNN-*.md`.

## Conventional Commits required

Every commit must follow Conventional Commits — CI rejects otherwise.

```
feat(scope): user-facing change
fix(scope): bug fix
chore(scope): tooling / scaffolding
docs(scope): documentation only
refactor(scope): code shape, no behavior change
test(scope): tests only
ci(scope): CI/CD changes
```

## Branching

- `main` — released only, protected, no direct push
- `dev` — working branch, auto-merge to `main` on green pipeline (via `glab mr merge --auto-merge --remove-source-branch=false`)
- Feature branches optional for big chunks; small fixes go straight on `dev`

## Tag format

`vX.Y.Z` semver pure. Annotation MUST follow the global CLAUDE.md "tag annotations formalise what was verified" rule — sections : Changes / Verified / Themes maîtrisés (10 axes) / Known limitations / Next checkpoint.

## Where things live

- **Broker code** : `src/secured_claude/`
- **Cerbos policies** : `policies/`
- **ADRs** : `docs/adr/`
- **Docker image of Claude Code** : `Dockerfile.claude-code` + `docker/`
- **Compose** : `docker-compose.yml`
- **CI** : `.gitlab-ci.yml`
- **Audit demo** : `src/secured_claude/audit_demo.py` + `bin/security-audit.sh`
- **Cross-platform install** : `install.sh` + `install.ps1`

## Cross-platform reminders

- Tests run on Linux runners in CI (Mac/Windows validated manually pre-release).
- Local dev primarily on Mac (M-series arm64) — Docker images built multi-arch via buildx.
- `host.docker.internal:host-gateway` declared in compose so Linux containers can reach the host gateway.

## Out-of-scope (do NOT touch in v0.1)

- Multi-user / SSO authentication (single principal `claude-code-default`)
- Web UI for audit review (CLI only)
- SIEM integrations
- gVisor / Firecracker hardening
- Signed Cerbos policy bundles

These are all valid v0.2+ work — open an issue, discuss, ADR, then implement.
