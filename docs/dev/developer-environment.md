# Developer environment

This document covers the **developer-side** setup — your machine where you
hack on `secured-claude` itself. It is distinct from the **deployer-side**
install (covered by `install.sh` / `install.ps1` for end users) and the
**agent-side** runtime (the secured Claude Code container).

Three independent layers, each with its own conventions :

```
┌─────────────────────────────────────┐
│ Developer machine (this doc)        │  ← uv, ruff, mypy, lefthook,
│   Python 3.13, brew, optional MCPs  │    Docker Desktop, GitLab runner
└─────────────────┬───────────────────┘
                  │ git push
┌─────────────────▼───────────────────┐
│ GitLab CI pipeline (.gitlab-ci.yml) │  ← lint / test / security /
│   on macbook-local runner           │    build / publish / release
└─────────────────┬───────────────────┘
                  │ docker pull / pipx install
┌─────────────────▼───────────────────┐
│ End-user host (install.sh)          │  ← Mac/Linux/Windows
│   Python 3.11+, Docker, secured-    │
│   claude CLI                        │
└─────────────────┬───────────────────┘
                  │ secured-claude up
┌─────────────────▼───────────────────┐
│ Container : Claude Code agent       │  ← gated by Cerbos PDP, all
│   (no developer tools, hardened)    │    tool calls audited
└─────────────────────────────────────┘
```

## Required tools

- **Python 3.13** (managed by `uv` — auto-installed via `uv sync --python 3.13`)
- **uv** — `brew install uv` (Mac) / `pipx install uv` / official installer
- **Docker Desktop** — for the agent container + Cerbos PDP, plus the
  in-CI hadolint / cerbos compile / build:image jobs
- **git** — obviously

## Recommended tools (auto-detected by `bin/security-scans.sh`)

| Tool | Install | Purpose |
|---|---|---|
| `gitleaks` | `brew install gitleaks` | secret scan layer L3 |
| `trivy` | `brew install trivy` | filesystem CVE/secret/config scan layer L4 |
| `grype` | `brew install grype` | dep CVE cross-check layer L2 |
| `syft` | `brew install syft` | SBOM (SPDX) generator |
| `shellcheck` | `brew install shellcheck` | shell lint layer L5 |
| `hadolint` | (Docker pull on demand) | Dockerfile lint layer L5 |
| `lefthook` | `brew install lefthook` | pre-commit hook runner (`.config/lefthook.yml`) |
| `glab` | `brew install glab` | GitLab CLI for MR / pipeline management |

After installing : `lefthook install` activates the commit-msg + pre-commit
hooks defined in `.config/lefthook.yml`.

## Recommended MCP servers (infra / dev category)

If you use Claude Code as your dev assistant on this project, enable the
**infra / dev** MCP servers below in your user-level Claude Code config.
They give your dev assistant ergonomic access to the systems we interact
with day-to-day :

| MCP server | What it exposes | Enable it for |
|---|---|---|
| `docker` | container lifecycle, exec, logs | inspecting `secured-claude` running containers |
| `kubernetes` | kubectl, pods, services, helm | future v0.3 helm chart development |
| `prometheus` | metrics queries | observing the broker once we ship metrics in v0.2 |
| `redis` | get/set/del/scan/hash/list | (n/a yet, useful when v0.2 adds rate-limit cache) |
| `grafana` | dashboards, annotations, queries | observing audit-log dashboards in v0.2+ |
| `filesystem` | structured file read/write | bulk policy edits across `policies/*.yaml` |
| `mcp-registry` | search the MCP marketplace | finding more dev MCPs |
| `scheduled-tasks` | cron-like tasks for Claude | re-running stability checks |
| `ccd_directory` | file tree exploration | navigating large dirs faster |

These are **not** allowlisted in the project's Cerbos `policies/mcp.yaml` —
that file gates what the **secured agent** is allowed to call inside the
container. The list above is for the **developer's** Claude Code session
running on the host, OUTSIDE the container, OUTSIDE the policy gate.

To enable them, edit your `~/.claude/settings.json` or your
plugin marketplace config. Per the Claude Code MCP docs :
<https://docs.claude.com/en/docs/claude-code/mcp>

## GitLab CI runner setup (one-time per dev machine)

The CI pipeline uses `tags: [macbook-local]` (per CLAUDE.md global "use
local runners ; never rely on GitLab SaaS quota"). The macbook-local
runner is registered at the **iris-7 group level** for the original Iris
projects.

To enable CI for `benoit.besson/secured-claude` (which lives outside the
iris-7 group), the runner must be either :

1. **Re-registered as a project-specific runner** for
   `benoit.besson/secured-claude` :
   ```bash
   # Get a registration token from
   #   https://gitlab.com/benoit.besson/secured-claude/-/settings/ci_cd → Runners
   # Then on the macbook :
   gitlab-runner register \
     --url https://gitlab.com \
     --token <project-runner-registration-token> \
     --executor shell \
     --description "macbook-local (secured-claude)" \
     --tag-list "macbook-local"
   ```

2. **Or moved to the user's namespace at the runner level** — promote the
   runner from group-scope to user-scope so it serves all projects under
   `benoit.besson/`.

3. **Or accept SaaS runners** — replace `tags: [macbook-local]` with
   `tags: [saas-linux-medium-amd64]` (paid, billed per minute). Not
   recommended per CLAUDE.md global.

Until one of (1)/(2) is done, pipeline runs will queue indefinitely
waiting for a matching runner.

## Workflow

```bash
# Setup (once)
git clone git@gitlab.com:benoit.besson/secured-claude.git
cd secured-claude
uv sync --all-extras
lefthook install   # activates commit-msg + pre-commit hooks

# Daily loop
git checkout dev
git pull --rebase

# Edit code
uv run pytest tests/ -m "not audit"           # fast feedback
uv run ruff check src/ tests/                 # lint
bin/security-scans.sh                         # full security pass before MR

# Commit (Conventional Commits ; lefthook validates the message)
git commit -m "feat(broker): ..."

# Push to dev (auto-merges to main when CI green)
git push origin dev
```

## Troubleshooting

- **`pytest` complains about missing dep** → `uv sync --all-extras` again.
- **`docker compose` fails** → check `docker compose version` and
  `docker info`. Docker Desktop must be running.
- **`cerbos compile` fails** → re-pull the image with the digest pin :
  `docker pull cerbos/cerbos:0.42.0`.
- **Pipeline stays queued forever** → see the GitLab CI runner section
  above ; the macbook-local runner needs to be enabled for this project.
