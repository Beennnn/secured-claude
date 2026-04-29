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

## GitLab CI runner setup

The CI pipeline uses `tags: [macbook-local]` (per CLAUDE.md global "use
local runners ; never rely on GitLab SaaS quota"). On 2026-04-29 we
registered a **project-specific** runner alongside the existing iris-7
group runner — the gitlab-runner daemon is the same Docker container
(`gitlab/gitlab-runner:latest`) and serves both via separate
`[[runners]]` blocks in `/etc/gitlab-runner/config.toml`.

### How it was done (reproducible) — for future siblings

```bash
# 1. Create a project-scoped runner via the API (returns a glrt-... token,
#    valid once for `gitlab-runner register`)
TOKEN=$(echo -e 'protocol=https\nhost=gitlab.com\n' \
  | glab auth git-credential get | grep '^password=' | cut -d= -f2-)
PROJECT_ID=81740556
curl -sS -X POST "https://gitlab.com/api/v4/user/runners" \
  -H "PRIVATE-TOKEN: $TOKEN" -H "Content-Type: application/json" \
  -d "{\"runner_type\":\"project_type\",\"project_id\":${PROJECT_ID},
       \"description\":\"macbook-local (secured-claude)\",
       \"tag_list\":[\"macbook-local\"],\"run_untagged\":false}"
# → { "id": ..., "token": "glrt-..." }

# 2. Register inside the existing gitlab-runner container (auto-appends a
#    new [[runners]] block to the volume-mounted config.toml)
docker exec gitlab-runner gitlab-runner register \
  --non-interactive \
  --url https://gitlab.com \
  --token "<the glrt-... token from step 1>" \
  --executor docker \
  --docker-image "python:3.13-slim" \
  --docker-privileged=false \
  --docker-volumes "/var/run/docker.sock:/var/run/docker.sock" \
  --docker-volumes "/cache" \
  --description "macbook-local (secured-claude)"

# 3. Restart the daemon so it picks up the new section (auto-reloads
#    on most Docker versions, restart is belt-and-braces)
docker restart gitlab-runner

# 4. Verify online
glab api "projects/${PROJECT_PATH//\//%2F}/runners" \
  | python3 -c "import json,sys,re; t=sys.stdin.read(); m=re.search(r'\\[.*\\]', t, re.S); d=json.loads(m.group(0) if m else t); [print(f'{r[\"description\"]}: {r[\"status\"]}') for r in d]"
# → "macbook-local (secured-claude): online"
```

### Why we couldn't just attach the iris-7 group runner

`POST /projects/<id>/runners` with `runner_id=<group-runner-id>` returns
HTTP 403 *"Runner is a group runner"* — GitLab forbids cross-namespace
attachment of group-level runners. The `POST /user/runners` route with
`runner_type=project_type` is the correct pattern.

### Default per-job image strategy

The default registration above sets `--docker-image python:3.13-slim`
but our `.gitlab-ci/*.yml` overrides this **per job** so each job runs
in an image already containing its tool — see ADR-0017 §"Caching".
Examples :

| Stage    | Image                                                      |
|----------|------------------------------------------------------------|
| lint:ruff/mypy/test:* | `ghcr.io/astral-sh/uv:python3.13-bookworm-slim` |
| lint:hadolint | `hadolint/hadolint:latest-debian` (entrypoint override) |
| lint:shellcheck | `koalaman/shellcheck-alpine:stable`            |
| lint:cerbos-compile | `docker:27` + `services: docker:27-dind` (cerbos image is distroless, no shell — DinD lets us `docker run` it) |
| lint:commits | `alpine/git:latest`                                  |
| security:gitleaks/trivy/grype/sbom | dedicated tool images   |
| build:image | `docker:27` + `docker:27-dind` for buildx multi-arch  |
| publish:cosign-sign | `gcr.io/projectsigstore/cosign:v2.4.1`        |

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
