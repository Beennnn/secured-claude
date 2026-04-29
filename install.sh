#!/usr/bin/env bash
# secured-claude installer — Mac / Linux.
#
#   curl -sSL https://gitlab.com/benoit.besson/secured-claude/-/raw/main/install.sh | bash
#
# Or, after cloning :
#   bash install.sh
#
# Per ADR-0015 (distribution via pipx + GitLab Package Registry).
#
# What this does :
#   1. Detect OS / arch
#   2. Verify Python ≥ 3.11
#   3. Verify Docker installed and reachable
#   4. Install pipx if missing
#   5. Install secured-claude (from GitLab Package Registry or local source)
#   6. Pre-pull the cerbos and claude-code Docker images
#   7. Run `secured-claude doctor` to validate the install end-to-end
#
# Optional env vars :
#   SC_INDEX_URL      override the PyPI index URL (default: GitLab Package Registry)
#   SC_PROJECT_ID     GitLab project ID (default: derived from path)
#   SC_VERSION        version to install (default: latest)
#   SC_LOCAL=1        install from local source instead of GitLab
#   SC_NO_DOCKER=1    skip Docker checks (for offline install)
#
# Auditable : the script is in the public repo, runs no network operation
# without explaining it. Reading + bash is the recommended secure path :
#   wget https://...install.sh
#   less install.sh
#   bash install.sh

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

YELLOW='\033[33m'
RED='\033[31m'
GREEN='\033[32m'
DIM='\033[2m'
RESET='\033[0m'

info()  { printf "${GREEN}✓${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}⚠${RESET} %s\n" "$*" >&2; }
fail()  { printf "${RED}✗${RESET} %s\n" "$*" >&2; exit 1; }
step()  { printf "\n${DIM}::${RESET} %s\n" "$*"; }

# ---------------------------------------------------------------------------
# 1. OS / arch detection
# ---------------------------------------------------------------------------

step "OS / arch detection"
case "$(uname -s)" in
    Darwin)  OS="macos" ; PKG_HINT="brew install" ;;
    Linux)   OS="linux"
             # Distinguish Debian-family vs Red Hat-family vs Arch for hints
             if [[ -f /etc/debian_version ]]; then PKG_HINT="apt install"
             elif [[ -f /etc/redhat-release ]]; then PKG_HINT="dnf install"
             elif [[ -f /etc/arch-release ]]; then PKG_HINT="pacman -S"
             else PKG_HINT="<your package manager>"
             fi ;;
    *)       fail "unsupported OS: $(uname -s) — Mac/Linux only ; Windows users see install.ps1" ;;
esac
ARCH="$(uname -m)"
info "${OS} ${ARCH}"

# ---------------------------------------------------------------------------
# 2. Python ≥ 3.11
# ---------------------------------------------------------------------------

step "Python ≥ 3.11"
if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 not found. Install : ${PKG_HINT} python3 python3-pip"
fi
PY_MAJOR_MINOR="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_OK="$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 11) else 0)')"
if [[ "${PY_OK}" != "1" ]]; then
    fail "python3 ${PY_MAJOR_MINOR} found, but ≥ 3.11 required (older versions are EOL). Install : ${PKG_HINT} python3.13"
fi
info "python3 ${PY_MAJOR_MINOR}"

# ---------------------------------------------------------------------------
# 3. Docker
# ---------------------------------------------------------------------------

if [[ "${SC_NO_DOCKER:-0}" != "1" ]]; then
    step "Docker (running)"
    if ! command -v docker >/dev/null 2>&1; then
        fail "docker not found. Install : Docker Desktop (Mac) / Docker Engine (Linux). https://docs.docker.com/get-docker/"
    fi
    if ! docker info >/dev/null 2>&1; then
        fail "docker daemon not running. Start Docker Desktop (Mac) or 'sudo systemctl start docker' (Linux)."
    fi
    info "docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'present')"
else
    warn "skipping Docker checks (SC_NO_DOCKER=1)"
fi

# ---------------------------------------------------------------------------
# 4. pipx
# ---------------------------------------------------------------------------

step "pipx"
if ! command -v pipx >/dev/null 2>&1; then
    info "pipx not found, installing via 'python3 -m pip install --user pipx'"
    python3 -m pip install --user --quiet pipx
    python3 -m pipx ensurepath >/dev/null 2>&1 || true
    # Prepend the pipx install dir to PATH for this session
    export PATH="${HOME}/.local/bin:${PATH}"
    if ! command -v pipx >/dev/null 2>&1; then
        fail "pipx still not on PATH after install. Restart your shell or run 'python3 -m pipx ensurepath'."
    fi
fi
info "pipx $(pipx --version 2>/dev/null || echo 'present')"

# ---------------------------------------------------------------------------
# 5. Install secured-claude
# ---------------------------------------------------------------------------

step "secured-claude"
if [[ "${SC_LOCAL:-0}" == "1" ]]; then
    REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
    info "installing from local source : ${REPO_ROOT}"
    pipx install --force "${REPO_ROOT}"
else
    SC_PROJECT_ID="${SC_PROJECT_ID:-81740556}"
    SC_INDEX_URL="${SC_INDEX_URL:-https://gitlab.com/api/v4/projects/${SC_PROJECT_ID}/packages/pypi/simple}"
    SC_VERSION_SPEC="${SC_VERSION:+==${SC_VERSION}}"
    info "installing from ${SC_INDEX_URL}"
    pipx install --force --index-url "${SC_INDEX_URL}" "secured-claude${SC_VERSION_SPEC}" || \
        warn "GitLab Package Registry install failed. If this is a fresh repo with no published version yet, set SC_LOCAL=1 to install from a local clone."
fi
if ! command -v secured-claude >/dev/null 2>&1; then
    fail "secured-claude not on PATH after install. Run 'python3 -m pipx ensurepath' and restart your shell."
fi
info "$(secured-claude version)"

# ---------------------------------------------------------------------------
# 6. Pre-pull Docker images (sized for first run, ~600 MB)
# ---------------------------------------------------------------------------

if [[ "${SC_NO_DOCKER:-0}" != "1" ]]; then
    step "pre-pull Docker images (one-time, ~600 MB)"
    docker pull cerbos/cerbos:0.42.0 >/dev/null 2>&1 || warn "cerbos image pull failed (continuing — will be retried on 'secured-claude up')"
    info "cerbos/cerbos:0.42.0 cached"
fi

# ---------------------------------------------------------------------------
# 7. Doctor check
# ---------------------------------------------------------------------------

step "doctor"
secured-claude doctor || warn "doctor reported issue(s) ; review above."

# ---------------------------------------------------------------------------
# 8. Next-steps prompt
# ---------------------------------------------------------------------------

cat <<'EOF'

──────────────────────────────────────────────────────────────────────
secured-claude is installed.

Next steps :

  1. Get an Anthropic API key
       https://console.anthropic.com/settings/keys

  2. Set the env var (or copy .env.example to .env and fill it)
       export ANTHROPIC_API_KEY=sk-ant-...

  3. Start the secured stack
       secured-claude up

  4. Run a Claude Code session
       secured-claude run "hello"

  5. Inspect the audit trail
       secured-claude audit

  6. Run the security audit (proves the policy gates fire)
       bin/security-audit.sh

Documentation : https://gitlab.com/benoit.besson/secured-claude/-/blob/main/README.md
Threat model :  https://gitlab.com/benoit.besson/secured-claude/-/blob/main/SECURITY.md
──────────────────────────────────────────────────────────────────────
EOF
