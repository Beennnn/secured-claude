# ADR-0015: Distribution via pipx + GitLab Package Registry + Docker pull on first run

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

## Context

How does an enterprise developer install secured-claude on Mac, Linux, or Windows ?

Constraints :

- **One command** target : `curl ... | bash` (Mac/Linux) or `irm ... | iex` (Windows), or a single `pipx install` line.
- **Cross-platform** : same UX on the three OSes.
- **Updateable** : `secured-claude self-update` or `pipx upgrade secured-claude` should pull the latest.
- **Verifiable** : users must be able to `cosign verify` the image and check SHA256 of the wheel.
- **Air-gapped capable** (v0.2) : enterprise networks without internet should also install.

Options :

1. **PyPI public** + Docker Hub — broadest reach, but requires PyPI namespace + maintainer dance.
2. **GitLab Package Registry** (PyPI-format) + GitLab Container Registry — one provider, OIDC-integrated CI, fits our hosting choice.
3. **Homebrew formula** + `brew install` — Mac-friendly, Linux less so, Windows not at all.
4. **Per-OS bundles** (`.pkg`, `.msi`, `.deb`, `.rpm`) — heaviest path, lots of packaging code, low marginal value at v0.1 scale.

## Decision

For **v0.1**, we ship :

- **Python wheel + sdist** to **GitLab Package Registry** (PyPI-format) at `https://gitlab.com/api/v4/projects/$ID/packages/pypi/simple`.
- **Container image** to **GitLab Container Registry** at `registry.gitlab.com/benoit.besson/secured-claude/claude-code:vX.Y.Z`.
- **Install scripts** (`install.sh`, `install.ps1`) at the repo root, served via raw URL.

The user-side install :

```bash
# Mac / Linux
curl -sSL https://gitlab.com/benoit.besson/secured-claude/-/raw/main/install.sh | bash

# Windows (PowerShell 5+)
irm https://gitlab.com/benoit.besson/secured-claude/-/raw/main/install.ps1 | iex
```

The script :

1. Detects OS / arch.
2. Verifies Python ≥ 3.11 and Docker installed + running.
3. Installs `pipx` if absent (`python -m pip install --user pipx && python -m pipx ensurepath`).
4. Runs `pipx install secured-claude --index-url https://gitlab.com/api/v4/projects/$PROJECT_ID/packages/pypi/simple`.
5. Pre-pulls Docker images : `docker pull cerbos/cerbos:0.42.0@sha256:...` + `docker pull registry.gitlab.com/benoit.besson/secured-claude/claude-code:vX.Y.Z`.
6. Runs `secured-claude doctor` to validate everything.
7. Prints next steps (set `ANTHROPIC_API_KEY`, run `secured-claude run`).

For **v0.2+** :

- **PyPI public** mirror — once the project is stable, mirror to `pypi.org/secured-claude` for `pipx install secured-claude` without `--index-url`.
- **Air-gapped bundle** — `secured-claude-vX.Y.Z-offline.tar.gz` containing the wheel, image tarballs (`docker save`), and an `install-offline.sh`.
- **Homebrew formula** — if Mac install volume justifies it.
- **Optional MSI / pkg / snap** — only if measured demand.

## Consequences

### Positive

- **One-command install** on all 3 OSes — meets the user-stated requirement "au maximum automatisé sur Mac, Linux et Windows".
- **`pipx`-based** — isolates secured-claude in its own venv, cleanly upgradeable, auto-PATH-managed via `pipx ensurepath`.
- **Single provider** (GitLab) — less surface to compromise. Both wheel and image come from same provider, cosign-signed, SBOM-attached.
- **Verifiable** — `cosign verify ...` checks image origin, `pip download --require-hashes` (v0.2) checks wheel SHA.
- **No sudo required** on Mac/Linux for `pipx install --user`. Windows install also user-mode (PowerShell as user).
- **Renovate keeps deps fresh** — install scripts pin install commands to the latest GitLab Release tag.

### Negative

- **GitLab Package Registry less discoverable than PyPI** — `pipx install secured-claude` plain doesn't work yet (need `--index-url`). Mitigated by the install scripts handling this.
- **`curl | bash` security perception** — some shops disallow piping internet content to a shell. Mitigated by : (a) the script is in the public repo (auditable), (b) we document `wget && review && bash install.sh` as the explicit path, (c) v0.2 may add `gpg --verify install.sh.asc` for offline verification.
- **Pre-pulling images at install time = slower install** — first install downloads ~600 MB (cerbos ~30 MB, claude-code base ~500 MB). Mitigated by : (a) progress bar, (b) Renovate-managed digest pins keep cache hits high after first install.
- **Docker as a hard prerequisite** — Linux without Docker can't use this. Acceptable per threat model (containerization is L3/L4 baseline).

### Neutral

- We accept that v0.1 is "not on PyPI public yet". Tracked as v0.2 follow-up.

## Alternatives considered

- **PyPI public from day 1** — adds maintainer dance (PyPI account, API token, name-squatting risk). Tracked v0.2 once project stability is proven.
- **Per-OS native bundles** (`.pkg`, `.msi`, `.deb`, `.rpm`) — significant packaging code, MSI especially painful (WiX, code signing certs). Out of scope v0.1. Tracked v0.3+ on demand.
- **Homebrew tap** — useful for Mac but doesn't help Linux/Windows. Tracked v0.2 if Mac-heavy user base.
- **`uv tool install`** instead of pipx — `uv` is faster and is what CLAUDE.md global mandates for project-level work. But for end-user install, pipx has wider adoption (8 years vs uv's 1 year). v0.2 may add `uv tool install` as the recommended path once uv penetration is high enough.
- **Static binary** (PyInstaller, Nuitka) — no Python prerequisite. Heavy build infrastructure, large binary, harder to reason about supply chain. Rejected for v0.1 ; tracked v0.3+.
- **Docker-only install** (`alias secured-claude='docker run --rm secured-claude/cli'`) — neat but : (a) loses host-side broker pattern (ADR-0006), (b) every command spawns a container which is slow. Rejected.

## References

- pipx documentation — https://pipx.pypa.io/
- GitLab Package Registry (PyPI) — https://docs.gitlab.com/ee/user/packages/pypi_repository/
- GitLab Container Registry — https://docs.gitlab.com/ee/user/packages/container_registry/
- Twelve-Factor App I. Codebase + V. Build, release, run — https://12factor.net/
- Implementation : [`install.sh`](../../install.sh), [`install.ps1`](../../install.ps1), `secured-claude doctor` (in [`src/secured_claude/cli.py`](../../src/secured_claude/cli.py))
- Related ADRs : [0007](0007-cross-platform-via-docker-sdk.md) (cross-platform), [0014](0014-gitlab-ci-pipeline-6-stages.md) (publish stage), [0016](0016-supply-chain-cosign-sbom.md) (signed artifacts)
