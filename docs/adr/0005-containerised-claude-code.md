# ADR-0005: Containerised Claude Code, not host-installed

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

## Context

Where does the Claude Code CLI binary actually run ? Two options :

1. **Host install** — `npm install -g @anthropic-ai/claude-code` on the developer's machine. Hooks run as a subprocess. Broker runs as a daemon.
2. **Containerised** — Claude Code installed inside a Docker container (`Dockerfile.claude-code`). Workspace mounted RW from the host project dir. Hooks talk to the host broker via `host.docker.internal`.

Constraints :

- An enterprise developer's HOME directory contains : SSH keys, AWS profile, GCP token, GitHub PAT, NPM token, browser cookies, password manager DB. The agent must not see these.
- The threat model assumes the LLM may be jailbroken (TA-2 in [threat-model.md](../security/threat-model.md)). If the agent has full host FS access, every Bash command Claude approves can syscall its way to anything.
- Claude Code is updated frequently — we want a single Anthropic-update path, not a host-pollution-and-cleanup workflow.
- Cross-platform is a hard requirement.

## Decision

Claude Code runs **inside a Docker container**, built from `Dockerfile.claude-code`. The host directory the user invokes `secured-claude run` from is mounted as `/workspace` (RW). Nothing else from the host filesystem is mounted.

Container hardening flags (see [ADR-0010](0010-network-egress-filter-allowlist.md) and [ADR-0012](0012-defense-in-depth-layers.md)) :

- Non-root user (UID 1000)
- Read-only root filesystem (`--read-only`) with explicit tmpfs for `/tmp`, `/home/agent`
- `--cap-drop=ALL` then add only what's needed (`--cap-add=NET_BIND_SERVICE` if claude binds a port)
- Default seccomp profile (Docker's default, blocks ~50 risky syscalls)
- Memory + CPU cgroup limits to bound DoS attempts (Linux ; Docker Desktop on Mac/Win has its own VM cap)

The broker on the host orchestrates the container lifecycle via Docker SDK ([ADR-0006](0006-host-side-broker.md), [ADR-0007](0007-cross-platform-via-docker-sdk.md)).

## Consequences

### Positive

- **Filesystem confinement** (defense-in-depth layer L3) — host secrets are *invisible* to Claude Code. `cat ~/.ssh/id_rsa` from inside Bash returns "no such file" because the path doesn't exist in the container.
- **Reproducible environment** — every developer gets identical OS, Node version, claude version, Python tools. Drift impossible.
- **Bounded blast radius** — a hypothetical Claude Code CVE that allowed arbitrary host execution is contained to `/workspace` + the container's ephemeral state.
- **Easy upgrade** — `docker pull` to update Claude Code ; rollback by changing tag.
- **No HOME pollution** — `~/.claude/projects/` lives in a Docker volume we manage, not in the user's HOME.
- **Cross-platform** — Docker Desktop on Mac / Windows + Docker Engine on Linux, the container behaves identically.

### Negative

- **Docker dependency** — users must have Docker installed and running. Mitigated by `secured-claude doctor` checking and giving install instructions.
- **TTY plumbing** — interactive `claude` needs `docker run -it`, terminal resize propagation, ANSI/mouse passthrough. Solved with Docker SDK `tty=True, stdin_open=True` ; tested manually on Mac iTerm2 + Linux GNOME Terminal + Windows Terminal/WSL2.
- **Cold-start latency** — starting the Claude Code container takes ~1-2 seconds on first invocation. Mitigated by keeping the container running between sessions (`secured-claude up` once, multiple `run` invocations exec into the running container).
- **Volume mounts on Mac** — Docker Desktop's VM-bridged file mounts have known performance overhead on macOS. For typical Claude usage (few hundred file reads per session) this is negligible ; for `npm install` of huge dep trees it can be slow. Acceptable for v0.1.
- **Clipboard / editor integration** — host clipboard isn't shared by default. v0.1 acceptable workaround : the user copies via the host terminal ; v0.2 may plumb `pbcopy`/`xclip` via a small forwarder.

### Neutral

- We adopt `node:22-slim` as the base image. Switch to `distroless` in v0.2 if image-size or attack-surface review demands.

## Alternatives considered

- **Host install with hooks calling broker** — simpler operationally, but loses the L3 (filesystem) and L4 (container hardening) defense layers. Approved Bash commands would have full HOME access, defeating much of the threat model. Rejected for an enterprise pitch.
- **VM (gVisor / Firecracker / qemu)** — stronger isolation than Docker namespaces. Considered for v0.3+ when high-assurance environments demand it. Too heavyweight for v0.1 dev workflow.
- **macOS sandbox-exec / Linux bubblewrap** — host-native sandboxing tools, no container needed. Rejected because :
  - macOS sandbox-exec is [deprecated by Apple](https://developer.apple.com/documentation/security/app_sandbox_design_guide) (still works, but discouraged) ; not present on Linux/Windows
  - bubblewrap is Linux-only
  - Both lack the reproducibility win of Docker
- **WSL2 nested isolation** (Windows-specific) — only one OS ; loses cross-platform.
- **Dev Container Spec (devcontainer.json)** — could leverage VSCode dev container infra. Interesting v0.2+ direction (enables one-click in VSCode), but not foundational.

## References

- Linux kernel namespaces overview — https://man7.org/linux/man-pages/man7/namespaces.7.html
- Docker security best practices — https://docs.docker.com/build/building/best-practices/#security-best-practices
- CIS Docker Benchmark — https://www.cisecurity.org/benchmark/docker
- gVisor (sandboxed runtime) — https://gvisor.dev/
- Implementation : [`Dockerfile.claude-code`](../../Dockerfile.claude-code), [`docker-compose.yml`](../../docker-compose.yml)
- Threat model usage — [`docs/security/threat-model.md`](../security/threat-model.md) §2 (Trust boundary 1)
- Related ADRs : [0006](0006-host-side-broker.md), [0010](0010-network-egress-filter-allowlist.md), [0011](0011-no-secret-baked-in-image.md), [0012](0012-defense-in-depth-layers.md)
