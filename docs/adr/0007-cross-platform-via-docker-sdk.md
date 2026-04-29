# ADR-0007: Cross-platform via Docker SDK + `host.docker.internal`

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

## Context

Enterprise developer fleets are heterogeneous : Mac (laptop, increasingly Apple Silicon), Linux (engineering workstations, WSL2 inside Windows), and Windows (managed corporate machines, often via Docker Desktop on WSL2 backend).

If secured-claude only runs on one OS, half the team can't use it, and the enterprise pitch dies on day one. We need a single codebase that runs identically on the three.

Constraints :

- **Docker daemon access** — the Docker socket lives at `/var/run/docker.sock` on Mac/Linux but is a named pipe (`npipe:////./pipe/docker_engine`) on Windows. Different protocols, different paths.
- **Container → host networking** — to call our host-side broker from inside the agent container, we need a network alias. Mac and Windows Docker Desktop provide `host.docker.internal` natively. Linux Docker Engine doesn't (until recently).
- **Filesystem paths** — `/Users/...` (Mac), `/home/...` (Linux), `C:\Users\...` (Windows). String concatenation breaks Windows paths immediately.
- **Subprocess invocations** — quoting, environment, executable lookup all differ.
- **Terminal handling** — TTY size propagation, ANSI escape codes, mouse events differ subtly.

## Decision

We adopt the following cross-platform stack :

1. **Docker access** : the `docker` Python SDK (`docker>=7.1.0`) auto-detects the daemon endpoint. No platform-specific code in the broker.
2. **Container → host networking** : `extra_hosts: ["host.docker.internal:host-gateway"]` declared in `docker-compose.yml`. This works on all three platforms — Mac/Windows already provide it natively (the line is a no-op there), Linux gets it via the `host-gateway` alias added in Docker 20.10+. The broker binds `127.0.0.1:8765` so the host port is reachable from the container as `host.docker.internal:8765`.
3. **Paths** : `pathlib.Path` everywhere, no string concatenation, no `os.path.join` with raw `/`.
4. **Data directory** : platform-aware in `_paths.py` :
   - Mac : `~/Library/Application Support/secured-claude/`
   - Linux : `${XDG_DATA_HOME:-~/.local/share}/secured-claude/`
   - Windows : `%LOCALAPPDATA%\secured-claude\`
5. **Subprocess** : `subprocess.run([...args], shell=False)` always (also a security choice — defeats shell-injection, see [bandit B602](https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html)).
6. **Line endings** : `.gitattributes` declares `* text=auto eol=lf` with `*.sh text eol=lf` to keep shell scripts LF on Windows clones too.
7. **Install scripts** : `install.sh` for Mac/Linux (POSIX shell), `install.ps1` for Windows (PowerShell 5+). Same logical flow, OS-specific implementations.
8. **Terminal interaction** : Docker SDK's `tty=True, stdin_open=True` parameters handle TTY allocation cross-platform.

## Consequences

### Positive

- **One codebase, three OS** — no fork per OS, no `if sys.platform == 'darwin'` sprinkled through business logic.
- **Standard tooling** — `pathlib`, `subprocess`, `docker` SDK are well-known, well-tested.
- **Cross-platform CI possible** — Linux runners suffice for the test matrix because the cross-platform abstractions are tested. Manual smoke tests on Mac (host) and Windows (post-release) cover the platform-specific paths.
- **Renovate-friendly** — pinned Docker SDK version updates atomically across all platforms.

### Negative

- **Linux requires Docker 20.10+** — for `host.docker.internal:host-gateway` support. Older Linux distros (Ubuntu 18.04, RHEL 7) ship Docker 19.x. Mitigated by `secured-claude doctor` checking and giving upgrade instructions ; v0.1 documents the minimum requirement.
- **Windows native (no WSL2)** — Docker Desktop on Windows requires WSL2 backend or Hyper-V. We document this as a prerequisite.
- **Mac Apple Silicon vs Intel** — the Claude Code container is built multi-arch via `docker buildx --platform linux/amd64,linux/arm64`. Cerbos has native arm64 ; npm `@anthropic-ai/claude-code` is JS, runtime-agnostic.
- **Path edge cases** — Windows long-path support, Mac case-insensitive FS, Linux ext4 reserved chars — all known tripwires. Mitigated by `pathlib`'s normalization and explicit tests for path edge cases in `tests/test_audit_demo.py::R6` (path traversal) which exercise some of these.

### Neutral

- The `host.docker.internal` mechanism on Linux requires `host-gateway` (a Docker-managed alias). This is documented but obscure. We capture it in [`SECURITY.md`](../../SECURITY.md) and the `secured-claude doctor` output.

## Alternatives considered

- **Pure subprocess + docker CLI** — invoke `docker` binary via subprocess. Works cross-platform but : (a) parsing `docker` CLI output is fragile (output format changes), (b) error handling is messier, (c) no native streaming for `docker run -it`. Rejected.
- **OS-specific install paths** : `~/.secured-claude/` on Mac/Linux, `%APPDATA%\secured-claude\` on Windows — but these don't follow OS conventions (Mac wants `~/Library/Application Support/`, Linux wants XDG, Windows wants `%LOCALAPPDATA%`). Following conventions is more polite to the OS and easier for users to find.
- **Dropping Windows support v0.1** — would simplify but kills enterprise pitch. Rejected.
- **Using `127.0.0.1` directly from container** — only works on Linux with `--network=host`, which defeats network isolation (defeats L2 in [ADR-0010](0010-network-egress-filter-allowlist.md)). Rejected.
- **Per-OS install bundles** (.pkg, .msi, .deb)** — over-engineering for v0.1 ; pipx works fine. Tracked v0.2+ if demand.

## References

- Python `pathlib` — https://docs.python.org/3/library/pathlib.html
- Docker SDK for Python — https://docker-py.readthedocs.io/
- Docker `host.docker.internal` on Linux — https://docs.docker.com/desktop/networking/#i-want-to-connect-from-a-container-to-a-service-on-the-host
- XDG Base Directory Specification — https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
- macOS App Support directory — https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/MacOSXDirectories/MacOSXDirectories.html
- Windows known folders — https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid
- Implementation : [`src/secured_claude/_paths.py`](../../src/secured_claude/_paths.py), [`docker-compose.yml`](../../docker-compose.yml), [`install.sh`](../../install.sh), [`install.ps1`](../../install.ps1)
- Related ADRs : [0005](0005-containerised-claude-code.md), [0006](0006-host-side-broker.md), [0015](0015-distribution-pipx-gitlab-registry.md)
