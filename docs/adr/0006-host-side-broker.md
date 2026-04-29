# ADR-0006: Host-side broker, not container-side

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

## Context

The broker is the component that : (a) orchestrates the Cerbos + Claude Code containers, (b) hosts the FastAPI gateway that the PreToolUse hook calls, (c) writes the SQLite audit log, (d) runs the CLI subcommands (`up`, `down`, `audit`, etc.).

Where should this broker live ?

1. **Host-side** — runs as a Python process on the developer machine.
2. **Container-side** — runs as a third container alongside Cerbos + Claude Code.

The user's stated requirement was "deux conteneurs Docker" (two containers), so the broker as a third container would already break the spec. But beyond that, there are deeper reasons.

## Decision

The broker runs **on the host** as a Python process (started by `secured-claude up`, daemonized to bind `127.0.0.1:8765`).

Architecture :

```
HOST                                  DOCKER (network: secured-claude-net)
┌─────────────────────┐              ┌────────────────────────────┐
│ broker (Python)     │              │ ┌──────────────────┐       │
│  - orchestrator     │ Docker SDK   │ │ cerbos PDP       │       │
│  - gateway :8765    │ ←──────────  │ └──────────────────┘       │
│  - SQLite audit DB  │              │ ┌──────────────────┐       │
│  - cerbos client    │ HTTP localhost│ │ Claude Code +    │       │
└─────────────────────┘              │ │ PreToolUse hook  │ ←─── HTTP
        ↑                            │ └────────┬─────────┘  → broker
   user terminal                     └──────────┼────────────────┘
                                                │
                                  host.docker.internal:8765
```

The hook in the agent container reaches the host broker via `host.docker.internal:8765` (built-in on Mac/Windows ; declared via `extra_hosts: ["host.docker.internal:host-gateway"]` in `docker-compose.yml` for Linux compatibility).

## Consequences

### Positive

- **Trust boundary clarity** — the broker is the trust authority ; the agent container is *untrusted by construction*. If the LLM is jailbroken, it can attempt to abuse the gateway endpoint, but the gateway validates every request against Cerbos. The agent CANNOT modify the policies, the audit DB, or the broker code.
- **Path resolution accuracy** — when the hook reports `Read /workspace/foo`, the broker can resolve this to the *real host path* (the user's project dir) and apply policies based on the actual location. A container-side broker would only see `/workspace` paths.
- **Audit DB host-side** — the SQLite DB lives on the host, in the OS data dir. The agent container has no FS access to it ([ADR-0005](0005-containerised-claude-code.md) §"Filesystem confinement"). Tamper-resistant.
- **Lifecycle ownership** — the broker manages container start/stop. If the broker were containerised, it'd need Docker socket access (= root-equivalent on Linux), which is a significant attack surface to expose to a container that itself is co-located with an untrusted agent.
- **Cross-OS Docker SDK** — Python `docker` SDK handles named pipe (Windows) / unix socket (Mac/Linux) transparently, so the broker is one codebase.
- **Easy debugging** — broker logs go to host stdout/file ; no `docker logs` needed.

### Negative

- **Two execution contexts** — the broker runs on host, hook runs in container ; latency (~1-3 ms) for the cross-boundary HTTP call is unavoidable. Acceptable.
- **Host has Python 3.11+ requirement** — adds a dep to the developer's host. Mitigated : Python is ubiquitous, install instructions cover the 3 OS, `pipx` isolates the install.
- **Two `host.docker.internal` configurations** — Mac/Windows native, Linux explicit. Mitigated by `extra_hosts` declaration in compose works on all 3.

### Neutral

- The CLI lives in the same Python process as the broker (one process, multiple subcommands). Considered separating CLI from daemon — too much ceremony for v0.1.

## Alternatives considered

- **Broker as a third container** — would require :
  - Mounting the host Docker socket into the broker container (security smell)
  - Resolving host paths from inside a container (clumsy)
  - Networking the audit DB volume between broker container and host
  Adds complexity without security benefit, and breaks the user's "deux conteneurs" spec. Rejected.
- **Broker inside the Claude Code container** — co-locating the gateway and the agent in one trust zone defeats the entire defense-in-depth premise. The whole point is the gateway is OUTSIDE the agent's reach. Rejected.
- **Broker as a daemon launched by systemd / launchd** — adds OS-specific service registration. v0.2+ may add this for "always-on" enterprise deploys. v0.1 daemonizes manually via `nohup` / Python `multiprocessing.Process`.
- **Broker as a binary (PyInstaller / Nuitka)** — would remove the Python runtime requirement on host. Considered for v0.3+ if user feedback demands it ; v0.1 keeps the Python dep for simplicity.

## References

- Docker socket security risks — https://docs.docker.com/engine/security/protect-access/
- Implementation : [`src/secured_claude/orchestrator.py`](../../src/secured_claude/orchestrator.py), [`src/secured_claude/gateway.py`](../../src/secured_claude/gateway.py)
- Cross-platform paths : [`src/secured_claude/_paths.py`](../../src/secured_claude/_paths.py)
- Threat model — [`docs/security/threat-model.md`](../security/threat-model.md) §3 (Trust boundary 1)
- Related ADRs : [0005](0005-containerised-claude-code.md), [0007](0007-cross-platform-via-docker-sdk.md), [0009](0009-hook-fails-closed.md)
