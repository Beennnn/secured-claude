# ADR-0012: Defense-in-depth — 4 independent layers

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

## Context

A common security failure pattern in agentic AI tools : a single point of enforcement (a hook, a policy file, a sandbox flag) that, once bypassed, leaves the entire system unprotected. Examples in the wild :

- LLM jailbreaks that convince a single-layer "harmlessness filter" to comply with malicious requests.
- Container escapes that bypass per-tool denylists but find no further controls.
- Network egress restrictions that fail open when the policy daemon crashes.

For an enterprise pitch, the security review will ask : "what happens if your <key component> is compromised ?". The answer cannot be "it's broken." It must be "the next layer catches it."

[NIST SP 800-160 Volume 1, §3.4](https://csrc.nist.gov/publications/detail/sp/800-160/vol-1-rev-1/final) formalizes this principle : "use multiple, independent layers of security, where the failure of any one layer does not compromise the entire system." Saltzer & Schroeder (1975) called it "complete mediation" — every access must be checked, ideally by independent mechanisms.

## Decision

secured-claude implements **four independent defense layers**, each with a distinct mechanism, mitigating a distinct threat class. **Each layer is, on its own, sufficient to block the class of attack it covers**, so compromising one does not compromise the system.

| Layer | Mechanism | Mitigates | ADR | Implementation |
|---|---|---|---|---|
| **L1 — Application (intent)** | PreToolUse hook → Cerbos PDP `CheckResources` → `permissionDecision` | Tool-intent abuse (Read sensitive paths, dangerous Bash, MCP exploitation, WebFetch to non-allowlisted) | [0001](0001-cerbos-as-policy-decision-point.md), [0002](0002-pretooluse-hook-as-interception-point.md), [0003](0003-default-deny-for-shell-network-mcp.md), [0009](0009-hook-fails-closed.md) | `policies/`, `src/secured_claude/{hook,gateway,cerbos_client}.py` |
| **L2 — Network egress** | Docker network with allowlist (`api.anthropic.com`, broker only) | Data exfiltration / C2 via syscall-level network from inside an approved Bash | [0010](0010-network-egress-filter-allowlist.md) | `docker-compose.yml` networks + iptables/proxy |
| **L3 — Filesystem confinement** | Container `/workspace` mount only, host FS invisible | Lateral access to host secrets (`~/.ssh`, `~/.aws`, `.env`, browser data) | [0005](0005-containerised-claude-code.md) | `Dockerfile.claude-code` + `docker-compose.yml` volumes |
| **L4 — Container hardening** | Non-root UID, read-only root FS, `cap-drop=ALL`, default seccomp profile, cgroup limits | Kernel-side privilege escalation, syscall abuse | [0005](0005-containerised-claude-code.md) | `Dockerfile.claude-code` USER directive + `docker-compose.yml` security_opt + read_only |

Compose file fragment showing layered defense :

```yaml
services:
  claude-code:
    image: $CI_REGISTRY_IMAGE/claude-code:vX.Y.Z@sha256:...
    user: "1000:1000"            # L4: non-root
    read_only: true              # L4: read-only rootfs
    cap_drop: [ALL]              # L4: drop all capabilities
    security_opt:
      - no-new-privileges:true   # L4
      - seccomp:default          # L4: default seccomp
    networks: [secured-claude-net]  # L2
    volumes:
      - ./:/workspace:rw         # L3: only /workspace
      - claude-state:/home/agent/.claude:rw  # L3: ephemeral, not host HOME
    extra_hosts:
      - host.docker.internal:host-gateway  # for L1 hook
    environment:
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}  # ADR-0011: runtime only
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2'              # L4: cgroup limits
networks:
  secured-claude-net:
    driver: bridge
    internal: false              # need egress to api.anthropic.com (L2 allowlist enforced via egress proxy in v0.2 ; iptables in v0.1 Linux)
```

## Consequences

### Positive

- **No single point of failure** — every threat in the threat model is mitigated by ≥ 2 layers ; most by 3+.
- **Compromise isolation** — even if Cerbos has a CVE, network and FS isolation hold ; even if container escape happens, the host is protected (in principle — see residual risks).
- **Pitch credibility** — when a security expert asks "what if X is bypassed ?", we have a concrete answer per X.
- **Maps to NIST SP 800-160 V1 §3.4 (Defense in depth)** and **NIST CSF 2.0 PR.AC**.
- **Maps to MITRE ATT&CK** : multiple Mitigations (M1018, M1026, M1030, M1038, M1042, M1047) collectively implemented.
- **Each layer can be tested independently** — `tests/test_audit_demo.py::R1` exercises L1 ; container-escape attempts are out of scope but L4 hardening is verified by `docker inspect` showing the flags ; L2 by network exfil tests in audit-demo.

### Negative

- **More moving parts** — 4 layers means 4 things to keep working. Mitigated by : (a) automated audit-demo on every release, (b) `secured-claude doctor` validates each layer, (c) regression tests per layer.
- **Higher operational complexity** — install requires Docker + network config + image pull + key setup. Mitigated by `install.sh` / `install.ps1` automating the lot.
- **Configuration drift risk** — a future change might inadvertently weaken one layer. Mitigated by : (a) hard-coded `--read-only --user --cap-drop=ALL` in the compose file, (b) hadolint enforces user-not-root in Dockerfile, (c) audit-demo would fail if a layer regresses.

### Neutral

- We accept that v0.1 doesn't address kernel CVEs (residual risk R-KERNEL-CVE in threat model). gVisor / Firecracker tracked v0.3+.

## Alternatives considered

- **One strong layer** — e.g. only do gVisor isolation, skip the application-level Cerbos. Higher per-layer assurance, but : (a) gVisor isn't cross-platform (Linux-only), (b) no audit log of "intents", just a wall of syscalls — useless for compliance, (c) one CVE in gVisor and everything is gone. Rejected.
- **Two layers** (e.g. just hook + container) — acceptable but weaker. The "approved Bash → npm install → exfil via curl in postinstall" attack passes hook, fails container only on FS not on network. We'd be vulnerable to network exfil. Rejected.
- **Five+ layers** — diminishing returns, increasing complexity. Considered : adding eBPF process tracing (L5) ; tracked v0.3+ if user feedback demands.

## References

- NIST SP 800-160 V1 §3.4 (Defense in depth) — https://csrc.nist.gov/publications/detail/sp/800-160/vol-1-rev-1/final
- Saltzer & Schroeder, "The Protection of Information in Computer Systems" (1975) — https://www.cs.virginia.edu/~evans/cs551/saltzer/
- NIST CSF 2.0 PR.AC (Identity Management, Access Control) — https://www.nist.gov/cyberframework
- MITRE ATT&CK Mitigations index — https://attack.mitre.org/mitigations/enterprise/
- Threat model — [`docs/security/threat-model.md`](../security/threat-model.md) (entire doc, especially §3 trust boundaries and §6 attack trees)
- Controls matrix — [`docs/security/controls-matrix.md`](../security/controls-matrix.md)
- Related ADRs : [0001-0011](.) — every other ADR contributes to one of the four layers
