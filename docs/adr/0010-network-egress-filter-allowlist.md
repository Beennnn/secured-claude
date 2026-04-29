# ADR-0010: Network egress filter — allowlist at Docker network layer

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

## Context

The PreToolUse hook ([ADR-0002](0002-pretooluse-hook-as-interception-point.md)) intercepts tool *intents*, not raw syscalls. So if Cerbos approves a Bash command like `npm install`, the underlying `npm` binary can :

- Open network connections to anywhere it wants (registry, post-install scripts)
- Resolve any DNS name
- Make any HTTP request

This means : a compromised npm package, an unexpected post-install script, or a `Bash`-launched process that does network operations is invisible to L1 (the application-level hook). We need a second layer that doesn't depend on the agent's cooperation.

OWASP [A10:2021 SSRF](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/) and the [MITRE ATT&CK M1030 (Network Segmentation)](https://attack.mitre.org/mitigations/M1030/) both call for network-layer enforcement, not just application-layer.

## Decision

The Claude Code container joins a **dedicated Docker network** (`secured-claude-net`) with **egress allowlist** at the network layer. Only the following destinations are reachable from inside the container :

- `api.anthropic.com` (TLS 443) — the legitimate Claude API endpoint
- `host.docker.internal:8765` — the broker gateway on the host
- DNS resolver provided by Docker (for the two above) — restricted to allowlisted names in v0.2

Implementation tactics by platform :

| Platform | Mechanism |
|---|---|
| **Linux Docker Engine** | Custom Docker network (`bridge` driver) + iptables rules on the host : `iptables -I FORWARD -s <container_subnet> -d <allowed_ips> -j ACCEPT ; iptables -I FORWARD -s <container_subnet> -j DROP` |
| **Docker Desktop (Mac/Win)** | Docker Desktop's network filter via the VM. Same allowlist but managed via Docker Desktop's settings (or vpnkit network policy in newer versions). v0.1 documents the manual setup ; v0.2 ships an installer that configures it. |
| **Future v0.2** | A sidecar HTTP CONNECT proxy (e.g. `tinyproxy` or custom Go) inside the container's network namespace, with allowlist of host:port pairs. Container `HTTP_PROXY=http://localhost:3128`. Simpler than iptables, OS-portable. |

The allowlist is small and explicit. Adding a domain requires :

1. PR to `policies/network.yaml` (Cerbos L1) AND
2. PR to `docker-compose.yml` / install script (L2 network rule) AND
3. ADR justifying why this domain is needed

## Consequences

### Positive

- **Independent of L1** — defeats the "approved Bash command does network anyway" attack class. Even if a hostile prompt convinces Cerbos to approve `Bash npm install`, npm cannot reach `evil.com`.
- **Defense-in-depth aligned** with NIST SP 800-160 V1 §3.4 — orthogonal layers means compromising one doesn't compromise the other.
- **Reduces blast radius of upstream CVEs** — a hypothetical Claude Code binary backdoor can only exfil to `api.anthropic.com` (already trusted) or `host.docker.internal:8765` (broker, which logs everything).
- **MITRE ATT&CK M1030** (Network Segmentation) — directly implemented.
- **OWASP A10 SSRF** — even if a tool input attempts to fetch internal IPs, the network layer denies it independently of URL canonicalization in policy.

### Negative

- **Linux iptables setup is OS-specific** — requires root or `setcap` on `iptables`, complicates the install. Mitigated by : (a) `install.sh` handles it via `sudo` with explicit prompt, (b) v0.2 sidecar proxy approach is OS-portable and rootless.
- **DNS leak risk** (v0.1 residual) — the container can resolve any DNS name even if connection is blocked. An adversary can encode data into DNS queries. Tracked as residual risk R-DNS-LEAK in [threat-model.md](../security/threat-model.md). v0.2 mitigation : dnsmasq sidecar with allowlist.
- **Adding a new allowed domain is a 3-step PR** — friction is by design, not a bug. Forces review.
- **`api.anthropic.com` IP changes** — Anthropic uses CloudFront ; IP set rotates. Mitigated by allowlisting at the DNS-resolution layer, not raw IP. The DNS resolver itself is constrained.

### Neutral

- We accept that the agent container has network access at all. A "no network at all" container would break Claude Code (it must reach `api.anthropic.com` to get model responses).

## Alternatives considered

- **No L2** (rely on L1 hook only) — strictly weaker. Bash commands that pretend to be benign (`npm install`, `git clone`) can carry malicious post-install scripts that exfil. Rejected.
- **VPN routing** (force all egress through a known proxy on the corporate VPN) — works in a managed enterprise context, but doesn't apply for individual dev machines. Out of scope v0.1.
- **Host firewall** (`ufw`, `pf`, Windows Firewall) — could enforce per-process egress but : (a) hard to make "only the agent container" rules without complex matching, (b) doesn't survive Docker Desktop NAT'ing. Rejected.
- **eBPF-based network policy** (Cilium, Falco) — powerful but Linux-only and requires kernel features ; over-engineering for v0.1. Tracked v0.3+.
- **Disallow network entirely, route Anthropic API through host broker** (broker fetches on behalf of agent) — adds complexity, makes streaming responses tricky, and exposes the broker to API-level abuse. Rejected.

## References

- OWASP A10:2021 SSRF — https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- MITRE ATT&CK M1030 (Network Segmentation) — https://attack.mitre.org/mitigations/M1030/
- NIST SP 800-160 V1 §3.4 (Defense-in-depth) — https://csrc.nist.gov/publications/detail/sp/800-160/vol-1-rev-1/final
- Docker network drivers — https://docs.docker.com/engine/network/drivers/
- Implementation : [`docker-compose.yml`](../../docker-compose.yml) (`networks:` + `extra_hosts:` + `internal: true` once allowlist proxy is up)
- Threat model usage — [`docs/security/threat-model.md`](../security/threat-model.md) §6 AT-2 (compromised npm dep) and AT-4 (network exfil)
- Related ADRs : [0005](0005-containerised-claude-code.md) (container hardening), [0012](0012-defense-in-depth-layers.md) (4 layers)
