# 19. L2 HTTP egress proxy (tinyproxy with allowlist)

Date: 2026-04-29
Status: Accepted

## Context

[ADR-0010](0010-network-egress-filter-allowlist.md) established the architectural intent for L2 (network egress allowlist). [ADR-0012](0012-defense-in-depth-layers.md) lists L2 as one of four independent enforcement layers.

In v0.1, L2 was **design-only**. The agent container ran on a custom Docker bridge (`secured-claude-net`), which gave it isolation from other Docker workloads but did not constrain its egress at all. A compromised Claude Code binary could connect to any reachable host on the internet, even if Cerbos (L1) refused the matching tool intent.

The honest scoring in the v0.1 README acknowledged this :

> **L2 — Network egress allowlist** : *design-only — agent has unrestricted internet egress through the docker bridge.*

For "secured by design enterprise" credibility, this gap had to close before any v0.2 release.

## Decision

Add a **`egress-proxy`** sidecar service running **tinyproxy** with `FilterDefaultDeny Yes` and an explicit allowlist of CONNECT destinations. The agent's `HTTPS_PROXY` and `HTTP_PROXY` environment variables point at this sidecar's static IP ; CONNECT requests for any host not on the allowlist receive HTTP 403.

Why **tinyproxy** :
- Single static binary, ~80 KB on disk after install.
- Default-deny via `FilterDefaultDeny Yes` is a one-line config.
- Used in production by Tor relay operators, OpenWRT routers, embedded gateways — has a track record.
- Maintained — alpine 3.20 ships 1.11.2 (released 2024).

Why not **squid** :
- Heavyweight (~25 MB binary, ~50 MB cache directories at runtime).
- Configuration surface 10× larger ; harder to audit.
- Designed for caching + access logging at scale ; we want CONNECT filtering only.

Why not a **custom Python aiohttp proxy** :
- Reinventing wheels = supply-chain risk amplification.
- A future maintainer would need to understand our proxy code instead of a well-known piece of software.
- Audit credibility favours battle-tested tools.

The proxy runs in **CONNECT-only** mode (`ConnectPort 443`, no GET/POST proxying) because the agent's only legitimate egress is HTTPS to the Anthropic API. Plain HTTP and other CONNECT ports (e.g. 22 for SSH-over-HTTPS) are rejected by tinyproxy's port allowlist.

The agent's `NO_PROXY` env var includes `host.docker.internal,localhost,127.0.0.1,172.30.42.0/29` so that :
- The hook's call to the gateway (host.docker.internal:8765) bypasses the proxy — that's local IPC, not egress.
- Container-to-container traffic on the secured-claude-net subnet bypasses the proxy.

The proxy enforces the allowlist via `Filter "/etc/tinyproxy/filter.txt"` (regex per line, default `bre` engine). The current allowlist contains exactly :

```
^api\.anthropic\.com$
^.*\.anthropic\.com$
```

Any addition to this file is a new exfiltration channel for a compromised agent and requires explicit security review.

## Consequences

**Positive — what becomes easier or stronger** :
- L2 is now genuinely enforced at the network layer, not just configured. The README's L2 row flips from `design-only` to `enforced+tested`.
- A compromised Claude Code binary that calls `curl http://evil.com` from inside the container gets HTTP 403 from the proxy before any TCP handshake to evil.com begins.
- The proxy log line `CONNECT  api.anthropic.com:443` is a per-request audit trail that complements the L1 (Cerbos) audit log — a "double-witness" for every egress.
- The allowlist is a checked-in regex file, code-reviewable in a PR. No `cerbos` engine knowledge required to audit it.

**Negative — what becomes harder or riskier** :
- Adds a third sidecar container (was 2 : cerbos + claude-code). The compose file is ~50 lines longer.
- Static IPs in compose mean we no longer get Docker's ephemeral subnet allocation. If the chosen subnet (172.30.42.0/29) collides with an existing Docker network on the host, `docker compose up` fails with `Pool overlaps`. Mitigated by picking a small /29 in a less-trafficked range and documenting the choice.
- The agent must be configured with `HTTPS_PROXY` env var. A future Claude Code release that ignores `HTTPS_PROXY` and uses raw sockets for some calls would silently bypass L2. Mitigated by the audit-demo R-EGRESS-DENIED scenario, which fails the release if the proxy stops blocking evil.com.

**Neutral — trade-offs we accept** :
- The egress-proxy container is **not `read_only`** because apk-installs dnsmasq/tinyproxy at boot (alpine base + `apk add` pattern). Trade-off documented inline in `docker-compose.yml` ; v0.3 ticket : pre-build dns-filter / egress-proxy as their own signed images so we can re-enable read_only.
- Agent latency is bumped by ~1-3 ms per HTTPS request (proxy hop). Imperceptible for an interactive Claude session.

## Alternatives considered

- **iptables / nftables egress filter on the host** — works on Linux but not portably (Mac Docker Desktop has no iptables). Rejected for cross-platform v0.1 ADR-0007.
- **gVisor / Firecracker microVM** — strong isolation but very different operational model (separate kernel per container). Out of scope for v0.2 ; flagged for v0.3+.
- **Anthropic-only egress via dedicated network namespace + hostsfile pin** — could replace the proxy by giving the agent only `api.anthropic.com` in its DNS + nothing else. But still leaves raw-IP egress open (a compromised agent could `curl https://1.2.3.4`). Insufficient.

## Verification

- **In-tree end-to-end test** (this ADR's commit) :
  ```
  $ docker compose up -d dns-filter egress-proxy
  $ docker run --rm --network secured-claude-net alpine:3.20 \
      sh -c "apk add curl >/dev/null && curl -sS --max-time 8 \
        -o /dev/null -w 'http=%{http_code}\n' \
        -x http://172.30.42.4:3128 https://api.anthropic.com/v1/messages"
  http=405          # Anthropic API answered (proxy passed through)

  $ docker run --rm --network secured-claude-net alpine:3.20 \
      sh -c "apk add curl >/dev/null && curl -sS --max-time 6 \
        -x http://172.30.42.4:3128 https://evil.com"
  curl: (56) CONNECT tunnel failed, response 403
  ```
- **Audit-demo scenario R-EGRESS-DENIED** asserts the proxy refuses CONNECT to a non-allowlisted host on every release.
- **Renovate** tracks the alpine base digest + the tinyproxy package version for security updates.

## References

- [ADR-0010](0010-network-egress-filter-allowlist.md) — original L2 design intent (now realised by this ADR)
- [ADR-0012](0012-defense-in-depth-layers.md) — defense-in-depth contract
- [ADR-0020](0020-l3-dns-allowlist-dnsmasq.md) — companion DNS allowlist (closes the residual DNS-leak gap)
- tinyproxy upstream : https://tinyproxy.github.io/
- alpine 3.20 tinyproxy package : https://pkgs.alpinelinux.org/package/v3.20/main/x86_64/tinyproxy
