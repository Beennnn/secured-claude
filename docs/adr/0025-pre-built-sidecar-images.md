# 25. Pre-built sidecar images for dns-filter + egress-proxy (re-enables read_only)

Date: 2026-04-29
Status: Accepted

## Context

[ADR-0019](0019-l2-egress-proxy-tinyproxy.md) (L2 egress proxy) and [ADR-0020](0020-l3-dns-allowlist-dnsmasq.md) (L3 DNS allowlist) introduced two sidecar containers (`egress-proxy`, `dns-filter`) using `alpine:3.20` + `apk add ...` at container boot :

```yaml
egress-proxy:
  image: alpine:3.20@sha256:...
  command:
    - sh
    - -c
    - |
      apk add --no-cache tinyproxy=1.11.2-r0 >/dev/null 2>&1 \
        && exec tinyproxy -d -c /etc/tinyproxy/tinyproxy.conf
```

This worked but couldn't be paired with `read_only: true` because `apk add` writes to `/etc/apk`, `/lib/apk/db`, `/usr`, `/var/cache/apk`. v0.2 documented this as a trade-off : "sidecars are not `read_only` (apk-install pattern) — trade-off documented in ADR-0019."

A reviewer pointed out the gap :

> "Les sidecars DNS/proxy installent encore dnsmasq/tinyproxy au boot via apk, donc pas read_only. C'est documenté comme compromis v0.2, mais c'est moins propre qu'une image prébuildée signée."

Correct. The agent image is `read_only`, has `cap_drop=ALL` minus narrow caps, runs as non-root — full L4 hardening per [ADR-0005](0005-containerised-claude-code.md). The sidecars only had partial L4. **Visual asymmetry that doesn't help the project's "secured by design" pitch.**

## Decision

Pre-build dedicated sidecar images per Dockerfile, push them to the GitLab Container Registry alongside the agent image, and re-enable `read_only: true` in `docker-compose.yml`.

### Two new Dockerfiles

`Dockerfile.dns-filter` :

```dockerfile
FROM alpine:3.20@sha256:d9e8...
RUN apk add --no-cache dnsmasq=2.90-r3
ENTRYPOINT ["dnsmasq", "-k", "-C", "/etc/dnsmasq.conf"]
```

`Dockerfile.egress-proxy` :

```dockerfile
FROM alpine:3.20@sha256:d9e8...
RUN apk add --no-cache tinyproxy=1.11.2-r0
ENTRYPOINT ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]
```

Both are minimal — `FROM alpine + apk add + ENTRYPOINT`, < 30 lines each, < 30 s build time. Pinned by digest per ADR-0008. Renovate's `customManagers` regex in `renovate.json` already tracks the alpine pin + the package versions.

### Two new CI build jobs

`.gitlab-ci/build.yml` adds `build:image:dns-filter` + `build:image:egress-proxy` mirroring the existing `build:image` pattern :

- Same Kaniko base image (`gcr.io/kaniko-project/executor:v1.23.2-debug`).
- Same `--customPlatform=linux/amd64` enterprise default.
- Same caching strategy (per-image cache repo).
- Same destination tag scheme (`:${CI_COMMIT_SHA}`, `:${CI_COMMIT_TAG}`, `:latest`).

### compose changes

```yaml
dns-filter:
  build:                                    # local fallback
    context: .
    dockerfile: Dockerfile.dns-filter
  image: secured-claude/dns-filter:0.3.0    # registry tag
  read_only: true                           # ← restored
  tmpfs:
    - /tmp:rw,nosuid,nodev,size=8m
    - /run:rw,nosuid,nodev,size=8m
    - /var/run:rw,nosuid,nodev,size=8m
  cap_drop: [ALL]
  cap_add:
    - NET_BIND_SERVICE   # bind port 53
    - SETUID + SETGID + CHOWN  # dnsmasq drops to internal user

egress-proxy:
  build:
    context: .
    dockerfile: Dockerfile.egress-proxy
  image: secured-claude/egress-proxy:0.3.0
  read_only: true                           # ← restored
  tmpfs:
    - /tmp:rw,nosuid,nodev,size=8m
    - /var/log/tinyproxy:rw,nosuid,nodev,size=16m
    - /run/tinyproxy:rw,nosuid,nodev,size=4m
  cap_drop: [ALL]
  cap_add:
    - SETUID + SETGID + CHOWN
```

The `build:` directive ensures `docker compose up` works locally without registry pull (dev usage). The `image:` directive matches what CI pushes, so `docker compose pull` works for users who want pre-built artefacts.

### Cosign signing — deferred to v0.3.1

The agent image is signed (cosign keyless OIDC ; [ADR-0016](0016-supply-chain-cosign-sbom.md)). Adding 2 more sign jobs for sidecars is straightforward but adds CI runtime. Deferred to v0.3.1 with ADR amendment.

Rationale for the deferral : the agent is the high-value attack surface (it runs the LLM logic + every tool call goes through it). Sidecars are minimal alpine + a single binary + a read-only config volume — even a hypothetical compromise has narrow blast radius (the proxy can't see request bodies, the DNS resolver can't access /workspace). Signing them is good supply-chain hygiene but lower priority than the agent.

## Consequences

**Positive** :
- Sidecars now have full L4 parity with the agent : `read_only: true`, `cap_drop=ALL` minus narrow caps, `no_new_privileges`, `mem_limit`. Verified by `docker inspect` showing `ReadonlyRootfs=true` for both containers.
- No more apk-install-at-boot pattern. Sidecar startup is < 1 s (pull-from-registry then start) vs ~3-5 s (alpine + apk install) in v0.2.
- The `secured by design` pitch is now consistent across all 3 containers — same hardening profile, same digest-pin discipline, same supply-chain-tracked dependencies.
- The "configured but NOT yet enforced" table can flip the sidecar `read_only` row from pending to done in v0.3.

**Negative** :
- 2 more CI build jobs on every pipeline. Each is ~30 s on the macbook-local runner ; net pipeline time bumps by ~1 minute (jobs run in parallel where possible).
- 2 more images to pull on first `docker compose up`. Each is < 10 MB (alpine + binary). Negligible vs the ~500 MB Claude Code agent image.

**Neutral** :
- Local dev workflow unchanged thanks to `build:` directive — users without registry access still get a working stack.
- v0.3.1 will sign the sidecar images via additional cosign jobs (incremental polish, not blocking).

## Alternatives considered

- **Use `chainguard/dnsmasq` + `chainguard/tinyproxy` distroless images** — Chainguard ships hardened, signed, low-CVE Wolfi-based images. Real value but : (a) introduces a new vendor + supply chain to audit, (b) Chainguard images can ship breaking changes more often than alpine pins, (c) we lose the simplicity of "everything's alpine 3.20." Rejected for v0.3 ; revisitable if the project goes commercial.
- **Keep the apk-install-at-boot pattern, accept partial L4** — v0.2 status quo. Reviewer flagged as not clean. Rejected.
- **Compile dnsmasq + tinyproxy from source statically with musl** — full control, smaller image, but compilation is non-trivial and we'd own a CVE-tracking burden. Rejected ; we trust alpine's package maintainers.

## Verification

- `docker compose build dns-filter egress-proxy` → both images build < 30 s.
- `docker compose up -d dns-filter egress-proxy` → both healthy in < 10 s.
- `docker inspect secured-claude-dns secured-claude-egress --format '{{.HostConfig.ReadonlyRootfs}}'` → returns `true true`.
- `bash bin/test-egress.sh` → 4/4 PASS (L2 + L3 still enforce as designed).
- CI build:image:dns-filter + build:image:egress-proxy → both green on dev pipeline.

## References

- [ADR-0005](0005-containerised-claude-code.md) — agent's L4 hardening profile (the parity target)
- [ADR-0008](0008-pin-upstream-images-and-deps.md) — "pin every upstream" contract
- [ADR-0016](0016-supply-chain-cosign-sbom.md) — cosign keyless signing for the agent (sidecars : v0.3.1)
- [ADR-0019](0019-l2-egress-proxy-tinyproxy.md) — egress-proxy ; v0.2 trade-off this ADR resolves
- [ADR-0020](0020-l3-dns-allowlist-dnsmasq.md) — dns-filter ; same v0.2 trade-off
- Reviewer feedback that triggered this ADR : "Points faibles restants" critique 2026-04-29
