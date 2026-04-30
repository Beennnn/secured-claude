# 36. Bake Cerbos policies into a custom image (close v0.5.4 smoke regression)

Date: 2026-04-30
Status: Accepted

## Context

[ADR-0035](0035-bake-sidecar-configs.md) (v0.5.4) baked the dns-filter + egress-proxy configs into their images, dropping bind-mounts of `docker/dnsmasq.conf` and `docker/tinyproxy.conf`. The CI smoke:full-stack still failed because `cerbos` had ITS own bind-mounts that I missed in v0.5.4 :

```yaml
cerbos:
  image: cerbos/cerbos:0.42.0@sha256:...
  volumes:
    - ./policies:/policies:ro
    - ./cerbos/config.yaml:/etc/cerbos/config.yaml:ro
```

Same Docker-in-Docker limitation : the macbook-local runner shares the host daemon, so `/builds/.../policies` paths from the CI container aren't visible to the host. The cerbos service refused to start :

```
Error response from daemon: mounts denied:
The path /builds/benoit.besson/secured-claude/policies is not shared
from the host and is not known to Docker.
```

## Decision

Same pattern as ADR-0035 — bake policies + config into a **custom Cerbos image** (`Dockerfile.cerbos`) that wraps the upstream `cerbos/cerbos:0.42.0` :

```dockerfile
FROM cerbos/cerbos:0.42.0@sha256:4302b6ce...
COPY policies /policies
COPY cerbos/config.yaml /etc/cerbos/config.yaml
# ENTRYPOINT/CMD inherited from upstream
```

Update `docker-compose.yml` cerbos service :
- `image: ${CI_REGISTRY_IMAGE:-secured-claude}/cerbos:${CI_COMMIT_SHA:-0.5.5}` — pull from registry in CI, fall back to `secured-claude/cerbos` locally.
- `build: { context: ., dockerfile: Dockerfile.cerbos }` — local fallback when registry image isn't pulled.
- Drop the `volumes:` block.

CI :
- Add `build:image:cerbos` (amd64) + `build:image:cerbos:arm64` jobs (same Kaniko + customPlatform pattern as the others).
- Update `build:image:manifest` to combine 5 images now (was 4 in v0.5.1).
- Add `publish:cosign-sign:cerbos` job.

The 5th image now goes through the same supply-chain pipeline as the agent + 3 sidecars + broker. **Cosign signing covers the policy bytes**, not just the cerbos binary — operators verifying `registry.gitlab.com/.../cerbos:v0.5.5` get a signed bundle that includes the dnsmasq + tinyproxy + cerbos rules across all 5 images.

## Consequences

**Positive** :
- v0.5.4's regression closed. smoke:full-stack now boots all 4 sidecars + agent without ANY bind-mount.
- 5th image cosign-signed → policy supply-chain story is complete.
- Local dev unchanged : `docker compose up` triggers a `docker compose build cerbos` if the image isn't cached. Edit `policies/foo.yaml`, rebuild cerbos service, restart.

**Negative** :
- 5th image to maintain (Renovate now tracks 5 base-image digests + 5 cosign sign jobs).
- Per-tag pipeline adds ~1 min for the cerbos build (small image, but Kaniko has overhead).

**Neutral** :
- The upstream `cerbos/cerbos:0.42.0` digest pin still applies — just inside our wrapping Dockerfile.
- ADR-0001 (Cerbos as PDP) unchanged ; same binary, same protocol, same audit log.

## Alternatives considered

- **`volumes: !reset` in docker-compose.ci.yml** — compose v2.16+ feature ; not reliably available across CI runner versions. Rejected.
- **Pre-populate a named volume from a ConfigMap-style image** — adds an init container + volume orchestration. More moving pieces than the COPY pattern. Rejected.
- **Pre-stage the policies in `/tmp` (which Mac Docker Desktop shares by default)** — fragile (depends on the runner's shared paths) + per-CI-run cleanup. Rejected.
- **Permanent `allow_failure: true`** — defeats the v0.5 contract. CLAUDE.md "no shields" rule. Rejected.

## Verification

- `bin/test-full-stack.sh` (local) → 2/2 PASS without any bind-mount on any service.
- `glab ci lint` → green YAML across 8 included files.
- v0.5.5 tag pipeline expected : 34/34 (was 32 in v0.5.4 — +2 cerbos build jobs + 1 cosign sign).

## References

- [ADR-0001](0001-cerbos-as-policy-decision-point.md) — Cerbos PDP rationale ; this image is the same binary
- [ADR-0008](0008-pin-upstream-images-and-deps.md) — pin every upstream ; the Dockerfile.cerbos `FROM` line keeps the digest pin
- [ADR-0033](0033-broker-containerised-for-ci-smoke.md) — broker containerised pattern this ADR mirrors
- [ADR-0035](0035-bake-sidecar-configs.md) — sibling ADR (dns-filter + egress-proxy)
