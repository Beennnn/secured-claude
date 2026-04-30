# 35. Bake sidecar configs into the images (close v0.5.3 allow_failure)

Date: 2026-04-30
Status: Accepted (closes the v0.5.3 dated TODO)

## Context

[ADR-0019](0019-l2-egress-proxy-tinyproxy.md) (egress-proxy) and [ADR-0020](0020-l3-dns-allowlist-dnsmasq.md) (dns-filter) shipped with their config files (`docker/tinyproxy.conf`, `docker/tinyproxy-filter.txt`, `docker/dnsmasq.conf`) as **bind-mounts** from the repo into the running container. This worked for local dev — operators could `vim docker/dnsmasq.conf` and restart the sidecar to see changes — but broke v0.5.1 / v0.5.2 / v0.5.3 in CI.

The failure was a Docker-in-Docker file-sharing limitation : the macbook-local runner shares the host's docker daemon, so `docker compose up` runs on the macbook (not inside the CI container). The bind-mount paths reference `/builds/benoit.besson/secured-claude/docker/dnsmasq.conf` — a path that lives inside the CI container's filesystem but doesn't exist on the host. The host daemon refused the mount with `mounts denied: not shared from the host`.

v0.5.3 patched it short-term with `allow_failure: true` + a dated TODO (remove by 2026-05-15). v0.5.4 (this ADR) closes the TODO permanently by baking the configs into the image bytes.

## Decision

Add `COPY` directives in both sidecar Dockerfiles + drop the corresponding bind-mounts from `docker-compose.yml`.

### `Dockerfile.dns-filter`

```dockerfile
RUN apk add --no-cache dnsmasq=2.90-r3
COPY --chmod=0644 docker/dnsmasq.conf /etc/dnsmasq.conf
USER nobody
ENTRYPOINT ["dnsmasq", "-k", "-C", "/etc/dnsmasq.conf"]
```

### `Dockerfile.egress-proxy`

```dockerfile
RUN apk add --no-cache tinyproxy=1.11.2-r0
COPY --chmod=0644 docker/tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY --chmod=0644 docker/tinyproxy-filter.txt /etc/tinyproxy/filter.txt
USER tinyproxy
ENTRYPOINT ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]
```

### `docker-compose.yml`

The `volumes:` blocks for these configs are gone. The defaults that ship in the image apply automatically. Operators who need a per-deployment override (a different DNS allowlist, an extra tinyproxy filter rule, ...) add their own `docker-compose.override.yml` :

```yaml
services:
  dns-filter:
    volumes:
      - ./my-org-dnsmasq.conf:/etc/dnsmasq.conf:ro
```

This is the recommended Docker pattern for "ship sane defaults, allow operator overrides via override file" — used by tons of upstream projects.

### `.gitlab-ci/smoke.yml`

Drops `allow_failure: true` from `smoke:full-stack`. The job now gates the release pipeline as designed since v0.5.0.

## Consequences

**Positive** :
- v0.5.3's dated TODO is closed cleanly. CI smoke:full-stack runs end-to-end without DinD bind-mount workarounds.
- The sidecar images are now **fully self-contained** : pull the image, run, get the v0.5.4-shipped allowlist policy. No external file dependencies.
- Cosign signing covers the configs : the cosign-signed image bytes include the dnsmasq + tinyproxy rules. An operator verifying the signature is verifying the policy bytes too. (v0.3.x's bind-mount approach signed the binary but the policy was a separate file the operator had to trust by some other means.)
- Local dev with no override : edit `docker/dnsmasq.conf`, run `docker compose build dns-filter`, restart. Same workflow, one extra `build` step.

**Negative** :
- Local dev edit-loop is ~5 s slower (rebuild on each config change). Mitigated : config rarely changes, and `compose build` only rebuilds the `COPY` layer (cached underneath).
- Operators who relied on the implicit bind-mount behaviour need to know about `docker-compose.override.yml` for overrides. Documented in the inline comment + ADR.

**Neutral** :
- No code change ; pure container-image / compose / CI yaml. The Cerbos PDP, the broker, the agent — all unchanged.

## Alternatives considered

- **Use `--mount type=bind,bind-propagation=shared` flag** — wouldn't help under DinD (the daemon still doesn't see the CI container's filesystem).
- **Mount the config from a tmpfs that the CI job pre-populates** — works but adds complexity. The COPY-into-image approach is simpler.
- **Keep `allow_failure: true` permanently** — defeats the v0.5 contract that smoke:full-stack gates the release. CLAUDE.md "no allow_failure shields" rule.
- **Move to a separate config-only image (`secured-claude/configs:tag`)** — adds a 5th image to maintain. Not worth the indirection for two text files.

## Verification

- `bin/test-full-stack.sh` (local) → 2/2 PASS without any bind-mount.
- `glab ci lint` → green YAML across 8 included files.
- v0.5.4 tag pipeline expected : 32/32 success (smoke:full-stack now hard-gates per ADR-0035 + this commit).

## References

- [ADR-0019](0019-l2-egress-proxy-tinyproxy.md) — egress-proxy (config-source for tinyproxy.conf / filter.txt)
- [ADR-0020](0020-l3-dns-allowlist-dnsmasq.md) — dns-filter (config-source for dnsmasq.conf)
- [ADR-0033](0033-broker-containerised-for-ci-smoke.md) — broker container + docker-compose.ci.yml overlay
- v0.5.3 commit 156d2c1 — the `allow_failure: true` short-term bridge this ADR closes.
