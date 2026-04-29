# 28. True multi-arch images via Kaniko + crane index append

Date: 2026-04-29
Status: Accepted

## Context

[ADR-0008](0008-pin-upstream-images-and-deps.md) requires every upstream image digest-pinned. v0.2.0 honoured this for Kaniko's Dockerfile build, but the `build:image` job ran on the macbook-local runner (arm64 Apple Silicon) and **without `--customPlatform=linux/amd64`** the resulting image was tagged with `architecture: arm64` only — invisible until the v0.2.0 release was inspected with `docker manifest inspect`. Enterprise users on amd64 (Intel/AMD desktops, GKE, EKS, AKS) hit `exec format error` unless they ran the image with `--platform linux/amd64` (which routes through QEMU emulation for every syscall).

v0.2.1 patched this by pinning Kaniko's build to `--customPlatform=linux/amd64`. amd64 users got native binaries, but the trade-off flipped : arm64 users (Apple Silicon dev fleets, AWS Graviton production) now ran amd64 images via QEMU. Both v0.2.x and v0.3.x README's "configured but NOT yet enforced" table tracked **true multi-arch (manifest list with both linux/amd64 + linux/arm64)** as a v0.3+ ticket.

The reviewer flagged this as a residual quality gap several times. v0.3.1 closed every other v0.3 deferred item — multi-arch was the last v0.3+ debt left.

## Decision

Build **per-arch images in parallel via Kaniko** + **combine into a manifest-list via `crane index append`**. The canonical `:${TAG}` (and `:${SHA}`) tags become **manifest indices** that reference both per-arch single-arch manifests. Docker / containerd / Podman runtime selects the right manifest automatically based on the host's architecture.

### Pipeline structure (tag pipeline)

```
build:image                  →  ${REG}/claude-code:${SHA}-amd64 + :${TAG}-amd64 + :${SHA} + :${TAG}
build:image:arm64            →  ${REG}/claude-code:${SHA}-arm64 + :${TAG}-arm64
build:image:dns-filter       →  same pattern
build:image:dns-filter:arm64
build:image:egress-proxy
build:image:egress-proxy:arm64
                              ↓ (all 6 in parallel, ~5-12 min wall time)
build:image:manifest         →  crane index append :SHA-amd64 + :SHA-arm64 → :SHA (multi-arch index)
                              →  crane index append :TAG-amd64 + :TAG-arm64 → :TAG (multi-arch index)
                              →  per image (3 of them)
publish:cosign-sign:*        →  cosign sign :TAG (the index ; signature covers both arches per cosign-on-manifest-list semantics)
```

### Pipeline structure (dev / MR / main)

The arm64 builds + manifest combiner are **tag-only** (per their `rules:`). Dev iteration loops stay amd64-only, saving ~5-10 minutes per dev pipeline. Main pipelines also stay amd64-only — the multi-arch index only matters on the canonical release tag.

The amd64 build job pushes the canonical `:${SHA}` (no suffix) and `:latest` (main only) directly, so :
- pre-v0.4 consumers (`docker pull ${REG}/claude-code:${SHA}`) get an amd64 image as before.
- post-v0.4 tag consumers (`docker pull ${REG}/claude-code:v0.4.0`) get a multi-arch index and the runtime resolves the right arch.

### Why this layout

- **No buildx / DinD / privileged runner.** Kaniko is daemonless ; same supply-chain story as v0.2-v0.3.
- **No QEMU emulation in CI.** arm64 builds run NATIVELY on the macbook-local runner. amd64 builds run with `--customPlatform=linux/amd64` which is a Kaniko-internal flag (no kernel emulation needed for the build itself, just for `RUN` commands inside the Dockerfile — and the macbook host's binfmt_misc handles that).
- **`crane index append`** is a single Go binary (~10 MB) from go-containerregistry. Pinned by version, downloaded in alpine. Supply-chain is "alpine + curl + crane".

### Cosign-signing semantics

When you `cosign sign ${REG}/claude-code:v0.4.0` and the tag points at a manifest-list :
- Cosign signs the **index manifest**'s digest (not any single arch).
- `cosign verify` against the same tag succeeds for any arch the verifier picks (containerd / Docker resolves arch first, then cosign checks the index signature).

So the existing 3 cosign-sign jobs (agent + dns-filter + egress-proxy) cover both arches without modification — they just need to depend on `build:image:manifest` instead of the per-image build directly.

## Consequences

**Positive** :
- Apple Silicon dev fleets + AWS Graviton production get native arm64 — no QEMU overhead at runtime.
- amd64 users (intel/AMD desktops, GKE/EKS/AKS) keep their native experience.
- The "secured by design" pitch is now consistent across architectures : same image bytes (per-arch), same cosign signature on the index, same SBOM.
- Pre-v0.4 consumers don't break — `:${TAG}` (and `:${SHA}`) still resolve, just to an index now. Container runtimes handle this transparently.

**Negative** :
- Tag pipelines do 6 image builds + 1 manifest combine (was 3 builds). Wall-time bumps by ~3-5 minutes (arm64 builds run in parallel with amd64, but the combiner adds a serial step at the end).
- `build:image:manifest` introduces a new dependency : if `crane` upstream changes its CLI, the combiner breaks. Mitigated by pinning `CRANE_VERSION`.

**Neutral** :
- The per-arch tags (`:${SHA}-amd64`, `:${SHA}-arm64`, `:${TAG}-amd64`, `:${TAG}-arm64`) are intermediate artefacts. They stay in the registry as a debugging aid (you can `docker pull --platform linux/amd64 :v0.4.0` OR explicitly `docker pull :v0.4.0-amd64` to skip the manifest resolver) — small storage overhead, useful for forensics.

## Alternatives considered

- **buildx + QEMU + DinD on a privileged runner** — works but requires a privileged runner (security compromise) and QEMU emulation for cross-arch builds (4-10x slowdown on the cross arch). The macbook-local arm64 runner running QEMU-amd64 was the v0.2.0 → v0.2.1 fix ; we don't want to multiply that pattern.
- **Two parallel runners (amd64 + arm64)** — provisioning a second physical/cloud runner for arm64. Real engineering effort + ongoing cost. The macbook-local runner already handles arm64 natively ; we don't need a second runner for v0.4.
- **Skip multi-arch (v0.3.1 status quo)** — what reviewers flagged as still-deferred. Rejected for v0.4.

## Verification

After v0.4.0 tag pipeline goes green :

```bash
$ docker manifest inspect registry.gitlab.com/benoit.besson/secured-claude/claude-code:v0.4.0 \
    | jq '.manifests[] | {arch: .platform.architecture, os: .platform.os}'
{"arch": "amd64", "os": "linux"}
{"arch": "arm64", "os": "linux"}

$ # Pull on Apple Silicon — gets arm64 native, no QEMU :
$ docker run --rm registry.gitlab.com/.../claude-code:v0.4.0 uname -m
aarch64

$ # Pull on amd64 — gets native amd64 :
$ docker run --rm registry.gitlab.com/.../claude-code:v0.4.0 uname -m
x86_64

$ # Cosign verify works for both — signature covers the index :
$ cosign verify ${REG}/claude-code:v0.4.0 \
    --certificate-identity-regexp '^https://gitlab.com/benoit.besson/secured-claude' \
    --certificate-oidc-issuer https://gitlab.com
Verification for ... -- The following checks were performed:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The code-signing certificate was verified using trusted certificate authority certificates
```

## References

- [ADR-0008](0008-pin-upstream-images-and-deps.md) — pin every upstream (the contract that v0.1.x silently broke for arch)
- [ADR-0016](0016-supply-chain-cosign-sbom.md) — cosign keyless OIDC ; covers both arches once the index is signed
- [ADR-0025](0025-pre-built-sidecar-images.md) — sidecar images ; this ADR makes them multi-arch alongside the agent
- crane index append : https://github.com/google/go-containerregistry/blob/main/cmd/crane/doc/crane_index_append.md
- OCI image index spec : https://github.com/opencontainers/image-spec/blob/main/image-index.md
