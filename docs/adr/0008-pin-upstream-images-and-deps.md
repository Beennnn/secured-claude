# ADR-0008: Pin every upstream image & dependency

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

## Context

A core supply-chain attack pattern : an upstream package or image is compromised (typo-squat, account hijack, malicious maintainer) ; consumers using floating tags (`:latest`, `>=1.0`) silently pull the malicious version on next build. Recent examples : `event-stream` (2018), `ua-parser-js` (2021), `node-ipc` (2022), `xz` (2024). This is [OWASP A08:2021 Software & Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/).

For an "enterprise grade" tool, we cannot ship floating-tag references. The audit-demo, the install script, the CI pipeline, the runtime images — every external reference must be pinned to a specific, content-addressed version.

The user's global CLAUDE.md already mandates this : "Pin every upstream reference. No floating tags."

## Decision

We pin every upstream reference, at the granularity each ecosystem supports best :

| Artifact type | Pinning level | Mechanism |
|---|---|---|
| **Docker images** in production paths (Cerbos, Node base, runners) | Image digest `@sha256:...` | `image: cerbos/cerbos:0.42.0@sha256:...` in compose & Dockerfile |
| **Python deps** | Exact version + transitive lock | `dependencies = ["fastapi>=0.115.0,<0.116"]` in `pyproject.toml` + `uv.lock` committed |
| **npm deps** (in agent container) | Exact version + integrity hash | `package.json` exact + `package-lock.json` SRI hashes |
| **OS packages** (`apt-get install …` in Dockerfile) | Pinned version (`pkg=1.2.3`) where Debian provides ABI guarantees | Lookup latest stable in CI on rebuild ; commit |
| **CI runner images** | Pinned tag + digest | `image: python:3.13-slim@sha256:...` |
| **GitLab CI image references** | Same | `:tag@sha256:...` |
| **GitHub Actions** (mirror only, low risk) | Major version + sha pin | `uses: actions/checkout@v4 # pinned to abc123...` |

We use [Renovate](https://docs.renovatebot.com/) for automated bump PRs :

- Auto-merge patch + minor (when CI green) for `devDependencies`, base images, security advisories
- Manual review for major bumps, new transitive deps, schema-changing migrations
- Grouped PRs by ecosystem (one weekly Python deps PR, one Docker digest refresh PR)

## Consequences

### Positive

- **Reproducible builds** — `git checkout vX.Y.Z` + `uv sync` + `docker buildx build` produces identical artifacts. Required for compliance audits and bug reproduction.
- **Defense against silent supply-chain compromise** — a compromised upstream won't propagate until a Renovate PR reviews and merges the change.
- **CVE-aware bumps** — Renovate's `vulnerabilityAlerts` config auto-PRs security-only bumps with a high-priority label, bypassing the schedule.
- **Hadolint enforcement** — DL3007 (no `:latest`) is a CI lint failure. Hard guarantee, not best-effort.
- **`pip-audit` + `trivy` + `grype`** — pinned versions = checkable versions. Floating versions can't be reliably scanned because "what's installed" depends on when you ran `docker build`.

### Negative

- **More PRs to review** — Renovate creates ~5-10 PRs/week for a steady-state project. Mitigated by : (a) auto-merge for safe categories, (b) grouped PRs (one PR for "all Python dep digest bumps").
- **Larger maintenance surface** — each pinned dep is a thing to track. Mitigated by Renovate ; without it this would be unmaintainable, with it it's tractable.
- **Slow first build** — pinning to digest means the first pull on a new machine downloads the full image (no cache hits if the digest is rare). Mitigated by `secured-claude doctor` pre-pulling at install time.
- **Stale pins drift in security posture** — a pinned dep that's never bumped accumulates known CVEs. Mitigated by : (a) Renovate ensures regular bumps, (b) `pip-audit` in CI fails the pipeline on known vulns regardless of pin recency.

### Neutral

- We accept that pinning by digest is more verbose than tag-only. The tradeoff is worth it for production-bound consumers.

## Alternatives considered

- **Pin tags only** (`cerbos/cerbos:0.42.0`) — much weaker. Tags are mutable on Docker Hub ; a compromised maintainer or a registry MITM can swap the image bytes. Digest pinning makes this impossible. Rejected as primary, used as a fallback "human-readable" alongside the digest.
- **Floating tags** (`:latest`, `:lts`) — explicitly forbidden by global CLAUDE.md and OWASP A06+A08. Rejected.
- **Vendor everything** (commit all deps as source) — atomic reproducibility, but enormous repo, no Renovate, no security advisories. Out of fashion for good reason. Rejected.
- **Rely on Sigstore policy + cosign verify on every build** instead of digest pinning — Sigstore is great (we use it for signing our own images, see [ADR-0016](0016-supply-chain-cosign-sbom.md)) but doesn't replace pinning : a verified signature on a compromised image is still a compromised image. Both layers are needed.
- **No `uv.lock`, only `pyproject.toml`** — would let transitive deps float. Loses reproducibility. Rejected.

## References

- OWASP A06:2021 — Vulnerable & Outdated Components — https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
- OWASP A08:2021 — Software & Data Integrity Failures — https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
- Renovate documentation — https://docs.renovatebot.com/
- Hadolint rule DL3007 — https://github.com/hadolint/hadolint/wiki/DL3007
- Image digest pinning rationale — https://docs.docker.com/build/cache/optimize/#use-immutable-image-digests
- Implementation : [`Dockerfile.claude-code`](../../Dockerfile.claude-code), [`docker-compose.yml`](../../docker-compose.yml), [`pyproject.toml`](../../pyproject.toml), [`renovate.json`](../../renovate.json)
- Supply-chain doc — [`docs/security/supply-chain.md`](../security/supply-chain.md)
- Related ADRs : [0014](0014-gitlab-ci-pipeline-6-stages.md) (CI enforces it), [0016](0016-supply-chain-cosign-sbom.md) (signing complements pinning)
