# Architecture Decision Records — secured-claude

This directory contains the project's Architecture Decision Records (ADRs), following the [Nygard format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions). Every load-bearing security or operational decision in this codebase has an ADR — so a security or architecture review can verify the **why** of each choice without re-deriving it.

## Format

See [`0000-template.md`](0000-template.md) for the canonical template. Each ADR has :

- **Status** — Proposed / Accepted / Deprecated / Superseded
- **Context** — what forces and constraints shape the decision
- **Decision** — what we decided, in active voice
- **Consequences** — what becomes easier, harder, or riskier (positive / negative / neutral)
- **Alternatives considered** — what we rejected and why
- **References** — code, RFCs, related ADRs

## Index

### Security architecture (the "secured by design" core)

| # | Title | Justification snapshot |
|---|---|---|
| [0001](0001-cerbos-as-policy-decision-point.md) | Cerbos as the Policy Decision Point | CNCF Sandbox, Git-versioned policies, signable bundles, security-team familiar |
| [0002](0002-pretooluse-hook-as-interception-point.md) | PreToolUse hook as the interception point | Native Claude Code mechanism — no binary patching ; sub-50ms overhead |
| [0003](0003-default-deny-for-shell-network-mcp.md) | Default-deny for shell / network / MCP | Closed-surface allowlist > whack-a-mole denylist (OWASP A01) |
| [0004](0004-append-only-sqlite-audit-log.md) | Append-only SQLite audit log | Compliance-ready, queryable, single-file, cross-platform, INSERT-only schema |
| [0005](0005-containerised-claude-code.md) | Containerised Claude Code, not host-installed | Process + FS isolation, environment reproducibility, bounded blast radius |
| [0006](0006-host-side-broker.md) | Host-side broker, not container-side | Trust boundary clarity ; broker controls Docker, untrusted agent can't tamper |
| [0007](0007-cross-platform-via-docker-sdk.md) | Cross-platform via Docker SDK + `host.docker.internal` | One codebase for Mac / Linux / Windows ; no OS-specific shortcuts |
| [0008](0008-pin-upstream-images-and-deps.md) | Pin every upstream image & dep | Supply-chain : digest pinning, lockfiles, no `:latest` |
| [0009](0009-hook-fails-closed.md) | Hook fails closed (DENY on broker unreachable) | Adversary can't bypass by killing the broker |
| [0010](0010-network-egress-filter-allowlist.md) | Network egress allowlist at Docker network layer | Defense-in-depth ; survives a compromised hook |
| [0011](0011-no-secret-baked-in-image.md) | No secret baked into image | Image scannable publicly without exposing API keys |
| [0012](0012-defense-in-depth-layers.md) | ~~Defense-in-depth — 4 independent layers~~ | **Superseded by [ADR-0022](0022-intent-layer-vs-confinement-layers.md)** — "4 independently sufficient" framing was overstated |
| [0017](0017-security-testing-evidence-pipeline.md) | Security testing & evidence pipeline | bandit / pip-audit / trivy / grype / gitleaks / SBOM / cerbos compile gate every release |
| [0019](0019-l2-egress-proxy-tinyproxy.md) | L2 HTTP egress proxy (tinyproxy with allowlist) | Closes the v0.1 design-only L2 gap ; CONNECT default-deny ; agent can only reach `api.anthropic.com` |
| [0020](0020-l3-dns-allowlist-dnsmasq.md) | L3 DNS allowlist (dnsmasq forwarder) | Closes R-DNS-LEAK ; agent's resolver returns SERVFAIL for non-allowlisted hostnames |
| [0022](0022-intent-layer-vs-confinement-layers.md) | 1 intent layer (L1) + 3 confinement layers (L2/L3/L4) | Honest framing — L1 sees intent ; L2/L3/L4 bound blast radius if L1 is bypassed but cannot replace it |
| [0024](0024-hash-chain-audit-log.md) | Hash-chain audit log (tamper-evident) | SHA-256 chain over each row ; `secured-claude audit-verify` exits 1 if a row was modified or removed |
| [0025](0025-pre-built-sidecar-images.md) | Pre-built sidecar images for dns-filter + egress-proxy | Re-enables read_only on the sidecars (L4 parity with the agent) ; closes v0.2 apk-install-at-boot trade-off |
| [0026](0026-runtime-smoke-ci-gate.md) | Runtime smoke as a CI gate (no API key burn) | Pulls the just-built images and verifies the wiring on every tag/main pipeline ; catches v0.1.1's hook-shebang class without burning Anthropic API budget |
| [0027](0027-multi-principal-directory.md) | Multi-principal directory (config/principals.yaml) | Activates the v0.1 derived_roles (trusted_agent, auditor) ; broker maps principal_id → roles+attrs at request time |
| [0028](0028-multi-arch-images-manifest-list.md) | True multi-arch images (linux/amd64 + linux/arm64) | Per-arch Kaniko builds + crane index append → manifest-list ; native binaries on Apple Silicon / Graviton, no QEMU |
| [0029](0029-external-hash-anchor.md) | External hash anchor for audit log | `audit-anchor` emits a JSON commit to latest row_hash ; `audit-verify-anchor` detects post-anchor file tampering |
| [0030](0030-real-llm-smoke-manual-trigger.md) | Real-LLM smoke as manual-trigger CI job | `smoke:llm-real` runs `claude -p` against the just-built image ; operator clicks to trigger after setting the protected API key variable |
| [0031](0031-principal-validate-cli.md) | `secured-claude principal validate` lint CLI | Catches YAML typos (role / atributes / wrong types) before runtime ; exit 1 on issues for pre-commit / CI gating |
| [0032](0032-auto-anchor-cron-templates.md) | Auto-anchor cron templates (launchd / systemd) | Daily `audit-anchor` cron + retention prune + optional external-sync hook ; ship hardened service unit |
| [0033](0033-broker-containerised-for-ci-smoke.md) | Broker containerised for CI full-stack smoke | Dockerfile.broker + docker-compose.ci.yml override ; production stays host-side per ADR-0006 |
| [0034](0034-principal-provider-abstraction.md) | PrincipalProvider abstraction (foundation for OIDC) | YAMLPrincipalProvider + HTTPPrincipalProvider + make_provider() factory ; SECURED_CLAUDE_IDP_URL env switches to URL fetch |
| [0035](0035-bake-sidecar-configs.md) | Bake sidecar configs into the images | COPY dnsmasq.conf + tinyproxy.conf + filter.txt into the images ; drop v0.5.3 allow_failure on smoke:full-stack |
| [0036](0036-cerbos-image-bake.md) | Bake Cerbos policies into a custom image | FROM cerbos/cerbos:0.42.0 + COPY policies + cerbos/config.yaml ; closes v0.5.4 smoke regression |
| [0037](0037-http-principals-cache-and-bearer-auth.md) | TTL cache + bearer auth on HTTPPrincipalProvider | 5-min default cache + stale-on-error + Authorization header ; closes the v0.5 deferred IdP tickets ; mTLS still v0.7+ |
| [0038](0038-jwt-validation-and-oidc-discovery.md) | JWT validation in /check + OIDC discovery | Optional `token` field on `/check` + `OIDCVerifier` that fetches `/.well-known/openid-configuration` + JWKS ; sub claim becomes principal_id ; fail-closed on signature / iss / exp / aud violation |
| [0039](0039-max-stale-age-for-cache-and-jwks.md) | Max stale-age for cache + JWKS | `max_stale_age_s` caps stale-on-error window ; closes "permanent IdP misconfig serves compromised state forever" ; shared `SECURED_CLAUDE_MAX_STALE_AGE_S` env across both providers |
| [0040](0040-mtls-client-cert-on-idp-fetches.md) | mTLS client cert/key on IdP fetches | `client_cert_path` + `client_key_path` pair on both providers ; closes the v0.7 mTLS ticket ; covers the residual ~20% of IdP integrations beyond bearer (PKI-backed enterprises, gov enclaves, HSM-backed keys) |
| [0041](0041-multi-issuer-allowlist.md) | Multi-issuer ALLOWLIST | `MultiIssuerVerifier` wraps N OIDCVerifiers ; comma-separated `SECURED_CLAUDE_IDP_ISSUER` activates ; routes tokens by `iss` claim ; unlocks multi-tenant SaaS, M&A migration windows, hybrid cloud, DR failover |

### Operational envelope (where the code lives, how it's shipped)

| # | Title | Justification snapshot |
|---|---|---|
| [0013](0013-gitlab-mono-repo-v01.md) | GitLab hosting + mono-repo for v0.1 | Personal namespace ; mirror to GitHub ; polyrepo split deferred to organic demand |
| [0014](0014-gitlab-ci-pipeline-6-stages.md) | GitLab CI pipeline with 6 stages | lint → test → security → build → publish → release ; security stage gates releases |
| [0015](0015-distribution-pipx-gitlab-registry.md) | Distribution via pipx + GitLab Package Registry | One-command cross-OS install ; no MSI / pkg / snap over-engineering |
| [0016](0016-supply-chain-cosign-sbom.md) | Supply-chain provenance — cosign keyless OIDC + Syft SBOM | Signed images, SPDX SBOM ; OWASP A08 covered |
| [0018](0018-hatch-vcs-version-from-git-tag.md) | Package version derived from git tag (hatch-vcs) | Each tag → unique wheel filename ; replaces v0.1.x publish:pypi shell-wrap shim |
| [0021](0021-pin-claude-code-npm-version.md) | Pin Claude Code npm version + Renovate auto-bump | Closes the @latest hole in ADR-0008 ; Renovate auto-PRs the bumps ; bin/update-claude-code.sh for ad-hoc |
| [0023](0023-release-asset-links-verifiable-from-outside.md) | Release asset links (every claim verifiable from outside) | 6 asset-links on every Release ; recipient can curl + jq sbom/trivy/grype/gitleaks/coverage/cosign without cloning |

## Reading order suggestion

For a **security reviewer** evaluating "is this really secured by design ?" :

1. [0012](0012-defense-in-depth-layers.md) — the 4-layer architecture in one read
2. [0001](0001-cerbos-as-policy-decision-point.md) + [0002](0002-pretooluse-hook-as-interception-point.md) — the L1 mechanism
3. [0010](0010-network-egress-filter-allowlist.md) + [0005](0005-containerised-claude-code.md) — L2 + L3 layers
4. [0009](0009-hook-fails-closed.md) — the no-bypass property
5. [0004](0004-append-only-sqlite-audit-log.md) — the audit posture
6. [0003](0003-default-deny-for-shell-network-mcp.md) — the closed-surface principle
7. [0008](0008-pin-upstream-images-and-deps.md) + [0016](0016-supply-chain-cosign-sbom.md) — supply chain

For a **new contributor** ramping up :

1. The [README](../../README.md) for the pitch
2. [SECURITY.md](../../SECURITY.md) for the policy
3. ADRs in numeric order (0001 → 0016)

## When to add a new ADR

- Any decision that constrains future development (we'd refer back to "why did we do X ?")
- Any security-relevant choice — even small ones
- Any choice with a non-obvious alternative — capture the rejected paths
- Any organizational convention (CI structure, branching, release flow)

## When NOT to add an ADR

- Stylistic preferences (4 vs 2 spaces)
- Obvious / forced choices (using Python because the project is Python)
- Pure bug fixes or feature additions inside an established pattern

## Updating an ADR

ADRs are **immutable once accepted**. To change a decision :

- Mark the old ADR as `Status: Superseded by ADR-XXXX`
- Write a new ADR explaining the new decision and why the old one no longer holds
- Cross-link both

This preserves the historical reasoning, which is the entire point of ADRs.
