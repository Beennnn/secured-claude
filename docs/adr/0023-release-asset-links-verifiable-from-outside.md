# 23. Release asset links — every claim verifiable from outside the repo

Date: 2026-04-29
Status: Accepted

## Context

[ADR-0017](0017-security-testing-evidence-pipeline.md) established a per-release evidence pipeline (bandit, pip-audit, trivy, grype, gitleaks, SBOM, audit-demo). The pipeline produces JSON / XML artefacts on every tag pipeline.

Up through v0.2.1, those artefacts existed but were **only reachable for someone who had cloned the repo and dug through the GitLab CI pipeline UI**. A reviewer reading the README's claims ("92 % coverage", "0 CRITICAL CVEs", "26/26 audit-demo PASS") had no way to *verify* them without :

1. Cloning the repo (~50 MB).
2. Authenticating to GitLab.
3. Navigating to the right pipeline.
4. Downloading specific job artefacts.

A reviewer pointed this out :

> "Le README dit 'every claim backed by artifact' : c'est mieux, mais ça reste ambitieux. Je ne peux pas vérifier ici que les 111 tests, 92,6 % coverage et 14 jobs CI sont réellement verts sans exécuter le repo."

The friction is real. Asset-link curl URLs that resolve to immutable artefacts close that gap.

## Decision

Attach **6 asset links** to every GitLab Release object, pointing at the relevant job artefacts of the same tag pipeline :

| # | Asset | Source job | Retention | What it proves |
|---|---|---|---|---|
| 1 | `sbom.spdx.json` | `security:sbom` | 1 year | What's actually in the released container image |
| 2 | `trivy.json` | `security:trivy` | 1 year | Filesystem CVE + secret + config scan ran clean (or with documented suppressions) |
| 3 | `grype.json` | `security:grype` | 1 year | Independent CVE cross-check — same delta or none vs trivy |
| 4 | `gitleaks.json` | `security:gitleaks` | 1 year | Repo had no leaked secrets at release time |
| 5 | `coverage.xml` | `test:py313` | 1 year | Test coverage % — recoverable by `xmllint --xpath` |
| 6 | Container image URL | `build:image` (cosign-signed by `publish:cosign-sign`) | (registry retention) | The actual binary — `cosign verify` proves provenance |

The `release:gitlab` job builds the `assets.links` array via `jq` and includes it in the POST `/projects/:id/releases` payload. URL pattern :

```
${CI_PROJECT_URL}/-/jobs/artifacts/${CI_COMMIT_TAG}/raw/<path>?job=<job_name>
```

This resolves to the latest matching job's artefact for the given ref. Retention is governed by the source job's `expire_in` (bumped to 1 year for the asset jobs in this commit).

The README's new "Verify the artifacts (no clone needed)" section gives recipients a copy-pasteable curl recipe + jq sanity-check assertions for each artefact.

## Consequences

**Positive** :
- A reviewer who never clones the repo can :
  - Download the SBOM and run `grype sbom:sbom-vX.Y.Z.spdx.json` for fresh CVE check.
  - Read `coverage.xml` with `xmllint` and confirm the % matches the README claim.
  - `cosign verify` the container image without trusting our infrastructure.
  - `jq 'length'` the gitleaks scan and confirm 0 leaks at release time.
- The "recipient builds trust without clone" pattern matches what enterprise security review teams already expect — GitHub Releases + Sigstore + SBOM at major OSS projects.
- The 1-year retention means a compliance audit 6 months post-release can still pull the same evidence the release shipped with. (Renovate / supply-chain review windows often extend that long.)

**Negative** :
- Bumping `expire_in` from 30 days → 1 year increases CI artefact storage cost. For this project the artefacts are tiny (kilobytes for trivy/grype/gitleaks, ~100 KB for sbom, ~10 KB for coverage) — total < 1 MB per tag, ~10 MB per year of releases. Negligible.
- Asset-link URLs depend on the artefact still existing. Past the 1-year window, the link 404s. Mitigated by the tag annotation including a snapshot of "what was true at release" — git history is the long-term record.

**Neutral** :
- The Release object's `description` (multi-line markdown banner) is unchanged. Only `assets.links` is new. Old releases (v0.1.x through v0.2.1) don't get retroactively patched ; the asset-links surface only on v0.3.0+.

## Alternatives considered

- **Upload the artefacts as project uploads** (POST `/projects/:id/uploads` for each, get back permanent URL, link in release) — gives infinite retention. Rejected for v0.3 : adds 6 extra API calls + uploads on the critical path of release:gitlab, which already had a flaky history (release-cli SIGSEGV, runner-stuck during v0.2.1). Lower-risk path : 1-year artefact link + revisit if/when retention matters.
- **Push artefacts to a separate "evidence" git branch / repo** — works but adds operational complexity. The asset-link pattern is the GitLab-native way and uses the existing release flow.
- **Skip the asset links, document the claim in the description** (the v0.2 status quo) — what the reviewer flagged as insufficient. Rejected.

## Verification

After the v0.3.0 tag pipeline goes green :

```
$ glab release view v0.3.0 --output json | jq '.assets.links | length'
6

$ curl -sSI "https://gitlab.com/benoit.besson/secured-claude/-/jobs/artifacts/v0.3.0/raw/sbom.spdx.json?job=security:sbom" | head -1
HTTP/2 200

$ curl -fsSL "https://gitlab.com/benoit.besson/secured-claude/-/jobs/artifacts/v0.3.0/raw/sbom.spdx.json?job=security:sbom" \
    | jq '.spdxVersion'
"SPDX-2.3"
```

Each asset returns 200 OK + valid content type. The README's "Verify the artifacts" recipe runs end-to-end without a repo clone.

## References

- [ADR-0016](0016-supply-chain-cosign-sbom.md) — cosign keyless OIDC + Syft SBOM (the supply-chain claim this ADR makes verifiable from outside)
- [ADR-0017](0017-security-testing-evidence-pipeline.md) — the evidence pipeline that produces the artefacts
- GitLab Release API : https://docs.gitlab.com/api/releases.html#assets-as-links
- GitLab job artefacts URL format : https://docs.gitlab.com/ci/jobs/job_artifacts.html#download-with-the-api
- Reviewer feedback that triggered this ADR : "Points faibles restants" critique 2026-04-29
