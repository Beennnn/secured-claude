# ADR-0013: GitLab hosting + mono-repo for v0.1

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

> **Note on terminology** — occurrences of `secured-claude/secured-claude` below refer to the *rejected* alternative GitLab namespace (a dedicated `secured-claude` group containing a `secured-claude` project), NOT a stale URL. The actual current namespace is `benoit.besson/secured-claude` (see "Decision → Namespace"). These textual references are deliberate and document the rejected option per ADR conventions ; they must not be rewritten to `benoit.besson/secured-claude` by automated cleanups.

## Context

Where does the project live, and how is it structured ?

Decisions to make :

1. **Hosting platform** : GitLab, GitHub, self-hosted, etc.
2. **Namespace** : personal (`benoit.besson/`) vs new group (`secured-claude/`).
3. **Repository structure** : mono-repo (everything in one repo) vs polyrepo (each component in its own repo).
4. **Mirroring** : do we mirror to a second platform for portfolio / community discoverability ?

Constraints :

- The project owner already uses GitLab as primary for related work (iris-7 polyrepo).
- A v0.1 mono-repo MAY want to split into a polyrepo group (`secured-claude` + `secured-claude-policies` + `secured-claude-helm` + `secured-claude-ui`) as components mature.
- Public visibility helps the enterprise pitch (community can verify the security claims).
- Anti-pattern from CLAUDE.md global : "Adding the same script in 2+ repos as duplicates" — don't split too eagerly.

## Decision

### Hosting

- **Primary** : GitLab.com — `gitlab.com/benoit.besson/secured-claude` (public).
- **Mirror** : GitHub.com — `github.com/Beennnn/secured-claude` (public, mirror of GitLab `main` branch).
- **CI lives on GitLab** ; GitHub mirror is read-only (push from GitLab, no Actions).

### Namespace

- **Personal namespace** (`benoit.besson/`) for v0.1.
- A dedicated `secured-claude/` group on GitLab is **NOT** created in v0.1, despite the future polyrepo possibility. Rationale : creating a group with one repo and zero collaborators is overhead for no gain. If/when a v0.2+ split happens, transferring `benoit.besson/secured-claude` to `secured-claude/secured-claude` is a single GitLab UI action.

### Repository structure

- **Mono-repo for v0.1** : `secured-claude` contains broker code, Cerbos policies, Dockerfile, CI, ADRs, all docs.
- **Polyrepo split deferred** to when an actual demand emerges (e.g. a vertical-specific policy bundle, a Helm chart, a web UI). Anticipated splits (NOT done in v0.1) :

| Future repo | When justified | Contents |
|---|---|---|
| `secured-claude-policies` | v0.2 if multiple verticals (banking, healthcare, public-sector) need distinct policy bundles | Cerbos YAML packs, signable, distributable separately |
| `secured-claude-helm` | v0.3 if k8s deployment is requested | Helm chart with PDP cluster-side, audit log → SIEM |
| `secured-claude-ui` | v0.3+ if web audit dashboard is requested | Angular or Next.js consuming the broker API |

### Branch model (per CLAUDE.md global)

- `main` — released-only, protected, push restricted to Maintainers, merge requires green CI + resolved discussions.
- `dev` — working branch, auto-merges into `main` via GitLab MR with `--auto-merge --remove-source-branch=false`.
- Feature branches optional for big chunks ; small fixes go straight to `dev`.

### Tag format

- `vX.Y.Z` semver pure, no prefix. (No need for the iris-7-style `stable-py-v` prefix — this project is its own namespace.)
- Annotation follows the global CLAUDE.md "tag annotations formalise what was verified" rule : Changes / Verified / Themes maîtrisés (10 axes) / Known limitations / Next checkpoint.

## Consequences

### Positive

- **Public open source** — a security expert can review every line, every policy, every commit. This *is* the pitch.
- **GitLab CI is canonical** — one CI to debug, no GitHub Actions to keep in sync. CLAUDE.md global rule applied.
- **GitHub mirror gives discoverability** — github.com is the search default for many ; a mirror brings traffic without GitLab abandonment.
- **Mono-repo simplicity** — one CI, one release, one CHANGELOG, one tag namespace. Anti-pattern "duplicates across repos" naturally avoided.
- **Easy to split later** — `git filter-branch` / `git subtree` can extract a sub-tree to a new repo in v0.2+ without losing history.
- **Low operational ceremony** — no submodule pin-bumps, no cross-repo MR coordination, no transitive version drift.

### Negative

- **One CI is a single bottleneck** — a broken pipeline blocks all changes. Mitigated by : (a) modular CI stages, (b) `audit-demo` is parallelizable.
- **No fine-grained access control per component** — a contributor with write access has access to everything. Acceptable for v0.1 (single maintainer) ; v0.2+ may revisit if multi-team contributions emerge.
- **Mirroring is manual or scripted** — push to GitLab and GitHub separately, OR set up a GitLab "push mirror" feature. v0.1 uses the simple approach (`git push origin && git push github`), v0.2 may automate via GitLab mirror push.

### Neutral

- We accept the personal namespace tradeoff : looks "less corporate" than `secured-claude/secured-claude` but avoids creating an empty group.

## Alternatives considered

- **Polyrepo from day 1** (`secured-claude/secured-claude`, `secured-claude-policies`, `secured-claude-helm`) — premature splitting, anti-pattern. The components don't yet have independent release cadences or owners. Rejected. (Iris-7 grew its 5 repos organically over months — same expected here.)
- **Hosted on GitHub primary, GitLab mirror** — would invert the CI choice (GitHub Actions). The owner's existing tooling and CLAUDE.md global rule lean GitLab. Rejected.
- **Self-hosted GitLab / Gitea** — too much ops burden for v0.1. Tracked v0.3+ if an enterprise deploys their own.
- **Dedicated `secured-claude` GitLab group from day 1** — coin-flip ; the URL `gitlab.com/secured-claude/secured-claude` is slightly redundant ("secured-claude/secured-claude") and we save zero by creating the group up front. Group can be created later.
- **Codeberg or other Gitea-based forge** — interesting alternative for FOSS-pure pitch, but smaller community, less CI tooling. Out of scope.

## References

- CLAUDE.md global "Iris polyrepo layout" — pattern reference for how a project family grows
- GitLab branch protection — https://docs.gitlab.com/ee/user/project/protected_branches.html
- GitLab push mirror — https://docs.gitlab.com/ee/user/project/repository/mirror/push.html
- Conventional Commits — https://www.conventionalcommits.org/
- Repos created : [gitlab.com/benoit.besson/secured-claude](https://gitlab.com/benoit.besson/secured-claude), [github.com/Beennnn/secured-claude](https://github.com/Beennnn/secured-claude)
- Related ADRs : [0014](0014-gitlab-ci-pipeline-6-stages.md) (CI), [0015](0015-distribution-pipx-gitlab-registry.md) (distribution)
