# Contributing to secured-claude

Thanks for taking a look. The bar for contributions is :

1. **Every change has a reason that survives 6 months of distance** —
   either an ADR or a non-obvious comment in code. If it's not obvious
   why we're doing it, the change WILL get reverted by a future
   reviewer who can't tell if it's load-bearing.
2. **Every change leaves the gates green** — `pytest` + `ruff` +
   `mypy` + `bandit` + `bin/test-full-stack.sh`. The CI runs the
   same gates ; please run them locally first.
3. **Every change names what it defends** — which of the 4 layers
   (L1 intent / L2 egress / L3 DNS / L4 hardening) it protects, OR
   which of the [Clean Code 7 non-negotiables](docs/adr/) it
   reinforces.

---

## Quick start

```bash
git clone https://gitlab.com/benoit.besson/secured-claude.git
cd secured-claude
uv sync --all-extras --frozen        # installs deps + dev tools (pytest, ruff, mypy, bandit)

# Static gates (~20 s) :
uv run pytest -q                      # unit + integration tests
uv run ruff check src/ tests/         # linter (S/security rules included)
uv run ruff format --check src/ tests/
uv run mypy src/secured_claude/       # strict typing
uv run bandit -r src/secured_claude/ -c pyproject.toml --quiet

# Live policy gate (~30 s ; needs Docker running) :
bash bin/security-audit.sh            # 28 red-team + 7 happy-path scenarios

# End-to-end smoke (needs Docker + the broker image built) :
bash bin/test-full-stack.sh           # boots the 5-container stack

# All gates clean ⇒ your patch is ready for review.
```

The `Makefile` and `bin/dev/` scripts wrap most of these for convenience —
`bash bin/dev/stability-check.sh` runs the full local gate set.

---

## Commit conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/) —
the CI commitlint job rejects malformed messages.

Format :

```
<type>(<scope>): <imperative subject>
[blank]
<body — explain WHY, not WHAT — multi-paragraph OK>
[blank]
Co-Authored-By: ...   (optional, if collaborating)
```

Common `<type>` values used in this repo :

- `feat` — new feature visible to operators / end users
- `fix` — bug fix (incl. CI fixes — `fix(ci): ...`)
- `docs` — documentation only
- `chore` — meta change (deps, branch hygiene, no behaviour change)
- `refactor` — internal restructure with no behaviour change
- `test` — test-only changes (also `fix(tests)` if fixing a real test bug)

Scopes follow the module / area : `audit`, `broker`, `agent`, `ci`,
`gateway`, `redaction`, `tests`, `docs`, `orchestrator`, ...

Subject line ≤ 70 chars, no trailing dot, imperative mood. The body
exists for the WHY and the trade-off discussion — long is fine.

---

## Branching & merging

- **`dev` is the working branch.** Push commits there ; never push
  directly to `main`.
- Open an MR from `dev` → `main`. The CI must be green before merging.
- Auto-merge with `--remove-source-branch=false` (we never delete `dev`).
- Squash-merge is OFF — we keep the per-commit history visible in `main`.

---

## Architecture Decision Records (ADRs)

**Every load-bearing security or operational decision lands an ADR**, so
a security review can verify the *why* of each choice without re-deriving
it. We use the [Nygard format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions).

When to add an ADR :

- A new security control or layer
- A change to the threat model
- A choice between alternatives where the rejected option is not
  obviously inferior
- A constraint that drove the design (e.g. "host-side broker per
  ADR-0006 because the broker controls Docker lifecycle")

How to add an ADR :

1. Copy `docs/adr/0000-template.md` to the next free number :
   ```bash
   N=$(printf "%04d" $(( $(ls docs/adr/[0-9]*.md | tail -1 | grep -oE '^[0-9]+') + 1 )))
   cp docs/adr/0000-template.md "docs/adr/${N}-my-decision-slug.md"
   ```
2. Fill in the sections : Status / Context / Decision / Consequences /
   Alternatives.
3. The Context should NAME the threat or constraint that forces the
   decision. The Decision should be one paragraph max. Alternatives
   should explain why each was rejected — not just listed.
4. Run `bash bin/dev/regen-adr-index.sh` (or whatever your local
   stability-check uses) to refresh `docs/adr/README.md`.
5. Reference the ADR in the relevant code comment :
   `# Per ADR-0042, we expose Prometheus counters at /metrics ...`.

Rejected decisions also get an ADR — see [ADR-0045](docs/adr/0045-non-features-rejected-for-scope.md)
for an example (3 v0.7.x speculative items rejected as out-of-scope).

---

## Testing standards

- **Coverage gate ≥ 90 %** (currently 91.27 %). New code that drops
  coverage below the gate is rejected.
- **Tests are isolated from ambient state** — no test should fail if a
  developer happens to have `secured-claude up` running. Mock the
  orchestrator / broker as needed (see `tests/test_cli.py` for the
  pattern after v0.8.3 fix).
- **Integration tests boot real Cerbos** (`tests/conftest.py`'s
  fixture). Mocking the PDP would defeat the point.
- **`bin/security-audit.sh`** runs 28 red-team + 7 happy-path scenarios
  against a real Cerbos PDP. Any new threat class adds a scenario here.

---

## Reporting security issues

See [`SECURITY.md`](SECURITY.md). TL;DR : disclose responsibly via
e-mail (in SECURITY.md), not via a public GitLab issue.

---

## Where to look first

- High-level pitch + what each tool does + threat-class table : [README.md](README.md)
- Threat model : [docs/security/threat-model.md](docs/security/threat-model.md)
- Controls matrix (threat ↔ ADR ↔ code) : [docs/security/controls-matrix.md](docs/security/controls-matrix.md)
- Supply-chain story : [docs/security/supply-chain.md](docs/security/supply-chain.md)
- Live evidence (audit reports, scans) : [docs/security/security-evidence.md](docs/security/security-evidence.md)
- Architecture decisions : [docs/adr/](docs/adr/) — start at [ADR-0001](docs/adr/0001-cerbos-as-policy-decision-point.md)
- Per-version changes : [CHANGELOG.md](CHANGELOG.md)
- Developer environment + debug recipes : [docs/dev/](docs/dev/)
