# ADR-0011: No secret baked into image

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

## Context

The Claude Code container needs `ANTHROPIC_API_KEY` to talk to `api.anthropic.com`. There are several ways to provide it :

1. **Bake into image** : `COPY .env /app/.env` or `ARG ANTHROPIC_API_KEY` at build time.
2. **Runtime env var** : `docker run -e ANTHROPIC_API_KEY=...`.
3. **Volume-mounted secret** : `docker run -v /path/to/secret.txt:/run/secrets/api_key:ro`.
4. **Docker secrets** (Swarm only) or **Kubernetes secrets** (orchestrator-managed).
5. **External vault** (HashiCorp Vault, AWS Secrets Manager, etc.) fetched at startup.

Constraints :

- The image we build is published publicly to a container registry (GitLab Container Registry, possibly mirrored).
- A leaked `ANTHROPIC_API_KEY` lets an attacker spawn agents on the user's Anthropic account.
- The image must be scannable by `trivy`, `grype`, anyone with a `docker pull` — no leaked secrets.

[OWASP A02:2021 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) and [SANS top 25 CWE-798 (Use of Hard-coded Credentials)](https://cwe.mitre.org/data/definitions/798.html) explicitly call out baked-in secrets as a vulnerability.

## Decision

The Claude Code image has **no secrets baked in**. The `ANTHROPIC_API_KEY` is provided as a **runtime environment variable** :

- The user fills `.env` from `.env.example` (template tracked in repo, real `.env` is `.gitignore`'d).
- `docker-compose up` reads `.env` and injects `ANTHROPIC_API_KEY` into the container at runtime via `environment:`.
- The Dockerfile does NOT use `ARG ANTHROPIC_API_KEY`, does NOT `COPY .env`, does NOT `ENV ANTHROPIC_API_KEY=`.
- `gitleaks` runs in CI on every commit ; would flag any accidental hardcoded key.
- `.gitignore` lists `.env`, `.env.local`, `*.pem`, `*.key`, `secrets.json` — preventing accidental commit.
- `gitleaks pre-commit hook` (lefthook) runs locally too (added v0.2 as Lefthook config).

For v0.2+, additional providers :

- HashiCorp Vault — `secured-claude run --vault-path secret/data/anthropic`
- macOS Keychain — `secured-claude run --keychain-key anthropic-api`
- AWS Secrets Manager — `secured-claude run --aws-secret-id anthropic-api-key`

The runtime-env approach is the v0.1 baseline ; advanced providers are progressive enhancement.

## Consequences

### Positive

- **Image is publicly publishable** — no key in the layer history (`docker history claude-code:vX.Y.Z` shows nothing sensitive).
- **`trivy` / `grype` / `gitleaks` clean** — secret scanners report zero findings.
- **Easy key rotation** — `export ANTHROPIC_API_KEY=...new...` then `secured-claude down && up`. No image rebuild.
- **Per-developer keys** — each developer can have their own key without impacting others.
- **Audit-friendly** — reviewers see no embedded credentials in the published artifacts.
- **Aligns with [Twelve-Factor App III](https://12factor.net/config)** — config in the environment.

### Negative

- **`.env` file management** — users must remember to fill `.env` and not commit it. Mitigated by : (a) `.gitignore` explicit, (b) `secured-claude doctor` checks `.env` exists and `ANTHROPIC_API_KEY` is set, (c) gitleaks pre-commit hook (v0.2).
- **Plain-text on disk** — `.env` lives unencrypted on the dev's home directory. Acceptable given the user's HOME is already a trusted zone for the developer's other secrets (SSH keys, etc.). Stronger storage (Keychain, Vault) is opt-in v0.2.
- **Process env-var visibility** — `ps -E` (with appropriate privileges) can show env vars. On a multi-tenant host this could leak. Mitigated by : (a) Docker passes envs via the daemon, not in the parent shell process, (b) the multi-tenant case is rare for individual dev machines.

### Neutral

- We don't claim to defend against an attacker with full access to the developer's HOME directory ; that's the host's responsibility (FileVault / LUKS / BitLocker).

## Alternatives considered

- **Bake the key at build time** (`ARG ANTHROPIC_API_KEY`) — disqualifying. Once baked, the key is in the image layers forever (squashing helps but is fragile). If the image ever leaks (registry misconfigure, accidental public push), the key leaks with it. Rejected.
- **Per-user image build** (each user builds their own with their own key baked in) — defeats CI/CD reproducibility, weakens supply-chain provenance (different users → different signed images). Rejected.
- **Volume-mounted secret file** (`-v ~/.config/secured-claude/key.txt:/secret/key:ro`) — works, but `docker-compose env_file:` is simpler and has the same security properties. Tracked as v0.2 enhancement (mode 0o400 file in `~/.config/`).
- **Inject via stdin** (`docker run ... <<<"$KEY"`) — clumsy, breaks lifecycle.
- **Always require an external vault** (no env-var fallback) — too high a bar for v0.1 individual-dev usage. Tracked v0.2+ for enterprise mode.

## References

- OWASP A02:2021 Cryptographic Failures — https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- CWE-798 (Use of Hard-coded Credentials) — https://cwe.mitre.org/data/definitions/798.html
- Twelve-Factor App III. Config — https://12factor.net/config
- gitleaks — https://github.com/gitleaks/gitleaks
- Implementation : [`docker-compose.yml`](../../docker-compose.yml) (`environment:` block), [`.env.example`](../../.env.example), [`.gitignore`](../../.gitignore)
- Verification : `gitleaks detect` in CI security stage, `docker history claude-code:vX.Y.Z` clean
- Related ADRs : [0008](0008-pin-upstream-images-and-deps.md) (no `ARG SECRET` either), [0016](0016-supply-chain-cosign-sbom.md) (signed images)
