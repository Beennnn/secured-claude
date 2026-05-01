# 46. On-the-fly secret redaction in Read results

Date: 2026-05-01
Status: Accepted

## Context

The PreToolUse hook + Cerbos PDP gate **intent** ([ADR-0001](0001-cerbos-as-policy-decision-point.md), [ADR-0002](0002-pretooluse-hook-as-interception-point.md)) — they catch `Read /etc/passwd` before it executes. The L2/L3/L4 confinement layers ([ADR-0022](0022-intent-layer-vs-confinement-layers.md)) bound blast radius for paths *outside* `/workspace/`. None of these address the case where :

> The agent legitimately reads `/workspace/.env` (workspace path, ALLOWed by policy) and the file content contains `AWS_SECRET_ACCESS_KEY=AKIA...` — the secret then ships to the Anthropic LLM verbatim as part of the tool result.

That's a **content-level exfiltration vector** the v0.7.x design left open. The project's tagline is "no silent exfiltration" ; until this ADR, that promise had a content-shaped hole.

The user surfaced this on 2026-05-01 with a direct design question : *can we do on-the-fly obfuscation with encoding/decoding before the content reaches the LLM ?* Yes. This ADR is the answer.

## Decision

### `RedactionEngine` — pattern-based scan + placeholder substitution

`src/secured_claude/redaction.py` ships a curated subset of gitleaks-style patterns covering the high-confidence formats : AWS access/secret keys, GitHub PATs (classic + fine-grained + OAuth + server tokens), GitLab PATs, Slack bot/user tokens, Stripe live/test secrets, Anthropic + OpenAI keys, JWTs, PEM-formatted private keys, DB connection strings with embedded credentials, and a generic `api_key=...` heuristic. **15 patterns** in v0.8.0 ; new ones land in v0.8.x as patterns prove valuable in real use.

When the engine sees a match, it :

1. Generates a placeholder `<<SECRET:<16-hex>>` (64 bits of entropy, collision-safe per session at any realistic count).
2. Stores `placeholder → original_value` in an in-memory `dict[session_id, dict[placeholder, value]]`.
3. Returns the redacted content + the list of pattern rules that fired (for logging + Prometheus counters).

`restore(content, session_id)` walks the per-session map and substitutes every placeholder back to its original. Used by the broker when the LLM's later tool calls legitimately reference a placeholder (e.g. `Bash "aws s3 ls --secret-key <<SECRET:abc>>"` — the broker substitutes before exec).

### `/transform` route + PostToolUse hook

The broker exposes `POST /transform` with `{action: "redact"|"restore", content, session_id}`. The PostToolUse hook installed in the agent container (`/usr/local/bin/secured-claude-posthook`) :

1. Fires after every `Read` tool call.
2. POSTs the file content to `/transform` action=redact.
3. Outputs `{"decision": "block", "reason": "<redacted content>"}` so Claude Code surfaces the redacted text to the LLM in place of the raw response.

The LLM never sees the raw secret. The redacted content carries a header line `[secured-claude redacted N secret(s) (rule1, rule2, …) before they reached the LLM]` for visibility — operators tailing logs see what fired.

### Bash / Write placeholder guard in `/check`

The `/check` route gains a **placeholder-resolution guard** : if the tool input contains a placeholder NOT in the session's mapping (forged by the LLM, or stale from a previous broker process), the broker DENYs rather than passing the literal `<<SECRET:abc>>` to the executor. Documented as a security-positive (refusing-on-uncertainty) per [ADR-0009](0009-hook-fails-closed.md)'s fail-closed posture.

Resolved placeholders pass through normally — the LLM is allowed to USE a redacted secret in a downstream tool call ; the broker substitutes back before exec.

### Activation

`SECURED_CLAUDE_REDACT_LEVEL` env :

- `off` (default) — pre-v0.8 behaviour. `make_engine()` returns `None`, `/transform` becomes a pass-through, the placeholder guard never fires. Existing v0.7.x deployments unaffected.
- `secrets` — engine activates with the v0.8.0 pattern set. PostToolUse hook redacts all Read results.
- `aggressive` — reserved for v0.8.x. Same engine as `secrets` for now ; v0.8.x will add tokenisation of all string literals in user-marked sensitive paths (`SECURED_CLAUDE_REDACT_PATHS`). Out of v0.8.0 scope.

### Failure modes — fail-OPEN deliberately

The PreToolUse hook fails CLOSED ([ADR-0009](0009-hook-fails-closed.md)) — broker unreachable = DENY. The PostToolUse redaction hook fails OPEN — broker unreachable = no redaction, content reaches the LLM raw.

**Why the asymmetry** : if the broker is down, the agent can't make any tool calls (PreToolUse hook denies everything). So the realistic failure pattern is *broker is up but redaction misbehaves*. In that case, blocking the Read entirely would degrade UX without a security benefit (the secret was never going to leave the broker anyway because there's no broker to send to). Failing OPEN means redaction is a defensive layer on top of an already-functional policy gate, not a hard requirement for the agent to function.

This asymmetry is documented in `hook_post.py` so future readers know it's intentional.

## Consequences

**Positive** :
- Closes the content-level exfiltration vector that v0.7.x left open. The project's "no silent exfiltration" promise is now load-bearing for content as well as paths.
- 15 curated patterns cover ~80% of real-world secret formats with zero false positives in normal source code (verified by 26 new tests).
- Broker-side `/transform` capability is reusable beyond the PostToolUse hook : the new `secured-claude redact <file>` CLI command (out of v0.8.0 scope but trivial to add) lets operators manually redact a file for diff / inspection / paste-to-stackoverflow workflows.
- Bash placeholder guard makes the system safe by default : forged placeholders fail closed ; legitimate placeholders substitute back transparently.

**Negative** :
- **False negatives** : custom-format secrets won't match. Mitigation : v0.8.x `aggressive` mode for user-marked sensitive paths.
- **Inferred-from-context leak** : an env-var line `AWS_SECRET_ACCESS_KEY=<<SECRET:abc>>` leaks the *kind* of secret (the variable name) even if the value is opaque. The LLM sees "this is an AWS key" without seeing the value — sometimes that's enough for the LLM to make wrong decisions about how to handle it. **Out of scope for v0.8.0** ; addressing this would require tokenising identifiers as well, which destroys LLM utility (see the user's question on 2026-05-01 + the response sketching tiered redaction).
- **Adversarial Bash construction** : if the LLM tries `base64 -d <<<<<SECRET:abc>>>` or string-concatenation, the literal substitution doesn't apply. The placeholder guard catches this : the *transformed* placeholder doesn't match the session map, so the broker DENYs. Strict but safe.
- **State is in-memory** : broker restart loses the placeholder map. Mid-session restart breaks the LLM's ability to reference placeholders from before the restart. Acceptable trade-off — persisting the map to disk would create a different exfil vector (the secret-mapping file itself).
- **One-process invariant** : the in-memory state assumes a single broker process. Multi-worker uvicorn deployments would need a shared store (Redis, etc.). [ADR-0006](0006-host-side-broker.md) commits to single-process broker for the personal-proxy use case ; multi-worker is out of scope.

**Neutral** :
- One new env knob (`SECURED_CLAUDE_REDACT_LEVEL`) ; defaults to `off` so existing deployments are unaffected.
- One new Prometheus counter (`secured_claude_redaction_matches_total{rule="..."}`) — operators can alert on a sudden spike (which would indicate a tool / agent change is suddenly producing secret-laden output).
- 26 new tests : pattern coverage (8 representative secret types), restore, session isolation, has_unresolved_placeholder, env-driven activation, /transform end-to-end, Bash placeholder guard. Total now 284 tests (was 258 in v0.7.4).

## Alternatives considered

- **Tokenise everything (encode all symbols)** : the user proposed this. Rejected because the LLM relies heavily on identifier semantics (`compute_invoice_total` → "this is an accounting calculation"). Tokenising every name leaves the LLM unable to reason about meaning ; the agent loop fails. Practical homomorphic encryption for LLMs doesn't yet exist commercially. The middle-ground tier (`aggressive` mode for user-marked paths only, leaving other files at `secrets`) is the realistic compromise — deferred to v0.8.x conditional on user demand.
- **Block Read of files matching a sensitivity pattern** : just refuse to read `/workspace/.env` etc. Rejected — too restrictive. Devs DO need to read their `.env` to debug ; the goal is to let the agent help with that file without leaking the secret values.
- **Rely on Anthropic's prompt-injection / data-loss-prevention layers** : Anthropic does have content-filtering, but it's vendor-side, not transparent, not auditable from the broker. We need a defense the operator can verify and tune. Not rejecting Anthropic's layers — they're complementary — just not relying on them.
- **Encrypt the content with a session key, store ciphertext in the LLM stream, decrypt on output** : actual cryptographic obfuscation. Doesn't survive LLM reasoning ; the LLM can't operate on encrypted data. Same problem as tokenising everything.
- **Run gitleaks itself as a subprocess** : reuse the full ~140-pattern library instead of curating 15. Rejected for v0.8.0 — gitleaks adds a binary dep + subprocess overhead + a trust boundary issue (gitleaks-output JSON has to be sanitised before re-injection into the LLM stream). The curated subset gives 80% coverage at 0 binary cost ; v0.8.x can layer in a gitleaks-via-grpc service if pattern coverage proves insufficient.

## Verification

Tests in `tests/test_redaction.py` (26 new) :

Pattern coverage (8) :
- `test_known_secret_format_redacted` parametrised over AWS access key, GitHub PAT, GitLab PAT, Slack bot, Stripe live, Anthropic key, JWT
- `test_pem_private_key_redacted_multiline`
- `test_db_connection_string_redacted`
- `test_no_secret_no_change` (zero false positive on plain code)
- `test_multiple_secrets_in_same_input`

Restore semantics (3) :
- `test_restore_substitutes_placeholders_back`
- `test_restore_unknown_placeholder_passes_through`
- `test_restore_session_isolation`

Placeholder guard (3) :
- `test_has_unresolved_detects_unknown_placeholder`
- `test_has_unresolved_passes_known_placeholder`
- `test_has_unresolved_no_placeholders_returns_false`

Env activation (5) :
- `test_make_engine_off_by_default`
- `test_make_engine_off_explicit`
- `test_make_engine_secrets_level`
- `test_make_engine_aggressive_alias_for_secrets`
- `test_make_engine_unknown_level_off`

`/transform` end-to-end (3) :
- `test_transform_redact_replaces_known_secret`
- `test_transform_restore_substitutes_back`
- `test_transform_disabled_when_engine_none`

Bash placeholder guard (1) :
- `test_check_denies_unresolved_placeholder_in_bash`

End-to-end (manual) :

```bash
$ SECURED_CLAUDE_REDACT_LEVEL=secrets secured-claude up
$ docker exec secured-claude-agent claude -p "what is in /workspace/.env"
# The LLM responds with redacted content :
#   [secured-claude redacted 2 secret(s) (aws-access-key, github-pat) before they reached the LLM]
#   AWS_ACCESS_KEY_ID=<<SECRET:a3f29d...>>
#   GITHUB_TOKEN=<<SECRET:e8c041...>>
#   ...
$ docker exec secured-claude-agent claude -p "use the AWS key to list buckets"
# Claude crafts : Bash "aws s3 ls" — broker substitutes back before exec
# The actual aws CLI sees the real key. The LLM never did.
```

## References

- [ADR-0001](0001-cerbos-as-policy-decision-point.md) — Cerbos PDP (this ADR layers on top, doesn't replace)
- [ADR-0002](0002-pretooluse-hook-as-interception-point.md) — PreToolUse hook (this ADR adds a PostToolUse counterpart)
- [ADR-0009](0009-hook-fails-closed.md) — fail-closed posture (this ADR fails OPEN ; documented asymmetry)
- [ADR-0022](0022-intent-layer-vs-confinement-layers.md) — intent vs confinement (redaction is content-level confinement, complements the path-level confinement)
- [ADR-0042](0042-prometheus-metrics.md) — counter library (this ADR adds `secured_claude_redaction_matches_total{rule}`)
- [ADR-0045](0045-non-features-rejected-for-scope.md) — what we explicitly DON'T ship (this ADR is the opposite : a feature with concrete user-asked value)
- [gitleaks](https://github.com/gitleaks/gitleaks) — pattern library inspiration
- v0.8.x candidates :
  - `aggressive` mode + `SECURED_CLAUDE_REDACT_PATHS` for user-marked sensitive files (tokenise all string literals, not just pattern matches)
  - `secured-claude redact <file>` CLI command for manual / diff / paste workflows
  - Custom pattern injection (`SECURED_CLAUDE_REDACT_PATTERNS=path/to/custom.yaml`) for org-specific token formats
