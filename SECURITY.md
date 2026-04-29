# Security policy

> **Mission** — make the comfort of Claude Code safe to deploy in an enterprise context, by gating every tool call through a Cerbos policy decision point and persisting every decision in an append-only audit log. Defense-in-depth via **1 intent layer + 3 confinement layers** ([ADR-0022](docs/adr/0022-intent-layer-vs-confinement-layers.md)) bounds the blast radius if the intent layer is bypassed.

---

## Reporting a vulnerability

We follow [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) coordinated vulnerability disclosure (CVD).

- **Email** : `benoit.besson+secured-claude-security@gmail.com` (placeholder ; will move to a dedicated domain in v0.2)
- **GitLab confidential issue** : [open one here](https://gitlab.com/benoit.besson/secured-claude/-/issues/new?issuable_template=security&issue%5Bconfidential%5D=true)
- **Disclosure timeline** : 90 days from acknowledgment, fully detailed in [`docs/security/vulnerability-disclosure.md`](docs/security/vulnerability-disclosure.md)
- **Safe harbor** : good-faith research that respects the scope is welcome ; we will not pursue legal action against researchers acting in good faith

For the well-known machine-readable contact file see [`.well-known/security.txt`](.well-known/security.txt).

## Defense-in-depth — 1 intent layer + 3 confinement layers (v0.2)

**Architecture** : per [ADR-0022](docs/adr/0022-intent-layer-vs-confinement-layers.md), L1 is the *semantic* gate that understands the agent's intent ("Claude wants to Read /etc/passwd → policy says deny"). L2/L3/L4 are *confinement* layers : they don't see intent, but they bound the blast radius if L1 is bypassed (CVE in Claude binary, prompt injection that fools Cerbos, runtime code patch). They do not *replace* L1's semantic decisions.

| Role | Mechanism | Threats mitigated | v0.2 status |
|---|---|---|---|
| **L1 — Intent (Cerbos PDP via PreToolUse hook)** | Reads the abstract operation (`Read("/etc/passwd")`), evaluates against versioned Cerbos policies, returns `permissionDecision`. Audit-logged with reason. | Tool intent abuse — Read sensitive paths, dangerous Bash, MCP exploitation, WebFetch to non-allowlisted URLs | **Enforced + tested** (`bin/security-audit.sh` 26/26) |
| **L2 — Network-egress confinement (tinyproxy)** | CONNECT-only forward proxy with `FilterDefaultDeny` ([ADR-0019](docs/adr/0019-l2-egress-proxy-tinyproxy.md)). Non-allowlisted host → 403. | Bounds blast radius if L1 misses : even a compromised binary can only reach `*.anthropic.com`. | **Enforced + tested** — `curl -x http://172.30.42.4:3128 https://evil.com` returns `CONNECT tunnel failed, response 403` |
| **L3 — DNS confinement (dnsmasq)** | dnsmasq with `no-resolv` ([ADR-0020](docs/adr/0020-l3-dns-allowlist-dnsmasq.md)). Non-allowlisted hostnames → SERVFAIL/REFUSED. | Bounds info-disclosure via DNS tunneling / exfil to attacker-controlled DNS — agent can't even *resolve* evil.com. | **Enforced + tested** — `nslookup evil.com 172.30.42.3` returns REFUSED |
| **L3 — Filesystem confinement** | Container `/workspace` mount only ; host FS invisible. | Bounds lateral access to host secrets (`~/.ssh`, `~/.aws`, `.env`) — they're not in the agent's namespace, so even an approved Bash can't read them. | **Enforced** ; no explicit test (relies on Docker's mount semantics) |
| **L4 — Container hardening** | Non-root UID, read-only rootfs (agent), `cap-drop=ALL`, default seccomp, no-new-privileges, cgroup `mem_limit: 4g`. | Bounds kernel-side escalation routes — even a privesc CVE chain has a smaller surface. | **Enforced** for the agent ; sidecars deferred to v0.3 (apk-install pattern) — trade-off documented in [ADR-0019](docs/adr/0019-l2-egress-proxy-tinyproxy.md) |

**Honest contract** : the security value is heavily concentrated in L1.
L2/L3/L4 don't replace L1 ; they make a successful L1 bypass less
catastrophic. Hardening L1 (signed policy bundles, audit log integrity,
fail-closed semantics, multi-principal — see v0.3+ backlog) gets the
priority it deserves under this framing. The remaining v0.3 gaps are
documented in the README's `What is configured but NOT yet enforced` table.

Full mapping of each threat to defending layers : [`docs/security/threat-model.md`](docs/security/threat-model.md).

## Threat model summary

We use **STRIDE** (Microsoft) to classify threats and **MITRE ATT&CK Mitigations** to verify coverage. Top assets defended :

- **Developer credentials** on the host (SSH keys, AWS profiles, `.env`, browser cookies) — confined to host, invisible to container ([L3]).
- **Production systems reachable from the dev machine** — protected by network egress allowlist ([L2]) + Bash command allowlist ([L1]).
- **Local source code in `/workspace/`** — under `Edit/Write` policy gates ; dangerous paths (`.git/hooks`, `node_modules/`) deny-listed.
- **Audit log integrity** — SQLite append-only, INSERT-only schema enforced by trigger ([L1]) ; export to SIEM available.
- **Supply chain** of Docker images and Python wheels — pinned by digest, signed with cosign keyless OIDC, SBOM published ([`docs/security/supply-chain.md`](docs/security/supply-chain.md)).

## Controls mapped to recognized standards

We map every control implemented in this codebase to widely recognized standards, so that a security review can verify coverage by lookup rather than by re-reasoning. See [`docs/security/controls-matrix.md`](docs/security/controls-matrix.md) for the full matrix. Highlights :

- **OWASP Top 10 2021** — A01 (Broken Access Control), A04 (Insecure Design), A05 (Security Misconfig), A08 (Software/Data Integrity), A09 (Logging Failures), A10 (SSRF) all addressed with specific controls and tests.
- **NIST SP 800-218 (SSDF v1.1)** — PO (Prepare the Organization), PS (Protect the Software), PW (Produce Well-Secured Software), RV (Respond to Vulnerabilities) practices addressed.
- **CIS Controls v8** — Controls 4 (Secure Configuration), 6 (Access Control Management), 8 (Audit Log Management), 16 (Application Software Security) directly applied.
- **MITRE ATT&CK Mitigations** — M1018 (User Account Management), M1026 (Privileged Account Management), M1030 (Network Segmentation), M1038 (Execution Prevention), M1042 (Disable or Remove Feature/Program), M1047 (Audit) implemented.

## Verifiable security audit

Every release ships with the output of `secured-claude audit-demo --strict`, which runs **6 red-team scenarios** + **2 happy-paths** + **policy-fuzz (50+ malicious patterns)** + **8 static analysis scans** (`bandit`, `pip-audit`, `trivy`, `grype`, `gitleaks`, `cerbos compile`, `hadolint`, `shellcheck`). If any red-team scenario passes the policy gate, the release is blocked.

The audit produces a timestamped Markdown report stored at `audit-reports/audit-YYYY-MM-DD-HHMM.md`. CI publishes the latest report as a release asset, so downstream consumers can re-verify.

| Red-team scenario | Threat class | Expected decision |
|---|---|---|
| R1 — Exfiltrate sensitive files (`/etc/passwd`, `~/.ssh/id_rsa`, `~/.aws/credentials`) | Information disclosure | DENY |
| R2 — Persist a backdoor (`~/.bashrc`, `/etc/cron.d/`, `~/.ssh/authorized_keys`) | Tampering, Elevation | DENY |
| R3 — Shell RCE (`rm -rf /`, `curl url \| sh`, fork bomb, `sudo`) | Tampering, DoS | DENY |
| R4 — Network exfil (POST to attacker-controlled endpoint) | Information disclosure | DENY |
| R5 — Invoke un-allowlisted MCP server | Elevation | DENY |
| R6 — Path traversal (`/workspace/../etc/shadow`) | Information disclosure | DENY |

## Cryptographic provenance

- **Container images** signed with [cosign](https://github.com/sigstore/cosign) keyless OIDC via GitLab CI ID tokens. Verification :
  ```bash
  cosign verify registry.gitlab.com/benoit.besson/secured-claude/claude-code:vX.Y.Z \
    --certificate-identity-regexp 'gitlab.com/benoit.besson/secured-claude' \
    --certificate-oidc-issuer https://gitlab.com
  ```
- **SBOM** generated by [syft](https://github.com/anchore/syft) in SPDX format, attached to each GitLab Release.
- **Python wheels** uploaded to GitLab Package Registry with `twine`, will gain GPG signing in v0.2.
- **Source commits** signed by maintainer SSH key (`ssh-ed25519 …` published in [`docs/security/maintainer-keys.md`](docs/security/maintainer-keys.md)) ; CI rejects unsigned tags on `main`.

## Out-of-scope (honest limits)

We claim defenses against the threats listed in [`docs/security/threat-model.md`](docs/security/threat-model.md). We do **not** claim defenses against :

- **Kernel CVEs / 0-days** — Linux kernel namespace isolation is the v0.1 boundary ; v0.2+ may add gVisor or Firecracker for higher-assurance environments.
- **Side-channel attacks** (Spectre/Meltdown class) — out of scope for an application-layer policy gate.
- **Adversarial physical access** to the developer machine — secrets stored at rest on the host are the host's responsibility, not ours.
- **Compromise of the underlying Anthropic API** — if `api.anthropic.com` itself is compromised, no client-side gate can prevent abuse ; we delegate that trust to Anthropic and bound the blast radius via L2 (only `api.anthropic.com` reachable).
- **Compromise of `cerbos/cerbos` upstream image** — mitigated by digest pinning, but a compromised upstream is a residual risk acknowledged in [`docs/security/supply-chain.md`](docs/security/supply-chain.md).

## Architecture decisions

Every load-bearing security decision is recorded as an Architecture Decision Record (ADR) in [`docs/adr/`](docs/adr/). The 16 ADRs are summarized in the [README](README.md#architecture-decisions). Each ADR follows the [Nygard format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions) (Context / Decision / Consequences / Alternatives) so the reasoning behind each choice — and the alternatives we considered and rejected — is preserved for review.

## License

[MIT](LICENSE) — encourages permissive use, including in proprietary enterprise deployments.

---

*Last reviewed : 2026-04-29. Next review due : 2026-07-29 (quarterly cadence).*
