# 22. Defense-in-depth — one intent layer + three confinement layers (supersedes ADR-0012)

Date: 2026-04-29
Status: Accepted (supersedes [ADR-0012](0012-defense-in-depth-layers.md))

## Context

[ADR-0012](0012-defense-in-depth-layers.md) framed the project's security posture as **"4 independent layers, each independently sufficient to block the class of attack it covers."** That framing was useful in v0.1 because it justified building four mechanisms instead of just one, but it overstates what the non-L1 layers actually do.

A careful reviewer pointed out the gap :

> "CLAUDE.md dit '4 independent layers', mais en réalité le hook Claude reste le point d'interception logique principal. Docker limite les dégâts, il ne comprend pas l'intention métier de l'action."

This is correct. **Only L1 understands the agent's intent.** When Claude Code wants to read `/etc/passwd`, the PreToolUse hook sees the abstract operation `Read(/etc/passwd)`, hands the resource description to Cerbos, and gets back a `permissionDecision: allow|deny` based on a policy that mentions `/etc/passwd` by name. That's a *semantic* decision.

The other layers don't see intent at all :

- **L2 (egress proxy)** sees `CONNECT evil.com:443` — a TCP destination, not "Claude is exfiltrating data."
- **L3-DNS (dnsmasq)** sees `A? evil.com` — a name lookup, not "Claude is encoding a payload in a hostname."
- **L3-FS (workspace mount)** sees `open(/etc/passwd, O_RDONLY)` — a syscall on a path that isn't mounted into the container, so it returns ENOENT before the kernel even checks the agent's UID. There's no "Claude wants to read passwords" judgement happening — there's just a path that doesn't exist in this namespace.
- **L4 (cap_drop, read_only, seccomp, cgroups)** sees attempted syscalls vs. what the kernel allows. Pure structural enforcement.

So the v0.1 framing — "4 independent layers, each sufficient" — is technically false. **L2/L3/L4 cannot replace L1 ; they can only bound the damage if L1 is bypassed.**

## Decision

Reframe the architecture as **one intent layer + three confinement layers**. Update README, SECURITY.md, threat-model.md, and ADR-0012's status.

### The honest contract

```
   ┌──────────────────────────────────────────────────────────────┐
   │ L1 — Intent layer (Cerbos PDP via PreToolUse hook)          │
   │  - Sees the abstract operation : Read("/etc/passwd")        │
   │  - Reasons about policy in domain terms : "this path is on │
   │    the deny-list because *.ssh, *.aws, *.env, etc."         │
   │  - Refuses or approves, audit-logged with reason            │
   │  → THIS is the semantic gate. Block here = no harm done.    │
   └──────────────────────────────────────────────────────────────┘
                           │ if bypassed (CVE, prompt-injection,
                           │  runtime-patched binary, ...)
                           ▼
   ┌──────────────────────────────────────────────────────────────┐
   │ L2 — Network egress confinement (tinyproxy + dnsmasq)        │
   │  - Sees CONNECT host:port + DNS A/AAAA queries              │
   │  - Refuses anything not on the destination allowlist        │
   │  → Bounds blast radius: even a compromised binary can       │
   │    only talk to api.anthropic.com.                          │
   └──────────────────────────────────────────────────────────────┘
                           │
                           ▼
   ┌──────────────────────────────────────────────────────────────┐
   │ L3 — Filesystem confinement (workspace-only mount)           │
   │  - Sees syscalls against the agent's namespace              │
   │  - Host's /Users, /etc, /root, ~/.ssh aren't there          │
   │  → Bounds blast radius: agent can't read what isn't mounted.│
   └──────────────────────────────────────────────────────────────┘
                           │
                           ▼
   ┌──────────────────────────────────────────────────────────────┐
   │ L4 — Container hardening (cap_drop ALL, read_only,          │
   │       seccomp, no-new-privs, mem_limit, non-root UID)       │
   │  - Sees raw syscall attempts at the kernel boundary         │
   │  - Refuses privileged ops the agent should never need       │
   │  → Bounds blast radius: even with a kernel CVE, escalation │
   │    routes are minimised.                                    │
   └──────────────────────────────────────────────────────────────┘
```

### What this changes

**Claim** :
- ❌ "4 independent layers, each independently sufficient to block its threat class"
- ✅ "1 intent layer (the primary semantic gate) + 3 confinement layers (blast-radius bounds for if L1 is bypassed)"

**Threat-model consequence** :
- The "what if Cerbos has a CVE ?" question used to get the answer "L2 + L3 + L4 still hold." That's true but misleading — they hold *structurally*, not *semantically*. A compromised L1 means the agent can do whatever the structural layers happen to permit, which for tools like Bash with allowlisted commands could still be substantial damage inside `/workspace/`.
- The honest answer is : "L2/L3/L4 ensure the damage is bounded to the agent's container — they prevent host compromise and exfiltration to attacker-controlled servers, but they don't replace L1's semantic understanding."

**What stays the same** :
- The implementation. We still build all four layers. Each one closes a specific class of attack.
- The defense-in-depth principle. Multiple independent mechanisms still > single point of enforcement.
- The dependency relationships. L2/L3 still implement [ADR-0010](0010-network-egress-filter-allowlist.md) ; L4 still implements [ADR-0005](0005-containerised-claude-code.md) ; etc.

## Consequences

**Positive** :
- The marketing claim "secured by design — 4 layers" no longer overpromises. A security review can verify each layer's actual contract instead of being misled by the "independently sufficient" framing.
- Future architecture discussions can correctly identify L1 as the load-bearing semantic component. Hardening L1 (signed Cerbos policy bundles, audit log integrity, fail-closed semantics) gets the priority it deserves.
- The README's "Honest scoring" table now matches reality : L1 = intent, L2-L4 = confinement.

**Negative** :
- The pitch is slightly less punchy. "1 intent + 3 confinement" doesn't fit on a slide as cleanly as "4 layers." Acceptable trade-off for honesty.
- Existing references to "ADR-0012's 4-layer model" in earlier ADRs (0019, 0020) need to point to ADR-0022 instead. We update those references in this commit.

**Neutral** :
- No code change. Pure framing.
- Renamed concept doesn't break Renovate, doesn't break CI, doesn't break tests.

## Alternatives considered

- **Don't reframe — keep ADR-0012 as-is** : preserves the catchier marketing claim but accumulates dishonesty as the project matures. Rejected — security projects can't afford even small overstatements ; one is the camel's nose.
- **Split into 4 ADRs (one per layer)** : more granular but loses the holistic "how the layers relate" picture. Rejected — the architectural view is the value-add.
- **Reframe more aggressively as "L1 only matters"** : technically false too. The confinement layers do real work — without L4, a kernel CVE chain could escape ; without L3-FS, host secrets are reachable from approved Bash. They're not vestigial. Rejected.

## Implementation in this commit

- `docs/adr/0012-defense-in-depth-layers.md` — Status changed to `Superseded by ADR-0022`. Added a header note pointing to this ADR.
- `README.md` — "What this project demonstrates mastery of" + "Status — verify in 60 seconds" + "Honest scoring" tables updated to use the intent/confinement framing.
- `SECURITY.md` — Layer table column "v0.2 status" reframed ; commentary now says "L1 is the semantic gate ; L2-L4 bound the blast radius."
- `docs/security/threat-model.md` — Trust boundaries diagram updated.
- `docs/adr/0019-l2-egress-proxy-tinyproxy.md`, `docs/adr/0020-l3-dns-allowlist-dnsmasq.md` — references to ADR-0012 updated to point to ADR-0022 alongside it.

## Verification

This is a documentation reframe, so verification is editorial :

- The phrase "independently sufficient" no longer appears in any user-facing doc (README, SECURITY).
- The phrase "intent layer" or "confinement layer" appears wherever a layer is described.
- A reviewer reading the README + ADR-0022 cold gets the same mental model that a reviewer reading the source code would.

`grep -rn "independently sufficient\|each independently" README.md SECURITY.md docs/` → returns nothing in user-facing docs (only in ADR-0012's superseded note + ADR-0022's "what changes" section, both correctly framing the change).

## References

- [ADR-0012](0012-defense-in-depth-layers.md) — original 4-layer framing, superseded by this ADR
- [ADR-0001](0001-cerbos-as-policy-decision-point.md) — L1 (intent) implementation
- [ADR-0010](0010-network-egress-filter-allowlist.md) — L2 design intent (now realised as confinement layer)
- [ADR-0019](0019-l2-egress-proxy-tinyproxy.md) — tinyproxy egress (the realised L2)
- [ADR-0020](0020-l3-dns-allowlist-dnsmasq.md) — dnsmasq DNS allowlist (the realised L3-DNS)
- [ADR-0005](0005-containerised-claude-code.md) — L3-FS + L4 implementation
- Reviewer feedback that triggered this reframe : commit message references "Points faibles restants" 2026-04-29
