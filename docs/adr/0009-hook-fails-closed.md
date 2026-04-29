# ADR-0009: Hook fails closed (DENY on broker unreachable)

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

## Context

The PreToolUse hook ([ADR-0002](0002-pretooluse-hook-as-interception-point.md)) calls the host broker for every tool intent. What should happen if that call fails ?

Failure modes :

1. Broker not running (`secured-claude up` not invoked, or daemon crashed)
2. Network unreachable (rare on localhost, but possible if Docker network is misconfigured)
3. HTTP timeout (broker overloaded ; > 2s response time)
4. Cerbos PDP returning an unparsable response
5. Broker returns 5xx (bug, panic, OOM)

Two policy options :

- **Fail open** : if the hook can't reach the broker, ALLOW the tool by default. Pros : no friction when broker is down. Cons : adversary can DoS the broker (or just kill it) and bypass all policy.
- **Fail closed** : DENY the tool. Pros : no bypass. Cons : when broker is down, claude is unusable until fixed.

This is a fundamental security posture decision.

## Decision

The hook **fails closed** : on any error reaching or parsing the broker's response, the hook returns `permissionDecision: deny` with reason `broker unavailable: <error>` and exits non-zero, blocking the tool.

Specifically :

```python
try:
    resp = requests.post(
        f"http://{BROKER_HOST}:{BROKER_PORT}/check",
        json=request_body,
        timeout=2.0,
    )
    resp.raise_for_status()
    result = resp.json()
except (requests.RequestException, ValueError, KeyError) as e:
    print(json.dumps({
        "permissionDecision": "deny",
        "permissionDecisionReason": f"secured-claude broker unavailable: {type(e).__name__}: {e}",
    }))
    sys.exit(2)
```

Same posture for the broker → Cerbos call : if Cerbos is unreachable or returns an unparsable response, the broker returns `{approve: false, reason: "cerbos PDP unavailable"}` to the hook.

## Consequences

### Positive

- **No bypass** — an attacker who manages to kill the broker or crash Cerbos cannot suddenly get DENY-protected actions approved. The system FAILS into the safer state.
- **Aligns with NIST SP 800-53 SC-24** ("Fail in Known State") and FIPS 200 §3.5.7.
- **Aligns with industry best practice** for security gates : firewalls, ACL servers, IAM brokers all fail closed.
- **Forces operational hygiene** — if the broker is unreliable, devs notice immediately ; we can't accumulate "broker has been silently down for weeks" debt.

### Negative

- **Friction on broker outage** — if the broker crashes mid-session, claude appears to "lose all permissions". The user must restart `secured-claude up` to recover. Mitigated by : (a) `secured-claude doctor` quickly diagnoses, (b) the broker is a small Python process with low crash probability, (c) v0.2 may add auto-restart via launchd / systemd.
- **Tight timeout budget** — 2 seconds for the hook → broker round-trip is generous (typical p99 < 50 ms) but means a slow network or busy CPU could trip the timeout. Tested locally — under stress (100 concurrent hook calls), p99 stays under 200 ms. Acceptable.
- **No partial-degradation mode** — there's no "Cerbos is down but use last-known policy" mode. Considered, rejected : (a) "last known policy" is exactly the kind of stale-state trap fail-closed avoids, (b) Cerbos restart is fast (~2 sec), (c) defense-in-depth ([ADR-0012](0012-defense-in-depth-layers.md)) means even with the L1 policy down, L2/L3/L4 still constrain damage.

### Neutral

- We accept that fail-closed turns broker availability into an operational requirement. Documented in [SECURITY.md](../../SECURITY.md) and `secured-claude doctor` output.

## Alternatives considered

- **Fail open** — strictly worse. The whole point of the gate is to prevent unsafe actions ; if the gate stops working, the safer default is "stop everything", not "let everything through". Rejected.
- **Fail to last-known decision per `(principal, resource_kind, action)` cached locally** — accumulates risk over time : a policy that yesterday allowed `Bash git status` may today need to deny it (e.g. new threat ID'd) ; cache says ALLOW. Rejected for v0.1 — too easy to get wrong. Considered for v0.3+ with explicit cache TTL and signed cache entries.
- **Heartbeat / circuit-breaker pattern** — broker pings Cerbos every 5 sec, broker hook responses based on broker's view of Cerbos health. Slightly fancier ; same end state (fail closed when Cerbos is down). Tracked v0.2 if measured-need.
- **Bypass mode for "trusted" principals** — would let an admin role skip the check. Defeats the entire model. Rejected.

## References

- NIST SP 800-53 SC-24 (Fail in Known State) — https://csrc.nist.gov/Projects/risk-management/sp800-53-controls
- FIPS 200 §3.5.7 — https://csrc.nist.gov/publications/detail/fips/200/final
- Defense-in-depth principle ; secure defaults — [Saltzer & Schroeder, "The Protection of Information in Computer Systems" (1975)](https://www.cs.virginia.edu/~evans/cs551/saltzer/)
- Implementation : [`src/secured_claude/hook.py`](../../src/secured_claude/hook.py), [`src/secured_claude/gateway.py`](../../src/secured_claude/gateway.py)
- Test : [`tests/test_fail_closed.py`](../../tests/test_fail_closed.py) — verifies hook DENY on broker down, on Cerbos down, on malformed response
- Threat model — [`docs/security/threat-model.md`](../security/threat-model.md) §4 (TA-2 prompt-injected LLM attempting to disable broker)
- Related ADRs : [0002](0002-pretooluse-hook-as-interception-point.md), [0006](0006-host-side-broker.md), [0012](0012-defense-in-depth-layers.md)
