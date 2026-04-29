# ADR-0002: PreToolUse hook as the interception point

- **Status**: Accepted
- **Date**: 2026-04-29
- **Deciders**: Benoit Besson

## Context

To gate Claude Code's tool calls, we must intercept them BEFORE they execute. Where should the interception happen ?

Options :

1. **Patch the Claude Code binary** to add policy checks.
2. **Network proxy** (mitmproxy, etc.) in front of the Anthropic API to filter responses with tool calls.
3. **Use Claude Code's native hook system** (`PreToolUse`, `PostToolUse`, `UserPromptSubmit`).
4. **Replace the tools** by configuring Claude Code with custom MCP-like tools that proxy through us.

Constraints :

- Must be **forward-compatible** with Claude Code releases — Anthropic ships frequently.
- Must catch **every** tool intent — no escape hatch.
- Must be **fast** — interactive CLI cannot tolerate hundreds of ms per tool.
- Must be **observable** — every decision must be visible to the broker.

## Decision

We use Claude Code's native **`PreToolUse` hook** as the interception point. Each Claude Code session in our container is configured (via `~/.claude/settings.json` injected at container start) to run our `secured-claude-hook` binary on every tool intent.

The hook :

- Reads the tool intent JSON from stdin (Claude Code's convention)
- POSTs the intent to the host-side gateway at `http://host.docker.internal:8765/check`
- Receives an `{approve, reason}` response
- Outputs `{permissionDecision: allow|deny, permissionDecisionReason: …}` to stdout
- Exits 0 (proceed) or 2 (block, feed reason back to the model)

If the hook is unreachable / times out / errors → fail closed (see [ADR-0009](0009-hook-fails-closed.md)).

## Consequences

### Positive

- **No binary patching** — Claude Code is treated as a black box, sandboxed by our 4 layers. We follow Anthropic releases without breakage : the hook contract is part of Claude Code's stable API surface.
- **Single chokepoint** — every tool, present and future, passes through `PreToolUse`. New tools (Anthropic adds a `Database` tool tomorrow ?) hit the same hook automatically.
- **Sub-50 ms p99** — measured locally, the hook → gateway → Cerbos → response round-trip is well within budget. The local latency stack : ~1 ms hook process spawn + ~3 ms HTTP localhost + ~5 ms Cerbos eval + ~3 ms HTTP return = ~12 ms p50.
- **Observable decisions** — every check is captured in our SQLite audit log, regardless of approve / deny.
- **Compatible with future tools (MCP, Task, custom)** — the hook fires for any tool the Claude Code runtime invokes, including MCP server tools and Task sub-agent calls.

### Negative

- **Depends on Claude Code's hook semantics being stable** — if Anthropic deprecates / changes the hook contract, we have to adapt. Mitigated by : (a) hooks are documented in Claude Code's official docs, (b) the contract is simple, (c) Anthropic has held the hook contract stable for multiple releases.
- **Hook subprocess overhead** — every tool call spawns a Python interpreter. Mitigated by : (a) the hook is < 100 lines of code, (b) Python startup on the container's `python3-slim` is ~30 ms, dominated by the network round-trip anyway.
- **No interception for non-tool actions** — Claude Code's "thinking" / "speech" output is not gated (it's not a tool call). This is acceptable : pure output is not an action ; the threat is the action.

### Neutral

- We rely on Claude Code's `permissionDecision` JSON output convention. If they change the JSON shape, we update our hook script.

## Alternatives considered

- **Patch the Claude Code binary** — catastrophic maintenance burden, breaks every release, defeats the "comfort of Claude Code" goal. Rejected.
- **Mitmproxy in front of api.anthropic.com** — would require :
  - Injecting our root CA into the container's trust store
  - Parsing the Anthropic API's tool-use responses to filter / rewrite
  - Reassembling the streaming response without breaking the SDK contract
  - DNS bypass risk (Claude could resolve a different host if we're not careful)
  - Doesn't catch FS access from a Bash command Claude invokes
  Rejected — too invasive, fragile, and doesn't cover non-network threats anyway.
- **Replace tools with custom MCP servers** — interesting, but requires either (a) Claude Code being configured to ONLY use our MCP and refuse built-in tools (no native mechanism for that) or (b) us implementing every built-in tool (Read/Write/Edit/Bash/...) as MCP wrappers (massive scope). Rejected.
- **OS-level interception (LD_PRELOAD, syscall filter via seccomp-bpf)** — works for network/filesystem but :
  - Linux-only (defeats cross-platform goal)
  - Doesn't see "intents" — only resulting syscalls (so a `Bash` invocation that does many syscalls produces noise, not a single decision)
  - Complex profile authoring
  Useful as a *second* layer for v0.2+, but not the primary interception. Rejected as primary.

## References

- Anthropic Claude Code hooks documentation — https://docs.claude.com/en/docs/claude-code/hooks
- Hook script implementation — [`src/secured_claude/hook.py`](../../src/secured_claude/hook.py)
- Hook config injected at container start — [`docker/settings.template.json`](../../docker/settings.template.json)
- Test of hook stdout JSON contract — [`tests/test_hook_format.py`](../../tests/test_hook_format.py)
- Related ADRs : [0001](0001-cerbos-as-policy-decision-point.md), [0009](0009-hook-fails-closed.md), [0006](0006-host-side-broker.md)
