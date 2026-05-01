# Debug : `claude -p` hangs inside the agent container

**Status (2026-05-01)** : ✅ **FIXED**. Root cause was EROFS on
`/home/agent/.claude.json` ; fix applied via tmpfs mount on
`/home/agent` (8 MB, owned by uid=1001) in `docker-compose.yml`.
Verified end-to-end : `claude -p "say hello"` now responds in ~5 s
(was : 30 s silent hang) and a Read tool invocation produces a
PreToolUse hook → broker `POST /check` → Cerbos ALLOW → audit row.

## Symptom

```
$ docker exec secured-claude-agent claude -p "say hello"
# (silence — no output)
# at t=30s, exits with code 0, no stdout, no stderr
```

The `/check` hook never fires (no audit row, no broker /check log
entry). The user sees a 30 s hang followed by silent exit.

## Reproducer

```bash
secured-claude up

# Detached run with output redirected to a tmpfs file in the container :
docker exec -d secured-claude-agent sh -c \
  'CLAUDE_DEBUG=1 claude -p "say hi" > /tmp/claude-out.log 2>&1; \
   echo "exit=$?" >> /tmp/claude-out.log'

# Sample at t=5, 15, 30 s :
docker exec secured-claude-agent stat -c %s /tmp/claude-out.log
# t=5  → 0 B
# t=15 → 0 B
# t=30 → 7 B   (just "exit=0")

# Process list (no `ps` in slim container, use /proc) :
for pid in $(docker exec secured-claude-agent ls /proc | grep -E "^[0-9]+$"); do
  cmd=$(docker exec secured-claude-agent cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
  [ -n "$cmd" ] && echo "$pid : $cmd"
done

# Claude's own debug log (the gold) :
docker exec secured-claude-agent cat /home/agent/.claude/debug/latest
```

## Root cause

Two failures stack to produce the silent 30 s hang :

### Issue 1 — EROFS on `/home/agent/.claude.json`

Claude Code persists user-level config (auth state, default flags,
theme) at `/home/agent/.claude.json` — a single file at HOME root.
Our agent compose has `read_only: true` (ADR-0029 hardening) with
mounts only for :

| Path | Mount type | RW |
|---|---|---|
| `/tmp` | tmpfs | ✅ |
| `/run` | tmpfs | ✅ |
| `/home/agent/.cache` | tmpfs | ✅ |
| `/home/agent/.claude/` | named volume `claude-state` | ✅ |

**`/home/agent/.claude.json`** sits at the HOME root, NOT inside the
`/home/agent/.claude/` volume. Its parent (`/home/agent/`) is the
read-only image layer → every claude startup fails to persist config.

Debug log evidence :

```
[ERROR] Failed to save config with lock: ENOENT '/home/agent/.claude.json'
[ERROR] Failed to write file atomically: EROFS '/home/agent/.claude.json.tmp.62.1777631836452'
[DEBUG] Falling back to non-atomic write for /home/agent/.claude.json
[DEBUG] Non-atomic write also failed: EROFS '/home/agent/.claude.json'
```

### Issue 2 — Remote settings timeout (30 s)

Without persistent config, claude can't resolve some auth/account
state, so its `Remote settings: Loading promise` (an HTTP call to
`api.anthropic.com` for account-level settings) blocks for the full
30 s default timeout, then "resolves anyway" :

```
2026-05-01T10:37:46.448Z [DEBUG] Remote settings: Loading promise timed out, resolving anyway
```

After the timeout, claude exits with code 0 but produces no stdout —
likely an unhandled "settings missing" code path silently bails on
the prompt invocation.

## Hypotheses ruled out

The previous TASKS.md hypothesis listed three candidates ; the trace
disproves all three :

- ❌ **OAuth token re-use rejection** — the agent container has its
  OWN `CLAUDE_CODE_OAUTH_TOKEN` env var, distinct from the host
  session token. Token re-use isn't the issue (the host's session
  uses a DIFFERENT token).
- ❌ **`claude --print` non-interactive startup quirk** — claude
  starts fine, reads its prompt, runs through init. The hang is
  specifically the remote-settings load, not a TTY/non-interactive
  issue.
- ❌ **Waits for interactive prompt** — the cmdline is `claude -p
  "say hi"` (non-interactive), and stdin is closed via `sh -c`.
  Claude does NOT wait for a prompt ; it waits for a network call
  that's gated on local config that can't be persisted.

## Why egress / DNS allowlist is NOT the cause

Earlier hypothesis : the L2 tinyproxy CONNECT allowlist or L3
dnsmasq DNS allowlist might block `api.anthropic.com`. Disproven :

- `*.anthropic.com` is in both allowlists.
- DNS resolution from inside the container works (logs show
  `dnsmasq[1]: cached api.anthropic.com is 160.79.104.10`).
- A bare `curl https://console.anthropic.com` from inside the
  container returns 302 reachably.

The hang is NOT a confinement leak ; it's a HOME-write permission
issue stacking with claude's settings-loader timeout.

## Fix (applied 2026-05-01)

Add `/home/agent` as a tmpfs mount in `docker-compose.yml` —
ephemeral HOME, ~1 MB cap (just enough for `.claude.json`). The
existing named-volume mount for `/home/agent/.claude/` overlays
on top, preserving session state. The cache tmpfs stays as-is.

```yaml
services:
  claude-code:
    read_only: true
    tmpfs:
      - /tmp:rw,nosuid,nodev,size=512m
      - /run:rw,nosuid,nodev,size=64m
      - /home/agent:rw,nosuid,nodev,size=8m,uid=1001,gid=1001  # NEW
      - /home/agent/.cache:rw,nosuid,nodev,size=512m
    volumes:
      - claude-state:/home/agent/.claude       # overlays HOME tmpfs
```

Trade-off : `/home/agent/.claude.json` is now ephemeral (lost on
container restart). Claude Code re-creates it on every startup
anyway, so this is acceptable. Session state (`/home/agent/.claude/`)
remains persistent via the named volume.

Note : the tmpfs needs `uid=1001,gid=1001` so the agent user (UID
1001 per Dockerfile.claude-code) actually owns it. Without those
options, the tmpfs mounts as root-owned mode 755 and the unprivileged
agent user gets EACCES → same broken behavior as before.

Hardening posture preserved : the rest of `/home/agent` is still
inaccessible to writes from the image layer ; the tmpfs only gives
write access to a small per-container scratch zone capped at 8 MB
and owned by the unprivileged agent user.

## Verification (passed 2026-05-01 12:43)

```bash
$ secured-claude down && secured-claude up
$ docker exec secured-claude-agent claude -p "say hello in 3 words"
Hello there, friend!     # ← was : silent for 30 s, then exit 0 with no output

$ docker exec secured-claude-agent claude -p "read /workspace/test-read.txt and tell me what it says"
The file contains one line:
> Hello from workspace test file

# Audit log shows the PreToolUse hook fired (file/read ALLOW) :
$ sqlite3 ~/Library/Application\ Support/secured-claude/approvals.db \
    "select ts, decision, resource_kind, resource_id from approvals order by ts desc limit 1"
2026-05-01T10:44:08.603+00:00|ALLOW|file|/workspace/test-read.txt

# Broker log shows the /check POST :
$ tail ~/Library/Application\ Support/secured-claude/broker.log
INFO: 127.0.0.1:55645 - "POST /check HTTP/1.1" 200 OK
```

End-to-end stack confirmed working : claude → PreToolUse hook → broker
→ Cerbos → ALLOW → claude executes Read → audit row inserted.

## Side finding — `secured-claude audit --since` filter bug

`secured-claude audit --since 2m` returned 0 rows even though the
new audit row WAS in the SQLite DB. `--since 1h` returned older rows
but missed the most recent. Likely a clock/timezone bug in the
`--since` parser. Filed for follow-up — not blocking the main fix.

## Related

- ADR-0005 — containerised claude-code (hardening rationale)
- ADR-0029 — read-only root FS (origin of the EROFS constraint)
- ADR-0009 — hook fail-closed (broker MUST stay reachable)
- TASKS.md item #2 (this issue)
