# 32. Auto-anchor cron templates (launchd / systemd)

Date: 2026-04-29
Status: Accepted

## Context

[ADR-0029](0029-external-hash-anchor.md) added `secured-claude audit-anchor` as the manual command to emit an external hash anchor. The ADR's "Negative" section :

> "Manual workflow : operators need to actually run `audit-anchor` periodically. A forgotten anchor doesn't catch tampering. v0.4.1 ticket : optional auto-anchor cron / launchd template."

This is the ticket. Without a daily anchor, the anchor's value drops to zero — the operator can only prove integrity at points they manually committed to, which they will forget.

## Decision

Ship two ready-to-edit templates :

- **`bin/launchd/com.secured-claude.audit-anchor.plist.example`** — macOS launchd plist that runs `secured-claude audit-anchor` daily at 04:30 local.
- **`bin/launchd/audit-anchor-wrapper.sh.example`** — wrapper script that produces date-stamped filenames (launchd's `StartCalendarInterval` can't substitute date placeholders) + prunes anchors older than 30 days + optionally hooks an external-sync command.
- **`bin/systemd/secured-claude-anchor.service.example`** — Linux systemd unit, oneshot.
- **`bin/systemd/secured-claude-anchor.timer.example`** — Linux systemd timer, daily at 04:30 with `RandomizedDelaySec=300`.

All four files end in `.example` so they aren't auto-loaded — operators copy + edit + load. The README's "Quick start" gets a new "Schedule daily anchors (optional)" section pointing at these.

### Wrapper script design

The wrapper handles the bits launchd / systemd timers can't do directly :

1. **Date-stamped output** : `anchor-YYYY-MM-DD.json` instead of overwriting one file. Lets operators retain history.
2. **Retention prune** : `find -mtime +30 -delete`. Configurable via `SECURED_CLAUDE_ANCHOR_RETENTION_DAYS` env.
3. **External-sync hook** : optional `SECURED_CLAUDE_ANCHOR_SYNC_CMD` env. If set, the wrapper runs `${CMD} <anchor-path>` after emitting. Operator wires this to their preferred external-store integration (`aws s3 cp`, `gh api releases create`, `git commit + push` to a public-anchor repo, …). The wrapper itself is sync-agnostic.
4. **Empty-DB tolerance** : `secured-claude audit-anchor` exits 1 on empty DB ; the wrapper catches it and exits 0 (no point in alarming on day-zero).

### What the templates DON'T do

- No automatic external-storage integration. Choosing where to store anchors (S3 with object-lock, GPG-signed git, Sigstore Rekor, RFC 3161 TSA, …) is operator threat-model territory ; the wrapper hooks but doesn't choose.
- No automatic key signing. Anchors are plain JSON ; operator can `gpg --sign` them, push to Rekor via cosign, etc. via the sync hook.
- No HA / leader election. If multiple machines run the same cron, they each emit their own anchors (different DBs). That's fine — anchors are per-DB.

## Consequences

**Positive** :
- Operators get a one-paste setup for daily anchors on both Linux and Mac.
- Hardening is built-in : the systemd unit ships with `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=read-only`, `ReadWritePaths=%h/.local/share/secured-claude`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `LockPersonality`, etc. Operators get the right cap-drop / namespace posture without thinking about it.
- The wrapper's external-sync hook is an extension point ; operators integrate their existing infra (S3, git, …) without forking the wrapper.
- 30-day retention default keeps the anchor dir small ; configurable via env.

**Negative** :
- Two platform-specific files (launchd + systemd). No Windows scheduled-task template ; v0.6 ticket if Windows demand surfaces. Documenting this gap.
- The cron is opt-in ; an operator who doesn't read the README still has manual-anchor-only. Acceptable — we ship a hint, not a mandate.

**Neutral** :
- No code change ; just static templates + a wrapper script. No tests required (the templates aren't part of the runtime ; copy-paste operations).

## Alternatives considered

- **Auto-install the cron during `secured-claude up`** — operators wouldn't expect a CLI verb to register a system cron. Surprising. Rejected.
- **systemd-timer-only, no launchd** — would skip Mac users (the project's primary dev fleet per CLAUDE.md). Rejected ; ship both.
- **A dedicated `secured-claude anchor schedule` CLI verb** — too magic ; the operator should see the actual unit file they're loading. Rejected.

## Verification

Static templates ; verification is editorial :

```
$ shellcheck bin/launchd/audit-anchor-wrapper.sh.example
(no output)

$ plutil -lint bin/launchd/com.secured-claude.audit-anchor.plist.example
... OK

$ systemd-analyze verify bin/systemd/secured-claude-anchor.service.example
(no output)
```

End-to-end (Mac, after operator setup) :

```
$ launchctl load ~/Library/LaunchAgents/com.secured-claude.audit-anchor.plist
$ launchctl list | grep secured-claude
0  -  com.secured-claude.audit-anchor
$ # Wait until 04:30 ; check ~/Library/Logs/secured-claude-anchor.log :
$ tail -3 ~/Library/Logs/secured-claude-anchor.log
✓ anchor written : ~/.local/share/secured-claude/anchors/anchor-2026-04-30.json
```

## References

- [ADR-0029](0029-external-hash-anchor.md) — `audit-anchor` CLI ; this ADR's automation companion
- launchd plist reference : https://developer.apple.com/library/archive/documentation/Darwin/Reference/ManPages/man5/launchd.plist.5.html
- systemd timer reference : https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html
- v0.6 ticket : Windows scheduled-task template if demand surfaces
