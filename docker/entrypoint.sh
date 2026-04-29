#!/usr/bin/env bash
# Entrypoint for the secured-claude/claude-code container.
# Materializes the user-side Claude Code settings file from the embedded
# template, then execs the binary the user requested (claude by default).

set -euo pipefail

TEMPLATE="/etc/secured-claude/settings.template.json"
SETTINGS="${HOME}/.claude/settings.json"

if [[ ! -f "${SETTINGS}" ]]; then
    mkdir -p "$(dirname "${SETTINGS}")"
    cp "${TEMPLATE}" "${SETTINGS}"
fi

# Sanity-check that an Anthropic credential is present. Either is accepted :
#   ANTHROPIC_API_KEY        — sk-ant-api03-...  (regular API key)
#   CLAUDE_CODE_OAUTH_TOKEN  — sk-ant-oat01-...  (Claude Code OAuth, e.g. from
#                               an active claude.ai/code subscription)
# claude binary picks the right one ; we just need at least one.
if [[ -z "${ANTHROPIC_API_KEY:-}" && -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]]; then
    echo "Neither ANTHROPIC_API_KEY nor CLAUDE_CODE_OAUTH_TOKEN is set." >&2
    echo "Set one in your .env (copy from .env.example) and re-run \`secured-claude up\`." >&2
    exit 78  # EX_CONFIG (sysexits.h)
fi

exec "$@"
