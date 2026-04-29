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

# Sanity-check the API key before we hand off to claude. claude itself will
# also error if missing, but failing here gives a clearer message.
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    echo "ANTHROPIC_API_KEY is not set in the container environment." >&2
    echo "Fill .env from .env.example then re-run \`secured-claude up\`." >&2
    exit 78  # EX_CONFIG (sysexits.h)
fi

exec "$@"
