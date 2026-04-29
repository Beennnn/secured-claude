"""Allow `python -m secured_claude` to invoke the CLI."""

from __future__ import annotations

from secured_claude.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
