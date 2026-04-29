"""Cross-platform path resolution (ADR-0007).

XDG on Linux, Apple App Support on macOS, LOCALAPPDATA on Windows.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "secured-claude"


def data_dir() -> Path:
    """OS-conventional data directory for the audit DB and persistent state."""
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
    path = base / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def cache_dir() -> Path:
    """OS-conventional cache directory for non-essential, recreatable state."""
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache"))
    path = base / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    """Path to the append-only SQLite audit DB (ADR-0004)."""
    return data_dir() / "approvals.db"


def log_path() -> Path:
    """Path to the broker daemon's log file."""
    return cache_dir() / "broker.log"


__all__ = ["APP_NAME", "cache_dir", "data_dir", "db_path", "log_path"]
