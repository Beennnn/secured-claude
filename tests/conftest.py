"""Pytest fixtures for secured-claude tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from secured_claude.store import Store


@pytest.fixture
def tmp_store(tmp_path: Path) -> Store:
    """A temporary Store backed by an in-tmp-dir SQLite DB."""
    return Store(path=tmp_path / "test.db")
