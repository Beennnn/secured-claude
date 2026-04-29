"""Tests for cross-platform paths (ADR-0007)."""

from __future__ import annotations

from secured_claude._paths import APP_NAME, cache_dir, data_dir, db_path, log_path


def test_data_dir_exists_and_is_dir() -> None:
    p = data_dir()
    assert p.exists()
    assert p.is_dir()
    assert p.name == APP_NAME


def test_cache_dir_exists_and_is_dir() -> None:
    p = cache_dir()
    assert p.exists()
    assert p.is_dir()
    assert p.name == APP_NAME


def test_db_path_under_data_dir() -> None:
    assert db_path().parent == data_dir()
    assert db_path().name == "approvals.db"


def test_log_path_under_cache_dir() -> None:
    assert log_path().parent == cache_dir()
    assert log_path().name == "broker.log"
