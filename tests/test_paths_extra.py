"""Coverage tests for the OS-specific branches of `_paths.py` (ADR-0007)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from secured_claude import _paths


def test_data_dir_macos(tmp_path: Path, monkeypatch) -> None:
    """On darwin, base is ~/Library/Application Support."""
    monkeypatch.setattr(_paths.sys, "platform", "darwin")
    monkeypatch.setattr(_paths.Path, "home", classmethod(lambda cls: tmp_path))
    p = _paths.data_dir()
    assert "Library" in str(p)
    assert "Application Support" in str(p)
    assert p.name == _paths.APP_NAME


def test_data_dir_linux_default(tmp_path: Path, monkeypatch) -> None:
    """On Linux without XDG_DATA_HOME, fallback is ~/.local/share."""
    monkeypatch.setattr(_paths.sys, "platform", "linux")
    monkeypatch.setattr(_paths.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    p = _paths.data_dir()
    assert ".local/share" in str(p) or ".local\\share" in str(p)


def test_data_dir_linux_with_xdg(tmp_path: Path, monkeypatch) -> None:
    """On Linux with XDG_DATA_HOME set, base is the XDG path."""
    monkeypatch.setattr(_paths.sys, "platform", "linux")
    custom = tmp_path / "custom-xdg"
    monkeypatch.setenv("XDG_DATA_HOME", str(custom))
    p = _paths.data_dir()
    assert str(custom) in str(p)


def test_data_dir_windows(tmp_path: Path, monkeypatch) -> None:
    """On Windows, base is %LOCALAPPDATA% (or ~/AppData/Local fallback)."""
    monkeypatch.setattr(_paths.sys, "platform", "win32")
    custom = tmp_path / "AppData-Local"
    monkeypatch.setenv("LOCALAPPDATA", str(custom))
    p = _paths.data_dir()
    assert str(custom) in str(p)


def test_cache_dir_macos(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(_paths.sys, "platform", "darwin")
    monkeypatch.setattr(_paths.Path, "home", classmethod(lambda cls: tmp_path))
    p = _paths.cache_dir()
    assert "Caches" in str(p)


def test_cache_dir_linux(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(_paths.sys, "platform", "linux")
    monkeypatch.setattr(_paths.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    p = _paths.cache_dir()
    assert ".cache" in str(p)


def test_data_dir_chmod_oserror_swallowed(tmp_path: Path, monkeypatch) -> None:
    """On platforms where chmod is restricted, swallow the OSError gracefully."""
    monkeypatch.setattr(_paths.sys, "platform", "linux")
    monkeypatch.setattr(_paths.Path, "home", classmethod(lambda cls: tmp_path))

    with patch.object(Path, "chmod", side_effect=PermissionError("denied")):
        p = _paths.data_dir()
    assert p.exists()
