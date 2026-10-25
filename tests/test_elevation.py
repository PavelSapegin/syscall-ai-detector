"""Unit tests for elevation and admin privilege checks."""

from __future__ import annotations

import sys

import pytest
from src.orchestrator.elevation import is_running_as_admin, verify_admin_privileges


def test_is_running_as_admin_unix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test elevation check on non-Windows platforms using os.geteuid."""
    monkeypatch.setattr(sys, "platform", "linux")

    # Simulate root (uid 0)
    monkeypatch.setattr("os.geteuid", lambda: 0, raising=False)
    assert is_running_as_admin() is True

    # Simulate non-root (uid 1000)
    monkeypatch.setattr("os.geteuid", lambda: 1000, raising=False)
    assert is_running_as_admin() is False


def test_is_running_as_admin_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test elevation check on Windows platform using ctypes mock."""
    monkeypatch.setattr(sys, "platform", "win32")

    mock_shell32 = type("MockShell32", (), {"IsUserAnAdmin": lambda: 1})
    mock_ctypes = type(
        "MockCtypes", (), {"windll": type("MockWindll", (), {"shell32": mock_shell32})}
    )
    monkeypatch.setitem(sys.modules, "ctypes", mock_ctypes)
    assert is_running_as_admin() is True


def test_verify_admin_privileges_elevated(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that verify_admin_privileges passes when elevated."""
    monkeypatch.setattr("src.orchestrator.elevation.is_running_as_admin", lambda: True)
    # Should not raise any exception
    verify_admin_privileges(bypass=False)


def test_verify_admin_privileges_bypass(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that bypass=True allows execution even without privileges."""
    monkeypatch.setattr("src.orchestrator.elevation.is_running_as_admin", lambda: False)
    # Should not raise any exception when bypass is True
    verify_admin_privileges(bypass=True)


def test_verify_admin_privileges_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that PermissionError is raised when not elevated and bypass=False."""
    monkeypatch.setattr("src.orchestrator.elevation.is_running_as_admin", lambda: False)
    with pytest.raises(PermissionError, match="requires Administrator privileges"):
        verify_admin_privileges(bypass=False)
