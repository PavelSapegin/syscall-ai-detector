"""Unit tests for MonitorSupervisor."""

from __future__ import annotations

import sys
import time

from src.orchestrator.supervisor import MonitorSupervisor


def test_start_and_stop_lifecycle() -> None:
    """Test starting and gracefully stopping a supervised process."""
    cmd = f'"{sys.executable}" -c "import time; time.sleep(10)"'
    supervisor = MonitorSupervisor(command=cmd, restart_cooldown_s=0.2)

    success = supervisor.start()
    assert success is True
    assert supervisor.is_alive
    assert supervisor.process is not None

    supervisor.stop(timeout_s=2.0)
    assert not supervisor.is_alive
    assert supervisor.process is None


def test_invalid_command_handled() -> None:
    """Test that bad command fails safely without uncaught exceptions."""
    supervisor = MonitorSupervisor(command="non_existent_executable_12345")
    success = supervisor.start()
    assert success is False
    assert not supervisor.is_alive


def test_watchdog_auto_restart() -> None:
    """Test watchdog auto-restarts process after unexpected death."""
    cmd = f'"{sys.executable}" -c "import time; time.sleep(10)"'
    supervisor = MonitorSupervisor(command=cmd, restart_cooldown_s=0.2)

    supervisor.start()
    assert supervisor.is_alive
    initial_proc = supervisor.process
    assert initial_proc is not None

    # Simulate unexpected crash by directly killing the subprocess
    initial_proc.kill()
    initial_proc.wait(timeout=1.0)

    # Allow watchdog to detect and restart (interval is 1.0s + cooldown 0.2s)
    time.sleep(2.0)

    assert supervisor.restart_count >= 1
    assert supervisor.is_alive
    assert supervisor.process is not None
    assert supervisor.process.pid != initial_proc.pid

    supervisor.stop()
