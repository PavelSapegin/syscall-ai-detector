"""Unit tests for ResponseEngine."""

from __future__ import annotations

import subprocess
import sys
import time
from collections.abc import Callable

from src.orchestrator.response import ResponseEngine


def test_kill_single_process(
    process_spawner: Callable[..., subprocess.Popen],
) -> None:
    """Test terminating an active target process."""
    proc = process_spawner("import time; time.sleep(30)")
    pid = proc.pid

    results = ResponseEngine.terminate_process_tree(pid)
    assert pid in results["killed"] or pid in results["already_dead"]
    proc.wait(timeout=2.0)
    assert proc.poll() is not None


def test_kill_process_tree(
    process_spawner: Callable[..., subprocess.Popen],
) -> None:
    """Test recursive termination of parent and spawned child."""
    py_exe = sys.executable
    parent_script = (
        "import subprocess, sys, time\n"
        f"child = subprocess.Popen(['{py_exe}', '-c', 'import time; time.sleep(30)'])\n"
        "time.sleep(30)\n"
    )
    parent = process_spawner(parent_script)
    parent_pid = parent.pid

    # Allow child time to spawn
    time.sleep(0.5)

    results = ResponseEngine.terminate_process_tree(parent_pid)
    assert parent_pid in results["killed"] or parent_pid in results["already_dead"]
    parent.wait(timeout=2.0)
    assert parent.poll() is not None


def test_already_dead_pid() -> None:
    """Test terminating a non-existent PID handles cleanly without failure."""
    dead_pid = 999999
    results = ResponseEngine.terminate_process_tree(dead_pid)
    assert dead_pid in results["already_dead"]
    assert len(results["failed"]) == 0


def test_explicit_descendants_kill(
    process_spawner: Callable[..., subprocess.Popen],
) -> None:
    """Test passing explicit descendant PIDs to terminate_process_tree."""
    proc1 = process_spawner("import time; time.sleep(30)")
    proc2 = process_spawner("import time; time.sleep(30)")

    results = ResponseEngine.terminate_process_tree(
        root_pid=proc1.pid,
        known_descendant_pids={proc2.pid},
    )

    all_terminated = set(results["killed"]) | set(results["already_dead"])
    assert proc1.pid in all_terminated
    assert proc2.pid in all_terminated
