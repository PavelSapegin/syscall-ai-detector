"""Unit tests for ProcessRegistry and ProcessRecord."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta

import pytest
from src.orchestrator.registry import ProcessRecord, ProcessRegistry, ProcessStatus


@pytest.fixture
def registry() -> ProcessRegistry:
    return ProcessRegistry(max_events_per_proc=100)


@pytest.fixture
def now() -> datetime:
    return datetime.now()


def test_process_record_status() -> None:
    """Test process record lifecycle and status transitions."""
    proc = ProcessRecord(pid=100)
    assert proc.status == ProcessStatus.ACTIVE
    assert proc.is_alive

    proc.status = ProcessStatus.STOPPED
    assert not proc.is_alive

    proc.status = ProcessStatus.KILLED
    assert not proc.is_alive

    proc.status = ProcessStatus.EVALUATED_BENIGN
    assert proc.is_alive

    proc.status = ProcessStatus.MALICIOUS
    # Malicious process is still running until explicitly killed
    assert proc.is_alive


def test_register_start_and_stop(registry: ProcessRegistry, now: datetime) -> None:
    """Test normal process start and stop recording."""
    proc = registry.register_process_start(
        pid=1001,
        ppid=1,
        image_file_name="app.exe",
        timestamp=now,
    )
    assert proc.pid == 1001
    assert proc.ppid == 1
    assert proc.image_file_name == "app.exe"
    assert proc.status == ProcessStatus.ACTIVE

    stop_time = now + timedelta(seconds=10)
    registry.register_process_stop(pid=1001, timestamp=stop_time, exit_code=0)
    assert proc.stop_time == stop_time
    assert proc.exit_code == 0
    assert proc.status == ProcessStatus.STOPPED


def test_killed_status_not_overwritten_by_stop(
    registry: ProcessRegistry, now: datetime
) -> None:
    """Ensure killed status survives a later ProcessStop event."""
    registry.register_process_start(
        pid=2001, ppid=1, image_file_name="bad.exe", timestamp=now
    )
    registry.mark_killed({2001})
    proc = registry.get(2001)
    assert proc is not None
    assert proc.status == ProcessStatus.KILLED

    # Later ProcessStop arrives
    registry.register_process_stop(
        pid=2001, timestamp=now + timedelta(seconds=1), exit_code=-9
    )
    assert proc.status == ProcessStatus.KILLED


def test_out_of_order_events(registry: ProcessRegistry, now: datetime) -> None:
    """Test child registration before parent, and events before ProcessStart."""
    # 1. Event arrives before ProcessStart
    registry.add_event(
        3001,
        {
            "Timestamp": now.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "EventType": "FileIOCreate",
            "ProcessID": 3001,
        },
    )
    proc = registry.get(3001)
    assert proc is not None
    assert len(proc.events) == 1

    # 2. ProcessStart arrives later
    registry.register_process_start(
        pid=3001, ppid=3000, image_file_name="test.exe", timestamp=now
    )
    assert proc.image_file_name == "test.exe"

    # 3. Parent registered after child
    parent = registry.register_process_start(
        pid=3000, ppid=1, image_file_name="parent.exe", timestamp=now
    )
    assert 3001 in (parent.children or {3001})


def test_hunt_tree_linear_and_branching(
    registry: ProcessRegistry, now: datetime
) -> None:
    """Test tree hunting for deep hierarchies and branching."""
    # Tree:
    #        10 (root)
    #       /  \
    #      20   30
    #     /
    #    40
    t0 = now
    registry.register_process_start(10, 1, "root.exe", t0)
    registry.register_process_start(20, 10, "child1.exe", t0 + timedelta(seconds=1))
    registry.register_process_start(30, 10, "child2.exe", t0 + timedelta(seconds=2))
    registry.register_process_start(40, 20, "grandchild.exe", t0 + timedelta(seconds=3))

    registry.add_event(
        40,
        {
            "Timestamp": (t0 + timedelta(seconds=4)).strftime("%Y-%m-%d %H:%M:%S.%f"),
            "EventType": "FileIOWrite",
            "ProcessID": 40,
        },
    )
    registry.add_event(
        10,
        {
            "Timestamp": (t0 + timedelta(seconds=1)).strftime("%Y-%m-%d %H:%M:%S.%f"),
            "EventType": "FileIOCreate",
            "ProcessID": 10,
        },
    )

    pids, events = registry.hunt_process_tree(10)
    assert pids == {10, 20, 30, 40}
    assert len(events) == 2
    # Check chronological ordering
    assert events[0]["ProcessID"] == 10
    assert events[1]["ProcessID"] == 40

    # Hunting from child2 (30) returns only {30}
    pids_sub, _ = registry.hunt_process_tree(30)
    assert pids_sub == {30}


def test_candidate_roots_filter(registry: ProcessRegistry, now: datetime) -> None:
    """Test criteria for selecting candidate processes for horizon evaluation."""
    t0 = now
    # Candidate 1: age 5.5s (eligible for horizon 5.0)
    registry.register_process_start(100, 1, "proc1.exe", t0 - timedelta(seconds=5.5))

    # Candidate 2: age 2.0s (not eligible for horizon 5.0)
    registry.register_process_start(200, 1, "proc2.exe", t0 - timedelta(seconds=2.0))

    # Candidate 3: age 6.0s but already evaluated for 5.0
    p3 = registry.register_process_start(
        300, 1, "proc3.exe", t0 - timedelta(seconds=6.0)
    )
    p3.evaluated_horizons.add(5.0)

    # Candidate 4: age 6.0s but already killed
    p4 = registry.register_process_start(
        400, 1, "proc4.exe", t0 - timedelta(seconds=6.0)
    )
    p4.status = ProcessStatus.KILLED

    candidates = registry.get_candidate_roots_for_horizon(5.0, t0)
    candidate_pids = {c.pid for c in candidates}
    assert candidate_pids == {100}


def test_mark_evaluated(registry: ProcessRegistry, now: datetime) -> None:
    """Test mark_evaluated status updates for benign and malicious."""
    p1 = registry.register_process_start(10, 1, "benign.exe", now)
    registry.mark_evaluated(10, 5.0, is_malicious=False)
    assert 5.0 in p1.evaluated_horizons
    assert p1.status == ProcessStatus.EVALUATED_BENIGN

    p2 = registry.register_process_start(20, 1, "bad.exe", now)
    registry.mark_evaluated(20, 5.0, is_malicious=True)
    assert 5.0 in p2.evaluated_horizons
    assert p2.status == ProcessStatus.MALICIOUS


def test_cleanup_old_processes(registry: ProcessRegistry, now: datetime) -> None:
    """Test pruning stopped processes exceeding TTL while preserving active."""
    old_time = now - timedelta(seconds=500)
    # Active process - should NOT be removed
    registry.register_process_start(10, 1, "active.exe", old_time)

    # Recently stopped process - should NOT be removed (TTL=300s)
    registry.register_process_start(20, 1, "recent_stop.exe", old_time)
    registry.register_process_stop(20, now - timedelta(seconds=50))

    # Ancient stopped process - SHOULD be removed
    registry.register_process_start(30, 1, "ancient_stop.exe", old_time)
    registry.register_process_stop(30, now - timedelta(seconds=400))

    removed = registry.cleanup_old_processes(max_age_seconds=300.0)
    assert removed == 1
    assert registry.get(10) is not None
    assert registry.get(20) is not None
    assert registry.get(30) is None


def test_concurrent_access(registry: ProcessRegistry, now: datetime) -> None:
    """Test thread safety under simultaneous readers and writers."""
    errors: list[Exception] = []

    def writer(start_pid: int) -> None:
        try:
            for i in range(100):
                pid = start_pid + i
                registry.register_process_start(pid, 1, "test.exe", now)
                registry.add_event(
                    pid,
                    {
                        "Timestamp": now.strftime("%Y-%m-%d %H:%M:%S.%f"),
                        "EventType": "FileIOCreate",
                        "ProcessID": pid,
                    },
                )
        except Exception as e:
            errors.append(e)

    def reader() -> None:
        try:
            for _ in range(50):
                registry.get_candidate_roots_for_horizon(
                    5.0, now + timedelta(seconds=10)
                )
                registry.hunt_process_tree(1000)
        except Exception as e:
            errors.append(e)

    threads = [
        threading.Thread(target=writer, args=(1000,)),
        threading.Thread(target=writer, args=(2000,)),
        threading.Thread(target=reader),
        threading.Thread(target=reader),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Thread errors: {errors}"
