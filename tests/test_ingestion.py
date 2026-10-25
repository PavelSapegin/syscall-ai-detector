"""Unit tests for EventIngestionWorker."""

from __future__ import annotations

import json
import time
from pathlib import Path

from src.orchestrator.ingestion import EventIngestionWorker
from src.orchestrator.registry import ProcessRegistry, ProcessStatus


def test_ingestion_routing(tmp_path: Path) -> None:
    """Test streaming ingestion and routing of event types into ProcessRegistry."""
    traces_path = tmp_path / "traces.jsonl"
    registry = ProcessRegistry()

    worker = EventIngestionWorker(
        traces_path=traces_path,
        registry=registry,
        read_from_beginning=True,
        poll_interval_s=0.02,
    )

    worker.start()
    time.sleep(0.1)

    events = [
        {
            "Timestamp": "2026-10-22 10:00:00.000",
            "EventType": "ProcessStart",
            "ProcessID": 5001,
            "ParentProcessID": 1000,
            "ImageFileName": "service.exe",
        },
        {
            "Timestamp": "2026-10-22 10:00:01.000",
            "EventType": "FileIOCreate",
            "ProcessID": 5001,
            "FileName": "C:\\config.ini",
        },
        {
            "Timestamp": "2026-10-22 10:00:02.000",
            "EventType": "ProcessStop",
            "ProcessID": 5001,
            "ExitCode": 0,
        },
    ]

    with open(traces_path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
            f.flush()

    time.sleep(0.3)
    worker.stop()

    assert worker.events_processed == 3
    proc = registry.get(5001)
    assert proc is not None
    assert proc.image_file_name == "service.exe"
    assert proc.status == ProcessStatus.STOPPED
    assert len(proc.events) == 3


def test_corrupted_json_and_incomplete_lines(tmp_path: Path) -> None:
    """Test handling of invalid JSON syntax and lines split across flush operations."""
    traces_path = tmp_path / "traces.jsonl"
    registry = ProcessRegistry()

    worker = EventIngestionWorker(
        traces_path=traces_path,
        registry=registry,
        read_from_beginning=True,
        poll_interval_s=0.02,
    )

    with open(traces_path, "w", encoding="utf-8") as f:
        # 1. Invalid JSON line
        f.write("CORRUPTED JSON LINE\n")
        f.flush()

    worker.start()
    time.sleep(0.1)

    # 2. Incomplete line chunk followed by remainder
    with open(traces_path, "a", encoding="utf-8") as f:
        f.write('{"Timestamp": "2026-10-22 10:00:00.000", "EventType": "FileIOWrite", ')
        f.flush()
        time.sleep(0.05)
        f.write('"ProcessID": 8000}\n')
        f.flush()

    time.sleep(0.3)
    worker.stop()

    assert worker.parse_errors >= 1
    assert worker.events_processed == 1
    assert registry.get(8000) is not None


def test_file_rotation(tmp_path: Path) -> None:
    """Test worker detects file rotation/truncation and continues reading."""
    traces_path = tmp_path / "traces.jsonl"
    registry = ProcessRegistry()

    # Create initial file with multiple events so file offset is large
    events = [
        {
            "Timestamp": "2026-10-22 10:00:00.000",
            "EventType": "ProcessStart",
            "ProcessID": 7001 + i,
            "ParentProcessID": 1,
            "ImageFileName": f"proc{i}.exe",
        }
        for i in range(5)
    ]
    traces_path.write_text(
        "".join(json.dumps(e) + "\n" for e in events), encoding="utf-8"
    )

    worker = EventIngestionWorker(
        traces_path=traces_path,
        registry=registry,
        read_from_beginning=True,
        poll_interval_s=0.02,
    )
    worker.start()
    time.sleep(0.2)

    assert registry.get(7001) is not None

    # Simulate rotation/truncation: rewrite file with smaller size and new event.
    # On Windows, deleting (unlink) an open file raises WinError 32, but in-place
    # truncation is supported and triggers curr_stat.st_size < trace_f.tell()
    new_event = {
        "Timestamp": "2026-10-22 10:00:05.000",
        "EventType": "ProcessStart",
        "ProcessID": 8888,
        "ParentProcessID": 1,
        "ImageFileName": "rotated.exe",
    }
    with open(traces_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(new_event) + "\n")

    time.sleep(0.3)
    worker.stop()

    assert registry.get(8888) is not None
