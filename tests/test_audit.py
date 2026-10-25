"""Unit tests for AuditLogger."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from src.orchestrator.audit import AuditLogger


def test_log_malicious_and_benign(tmp_path: Path) -> None:
    """Test JSONL records structure for both malicious and benign decisions."""
    audit_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit_path)

    # 1. Malicious decision
    logger.log_decision(
        target_pid=111,
        image_name="malware.exe",
        ppid=1,
        descendant_pids=[222],
        horizon=5.0,
        lifetime_s=5.1,
        probability=0.95,
        threshold=0.73,
        verdict="MALICIOUS",
        action="BLOCKED_AND_KILLED",
        termination_info={"killed": [111, 222]},
        top_signals={"n_events": 10},
    )

    # 2. Benign decision
    logger.log_decision(
        target_pid=333,
        image_name="calc.exe",
        ppid=1,
        descendant_pids=[],
        horizon=5.0,
        lifetime_s=5.2,
        probability=0.05,
        threshold=0.73,
        verdict="BENIGN",
        action="ALLOWED",
    )

    assert audit_path.exists()
    with open(audit_path, encoding="utf-8") as f:
        lines = [json.loads(line) for line in f if line.strip()]

    assert len(lines) == 2

    r1 = lines[0]
    assert r1["target_pid"] == 111
    assert r1["verdict"] == "MALICIOUS"
    assert r1["action"] == "BLOCKED_AND_KILLED"
    assert r1["killed_pids"] == [111, 222]
    assert r1["top_signals"]["n_events"] == 10

    r2 = lines[1]
    assert r2["target_pid"] == 333
    assert r2["verdict"] == "BENIGN"
    assert r2["action"] == "ALLOWED"


def test_concurrent_logging(tmp_path: Path) -> None:
    """Test thread-safe concurrent writing to audit log."""
    audit_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit_path)

    def writer_task(pid_start: int) -> None:
        for i in range(25):
            logger.log_decision(
                target_pid=pid_start + i,
                image_name="proc.exe",
                ppid=1,
                descendant_pids=[],
                horizon=5.0,
                lifetime_s=5.0,
                probability=0.1,
                threshold=0.5,
                verdict="BENIGN",
                action="ALLOWED",
            )

    threads = [
        threading.Thread(target=writer_task, args=(1000,)),
        threading.Thread(target=writer_task, args=(2000,)),
        threading.Thread(target=writer_task, args=(3000,)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    with open(audit_path, encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]

    assert len(records) == 75
