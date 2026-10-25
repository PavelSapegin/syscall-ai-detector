"""End-to-End integration tests for Orchestrator."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from src.orchestrator.config import OrchestratorConfig
from src.orchestrator.main import Orchestrator
from src.orchestrator.registry import ProcessStatus


def _create_orchestrator(
    tmp_path: Path,
    horizon: float = 0.5,
    threshold: float = 0.7,
) -> Orchestrator:
    """Helper to initialize an orchestrator instance pointing to tmp_path."""
    config = OrchestratorConfig(
        horizon=horizon,
        timer_interval_s=0.15,
        traces_path=tmp_path / "traces.jsonl",
        audit_log_path=tmp_path / "audit.jsonl",
        log_file_path=tmp_path / "orchestrator.log",
        bypass_admin_check=True,
        mock_mode=False,
        threshold=threshold,
    )
    orch = Orchestrator(config)
    orch.ingestion_worker.read_from_beginning = True
    return orch


def test_e2e_benign_lifecycle(
    tmp_path: Path,
    sample_benign_events: list[dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end test: Benign process is permitted to continue running."""
    traces_path = tmp_path / "traces.jsonl"
    audit_path = tmp_path / "audit.jsonl"

    traces_path.write_text(
        "".join(json.dumps(ev) + "\n" for ev in sample_benign_events),
        encoding="utf-8",
    )

    # Use high threshold so notepad is evaluated benign
    orch = _create_orchestrator(tmp_path, horizon=0.5, threshold=0.99)
    monkeypatch.setattr(orch.inference_engine, "predict", lambda _: (0.1, False))
    orch.ingestion_worker.start()
    orch.scheduler.start()

    time.sleep(1.5)
    orch.scheduler.stop()
    orch.ingestion_worker.stop()

    assert audit_path.exists()
    raw_lines = audit_path.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in raw_lines if line]
    assert len(records) >= 1

    rec = next(r for r in records if r["target_pid"] == 4444)
    assert rec["verdict"] == "BENIGN"
    assert rec["action"] == "ALLOWED"

    proc = orch.registry.get(4444)
    assert proc is not None
    assert proc.status == ProcessStatus.EVALUATED_BENIGN


def test_e2e_malware_detection_and_blocking(
    tmp_path: Path,
    sample_malware_events: list[dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end test: Malware sequence is detected and blocked."""
    traces_path = tmp_path / "traces.jsonl"
    audit_path = tmp_path / "audit.jsonl"

    traces_path.write_text(
        "".join(json.dumps(ev) + "\n" for ev in sample_malware_events),
        encoding="utf-8",
    )

    orch = _create_orchestrator(tmp_path, horizon=0.5, threshold=0.5)
    monkeypatch.setattr(orch.inference_engine, "predict", lambda _: (0.9, True))
    orch.ingestion_worker.start()
    orch.scheduler.start()

    time.sleep(1.5)
    orch.scheduler.stop()
    orch.ingestion_worker.stop()

    assert audit_path.exists()
    raw_lines = audit_path.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in raw_lines if line]
    assert len(records) >= 1

    rec = next(r for r in records if r["target_pid"] == 8888)
    assert rec["verdict"] == "MALICIOUS"
    assert rec["action"] == "BLOCKED_AND_KILLED"

    proc = orch.registry.get(8888)
    assert proc is not None
    assert proc.status in (ProcessStatus.KILLED, ProcessStatus.MALICIOUS)


def test_e2e_mock_monitor_integration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end test: MockMonitor generates events that are evaluated."""
    traces_path = tmp_path / "traces.jsonl"
    audit_path = tmp_path / "audit.jsonl"
    log_path = tmp_path / "orchestrator.log"

    config = OrchestratorConfig(
        horizon=1.0,
        timer_interval_s=0.15,
        traces_path=traces_path,
        audit_log_path=audit_path,
        log_file_path=log_path,
        bypass_admin_check=True,
        mock_mode=True,
        mock_speedup=50.0,
        threshold=0.5,
    )
    orch = Orchestrator(config)
    monkeypatch.setattr(orch.inference_engine, "predict", lambda _: (0.9, True))
    orch.start()

    time.sleep(2.5)
    orch.stop()

    assert traces_path.exists()
    assert audit_path.exists()

    raw_lines = audit_path.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in raw_lines if line]
    assert len(records) > 0
