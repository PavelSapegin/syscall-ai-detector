"""Unit tests for HorizonScheduler."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from src.orchestrator.audit import AuditLogger
from src.orchestrator.features_adapter import FeaturesAdapter
from src.orchestrator.inference import InferenceEngine
from src.orchestrator.registry import ProcessRegistry, ProcessStatus
from src.orchestrator.response import ResponseEngine
from src.orchestrator.scheduler import HorizonScheduler


@pytest.fixture
def scheduler_setup(tmp_path: Path, dummy_features_json: Path) -> dict:
    registry = ProcessRegistry()
    adapter = FeaturesAdapter(dummy_features_json)
    inference = MagicMock(spec=InferenceEngine)
    inference.threshold = 0.5
    inference.get_threshold.return_value = 0.5
    response = MagicMock(spec=ResponseEngine)
    response.terminate_process_tree.return_value = {
        "killed": [],
        "already_dead": [999],
        "failed": [],
    }
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLogger(audit_path)

    scheduler = HorizonScheduler(
        registry=registry,
        features_adapter=adapter,
        inference_engine=inference,
        response_engine=response,
        audit_logger=audit,
        horizon=2.0,
        interval_s=0.05,
    )

    return {
        "registry": registry,
        "adapter": adapter,
        "inference": inference,
        "response": response,
        "audit": audit,
        "audit_path": audit_path,
        "scheduler": scheduler,
    }


def test_scheduler_tick_benign(scheduler_setup: dict) -> None:
    """Test scheduler tick when process is classified as benign."""
    registry: ProcessRegistry = scheduler_setup["registry"]
    inference: MagicMock = scheduler_setup["inference"]
    scheduler: HorizonScheduler = scheduler_setup["scheduler"]
    audit_path: Path = scheduler_setup["audit_path"]

    # Configure inference to return non-malicious
    inference.predict.return_value = (0.15, False)

    # Register process started 3 seconds ago (horizon=2.0)
    t0 = datetime.now() - timedelta(seconds=3.0)
    registry.register_process_start(
        pid=555, ppid=1, image_file_name="calc.exe", timestamp=t0
    )
    registry.add_event(
        555,
        {
            "Timestamp": t0.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "EventType": "ProcessStart",
            "ProcessID": 555,
        },
    )

    # Run single tick
    scheduler._tick()

    proc = registry.get(555)
    assert proc is not None
    assert proc.status == ProcessStatus.EVALUATED_BENIGN
    assert 2.0 in proc.evaluated_horizons

    # Audit log was written
    assert audit_path.exists()
    raw_lines = audit_path.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in raw_lines if line]
    assert len(records) == 1
    assert records[0]["target_pid"] == 555
    assert records[0]["verdict"] == "BENIGN"
    assert records[0]["action"] == "ALLOWED"


def test_scheduler_tick_malicious(scheduler_setup: dict) -> None:
    """Test scheduler tick when process is classified as malicious and terminated."""
    registry: ProcessRegistry = scheduler_setup["registry"]
    inference: MagicMock = scheduler_setup["inference"]
    response: MagicMock = scheduler_setup["response"]
    scheduler: HorizonScheduler = scheduler_setup["scheduler"]
    audit_path: Path = scheduler_setup["audit_path"]

    # Configure inference to return malicious
    inference.predict.return_value = (0.92, True)

    t0 = datetime.now() - timedelta(seconds=3.0)
    registry.register_process_start(
        pid=666, ppid=1, image_file_name="bad.exe", timestamp=t0
    )
    registry.add_event(
        666,
        {
            "Timestamp": t0.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "EventType": "ProcessStart",
            "ProcessID": 666,
        },
    )

    # Run single tick
    scheduler._tick()

    proc = registry.get(666)
    assert proc is not None
    assert proc.status in (ProcessStatus.KILLED, ProcessStatus.MALICIOUS)
    assert 2.0 in proc.evaluated_horizons

    # Check response engine was called
    response.terminate_process_tree.assert_called_once()

    # Check audit log
    raw_lines = audit_path.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in raw_lines if line]
    assert len(records) == 1
    assert records[0]["target_pid"] == 666
    assert records[0]["verdict"] == "MALICIOUS"
    assert records[0]["action"] == "BLOCKED_AND_KILLED"


def test_scheduler_lifecycle(scheduler_setup: dict) -> None:
    """Test starting and stopping scheduler thread."""
    scheduler: HorizonScheduler = scheduler_setup["scheduler"]
    scheduler.start()
    assert scheduler._thread is not None
    assert scheduler._thread.is_alive()

    scheduler.stop()
    assert not scheduler._thread.is_alive()


def test_extract_top_signals(scheduler_setup: dict) -> None:
    """Test extracting summary of key behavioral features for audit log."""
    scheduler: HorizonScheduler = scheduler_setup["scheduler"]
    raw_features = {
        "n_events": 25,
        "n_ProcessStart": 2,
        "n_fio_create": 3,
        "unused_feature": 999,
    }
    signals = scheduler._extract_top_signals(raw_features)
    assert signals["n_events"] == 25
    assert signals["n_ProcessStart"] == 2
    assert signals["n_fio_create"] == 3
    assert "unused_feature" not in signals


def test_scheduler_cascade_progression(
    tmp_path: Path, dummy_features_json: Path
) -> None:
    """Test process progression through cascade: passes 2s, killed on 5s."""
    registry = ProcessRegistry()
    adapter = FeaturesAdapter(dummy_features_json)
    inference = MagicMock(spec=InferenceEngine)

    def mock_predict(dmatrix, horizon=None):
        if horizon == 2.0:
            return 0.1, False
        if horizon == 5.0:
            return 0.95, True
        return 0.99, True

    inference.predict.side_effect = mock_predict
    inference.get_threshold.return_value = 0.5

    response = MagicMock(spec=ResponseEngine)
    response.terminate_process_tree.return_value = {
        "killed": [9001],
        "already_dead": [],
        "failed": [],
    }

    audit_path = tmp_path / "audit_cascade.jsonl"
    audit = AuditLogger(audit_path)

    scheduler = HorizonScheduler(
        registry=registry,
        features_adapter=adapter,
        inference_engine=inference,
        response_engine=response,
        audit_logger=audit,
        horizons=[2.0, 5.0, 10.0],
        interval_s=0.05,
    )

    t0 = datetime.now() - timedelta(seconds=6.0)
    registry.register_process_start(
        pid=9001, ppid=1, image_file_name="suspicious.exe", timestamp=t0
    )
    registry.add_event(
        9001,
        {
            "Timestamp": t0.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "EventType": "ProcessStart",
            "ProcessID": 9001,
        },
    )

    # In single tick with age=6.0s:
    # 1. Horizon 2.0s is evaluated -> predict returns False -> 2.0 in evaluated_horizons
    # 2. Horizon 5.0s is evaluated -> predict returns True -> Process 9001 is killed!
    # 3. Horizon 10.0s: age (6.0s) has not reached 10.0s, plus process not alive
    scheduler._tick()

    proc = registry.get(9001)
    assert proc is not None
    assert 2.0 in proc.evaluated_horizons
    assert 5.0 in proc.evaluated_horizons
    assert 10.0 not in proc.evaluated_horizons
    assert proc.status in (ProcessStatus.KILLED, ProcessStatus.MALICIOUS)

    # Verify audit logs captured both evaluations (benign at 2s, malicious at 5s)
    raw_lines = audit_path.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in raw_lines if line]
    assert len(records) == 2
    assert records[0]["horizon_s"] == 2.0
    assert records[0]["verdict"] == "BENIGN"
    assert records[1]["horizon_s"] == 5.0
    assert records[1]["verdict"] == "MALICIOUS"
