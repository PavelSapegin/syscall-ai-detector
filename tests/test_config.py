"""Unit tests for OrchestratorConfig and CLI argument parsing."""

from __future__ import annotations

from pathlib import Path

import pytest
from src.orchestrator.config import OrchestratorConfig, parse_args


def test_default_config() -> None:
    """Test default values of OrchestratorConfig dataclass."""
    cfg = OrchestratorConfig()
    assert cfg.horizon == 5.0
    assert cfg.model_path == Path("out/models/xgboost_horizon_5s.json")
    assert cfg.metrics_path == Path("out/models/metrics_horizon_5s.json")
    assert cfg.reference_features_path == Path(
        "out/models/reference_features_horizon_5s.json"
    )
    assert cfg.threshold is None
    assert cfg.traces_path == Path("traces.jsonl")
    assert cfg.monitor_cmd is None
    assert cfg.audit_log_path == Path("out/audit.jsonl")
    assert cfg.log_file_path == Path("out/orchestrator.log")
    assert cfg.timer_interval_s == 0.5
    assert not cfg.bypass_admin_check
    assert not cfg.mock_mode
    assert cfg.mock_speedup == 1.0
    assert cfg.process_ttl_s == 300.0


def test_parse_args_defaults() -> None:
    """Test parse_args with empty argument list returns default paths for horizon 5s."""
    cfg = parse_args([])
    assert cfg.horizon == 5.0
    assert cfg.model_path == Path("out/models/xgboost_horizon_5s.json")
    assert cfg.metrics_path == Path("out/models/metrics_horizon_5s.json")
    assert cfg.reference_features_path == Path(
        "out/models/reference_features_horizon_5s.json"
    )
    assert cfg.threshold is None
    assert not cfg.bypass_admin_check
    assert not cfg.mock_mode


@pytest.mark.parametrize("h", [2.0, 10.0, 30.0])
def test_parse_args_horizon_dynamic_paths(h: float) -> None:
    """Test that setting horizon dynamically adjusts default model and metric paths."""
    h_int = int(h)
    cfg = parse_args(["--horizon", str(h)])
    assert cfg.horizon == h
    assert cfg.model_path == Path(f"out/models/xgboost_horizon_{h_int}s.json")
    assert cfg.metrics_path == Path(f"out/models/metrics_horizon_{h_int}s.json")
    assert cfg.reference_features_path == Path(
        f"out/models/reference_features_horizon_{h_int}s.json"
    )


def test_parse_args_custom_overrides(tmp_path: Path) -> None:
    """Test explicit command-line overrides for paths and flags."""
    custom_model = tmp_path / "custom_model.json"
    custom_metrics = tmp_path / "custom_metrics.json"
    custom_ref = tmp_path / "custom_ref.json"
    custom_traces = tmp_path / "custom_traces.jsonl"
    custom_audit = tmp_path / "custom_audit.jsonl"
    custom_log = tmp_path / "custom.log"

    args = [
        "--horizon",
        "10",
        "--model-path",
        str(custom_model),
        "--metrics-path",
        str(custom_metrics),
        "--reference-features",
        str(custom_ref),
        "--threshold",
        "0.82",
        "--traces-path",
        str(custom_traces),
        "--monitor-cmd",
        "SyscallMonitor.exe",
        "--audit-log",
        str(custom_audit),
        "--log-file",
        str(custom_log),
        "--timer-interval",
        "0.25",
        "--bypass-admin-check",
        "--mock-mode",
        "--mock-trace",
        "sample.jsonl",
        "--mock-speedup",
        "5.0",
        "--process-ttl",
        "60.0",
    ]

    cfg = parse_args(args)
    assert cfg.horizon == 10.0
    assert cfg.model_path == custom_model
    assert cfg.metrics_path == custom_metrics
    assert cfg.reference_features_path == custom_ref
    assert cfg.threshold == 0.82
    assert cfg.traces_path == custom_traces
    assert cfg.monitor_cmd == "SyscallMonitor.exe"
    assert cfg.audit_log_path == custom_audit
    assert cfg.log_file_path == custom_log
    assert cfg.timer_interval_s == 0.25
    assert cfg.bypass_admin_check is True
    assert cfg.mock_mode is True
    assert cfg.mock_trace_path == Path("sample.jsonl")
    assert cfg.mock_speedup == 5.0
    assert cfg.process_ttl_s == 60.0
