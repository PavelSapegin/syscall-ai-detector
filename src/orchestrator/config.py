"""Configuration dataclass and CLI parsing for the malware detection orchestrator."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path


@dataclass
class OrchestratorConfig:
    # Horizon window in seconds (e.g. 5.0, 10.0, 30.0)
    horizon: float = 5.0

    # Path to trained XGBoost model JSON
    model_path: Path = Path("out/models/xgboost_horizon_5s.json")

    # Path to metrics JSON (to extract optimal_threshold_f1)
    metrics_path: Path | None = Path("out/models/metrics_horizon_5s.json")

    # Path to reference features JSON
    reference_features_path: Path = Path(
        "out/models/reference_features_horizon_5s.json"
    )

    # Threshold for malware probability. If None, loaded from metrics_path
    threshold: float | None = None

    # Path to traces.jsonl produced by SyscallMonitor
    traces_path: Path = Path("traces.jsonl")

    # Monitor command or binary path (e.g., SyscallMonitor.exe)
    monitor_cmd: str | None = None

    # Audit log output path
    audit_log_path: Path = Path("out/audit.jsonl")

    # General log file path
    log_file_path: Path = Path("out/orchestrator.log")

    # Horizon scheduler tick interval in seconds
    timer_interval_s: float = 0.5

    # Whether to bypass admin check (useful for debugging/local tests)
    bypass_admin_check: bool = False

    # Whether to run a mock monitor replaying trace files (for non-Windows or testing)
    mock_mode: bool = False
    mock_trace_path: Path | None = None
    mock_speedup: float = 1.0

    # Maximum age of terminated processes to keep in memory (seconds)
    process_ttl_s: float = 300.0


def parse_args(args: list[str] | None = None) -> OrchestratorConfig:
    """Parse CLI arguments into OrchestratorConfig."""
    parser = argparse.ArgumentParser(
        description="Syscall AI Detector - Real-time Process Orchestrator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--horizon",
        type=float,
        default=5.0,
        help="Evaluation horizon window in seconds (2, 5, 10, 30)",
    )
    parser.add_argument(
        "--model-path",
        type=Path,
        default=None,
        help="Path to XGBoost model JSON (default: out/models/xgboost_...)",
    )
    parser.add_argument(
        "--metrics-path",
        type=Path,
        default=None,
        help="Path to metrics JSON to load optimal F1 threshold",
    )
    parser.add_argument(
        "--reference-features",
        type=Path,
        default=None,
        help="Path to reference features JSON",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Decision threshold for P(malware). If omitted, loaded from metrics JSON",
    )
    parser.add_argument(
        "--traces-path",
        type=Path,
        default=Path("traces.jsonl"),
        help="Path to traces.jsonl produced by SyscallMonitor",
    )
    parser.add_argument(
        "--monitor-cmd",
        type=str,
        default=None,
        help="Command to launch SyscallMonitor (e.g. SyscallMonitor.exe)",
    )
    parser.add_argument(
        "--audit-log",
        type=Path,
        default=Path("out/audit.jsonl"),
        help="Path to JSONL audit log",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("out/orchestrator.log"),
        help="Path to text log file",
    )
    parser.add_argument(
        "--timer-interval",
        type=float,
        default=0.5,
        help="Interval in seconds for the horizon scheduler loop",
    )
    parser.add_argument(
        "--bypass-admin-check",
        action="store_true",
        help="Bypass administrator check (for non-admin or dev testing)",
    )
    parser.add_argument(
        "--mock-mode",
        action="store_true",
        help="Enable mock monitor (replay traces without SyscallMonitor.exe)",
    )
    parser.add_argument(
        "--mock-trace",
        type=Path,
        default=None,
        help="Path to sample JSONL trace to replay in mock mode",
    )
    parser.add_argument(
        "--mock-speedup",
        type=float,
        default=1.0,
        help="Speedup multiplier for mock trace playback",
    )
    parser.add_argument(
        "--process-ttl",
        type=float,
        default=300.0,
        help="Maximum age of terminated processes to keep in memory (seconds)",
    )

    parsed = parser.parse_args(args)
    horizon_int = int(parsed.horizon) if parsed.horizon.is_integer() else parsed.horizon

    model_path = parsed.model_path or Path(
        f"out/models/xgboost_horizon_{horizon_int}s.json"
    )
    metrics_path = parsed.metrics_path or Path(
        f"out/models/metrics_horizon_{horizon_int}s.json"
    )
    reference_features_path = parsed.reference_features or Path(
        f"out/models/reference_features_horizon_{horizon_int}s.json"
    )

    return OrchestratorConfig(
        horizon=parsed.horizon,
        model_path=model_path,
        metrics_path=metrics_path,
        reference_features_path=reference_features_path,
        threshold=parsed.threshold,
        traces_path=parsed.traces_path,
        monitor_cmd=parsed.monitor_cmd,
        audit_log_path=parsed.audit_log,
        log_file_path=parsed.log_file,
        timer_interval_s=parsed.timer_interval,
        bypass_admin_check=parsed.bypass_admin_check,
        mock_mode=parsed.mock_mode,
        mock_trace_path=parsed.mock_trace,
        mock_speedup=parsed.mock_speedup,
        process_ttl_s=parsed.process_ttl,
    )
