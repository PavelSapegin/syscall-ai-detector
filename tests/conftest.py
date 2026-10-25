"""Pytest fixtures for orchestrator tests."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable, Generator
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """Return the absolute path to repository root."""
    return Path(__file__).resolve().parent.parent


REFERENCE_90_FEATURES = [
    "n_events",
    "n_FileIOCreate",
    "n_FileIOWrite",
    "events_per_sec",
    "max_events_1s_bin",
    "frac_events_first_half",
    "t_first_FileIOCreate",
    "t_first_FileIOWrite",
    "iat_mean",
    "iat_std",
    "iat_max",
    "n_pids",
    "n_children_spawned",
    "max_tree_depth",
    "spawn_rate",
    "n_lolbin_wmic",
    "n_lolbin_certutil",
    "n_lolbin_vssadmin",
    "n_lolbin_cscript",
    "n_lolbin_regsvr32",
    "n_lolbin_schtasks",
    "n_lolbin_mshta",
    "n_lolbin_wscript",
    "n_lolbin_wevtutil",
    "n_lolbin_bitsadmin",
    "n_lolbin_rundll32",
    "n_lolbin_powershell",
    "n_lolbin_net",
    "n_lolbin_reg",
    "n_lolbin_taskkill",
    "n_lolbin_cmd",
    "has_lolbin_wmic",
    "has_lolbin_certutil",
    "has_lolbin_vssadmin",
    "has_lolbin_cscript",
    "has_lolbin_regsvr32",
    "has_lolbin_schtasks",
    "has_lolbin_mshta",
    "has_lolbin_wscript",
    "has_lolbin_wevtutil",
    "has_lolbin_bitsadmin",
    "has_lolbin_rundll32",
    "has_lolbin_powershell",
    "has_lolbin_net",
    "has_lolbin_reg",
    "has_lolbin_taskkill",
    "has_lolbin_cmd",
    "n_fio_create",
    "n_fio_write",
    "n_unique_files_created",
    "n_unique_files_written",
    "n_unique_dirs_written",
    "bytes_written_total",
    "iosize_mean",
    "iosize_std",
    "iosize_max",
    "frac_sequential_writes",
    "frac_path_system",
    "frac_path_programdata",
    "frac_path_programfiles",
    "frac_path_temp",
    "frac_path_appdata_other",
    "frac_path_userdocs",
    "frac_path_startup",
    "frac_path_unc",
    "mean_path_depth",
    "n_distinct_extensions_created",
    "frac_exec_ext_created",
    "max_same_basename_across_dirs",
    "mean_filename_entropy",
    "n_reg_create",
    "n_reg_setvalue",
    "n_unique_reg_keys",
    "n_reg_persistence",
    "n_reg_defender_tamper",
    "frac_reg_hklm",
    "event_type_entropy",
    "write_to_create_ratio",
    "new_dirs_per_sec",
    "n_events_le_1s",
    "n_events_le_2s",
    "n_events_le_5s",
    "n_ProcessStart",
    "t_first_ProcessStart",
    "n_RegistryCreate",
    "n_RegistrySetValue",
    "t_first_RegistryCreate",
    "t_first_RegistrySetValue",
    "n_ProcessStop",
    "t_first_ProcessStop",
]


@pytest.fixture(scope="session", autouse=True)
def ensure_default_model_artifacts(repo_root: Path) -> Generator[None, None, None]:
    """Ensure minimal model artifacts exist for environments without models."""
    models_dir = repo_root / "out" / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    ref_path = models_dir / "reference_features_horizon_5s.json"
    metrics_path = models_dir / "metrics_horizon_5s.json"
    model_path = models_dir / "xgboost_horizon_5s.json"

    created_files: list[Path] = []

    if not ref_path.exists():
        ref_path.write_text(json.dumps(REFERENCE_90_FEATURES), encoding="utf-8")
        created_files.append(ref_path)

    if not metrics_path.exists():
        metrics_payload = {
            "optimal_f1_threshold": 0.7327,
            "optimal_threshold_f1": 0.7327,
        }
        metrics_path.write_text(json.dumps(metrics_payload), encoding="utf-8")
        created_files.append(metrics_path)

    if not model_path.exists():
        import numpy as np
        import xgboost as xgb

        dummy_x = np.zeros((2, len(REFERENCE_90_FEATURES)))
        dummy_y = np.array([0, 1])
        clf = xgb.XGBClassifier(n_estimators=1, max_depth=1)
        clf.fit(dummy_x, dummy_y)
        clf.save_model(model_path)
        created_files.append(model_path)

    yield

    # Clean up only synthetic files we created in environments where missing
    for f in created_files:
        import contextlib

        with contextlib.suppress(Exception):
            f.unlink()


@pytest.fixture
def default_ref_features_path(repo_root: Path) -> Path:
    """Return path to 5s reference features if present, or fallback."""
    return repo_root / "out" / "models" / "reference_features_horizon_5s.json"


@pytest.fixture
def default_model_path(repo_root: Path) -> Path:
    """Return path to 5s XGBoost model if present."""
    return repo_root / "out" / "models" / "xgboost_horizon_5s.json"


@pytest.fixture
def default_metrics_path(repo_root: Path) -> Path:
    """Return path to 5s metrics if present."""
    return repo_root / "out" / "models" / "metrics_horizon_5s.json"


@pytest.fixture
def dummy_features_json(tmp_path: Path) -> Path:
    """Create a temporary valid 90-feature schema JSON."""
    features = [f"feat_{i}" for i in range(88)] + ["n_events", "events_per_sec"]
    schema_path = tmp_path / "dummy_features.json"
    schema_path.write_text(json.dumps(features), encoding="utf-8")
    return schema_path


@pytest.fixture
def sample_benign_events() -> list[dict[str, Any]]:
    """Return typical benign ETW sequence."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    return [
        {
            "Timestamp": now_str,
            "EventType": "ProcessStart",
            "ProcessID": 4444,
            "ParentProcessID": 100,
            "ImageFileName": "notepad.exe",
        },
        {
            "Timestamp": now_str,
            "EventType": "FileIOCreate",
            "ProcessID": 4444,
            "FileName": "C:\\Users\\User\\Documents\\note.txt",
        },
        {
            "Timestamp": now_str,
            "EventType": "FileIOWrite",
            "ProcessID": 4444,
            "FileName": "C:\\Users\\User\\Documents\\note.txt",
            "IoSize": 256,
        },
    ]


@pytest.fixture
def sample_malware_events() -> list[dict[str, Any]]:
    """Return typical suspicious / malware ETW sequence."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    return [
        {
            "Timestamp": now_str,
            "EventType": "ProcessStart",
            "ProcessID": 8888,
            "ParentProcessID": 100,
            "ImageFileName": "powershell.exe",
        },
        {
            "Timestamp": now_str,
            "EventType": "FileIOCreate",
            "ProcessID": 8888,
            "FileName": "C:\\Windows\\Temp\\payload.exe",
        },
        {
            "Timestamp": now_str,
            "EventType": "FileIOWrite",
            "ProcessID": 8888,
            "FileName": "C:\\Windows\\Temp\\payload.exe",
            "IoSize": 8192,
        },
        {
            "Timestamp": now_str,
            "EventType": "RegistryCreate",
            "ProcessID": 8888,
            "KeyName": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        },
        {
            "Timestamp": now_str,
            "EventType": "RegistrySetValue",
            "ProcessID": 8888,
            "KeyName": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "ValueName": "Backdoor",
        },
        {
            "Timestamp": now_str,
            "EventType": "ProcessStart",
            "ProcessID": 8889,
            "ParentProcessID": 8888,
            "ImageFileName": "cmd.exe",
        },
    ]


@pytest.fixture
def process_spawner() -> Generator[Callable[..., subprocess.Popen], None, None]:
    """Factory fixture to spawn subprocesses and ensure cleanup on test completion."""
    spawned: list[subprocess.Popen] = []

    def _spawn(script: str = "import time; time.sleep(30)") -> subprocess.Popen:
        proc = subprocess.Popen([sys.executable, "-c", script])
        spawned.append(proc)
        return proc

    yield _spawn

    for proc in spawned:
        if proc.poll() is None:
            import contextlib

            with contextlib.suppress(Exception):
                proc.kill()
                proc.wait(timeout=1.0)
