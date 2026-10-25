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


@pytest.fixture
def repo_root() -> Path:
    """Return the absolute path to repository root."""
    return Path(__file__).resolve().parent.parent


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
