"""Unit tests for FeaturesAdapter."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest
from src.orchestrator.features_adapter import FeaturesAdapter


def test_load_schema_success(default_ref_features_path: Path) -> None:
    """Test loading valid reference features schema."""
    if not default_ref_features_path.exists():
        pytest.skip("Default reference schema file not found")

    adapter = FeaturesAdapter(default_ref_features_path)
    assert len(adapter.reference_features) == 90
    assert "n_events" in adapter.reference_features
    assert "events_per_sec" in adapter.reference_features


def test_load_schema_errors(tmp_path: Path) -> None:
    """Test schema loader error handling on missing or corrupt files."""
    # 1. Non-existent file
    with pytest.raises(FileNotFoundError):
        FeaturesAdapter(Path("non_existent_features_12345.json"))

    # 2. Corrupt / invalid format (dict instead of list)
    corrupt_file = tmp_path / "corrupt_schema.json"
    corrupt_file.write_text('{"invalid": "format"}', encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid reference features file format"):
        FeaturesAdapter(corrupt_file)

    # 3. Invalid JSON syntax
    bad_syntax = tmp_path / "bad_syntax.json"
    bad_syntax.write_text("{broken", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        FeaturesAdapter(bad_syntax)


def test_build_matrix_partial_events(default_ref_features_path: Path) -> None:
    """Test feature alignment when only a small subset of event types occurred."""
    if not default_ref_features_path.exists():
        pytest.skip("Default reference schema file not found")

    adapter = FeaturesAdapter(default_ref_features_path)
    now = datetime.now()
    events = [
        {
            "Timestamp": now.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "EventType": "ProcessStart",
            "ProcessID": 500,
            "ParentProcessID": 1,
            "ImageFileName": "notepad.exe",
        }
    ]

    dmatrix, raw_dict = adapter.build_feature_matrix(events, now, 5.0)
    assert dmatrix.num_row() == 1
    assert dmatrix.num_col() == 90
    assert dmatrix.feature_names == adapter.reference_features
    assert raw_dict.get("n_events") == 1


def test_build_matrix_empty_events(default_ref_features_path: Path) -> None:
    """Test feature extraction with zero events."""
    if not default_ref_features_path.exists():
        pytest.skip("Default reference schema file not found")

    adapter = FeaturesAdapter(default_ref_features_path)
    now = datetime.now()
    dmatrix, raw_dict = adapter.build_feature_matrix([], now, 5.0)
    assert dmatrix.num_row() == 1
    assert dmatrix.num_col() == 90
    assert raw_dict.get("n_events") == 0


def test_build_matrix_with_dummy_schema(dummy_features_json: Path) -> None:
    """Test build matrix with synthetic schema from conftest."""
    adapter = FeaturesAdapter(dummy_features_json)
    now = datetime.now()
    events = [
        {
            "Timestamp": now.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "EventType": "FileIOCreate",
            "ProcessID": 777,
        }
    ]
    dmatrix, _ = adapter.build_feature_matrix(events, now, 2.0)
    assert dmatrix.num_row() == 1
    assert dmatrix.num_col() == len(adapter.reference_features)
