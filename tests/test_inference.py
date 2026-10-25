"""Unit tests for InferenceEngine."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest
from src.orchestrator.features_adapter import FeaturesAdapter
from src.orchestrator.inference import InferenceEngine


def test_missing_model_file() -> None:
    """Test exception when model file does not exist."""
    with pytest.raises(FileNotFoundError, match="Model file not found"):
        InferenceEngine(model_path=Path("non_existent_model_12345.json"))


def test_custom_threshold_override(default_model_path: Path) -> None:
    """Test that custom threshold takes precedence over metrics file."""
    if not default_model_path.exists():
        pytest.skip("Model file not found")

    engine = InferenceEngine(model_path=default_model_path, custom_threshold=0.88)
    assert engine.threshold == 0.88


def test_threshold_from_metrics(
    default_model_path: Path, default_metrics_path: Path
) -> None:
    """Test loading optimal F1 threshold from metrics.json."""
    if not default_model_path.exists() or not default_metrics_path.exists():
        pytest.skip("Model or metrics file missing")

    engine = InferenceEngine(
        model_path=default_model_path, metrics_path=default_metrics_path
    )
    # For horizon 5s metrics, optimal F1 threshold is around 0.7327
    assert 0.1 <= engine.threshold <= 0.99


def test_threshold_fallback_on_corrupt_or_missing_metrics(
    default_model_path: Path, tmp_path: Path
) -> None:
    """Test fallback to 0.5 when metrics file is missing or invalid."""
    if not default_model_path.exists():
        pytest.skip("Model file missing")

    # 1. Non-existent metrics file
    engine_missing = InferenceEngine(
        model_path=default_model_path,
        metrics_path=tmp_path / "missing_metrics.json",
    )
    assert engine_missing.threshold == 0.5

    # 2. Corrupt metrics file
    corrupt_metrics = tmp_path / "corrupt_metrics.json"
    corrupt_metrics.write_text("not json", encoding="utf-8")
    engine_corrupt = InferenceEngine(
        model_path=default_model_path,
        metrics_path=corrupt_metrics,
    )
    assert engine_corrupt.threshold == 0.5

    # 3. Valid JSON but without threshold key
    empty_metrics = tmp_path / "empty_metrics.json"
    empty_metrics.write_text(json.dumps({"accuracy": 0.9}), encoding="utf-8")
    engine_empty = InferenceEngine(
        model_path=default_model_path,
        metrics_path=empty_metrics,
    )
    assert engine_empty.threshold == 0.5


def test_predict_decision_logic(
    default_model_path: Path, default_ref_features_path: Path
) -> None:
    """Test binary decision logic against threshold."""
    if not default_model_path.exists() or not default_ref_features_path.exists():
        pytest.skip("Model or ref features missing")

    adapter = FeaturesAdapter(default_ref_features_path)
    engine = InferenceEngine(
        model_path=default_model_path,
        custom_threshold=0.5,
    )

    dmatrix, _ = adapter.build_feature_matrix([], datetime.now(), 5.0)
    proba, is_malicious = engine.predict(dmatrix)

    assert isinstance(proba, float)
    assert 0.0 <= proba <= 1.0
    assert isinstance(is_malicious, bool)
    assert is_malicious == (proba >= 0.5)
