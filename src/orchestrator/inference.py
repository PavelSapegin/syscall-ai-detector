"""Inference engine for XGBoost malware detection models across cascade horizons."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import xgboost as xgb

logger = logging.getLogger("orchestrator.inference")


class InferenceEngine:
    """Calculates malware probability against calibrated thresholds across horizons."""

    def __init__(
        self,
        model_path: Path | dict[float, Path],
        metrics_path: Path | dict[float, Path] | None = None,
        custom_threshold: float | None = None,
    ) -> None:
        self.custom_threshold = custom_threshold

        # Normalize model paths dict
        if isinstance(model_path, Path):
            self.model_paths: dict[float, Path] = {5.0: model_path}
        else:
            self.model_paths = dict(model_path)

        # Normalize metrics paths dict
        if metrics_path is None:
            self.metrics_paths: dict[float, Path] = {}
        elif isinstance(metrics_path, Path):
            self.metrics_paths = {5.0: metrics_path}
        else:
            self.metrics_paths = dict(metrics_path)

        self.models: dict[float, xgb.Booster] = {}
        self.thresholds: dict[float, float] = {}

        # Load models and thresholds for each horizon
        for h, m_path in self.model_paths.items():
            if not m_path.exists():
                raise FileNotFoundError(
                    f"Model file not found for horizon {h}s: {m_path}"
                )

            booster = xgb.Booster()
            booster.load_model(str(m_path))
            self.models[h] = booster
            logger.info("XGBoost model loaded for horizon %.1fs from %s", h, m_path)

            m_metrics = self.metrics_paths.get(h)
            thresh = self._resolve_threshold(m_metrics, custom_threshold)
            self.thresholds[h] = thresh
            logger.info("Decision threshold for horizon %.1fs: %.4f", h, thresh)

        # Backward compatibility properties pointing to default/first horizon
        self._primary_horizon = next(iter(self.models.keys()))
        self.model = self.models[self._primary_horizon]
        self.threshold = self.thresholds[self._primary_horizon]
        self.model_path = self.model_paths[self._primary_horizon]
        self.metrics_path = self.metrics_paths.get(self._primary_horizon)

    def _resolve_threshold(
        self, metrics_file: Path | None, custom: float | None
    ) -> float:
        if custom is not None:
            return float(custom)

        if metrics_file and metrics_file.exists():
            try:
                with open(metrics_file, encoding="utf-8") as f:
                    metrics = json.load(f)
                optimal_f1 = metrics.get("optimal_threshold_f1") or metrics.get(
                    "optimal_f1_threshold"
                )
                if optimal_f1 is not None:
                    logger.info(
                        "Loaded optimal F1 threshold %.4f from %s",
                        float(optimal_f1),
                        metrics_file,
                    )
                    return float(optimal_f1)
            except Exception as e:
                logger.warning(
                    "Could not read optimal threshold from %s: %s",
                    metrics_file,
                    e,
                )

        logger.warning("Falling back to default threshold 0.5")
        return 0.5

    def get_threshold(self, horizon: float | None = None) -> float:
        """Return threshold for the specified horizon."""
        if horizon is not None and horizon in self.thresholds:
            return self.thresholds[horizon]
        return self.threshold

    def predict(
        self, dmatrix: xgb.DMatrix, horizon: float | None = None
    ) -> tuple[float, bool]:
        """Predict malware probability for given horizon.

        Returns:
            probability: float between 0.0 and 1.0.
            is_malicious: True if probability >= threshold.
        """
        model = self.models.get(horizon, self.model) if horizon else self.model
        thresh = self.get_threshold(horizon)

        raw_pred = model.predict(dmatrix)
        proba = float(raw_pred[0])
        is_malicious = proba >= thresh
        return proba, is_malicious
