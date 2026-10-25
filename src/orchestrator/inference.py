"""Inference engine for XGBoost malware detection model."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import xgboost as xgb

logger = logging.getLogger("orchestrator.inference")


class InferenceEngine:
    """Calculates malware probability against calibrated threshold."""

    def __init__(
        self,
        model_path: Path,
        metrics_path: Path | None = None,
        custom_threshold: float | None = None,
    ) -> None:
        self.model_path = model_path
        self.metrics_path = metrics_path

        # Load Booster model
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        self.model = xgb.Booster()
        self.model.load_model(str(model_path))
        logger.info("XGBoost model loaded from %s", model_path)

        # Determine threshold
        self.threshold = self._resolve_threshold(custom_threshold)
        logger.info("Active decision threshold: %.4f", self.threshold)

    def _resolve_threshold(self, custom: float | None) -> float:
        if custom is not None:
            return float(custom)

        if self.metrics_path and self.metrics_path.exists():
            try:
                with open(self.metrics_path, encoding="utf-8") as f:
                    metrics = json.load(f)
                optimal_f1 = metrics.get("optimal_threshold_f1")
                if optimal_f1 is not None:
                    logger.info(
                        "Loaded optimal F1 threshold %.4f from %s",
                        optimal_f1,
                        self.metrics_path,
                    )
                    return float(optimal_f1)
            except Exception as e:
                logger.warning(
                    "Could not read optimal threshold from %s: %s",
                    self.metrics_path,
                    e,
                )

        # Default fallback
        logger.warning("Falling back to default threshold 0.5")
        return 0.5

    def predict(self, dmatrix: xgb.DMatrix) -> tuple[float, bool]:
        """Predict malware probability.

        Returns:
            probability: float between 0.0 and 1.0.
            is_malicious: True if probability >= threshold.
        """
        raw_pred = self.model.predict(dmatrix)
        proba = float(raw_pred[0])
        is_malicious = proba >= self.threshold
        return proba, is_malicious
