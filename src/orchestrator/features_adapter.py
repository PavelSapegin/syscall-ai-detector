"""Feature extraction adapter and schema alignment for real-time inference."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import xgboost as xgb
from src.features import extract_features

logger = logging.getLogger("orchestrator.features_adapter")


class FeaturesAdapter:
    """Extracts behavioral features and aligns them with the trained model schema."""

    def __init__(self, reference_features_path: Path) -> None:
        self.reference_features_path = reference_features_path
        self.reference_features: list[str] = self._load_reference_features(
            reference_features_path
        )
        logger.info(
            "FeaturesAdapter initialized with %d reference features from %s",
            len(self.reference_features),
            reference_features_path,
        )

    @staticmethod
    def _load_reference_features(path: Path) -> list[str]:
        if not path.exists():
            raise FileNotFoundError(f"Reference features file not found: {path}")

        with open(path, encoding="utf-8") as f:
            features = json.load(f)

        if not isinstance(features, list) or not all(
            isinstance(x, str) for x in features
        ):
            raise ValueError(f"Invalid reference features file format in {path}")
        return features

    def build_feature_matrix(
        self,
        events: list[dict[str, Any]],
        t_start: datetime,
        horizon: float,
    ) -> tuple[xgb.DMatrix, dict[str, Any]]:
        """Extract features from events and format as XGBoost DMatrix.

        Args:
            events: List of raw ETW/syscall events for the process subtree.
            t_start: Datetime marking the start of observation window.
            horizon: Duration of window in seconds.

        Returns:
            dmatrix: xgb.DMatrix with columns exactly matching reference features.
            raw_features: Dictionary of extracted features.
        """
        # Call the project's standard feature extraction
        raw_features = extract_features(events, t_start, horizon)

        # Build feature vector aligned with reference features
        row: dict[str, float] = {}
        for feat in self.reference_features:
            val = raw_features.get(feat)
            if val is None:
                # Missing feature defaults to 0.0
                row[feat] = 0.0
            else:
                try:
                    fval = float(val)
                    row[feat] = 0.0 if np.isnan(fval) else fval
                except (ValueError, TypeError):
                    row[feat] = 0.0

        # Create DataFrame to preserve column names and order
        df = pd.DataFrame([row], columns=self.reference_features)
        dmatrix = xgb.DMatrix(df, feature_names=self.reference_features)
        return dmatrix, raw_features
