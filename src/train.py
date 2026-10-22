"""Training and hyperparameter optimization for XGBoost malware detector.

Trains an XGBoost model on early behavioral syscall features extracted from ETW traces.
Includes hyperparameter optimization via Optuna, group-aware cross-validation
to prevent data leakage across trace files, decision threshold tuning by F1-score,
and comprehensive metric evaluation (ROC-AUC, PR-AUC, F1, precision, recall).
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
import optuna
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("train_xgboost")

# Columns that represent metadata or target, and must never be used as training features
METADATA_COLUMNS = {
    "sample_id",
    "trace_file",
    "root_pid",
    "horizon",
    "label_binary",
    "group",
    "class",
    "t_start_source",
    "t_start_gap_s",
    "t_start",
    "t_start_ps",
}


def load_dataset(
    data_path: Path,
    horizon: int = 5,
    network_path: Path | None = None,
) -> tuple[pd.DataFrame, pd.Series, pd.Series, list[str], pd.DataFrame]:
    """Loads features dataset, filters by horizon, and isolates feature matrix.

    Args:
        data_path: Path to features.parquet (or features.csv).
        horizon: Horizon window in seconds (2, 5, 10, or 30).
        network_path: Optional path to features_network.parquet.

    Returns:
        X: Feature DataFrame.
        y: Binary target Series (1 = malware, 0 = benign).
        groups: Series containing trace_file identifiers for group splitting.
        feature_names: List of feature column names.
        metadata_df: DataFrame containing sample metadata for trace attribution.
    """
    logger.info("Loading dataset from %s (horizon=%ds)", data_path, horizon)
    if data_path.suffix == ".parquet":
        df = pd.read_parquet(data_path)
    else:
        df = pd.read_csv(data_path)

    if "horizon" in df.columns:
        df = df[df["horizon"] == horizon].copy()
        if df.empty:
            raise ValueError(f"No samples found for horizon={horizon}s in {data_path}")
    else:
        logger.warning("'horizon' column not found, using full dataset")

    if network_path and network_path.exists():
        logger.info("Merging network features from %s", network_path)
        if network_path.suffix == ".parquet":
            df_net = pd.read_parquet(network_path)
        else:
            df_net = pd.read_csv(network_path)

        if "horizon" in df_net.columns:
            df_net = df_net[df_net["horizon"] == horizon].copy()

        net_feature_cols = [c for c in df_net.columns if c not in METADATA_COLUMNS]
        merge_keys = [
            c
            for c in ["sample_id", "horizon"]
            if c in df.columns and c in df_net.columns
        ]
        if merge_keys:
            df = df.merge(
                df_net[merge_keys + net_feature_cols], on=merge_keys, how="left"
            )
            logger.info("Merged %d network features", len(net_feature_cols))

    if "label_binary" not in df.columns:
        raise KeyError("Column 'label_binary' not found in dataset")

    y = df["label_binary"].astype(int)
    groups = df["trace_file"] if "trace_file" in df.columns else pd.Series(df.index)

    # Exclude all metadata and target columns from features
    feature_cols = [c for c in df.columns if c not in METADATA_COLUMNS]

    # Convert features to numeric float32
    X = df[feature_cols].apply(pd.to_numeric, errors="coerce").astype(np.float32)

    logger.info(
        "Dataset ready: %d samples (%d benign, %d malware), %d features",
        len(X),
        (y == 0).sum(),
        (y == 1).sum(),
        len(feature_cols),
    )
    logger.info("Unique traces (groups): %d", groups.nunique())

    meta_cols = [
        c
        for c in ["sample_id", "trace_file", "root_pid", "class", "group"]
        if c in df.columns
    ]
    metadata_df = df[meta_cols].copy()

    return X, y, groups, feature_cols, metadata_df


def find_optimal_threshold_f1(
    y_true: np.ndarray, y_pred_proba: np.ndarray
) -> tuple[float, float]:
    """Finds decision threshold maximizing the F1-score using precision-recall curve.

    Args:
        y_true: Ground truth binary labels.
        y_pred_proba: Predicted probabilities for the positive class (malware).

    Returns:
        optimal_threshold: Threshold in range (0, 1) maximizing F1.
        max_f1: Maximum achievable F1-score at this threshold.
    """
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_pred_proba)

    # thresholds has length len(precisions) - 1
    denom = precisions[:-1] + recalls[:-1]
    f1_scores = np.divide(
        2 * precisions[:-1] * recalls[:-1],
        denom,
        out=np.zeros_like(denom),
        where=denom > 0,
    )

    if len(f1_scores) == 0:
        return 0.5, 0.0

    best_idx = int(np.argmax(f1_scores))
    best_threshold = float(thresholds[best_idx])
    best_f1 = float(f1_scores[best_idx])
    return best_threshold, best_f1


def compute_metrics(
    y_true: np.ndarray, y_pred_proba: np.ndarray, threshold: float = 0.5
) -> dict[str, float]:
    """Calculates classification metrics: ROC-AUC, PR-AUC, F1, Precision, Recall."""
    y_pred = (y_pred_proba >= threshold).astype(int)

    # Calculate ROC-AUC safely
    try:
        roc_auc = float(roc_auc_score(y_true, y_pred_proba))
    except ValueError:
        roc_auc = float("nan")

    # Calculate PR-AUC (Average Precision)
    try:
        pr_auc = float(average_precision_score(y_true, y_pred_proba))
    except ValueError:
        pr_auc = float("nan")

    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    return {
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "f1": f1,
        "precision": prec,
        "recall": rec,
        "threshold": float(threshold),
    }


def evaluate_cv(
    model_params: dict[str, Any],
    X: pd.DataFrame,
    y: pd.Series,
    groups: pd.Series,
    n_splits: int = 5,
    use_group_kfold: bool = True,
    tune_threshold: bool = True,
    random_state: int = 42,
) -> tuple[dict[str, float], float, dict[str, float], np.ndarray]:
    """Evaluates XGBoost model using cross-validation.

    Returns:
        metrics_default: Metrics at standard 0.5 threshold.
        optimal_threshold: Threshold maximizing F1 on OOF predictions.
        metrics_optimal: Metrics at optimal threshold.
        oof_preds: Out-of-fold probability predictions.
    """
    if use_group_kfold and groups.nunique() >= n_splits:
        cv = StratifiedGroupKFold(
            n_splits=n_splits, shuffle=True, random_state=random_state
        )
        splits = list(cv.split(X, y, groups=groups))
    else:
        cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
        splits = list(cv.split(X, y))

    oof_preds = np.zeros(len(y), dtype=np.float32)

    for fold, (train_idx, val_idx) in enumerate(splits):
        X_train, y_train = X.iloc[train_idx], y.iloc[train_idx]
        X_val, y_val = X.iloc[val_idx], y.iloc[val_idx]

        model = xgb.XGBClassifier(
            **model_params,
            random_state=random_state + fold,
            eval_metric="logloss",
            early_stopping_rounds=30,
            tree_method="hist",
        )

        model.fit(
            X_train,
            y_train,
            eval_set=[(X_val, y_val)],
            verbose=False,
        )

        oof_preds[val_idx] = model.predict_proba(X_val)[:, 1]

    y_arr = y.to_numpy()
    metrics_default = compute_metrics(y_arr, oof_preds, threshold=0.5)

    if tune_threshold:
        optimal_threshold, _ = find_optimal_threshold_f1(y_arr, oof_preds)
    else:
        optimal_threshold = 0.5

    metrics_optimal = compute_metrics(y_arr, oof_preds, threshold=optimal_threshold)

    return metrics_default, optimal_threshold, metrics_optimal, oof_preds


def optimize_hyperparameters(
    X: pd.DataFrame,
    y: pd.Series,
    groups: pd.Series,
    n_trials: int = 50,
    n_splits: int = 5,
    optimization_metric: str = "roc_auc",
    use_group_kfold: bool = True,
    random_state: int = 42,
) -> dict[str, Any]:
    """Runs hyperparameter search via Optuna."""
    neg_count = (y == 0).sum()
    pos_count = (y == 1).sum()
    default_imbalance_ratio = float(neg_count / max(1, pos_count))

    logger.info(
        "Starting Optuna optimization: %d trials, optimizing '%s' \
            (imbalance ratio: %.2f)",
        n_trials,
        optimization_metric,
        default_imbalance_ratio,
    )

    # Disable verbose Optuna logs
    optuna.logging.set_verbosity(optuna.logging.WARNING)

    def objective(trial: optuna.Trial) -> float:
        params: dict[str, Any] = {
            "n_estimators": trial.suggest_int("n_estimators", 100, 600, step=50),
            "max_depth": trial.suggest_int("max_depth", 3, 9),
            "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.3, log=True),
            "subsample": trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),
            "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
            "gamma": trial.suggest_float("gamma", 0.0, 5.0),
            "reg_alpha": trial.suggest_float("reg_alpha", 1e-6, 10.0, log=True),
            "reg_lambda": trial.suggest_float("reg_lambda", 1e-6, 10.0, log=True),
            "scale_pos_weight": trial.suggest_float(
                "scale_pos_weight",
                max(1.0, default_imbalance_ratio * 0.5),
                default_imbalance_ratio * 2.0,
            ),
            "n_jobs": -1,
        }

        metrics_default, _opt_thresh, metrics_optimal, _ = evaluate_cv(
            model_params=params,
            X=X,
            y=y,
            groups=groups,
            n_splits=n_splits,
            use_group_kfold=use_group_kfold,
            tune_threshold=True,
            random_state=random_state,
        )

        # When optimizing for F1, we use the F1 at optimal threshold
        if optimization_metric == "f1":
            score = metrics_optimal.get("f1", 0.0)
        else:
            score = metrics_default.get(optimization_metric, 0.0)

        return float(score)

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=n_trials, show_progress_bar=True)

    logger.info("Best trial: Score (%.4f) = %s", study.best_value, study.best_params)
    return study.best_params


def train_and_evaluate(
    data_path: Path,
    horizon: int = 5,
    network_path: Path | None = None,
    n_trials: int = 50,
    n_splits: int = 5,
    optimization_metric: str = "roc_auc",
    use_group_kfold: bool = True,
    output_dir: Path = Path("out/models"),
    random_state: int = 42,
) -> None:
    """
    Full pipeline: load data, tune hyperparameters, cross-validate, and save results.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    X, y, groups, feature_names, metadata_df = load_dataset(
        data_path=data_path,
        horizon=horizon,
        network_path=network_path,
    )

    if n_trials > 0:
        best_params = optimize_hyperparameters(
            X=X,
            y=y,
            groups=groups,
            n_trials=n_trials,
            n_splits=n_splits,
            optimization_metric=optimization_metric,
            use_group_kfold=use_group_kfold,
            random_state=random_state,
        )
    else:
        logger.info("Skipping Optuna search, using default robust hyperparameters")
        neg_count = (y == 0).sum()
        pos_count = (y == 1).sum()
        best_params = {
            "n_estimators": 300,
            "max_depth": 5,
            "learning_rate": 0.05,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "min_child_weight": 2,
            "gamma": 0.1,
            "reg_alpha": 0.01,
            "reg_lambda": 1.0,
            "scale_pos_weight": float(neg_count / max(1, pos_count)),
            "n_jobs": -1,
        }

    # Final Cross-Validation Evaluation with Best Parameters
    logger.info(
        "Evaluating final model via %d-fold CV and tuning threshold...", n_splits
    )
    metrics_05, optimal_thresh, metrics_opt, oof_preds = evaluate_cv(
        model_params=best_params,
        X=X,
        y=y,
        groups=groups,
        n_splits=n_splits,
        use_group_kfold=use_group_kfold,
        tune_threshold=True,
        random_state=random_state,
    )

    y_true_arr = y.to_numpy()

    # Confusion matrix at 0.5
    cm_05 = confusion_matrix(y_true_arr, (oof_preds >= 0.5).astype(int))
    tn_05, fp_05, fn_05, tp_05 = cm_05.ravel()

    # Confusion matrix at optimal threshold
    cm_opt = confusion_matrix(y_true_arr, (oof_preds >= optimal_thresh).astype(int))
    tn_opt, fp_opt, fn_opt, tp_opt = cm_opt.ravel()

    print("\n" + "=" * 65)
    print(f"EVALUATION RESULTS (Horizon = {horizon}s, {n_splits}-fold CV)")
    print("=" * 65)
    print(f"ROC-AUC:                {metrics_05['roc_auc']:.4f}")
    print(f"PR-AUC:                 {metrics_05['pr_auc']:.4f}")
    print("-" * 65)
    print("Default Threshold:      0.5000")
    print(f"  F1-Score:             {metrics_05['f1']:.4f}")
    print(f"  Precision:            {metrics_05['precision']:.4f}")
    print(f"  Recall:               {metrics_05['recall']:.4f}")
    print(f"  Confusion Matrix:     TN={tn_05}, FP={fp_05}, FN={fn_05}, TP={tp_05}")
    print("-" * 65)
    print(f"Optimal Threshold (by F1): {optimal_thresh:.4f}")
    print(f"  F1-Score:             {metrics_opt['f1']:.4f}")
    print(f"  Precision:            {metrics_opt['precision']:.4f}")
    print(f"  Recall:               {metrics_opt['recall']:.4f}")
    print(f"  Confusion Matrix:     TN={tn_opt}, FP={fp_opt}, FN={fn_opt}, TP={tp_opt}")
    print("-" * 65)
    print(f"\nClassification Report (at optimal threshold = {optimal_thresh:.4f}):")
    print(
        classification_report(
            y_true_arr,
            (oof_preds >= optimal_thresh).astype(int),
            target_names=["Benign", "Malware"],
        )
    )
    print("=" * 65 + "\n")

    # Fit final model on all data
    final_model = xgb.XGBClassifier(
        **best_params,
        random_state=random_state,
        eval_metric="logloss",
        tree_method="hist",
    )
    final_model.fit(X, y)

    # Feature importances
    importances = final_model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = [
        {"feature": feature_names[i], "importance": float(importances[i])}
        for i in sorted_idx[:30]
    ]

    # Save model
    model_file = output_dir / f"xgboost_horizon_{horizon}s.json"
    final_model.save_model(model_file)
    logger.info("Model saved to %s", model_file)

    # Save metrics and threshold report
    results_file = output_dir / f"metrics_horizon_{horizon}s.json"
    results = {
        "horizon": horizon,
        "n_samples": len(X),
        "benign_samples": int((y == 0).sum()),
        "malware_samples": int((y == 1).sum()),
        "best_hyperparameters": best_params,
        "optimal_threshold_f1": float(optimal_thresh),
        "metrics_default_threshold_05": {
            **metrics_05,
            "confusion_matrix": {
                "TN": int(tn_05),
                "FP": int(fp_05),
                "FN": int(fn_05),
                "TP": int(tp_05),
            },
        },
        "metrics_optimal_threshold": {
            **metrics_opt,
            "confusion_matrix": {
                "TN": int(tn_opt),
                "FP": int(fp_opt),
                "FN": int(fn_opt),
                "TP": int(tp_opt),
            },
        },
        "top_features": top_features,
    }
    with results_file.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    logger.info("Metrics report saved to %s", results_file)

    # Save OOF predictions with metadata and error categories for detailed analysis
    oof_df = metadata_df.copy()
    oof_df["label_binary"] = y_true_arr
    oof_df["pred_proba"] = oof_preds
    oof_df["pred_05"] = (oof_preds >= 0.5).astype(int)
    oof_df["pred_opt"] = (oof_preds >= optimal_thresh).astype(int)

    def _cat(label: int, pred: int) -> str:
        if label == 1:
            return "TP" if pred == 1 else "FN"
        return "FP" if pred == 1 else "TN"

    oof_df["category_05"] = [
        _cat(lbl, prd) for lbl, prd in zip(y_true_arr, oof_df["pred_05"], strict=False)
    ]
    oof_df["category_opt"] = [
        _cat(lbl, prd) for lbl, prd in zip(y_true_arr, oof_df["pred_opt"], strict=False)
    ]

    oof_parquet = output_dir / f"oof_predictions_horizon_{horizon}s.parquet"
    try:
        oof_df.to_parquet(oof_parquet, index=False)
        logger.info("OOF predictions saved to %s", oof_parquet)
    except Exception as e:
        logger.warning("Could not save parquet predictions: %s", e)
    oof_csv = output_dir / f"oof_predictions_horizon_{horizon}s.csv"
    oof_df.to_csv(oof_csv, index=False)
    logger.info("OOF predictions CSV saved to %s", oof_csv)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Train XGBoost model on early syscall trace features with "
            "Optuna tuning and F1 threshold search."
        )
    )
    parser.add_argument(
        "--data-path",
        type=Path,
        default=Path("out/features.parquet"),
        help="Path to features parquet/csv file (default: out/features.parquet)",
    )
    parser.add_argument(
        "--network-path",
        type=Path,
        default=None,
        help="Optional path to features_network.parquet to include network features",
    )
    parser.add_argument(
        "--horizon",
        type=int,
        default=5,
        choices=[2, 5, 10, 30],
        help="Observation horizon window in seconds (default: 5)",
    )
    parser.add_argument(
        "--n-trials",
        type=int,
        default=50,
        help="Number of Optuna optimization trials (0 to skip and use robust defaults)",
    )
    parser.add_argument(
        "--n-splits",
        type=int,
        default=5,
        help="Number of cross-validation splits (default: 5)",
    )
    parser.add_argument(
        "--metric",
        type=str,
        default="roc_auc",
        choices=["roc_auc", "f1", "pr_auc"],
        help="Metric to optimize during Optuna search (default: roc_auc)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out/models"),
        help="Directory to save trained model and metrics (default: out/models)",
    )
    parser.add_argument(
        "--no-group-split",
        action="store_true",
        help=(
            "Disable group-aware splitting by trace_file "
            "(NOT recommended due to leakage)"
        ),
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )
    args = parser.parse_args()

    train_and_evaluate(
        data_path=args.data_path,
        horizon=args.horizon,
        network_path=args.network_path,
        n_trials=args.n_trials,
        n_splits=args.n_splits,
        optimization_metric=args.metric,
        use_group_kfold=not args.no_group_split,
        output_dir=args.output_dir,
        random_state=args.random_state,
    )


if __name__ == "__main__":
    main()
