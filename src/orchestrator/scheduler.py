"""Horizon timer and detection scheduler."""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Any

from src.orchestrator.audit import AuditLogger
from src.orchestrator.features_adapter import FeaturesAdapter
from src.orchestrator.inference import InferenceEngine
from src.orchestrator.registry import ProcessRegistry
from src.orchestrator.response import ResponseEngine

logger = logging.getLogger("orchestrator.scheduler")


class HorizonScheduler:
    """Queries processes reaching horizon window and executes detection."""

    def __init__(
        self,
        registry: ProcessRegistry,
        features_adapter: FeaturesAdapter,
        inference_engine: InferenceEngine,
        response_engine: ResponseEngine,
        audit_logger: AuditLogger,
        horizon: float = 5.0,
        interval_s: float = 0.5,
    ) -> None:
        self.registry = registry
        self.features_adapter = features_adapter
        self.inference_engine = inference_engine
        self.response_engine = response_engine
        self.audit_logger = audit_logger
        self.horizon = horizon
        self.interval_s = interval_s

        self._stop_requested = threading.Event()
        self._thread: threading.Thread | None = None

    def _extract_top_signals(self, raw_features: dict[str, Any]) -> dict[str, Any]:
        """Extract a small summary of interesting signals for audit logging."""
        interesting_keys = [
            "n_events",
            "n_ProcessStart",
            "n_children_spawned",
            "max_tree_depth",
            "n_fio_create",
            "n_fio_write",
            "frac_exec_ext_created",
            "n_reg_create",
            "n_reg_persistence",
            "n_reg_defender_tamper",
            "events_per_sec",
        ]
        return {k: raw_features[k] for k in interesting_keys if k in raw_features}

    def _tick(self) -> None:
        """Run a single evaluation pass over candidate processes."""
        now = datetime.now()
        candidates = self.registry.get_candidate_roots_for_horizon(self.horizon, now)

        for proc in candidates:
            if self._stop_requested.is_set():
                break

            target_pid = proc.pid
            start_time = proc.start_time
            if start_time is None:
                continue

            lifetime_s = (now - start_time).total_seconds()

            # 1. Hunt target process and all its recursive descendants
            all_pids, all_events = self.registry.hunt_process_tree(target_pid)
            descendant_pids = [p for p in all_pids if p != target_pid]

            logger.info(
                "Evaluating PID %d (%s) at horizon %.1fs (life=%.2fs, evs=%d, ch=%d)",
                target_pid,
                proc.image_file_name,
                self.horizon,
                lifetime_s,
                len(all_events),
                len(descendant_pids),
            )

            # 2. Extract features and construct DMatrix
            try:
                dmatrix, raw_features = self.features_adapter.build_feature_matrix(
                    all_events, start_time, self.horizon
                )
            except Exception as e:
                logger.error(
                    "Feature extraction failed for PID %d: %s",
                    target_pid,
                    e,
                    exc_info=True,
                )
                continue

            # 3. Model inference
            try:
                probability, is_malicious = self.inference_engine.predict(dmatrix)
            except Exception as e:
                logger.error(
                    "Inference failed for PID %d: %s",
                    target_pid,
                    e,
                    exc_info=True,
                )
                continue

            top_signals = self._extract_top_signals(raw_features)

            # 4. Response & Audit
            if is_malicious:
                logger.warning(
                    "MALWARE ALERT! PID %d (%s) proba=%.4f >= thresh=%.4f",
                    target_pid,
                    proc.image_file_name,
                    probability,
                    self.inference_engine.threshold,
                )

                # Forcibly terminate root PID and all its descendants
                term_info = self.response_engine.terminate_process_tree(
                    target_pid, set(descendant_pids)
                )

                # Update registry status
                self.registry.mark_killed(all_pids)
                self.registry.mark_evaluated(
                    target_pid, self.horizon, is_malicious=True
                )

                # Audit log
                self.audit_logger.log_decision(
                    target_pid=target_pid,
                    image_name=proc.image_file_name,
                    ppid=proc.ppid,
                    descendant_pids=descendant_pids,
                    horizon=self.horizon,
                    lifetime_s=lifetime_s,
                    probability=probability,
                    threshold=self.inference_engine.threshold,
                    verdict="MALICIOUS",
                    action="BLOCKED_AND_KILLED",
                    termination_info=term_info,
                    top_signals=top_signals,
                )
            else:
                # Legitimate process continues running
                self.registry.mark_evaluated(
                    target_pid, self.horizon, is_malicious=False
                )

                # Audit log
                self.audit_logger.log_decision(
                    target_pid=target_pid,
                    image_name=proc.image_file_name,
                    ppid=proc.ppid,
                    descendant_pids=descendant_pids,
                    horizon=self.horizon,
                    lifetime_s=lifetime_s,
                    probability=probability,
                    threshold=self.inference_engine.threshold,
                    verdict="BENIGN",
                    action="ALLOWED",
                    top_signals=top_signals,
                )

        # Cleanup old stopped processes
        self.registry.cleanup_old_processes()

    def _loop(self) -> None:
        """Main timer loop."""
        logger.info(
            "HorizonScheduler running (horizon=%.1fs, interval=%.2fs)...",
            self.horizon,
            self.interval_s,
        )
        while not self._stop_requested.is_set():
            try:
                self._tick()
            except Exception as e:
                logger.error("Error in scheduler tick: %s", e, exc_info=True)

            self._stop_requested.wait(self.interval_s)
        logger.info("HorizonScheduler loop terminated.")

    def start(self) -> None:
        """Start scheduler thread."""
        self._stop_requested.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="HorizonSchedulerThread",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop scheduler."""
        self._stop_requested.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
