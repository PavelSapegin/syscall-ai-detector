"""Audit logger for recording detection verdicts and response actions."""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("orchestrator.audit")


class AuditLogger:
    """Records audit decisions in JSONL format and displays console alerts."""

    def __init__(self, audit_file_path: Path) -> None:
        self.audit_file_path = audit_file_path
        self._lock = threading.Lock()

        # Ensure parent directory exists
        self.audit_file_path.parent.mkdir(parents=True, exist_ok=True)

    def log_decision(
        self,
        target_pid: int,
        image_name: str,
        ppid: int,
        descendant_pids: list[int],
        horizon: float,
        lifetime_s: float,
        probability: float,
        threshold: float,
        verdict: str,
        action: str,
        termination_info: dict[str, list[int]] | None = None,
        top_signals: dict[str, Any] | None = None,
    ) -> None:
        """Write an audit entry and output a formatted alert banner."""
        timestamp = datetime.now().isoformat()
        termination_info = termination_info or {}

        record = {
            "timestamp": timestamp,
            "target_pid": target_pid,
            "image_name": image_name,
            "ppid": ppid,
            "descendant_pids": sorted(descendant_pids),
            "horizon_s": horizon,
            "lifetime_s": round(lifetime_s, 3),
            "probability": round(probability, 4),
            "threshold": round(threshold, 4),
            "verdict": verdict,
            "action": action,
            "killed_pids": termination_info.get("killed", []),
            "already_dead_pids": termination_info.get("already_dead", []),
            "failed_pids": termination_info.get("failed", []),
            "top_signals": top_signals or {},
        }

        # Write to audit JSONL file
        with self._lock, open(self.audit_file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        # Visual banner for operators
        if verdict == "MALICIOUS":
            print("\n" + "=" * 70)
            print(f"[MALWARE DETECTED & BLOCKED] PID: {target_pid} ({image_name})")
            print(f"   Probability: {probability:.4f} (Threshold: {threshold:.4f})")
            print(f"   Horizon: {horizon}s | Descendant PIDs: {descendant_pids}")
            print(f"   Action: {action}")
            if termination_info.get("killed"):
                print(f"   Killed PIDs: {termination_info['killed']}")
            if top_signals:
                print(f"   Key Signals: {top_signals}")
            print("=" * 70 + "\n")
        else:
            logger.info(
                "[OK - BENIGN] PID %d (%s) | Proba=%.4f <= Thresh=%.4f | Allowed",
                target_pid,
                image_name,
                probability,
                threshold,
            )
