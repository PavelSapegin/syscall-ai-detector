"""Real-time event streaming and ingestion from traces.jsonl into ProcessRegistry."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
import time
from datetime import datetime
from pathlib import Path

from src.features import parse_ts
from src.orchestrator.registry import ProcessRegistry

logger = logging.getLogger("orchestrator.ingestion")


class EventIngestionWorker:
    """Follows (tails) traces.jsonl and ingests ETW records into ProcessRegistry."""

    def __init__(
        self,
        traces_path: Path,
        registry: ProcessRegistry,
        read_from_beginning: bool = False,
        poll_interval_s: float = 0.05,
    ) -> None:
        self.traces_path = traces_path
        self.registry = registry
        self.read_from_beginning = read_from_beginning
        self.poll_interval_s = poll_interval_s

        self._stop_requested = threading.Event()
        self._thread: threading.Thread | None = None
        self.events_processed = 0
        self.parse_errors = 0

    def _ingest_line(self, raw_line: str) -> None:
        """Parse a single JSONL line and update the registry."""
        raw_line = raw_line.strip()
        if not raw_line:
            return

        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError:
            self.parse_errors += 1
            return

        if not isinstance(event, dict):
            return

        event_type = event.get("EventType", "")
        pid_raw = event.get("ProcessID")
        if pid_raw is None:
            return

        try:
            pid = int(pid_raw)
        except (ValueError, TypeError):
            return

        # Parse timestamp
        ts_str = event.get("Timestamp")
        ts = None
        if ts_str:
            try:
                ts = parse_ts(ts_str)
            except Exception:
                ts = datetime.now()
        else:
            ts = datetime.now()

        # Update registry based on event type
        if event_type == "ProcessStart":
            ppid = int(event.get("ParentProcessID") or 0)
            image = str(event.get("ImageFileName") or "")
            self.registry.register_process_start(pid, ppid, image, ts)
        elif event_type == "ProcessStop":
            exit_code = event.get("ExitCode")
            self.registry.register_process_stop(pid, ts, exit_code)

        # Store event
        self.registry.add_event(pid, event)
        self.events_processed += 1

    def _tail_loop(self) -> None:
        """Tail file continuously, handling file creation and rotation."""
        logger.info("Event ingestion loop started for: %s", self.traces_path)

        # Wait for file to exist
        while not self._stop_requested.is_set():
            if self.traces_path.exists():
                break
            time.sleep(0.2)

        if self._stop_requested.is_set():
            return

        try:
            trace_f = open(self.traces_path, encoding="utf-8", errors="replace")  # noqa: SIM115
            if not self.read_from_beginning:
                trace_f.seek(0, os.SEEK_END)

            partial_line = ""
            last_inode = os.fstat(trace_f.fileno()).st_ino

            try:
                while not self._stop_requested.is_set():
                    # Check for file rotation or truncation
                    with contextlib.suppress(Exception):
                        curr_stat = os.stat(self.traces_path)
                        if (
                            curr_stat.st_ino != last_inode
                            or curr_stat.st_size < trace_f.tell()
                        ):
                            logger.info(
                                "Traces file rotated or truncated. Reopening..."
                            )
                            trace_f.close()
                            trace_f = open(  # noqa: SIM115
                                self.traces_path,
                                encoding="utf-8",
                                errors="replace",
                            )
                            last_inode = os.fstat(trace_f.fileno()).st_ino
                            partial_line = ""

                    line = trace_f.readline()
                    if line:
                        if line.endswith("\n"):
                            full_line = partial_line + line
                            partial_line = ""
                            self._ingest_line(full_line)
                        else:
                            partial_line += line
                    else:
                        time.sleep(self.poll_interval_s)
            finally:
                trace_f.close()

        except Exception as e:
            if not self._stop_requested.is_set():
                logger.error("Error in event ingestion tail loop: %s", e, exc_info=True)

        logger.info(
            "Event ingestion terminated. Processed %d events.",
            self.events_processed,
        )

    def start(self) -> None:
        """Start the ingestion thread."""
        self._stop_requested.clear()
        self._thread = threading.Thread(
            target=self._tail_loop,
            name="EventIngestionThread",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop ingestion worker."""
        self._stop_requested.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
