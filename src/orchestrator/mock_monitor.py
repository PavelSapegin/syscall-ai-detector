"""Mock monitor that replays JSONL traces for local testing and simulation."""

from __future__ import annotations

import contextlib
import json
import logging
import threading
import time
from datetime import datetime
from pathlib import Path

from src.features import parse_ts

logger = logging.getLogger("orchestrator.mock_monitor")


class MockMonitor:
    """Simulates SyscallMonitor by replaying trace events into traces.jsonl."""

    def __init__(
        self,
        output_path: Path,
        sample_trace_path: Path | None = None,
        speedup: float = 1.0,
    ) -> None:
        self.output_path = output_path
        self.sample_trace_path = sample_trace_path
        self.speedup = max(speedup, 0.01)

        self._stop_requested = threading.Event()
        self._thread: threading.Thread | None = None

    def _generate_synthetic_events(self) -> list[dict]:
        """Generate synthetic malware-like sequence if no trace file provided."""
        now = datetime.now()
        base_ts = now.strftime("%Y-%m-%d %H:%M:%S.%f")
        return [
            {
                "Timestamp": base_ts,
                "EventType": "ProcessStart",
                "ProcessID": 9999,
                "ParentProcessID": 1000,
                "ImageFileName": "powershell.exe",
            },
            {
                "Timestamp": base_ts,
                "EventType": "FileIOCreate",
                "ProcessID": 9999,
                "FileName": "C:\\Windows\\Temp\\payload.exe",
            },
            {
                "Timestamp": base_ts,
                "EventType": "FileIOWrite",
                "ProcessID": 9999,
                "FileName": "C:\\Windows\\Temp\\payload.exe",
                "IoSize": 4096,
            },
            {
                "Timestamp": base_ts,
                "EventType": "RegistryCreate",
                "ProcessID": 9999,
                "KeyName": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            },
            {
                "Timestamp": base_ts,
                "EventType": "RegistrySetValue",
                "ProcessID": 9999,
                "KeyName": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "ValueName": "Updater",
            },
            {
                "Timestamp": base_ts,
                "EventType": "ProcessStart",
                "ProcessID": 10000,
                "ParentProcessID": 9999,
                "ImageFileName": "cmd.exe",
            },
        ]

    def _replay_loop(self) -> None:
        """Write events into output_path matching time intervals."""
        logger.info(
            "MockMonitor started writing to %s (speedup=%.1fx)",
            self.output_path,
            self.speedup,
        )
        events: list[dict] = []

        if self.sample_trace_path and self.sample_trace_path.exists():
            with open(self.sample_trace_path, encoding="utf-8") as f:
                for raw_line in f:
                    stripped = raw_line.strip()
                    if stripped:
                        with contextlib.suppress(Exception):
                            events.append(json.loads(stripped))
        else:
            events = self._generate_synthetic_events()

        if not events:
            logger.warning("No events to replay in MockMonitor.")
            return

        # Prepare output file
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "a", encoding="utf-8") as out_f:
            start_wall = time.time()
            first_event_ts: float | None = None

            for ev in events:
                if self._stop_requested.is_set():
                    break

                ts_str = ev.get("Timestamp")
                if ts_str:
                    with contextlib.suppress(Exception):
                        ev_dt = parse_ts(ts_str)
                        ev_ts = ev_dt.timestamp()
                        if first_event_ts is None:
                            first_event_ts = ev_ts

                        delay = (ev_ts - first_event_ts) / self.speedup
                        target_time = start_wall + delay
                        sleep_s = target_time - time.time()
                        if sleep_s > 0:
                            time.sleep(min(sleep_s, 1.0))

                # Update timestamp to current time for live emulation
                ev_copy = dict(ev)
                ev_copy["Timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

                out_f.write(json.dumps(ev_copy) + "\n")
                out_f.flush()

        logger.info("MockMonitor replay completed.")

    def start(self) -> None:
        self._stop_requested.clear()
        self._thread = threading.Thread(
            target=self._replay_loop,
            name="MockMonitorThread",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_requested.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
