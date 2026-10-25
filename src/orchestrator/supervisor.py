"""Monitor supervisor and watchdog for SyscallMonitor process."""

from __future__ import annotations

import contextlib
import logging
import shlex
import subprocess
import threading
import time
from pathlib import Path

logger = logging.getLogger("orchestrator.supervisor")


class MonitorSupervisor:
    """Manages SyscallMonitor lifecycle with automatic watchdog restart."""

    def __init__(
        self,
        command: str | None = None,
        working_dir: Path | None = None,
        restart_cooldown_s: float = 2.0,
    ) -> None:
        self.command_str = command
        self.working_dir = working_dir or Path.cwd()
        self.restart_cooldown_s = restart_cooldown_s

        self.process: subprocess.Popen[bytes] | None = None
        self._stop_requested = threading.Event()
        self._watchdog_thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.restart_count = 0

    def _resolve_default_command(self) -> list[str]:
        """Resolve default SyscallMonitor command based on platform."""
        if self.command_str:
            return shlex.split(self.command_str)

        # Check candidate paths for compiled C# binary
        candidates = [
            Path("SyscallMonitor/bin/Release/net8.0/SyscallMonitor.exe"),
            Path("SyscallMonitor/bin/Debug/net8.0/SyscallMonitor.exe"),
            Path("SyscallMonitor/bin/Release/net8.0/SyscallMonitor"),
            Path("SyscallMonitor/bin/Debug/net8.0/SyscallMonitor"),
        ]
        for candidate in candidates:
            if candidate.exists():
                return [str(candidate.resolve())]

        # Check if dotnet is available
        return [
            "dotnet",
            "run",
            "--project",
            "SyscallMonitor/SyscallMonitor.csproj",
            "--no-build",
        ]

    def _spawn(self) -> bool:
        """Spawn the monitor subprocess."""
        cmd = self._resolve_default_command()
        logger.info("Spawning monitor process: %s", " ".join(cmd))
        try:
            self.process = subprocess.Popen(  # noqa: S603
                cmd,
                cwd=str(self.working_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            logger.info("Monitor started successfully (PID: %d)", self.process.pid)
            return True
        except FileNotFoundError as e:
            logger.error("Failed to find executable for monitor: %s", e)
            return False
        except Exception as e:
            logger.error("Error starting monitor process: %s", e)
            return False

    def _watchdog_loop(self) -> None:
        """Watchdog loop to monitor and auto-restart process if it crashes."""
        logger.info("Monitor watchdog started.")
        while not self._stop_requested.is_set():
            time.sleep(1.0)
            if self._stop_requested.is_set():
                break

            with self._lock:
                if self.process is None:
                    continue

                returncode = self.process.poll()
                if returncode is not None and not self._stop_requested.is_set():
                    self.restart_count += 1
                    logger.warning(
                        "Monitor PID %s died with code %s! Restart #%d...",
                        self.process.pid,
                        returncode,
                        self.restart_count,
                    )

                    with contextlib.suppress(Exception):
                        _, stderr = self.process.communicate(timeout=1.0)
                        if stderr:
                            logger.warning(
                                "Monitor stderr: %s",
                                stderr.decode(errors="replace"),
                            )

                    time.sleep(self.restart_cooldown_s)
                    if not self._stop_requested.is_set():
                        self._spawn()

    def start(self) -> bool:
        """Start the monitor and the supervisor watchdog thread."""
        with self._lock:
            self._stop_requested.clear()
            if not self._spawn():
                return False

            self._watchdog_thread = threading.Thread(
                target=self._watchdog_loop,
                name="MonitorWatchdogThread",
                daemon=True,
            )
            self._watchdog_thread.start()
            return True

    def stop(self, timeout_s: float = 5.0) -> None:
        """Gracefully stop the monitor and watchdog thread."""
        logger.info("Stopping monitor supervisor...")
        self._stop_requested.set()

        with self._lock:
            if self.process and self.process.poll() is None:
                try:
                    logger.info(
                        "Sending termination to monitor PID %d", self.process.pid
                    )
                    self.process.terminate()
                    self.process.wait(timeout=timeout_s)
                except subprocess.TimeoutExpired:
                    logger.warning(
                        "Monitor did not exit in %0.1fs, killing forcibly...",
                        timeout_s,
                    )
                    self.process.kill()
                    self.process.wait(timeout=2.0)
                except Exception as e:
                    logger.error("Error stopping monitor: %s", e)
                finally:
                    self.process = None

        if self._watchdog_thread and self._watchdog_thread.is_alive():
            self._watchdog_thread.join(timeout=2.0)
        logger.info("Monitor supervisor stopped.")

    @property
    def is_alive(self) -> bool:
        with self._lock:
            return self.process is not None and self.process.poll() is None
