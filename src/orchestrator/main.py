"""Main orchestrator coordinator and CLI entry point."""

from __future__ import annotations

import logging
import signal
import sys
import time
from pathlib import Path

from src.orchestrator.audit import AuditLogger
from src.orchestrator.config import OrchestratorConfig, parse_args
from src.orchestrator.elevation import verify_admin_privileges
from src.orchestrator.features_adapter import FeaturesAdapter
from src.orchestrator.inference import InferenceEngine
from src.orchestrator.ingestion import EventIngestionWorker
from src.orchestrator.mock_monitor import MockMonitor
from src.orchestrator.registry import ProcessRegistry
from src.orchestrator.response import ResponseEngine
from src.orchestrator.scheduler import HorizonScheduler
from src.orchestrator.supervisor import MonitorSupervisor

logger = logging.getLogger("orchestrator")


def setup_logging(log_file_path: Path) -> None:
    """Setup root logging to console and file."""
    log_file_path.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(log_file_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)


class Orchestrator:
    """Coordinates monitor supervisor, ingestion, features, model, and response."""

    def __init__(self, config: OrchestratorConfig) -> None:
        self.config = config
        self._shutdown_requested = False

        # Verify privileges
        verify_admin_privileges(self.config.bypass_admin_check)

        # 1. Feature Adapter & Schema
        self.features_adapter = FeaturesAdapter(self.config.reference_features_path)

        # 2. ML Model & Inference
        self.inference_engine = InferenceEngine(
            model_path=self.config.model_path,
            metrics_path=self.config.metrics_path,
            custom_threshold=self.config.threshold,
        )

        # 3. Data structures & Engines
        self.registry = ProcessRegistry()
        self.response_engine = ResponseEngine()
        self.audit_logger = AuditLogger(self.config.audit_log_path)

        # 4. Monitor Supervisor (or Mock)
        self.mock_monitor: MockMonitor | None = None
        self.monitor_supervisor: MonitorSupervisor | None = None

        if self.config.mock_mode:
            logger.info("Initializing in MOCK monitor mode.")
            self.mock_monitor = MockMonitor(
                output_path=self.config.traces_path,
                sample_trace_path=self.config.mock_trace_path,
                speedup=self.config.mock_speedup,
            )
        else:
            self.monitor_supervisor = MonitorSupervisor(
                command=self.config.monitor_cmd,
            )

        # 5. Ingestion worker
        self.ingestion_worker = EventIngestionWorker(
            traces_path=self.config.traces_path,
            registry=self.registry,
            read_from_beginning=self.config.mock_mode,
        )

        # 6. Horizon scheduler
        self.scheduler = HorizonScheduler(
            registry=self.registry,
            features_adapter=self.features_adapter,
            inference_engine=self.inference_engine,
            response_engine=self.response_engine,
            audit_logger=self.audit_logger,
            horizon=self.config.horizon,
            interval_s=self.config.timer_interval_s,
        )

    def start(self) -> None:
        """Start all background subsystems."""
        logger.info("==================================================")
        logger.info("   Starting Syscall AI Detector Orchestrator      ")
        logger.info(
            "   Horizon: %.1fs | Threshold: %.4f",
            self.config.horizon,
            self.inference_engine.threshold,
        )
        logger.info("==================================================")

        # Start ingestion
        self.ingestion_worker.start()

        # Start monitor
        if self.mock_monitor:
            self.mock_monitor.start()
        elif self.monitor_supervisor:
            success = self.monitor_supervisor.start()
            if not success:
                logger.error("Failed to start monitor supervisor!")

        # Start scheduler
        self.scheduler.start()

        logger.info("All orchestrator subsystems active.")

    def stop(self) -> None:
        """Gracefully stop all subsystems."""
        if self._shutdown_requested:
            return
        self._shutdown_requested = True

        logger.info("Initiating graceful orchestrator shutdown...")

        # Stop scheduler first to avoid new decisions during teardown
        self.scheduler.stop()

        # Stop ingestion
        self.ingestion_worker.stop()

        # Stop monitor
        if self.mock_monitor:
            self.mock_monitor.stop()
        elif self.monitor_supervisor:
            self.monitor_supervisor.stop()

        logger.info("Orchestrator successfully terminated.")

    def run_forever(self) -> None:
        """Run until SIGINT or SIGTERM."""

        def _handle_signal(sig, frame):
            logger.info("Termination signal received (signal %s).", sig)
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        self.start()
        try:
            while not self._shutdown_requested:
                time.sleep(0.5)
        except (KeyboardInterrupt, SystemExit):
            self.stop()


def main() -> None:
    config = parse_args()
    setup_logging(config.log_file_path)
    orchestrator = Orchestrator(config)
    orchestrator.run_forever()


if __name__ == "__main__":
    main()
