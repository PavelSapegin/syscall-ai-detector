"""Response system: forcefully terminates malicious process and all its descendants."""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys

import psutil

logger = logging.getLogger("orchestrator.response")


class ResponseEngine:
    """Terminates malicious target process and its complete descendant tree."""

    @staticmethod
    def terminate_process_tree(
        root_pid: int,
        known_descendant_pids: set[int] | None = None,
    ) -> dict[str, list[int]]:
        """Forcefully kill target PID and all its children.

        Args:
            root_pid: Target process PID.
            known_descendant_pids: Set of descendant PIDs tracked by ProcessRegistry.

        Returns:
            Dictionary with lists of killed, failed, and already dead PIDs.
        """
        results: dict[str, list[int]] = {
            "killed": [],
            "failed": [],
            "already_dead": [],
        }

        all_target_pids = set(known_descendant_pids or set())
        all_target_pids.add(root_pid)

        # 1. Discover active processes in the system via psutil
        try:
            root_proc = psutil.Process(root_pid)
            try:
                children = root_proc.children(recursive=True)
                for child in children:
                    all_target_pids.add(child.pid)
            except Exception as e:
                logger.debug(
                    "Could not query psutil children for PID %d: %s",
                    root_pid,
                    e,
                )
        except psutil.NoSuchProcess:
            results["already_dead"].append(root_pid)
        except Exception as e:
            logger.warning("Error querying root PID %d with psutil: %s", root_pid, e)

        # 2. On Windows, use native taskkill /F /T /PID as the primary robust weapon
        if sys.platform == "win32":
            try:
                cmd = ["taskkill", "/F", "/T", "/PID", str(root_pid)]
                logger.info("Executing Windows tree kill: %s", " ".join(cmd))
                res = subprocess.run(  # noqa: S603
                    cmd,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                )
                if res.returncode == 0:
                    logger.info("taskkill succeeded: %s", res.stdout.strip())
                else:
                    logger.warning(
                        "taskkill returned code %d: %s",
                        res.returncode,
                        res.stderr.strip(),
                    )
            except Exception as e:
                logger.error("Failed to execute taskkill for PID %d: %s", root_pid, e)

        # 3. Direct kill of all identified PIDs (children first, then root)
        target_list = [p for p in all_target_pids if p != root_pid] + [root_pid]

        for pid in target_list:
            if not psutil.pid_exists(pid):
                if pid not in results["already_dead"]:
                    results["already_dead"].append(pid)
                continue

            try:
                p = psutil.Process(pid)
                p.kill()
                results["killed"].append(pid)
                logger.info("Killed process PID %d (%s)", pid, p.name())
            except psutil.NoSuchProcess:
                results["already_dead"].append(pid)
            except psutil.AccessDenied as e:
                logger.error("Access denied killing PID %d: %s", pid, e)
                # Try fallback os.kill
                try:
                    os.kill(pid, signal.SIGKILL if hasattr(signal, "SIGKILL") else 9)
                    results["killed"].append(pid)
                except Exception as ex:
                    results["failed"].append(pid)
                    logger.critical("Failed to terminate PID %d: %s", pid, ex)
            except Exception as e:
                results["failed"].append(pid)
                logger.error("Unexpected error killing PID %d: %s", pid, e)

        return results
