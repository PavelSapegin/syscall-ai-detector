"""Privilege and elevation verification for the orchestrator."""

from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger("orchestrator.elevation")


def is_running_as_admin() -> bool:
    """Check if the current process is running with Administrator/root privileges.

    Returns:
        True if running with elevated privileges, False otherwise.
    """
    if sys.platform == "win32":
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            logger.warning("Could not check Windows admin rights via ctypes: %s", e)
            return False
    else:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False


def verify_admin_privileges(bypass: bool = False) -> None:
    """Verify administrator privileges or raise PermissionError.

    Args:
        bypass: If True, log warning and bypass check.

    Raises:
        PermissionError: If not elevated and bypass is False.
    """
    if is_running_as_admin():
        logger.info("Administrator / elevated privileges verified.")
        return

    if bypass:
        logger.warning(
            "WARNING: Running without Administrator privileges! "
            "(Bypass active. Monitor ETW session or process termination may fail)."
        )
        return

    error_msg = (
        "This program requires Administrator privileges to run ETW tracing, "
        "interact with SyscallMonitor, and terminate malicious processes.\n"
        "Please restart your terminal/process as Administrator (or root).\n"
        "To bypass for testing/debugging, pass the --bypass-admin-check flag."
    )
    logger.critical(error_msg)
    raise PermissionError(error_msg)
