#!/usr/bin/env python3
"""Launcher for Syscall AI Detector Orchestrator."""

import os
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.orchestrator.main import main

if __name__ == "__main__":
    main()
