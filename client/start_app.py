#!/usr/bin/env python3
"""Entry point for source and the packaged macOS application."""
import multiprocessing
from app import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
