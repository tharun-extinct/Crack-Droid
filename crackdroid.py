#!/usr/bin/env python3
"""
Crack Droid - Main CLI Entry Point

This script provides the main command-line interface for the Crack Droid
Android forensics toolkit.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from forensics_toolkit.ui.cli import main

if __name__ == '__main__':
    sys.exit(main())
