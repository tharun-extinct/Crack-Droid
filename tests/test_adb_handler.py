"""
Unit tests for ADB Handler with mocked ADB responses
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import subprocess
from datetime import datetime
from typing import List

from forensics_toolkit.services.adb_handler import ADBHandler, ADBException, ADBCommand
from forensics_toolkit.interfaces import AndroidDevice, LockType
from forensics_toolkit.models.device import LockoutPolicy


class TestADBHandler(unittest.TestCase):
    """Test cases for ADB Handler"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.adb_path = "/usr/bin/adb"
        
        # Mock successful ADB version check
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Android Debug Bridge version 1.0.41",
                stderr=""
            )
            self.handler = ADBHandler(adb_path=self.adb_path, timeout=10)
    
    def test_init_success(self):
        """Test successful ADB handler initialization"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Android Debug Bridge version 1.0.41",
                stderr=""
            )
            
            handler = ADBHandler()
            self.assertEqual(handler.adb_path, "adb")
            self.assertEqual(handler.timeout, 30)
            self.assertEqual(l