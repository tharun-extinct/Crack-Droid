"""
Unit tests for AttackStrategy and EvidenceRecord models
"""

import pytest
import json
from datetime import datetime, timedelta
from forensics_toolkit.models.attack import (
    AttackStrategy, EvidenceRecord, CustodyEvent, 
    AttackValidationError, DelayStrategy, AttackStatus
)
from forensics_toolkit.models.device import AndroidDevice
from forensics_toolkit.interfaces import AttackType, LockType, ForensicsException


class TestAttackStrategy:
    """Test AttackStrategy model validation and functionality"""
    
    def create_test_device(self) -> AndroidDevice:
        """Create a test Android device"""
        return AndroidDevice(
            serial="TEST123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            usb_debugging=True,
            lock_type=LockType.PIN
