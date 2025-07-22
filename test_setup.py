#!/usr/bin/env python3
"""
Test script to verify the project structure and core interfaces
"""

import sys
import os
from pathlib import Path

def test_imports():
    """Test that all core modules can be imported"""
    try:
        from forensics_toolkit.interfaces import (
            IDeviceHandler, IAttackEngine, IEvidenceManager, IForensicsEngine,
            AndroidDevice, AttackStrategy, AttackResult, EvidenceRecord,
            LockType, AttackType, ForensicsException
        )
        print("✓ Core interfaces imported successfully")
        
        from forensics_toolkit.config import ConfigManager, config_manager
        print("✓ Configuration management imported successfully")
        
        from forensics_toolkit.logging_system import EvidenceLogger, evidence_logger
        print("✓ Logging system imported successfully")
        
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def test_config_manager():
    """Test configuration manager functionality"""
    try:
        from forensics_toolkit.config import ConfigManager
        
        # Create a test config manager
        test_config = ConfigManager("./test_config.json")
        
        # Test tool path validation
        validation = test_config.validate_tool_paths()
        print(f"✓ Tool path validation completed: {validation}")
        
        # Test evidence path creation
        evidence_path = test_config.get_evidence_path("TEST_CASE_001")
        print(f"✓ Evidence path created: {evidence_path}")
        
        return True
    except Exception as e:
        print(f"✗ Config manager error: {e}")
        return False

def test_evidence_logger():
    """Test evidence logging functionality"""
    try:
        from forensics_toolkit.logging_system import EvidenceLogger
        
        # Create test logger
        test_logger = EvidenceLogger("./test_logs", encrypt_logs=False)
        
        # Test logging operation
        log_entry = test_logger.log_operation(
            level="INFO",
            operation="TEST_OPERATION",
            message="Testing evidence logging system",
            case_id="TEST_CASE_001",
            device_serial="TEST_DEVICE_123",
            metadata={"test": True}
        )
        
        print(f"✓ Log entry created with hash: {log_entry.hash_value[:16]}...")
        
        # Test integrity verification
        is_valid = log_entry.verify_integrity()
        print(f"✓ Log integrity verification: {is_valid}")
        
        return True
    except Exception as e:
        print(f"✗ Evidence logger error: {e}")
        return False

def test_data_models():
    """Test core data models"""
    try:
        from forensics_toolkit.interfaces import AndroidDevice, AttackStrategy, LockType, AttackType
        
        # Test AndroidDevice model
        device = AndroidDevice(
            serial="TEST123",
            model="Pixel 6",
            brand="Google",
            android_version="12",
            usb_debugging=True,
            lock_type=LockType.PIN
        )
        print(f"✓ AndroidDevice model created: {device.brand} {device.model}")
        
        # Test AttackStrategy model
        strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=device,
            wordlists=["common_pins.txt"],
            mask_patterns=["?d?d?d?d"],
            max_attempts=10000
        )
        print(f"✓ AttackStrategy model created: {strategy.strategy_type.value}")
        
        return True
    except Exception as e:
        print(f"✗ Data model error: {e}")
        return False

def main():
    """Run all tests"""
    print("Testing ForenCrack Droid project setup...")
    print("=" * 50)
    
    tests = [
        ("Import Tests", test_imports),
        ("Configuration Manager", test_config_manager),
        ("Evidence Logger", test_evidence_logger),
        ("Data Models", test_data_models)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        print("-" * 30)
        if test_func():
            passed += 1
            print(f"✓ {test_name} PASSED")
        else:
            print(f"✗ {test_name} FAILED")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All tests passed! Project setup is complete.")
        return 0
    else:
        print("✗ Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())