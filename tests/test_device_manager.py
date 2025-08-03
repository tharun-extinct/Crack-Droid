"""
Unit tests for DeviceManager class

This module contains comprehensive unit tests for the DeviceManager class,
testing multi-device handling, state tracking, concurrent processing,
and health monitoring capabilities.
"""

import unittest
import threading
import time
from unittest.mock import Mock, MagicMock, patch, call
from datetime import datetime, timedelta
from concurrent.futures import Future

from forensics_toolkit.interfaces import AndroidDevice, LockType, IDeviceHandler
from forensics_toolkit.services.device_manager import (
    DeviceManager, DeviceState, DeviceHealthStatus, DeviceStatus,
    DeviceManagerException
)


class MockDeviceHandler(IDeviceHandler):
    """Mock device handler for testing"""
    
    def __init__(self, name: str, devices: list = None, should_fail: bool = False):
        self.name = name
        self.devices = devices or []
        self.should_fail = should_fail
        self.detect_calls = 0
        self.connect_calls = 0
        self.accessible_calls = 0
    
    def detect_devices(self):
        self.detect_calls += 1
        if self.should_fail:
            raise Exception(f"Handler {self.name} detection failed")
        return self.devices.copy()
    
    def connect_device(self, device: AndroidDevice):
        self.connect_calls += 1
        if self.should_fail:
            return False
        return True
    
    def get_device_info(self, device: AndroidDevice):
        return device
    
    def is_device_accessible(self, device: AndroidDevice):
        self.accessible_calls += 1
        if self.should_fail:
            return False
        return True


class TestDeviceStatus(unittest.TestCase):
    """Test DeviceStatus class functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.device = AndroidDevice(
            serial="TEST123",
            model="TestPhone",
            brand="TestBrand",
            android_version="11",
            usb_debugging=True
        )
        self.status = DeviceStatus(device=self.device)
    
    def test_initial_state(self):
        """Test initial device status state"""
        self.assertEqual(self.status.state, DeviceState.UNKNOWN)
        self.assertEqual(self.status.health, DeviceHealthStatus.OFFLINE)
        self.assertEqual(self.status.connection_attempts, 0)
        self.assertEqual(self.status.error_count, 0)
        self.assertIsNone(self.status.last_error)
        self.assertIsNone(self.status.handler_name)
        self.assertIsNone(self.status.current_operation)
        self.assertIsNone(self.status.lockout_until)
    
    def test_is_available_connected(self):
        """Test device availability when connected"""
        self.status.state = DeviceState.CONNECTED
        self.assertTrue(self.status.is_available)
    
    def test_is_available_disconnected(self):
        """Test device availability when disconnected"""
        self.status.state = DeviceState.DISCONNECTED
        self.assertFalse(self.status.is_available)
    
    def test_is_available_error(self):
        """Test device availability when in error state"""
        self.status.state = DeviceState.ERROR
        self.assertFalse(self.status.is_available)
    
    def test_is_available_locked_out(self):
        """Test device availability when locked out"""
        self.status.state = DeviceState.CONNECTED
        self.status.lockout_until = datetime.now() + timedelta(minutes=5)
        self.assertFalse(self.status.is_available)
    
    def test_is_available_lockout_expired(self):
        """Test device availability when lockout has expired"""
        self.status.state = DeviceState.CONNECTED
        self.status.lockout_until = datetime.now() - timedelta(minutes=5)
        self.assertTrue(self.status.is_available)
    
    def test_time_since_last_seen(self):
        """Test time since last seen calculation"""
        past_time = datetime.now() - timedelta(minutes=10)
        self.status.last_seen = past_time
        
        time_diff = self.status.time_since_last_seen
        self.assertGreaterEqual(time_diff.total_seconds(), 600)  # At least 10 minutes
    
    def test_update_state(self):
        """Test state update functionality"""
        old_time = self.status.last_seen
        time.sleep(0.01)  # Small delay to ensure time difference
        
        self.status.update_state(
            DeviceState.BUSY,
            operation="test_operation",
            error="test_error"
        )
        
        self.assertEqual(self.status.state, DeviceState.BUSY)
        self.assertEqual(self.status.current_operation, "test_operation")
        self.assertEqual(self.status.last_error, "test_error")
        self.assertEqual(self.status.error_count, 1)
        self.assertGreater(self.status.last_seen, old_time)
    
    def test_update_state_error_count_reset(self):
        """Test error count reset on successful connection"""
        self.status.error_count = 5
        self.status.update_state(DeviceState.CONNECTED)
        
        self.assertEqual(self.status.error_count, 4)  # Decremented by 1


class TestDeviceManager(unittest.TestCase):
    """Test DeviceManager class functionality"""
    
    def setUp(self):
        """Set up test environment"""
        # Create test devices
        self.device1 = AndroidDevice(
            serial="DEVICE001",
            model="TestPhone1",
            brand="TestBrand",
            android_version="11",
            usb_debugging=True
        )
        
        self.device2 = AndroidDevice(
            serial="DEVICE002",
            model="TestPhone2",
            brand="TestBrand",
            android_version="12",
            usb_debugging=False
        )
        
        # Create mock handlers
        self.handler1 = MockDeviceHandler("adb", [self.device1])
        self.handler2 = MockDeviceHandler("edl", [self.device2])
        
        self.device_handlers = {
            "adb": self.handler1,
            "edl": self.handler2
        }
        
        # Create device manager with short health check interval for testing
        self.device_manager = DeviceManager(
            device_handlers=self.device_handlers,
            max_concurrent_devices=2,
            health_check_interval=1,  # 1 second for testing
            logger=Mock()
        )
    
    def tearDown(self):
        """Clean up test environment"""
        self.device_manager.shutdown()
    
    def test_initialization(self):
        """Test device manager initialization"""
        self.assertEqual(len(self.device_manager.device_handlers), 2)
        self.assertEqual(self.device_manager.max_concurrent_devices, 2)
        self.assertEqual(self.device_manager.health_check_interval, 1)
        self.assertIsNotNone(self.device_manager._executor)
        self.assertIsNotNone(self.device_manager._health_monitor_thread)
    
    def test_discover_devices(self):
        """Test device discovery functionality"""
        devices = self.device_manager.discover_devices()
        
        self.assertEqual(len(devices), 2)
        device_serials = [d.serial for d in devices]
        self.assertIn("DEVICE001", device_serials)
        self.assertIn("DEVICE002", device_serials)
        
        # Check that handlers were called
        self.assertEqual(self.handler1.detect_calls, 1)
        self.assertEqual(self.handler2.detect_calls, 1)
        
        # Check that devices were registered
        self.assertEqual(len(self.device_manager.device_status), 2)
        self.assertIn("DEVICE001", self.device_manager.device_status)
        self.assertIn("DEVICE002", self.device_manager.device_status)
    
    def test_discover_devices_with_handler_failure(self):
        """Test device discovery with handler failure"""
        self.handler1.should_fail = True
        
        devices = self.device_manager.discover_devices()
        
        # Should still get device from working handler
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].serial, "DEVICE002")
    
    def test_discover_devices_duplicate_prevention(self):
        """Test that duplicate devices are not added"""
        # Add same device to both handlers
        self.handler2.devices.append(self.device1)
        
        devices = self.device_manager.discover_devices()
        
        # Should only have unique devices
        device_serials = [d.serial for d in devices]
        self.assertEqual(device_serials.count("DEVICE001"), 1)
    
    def test_get_device_status(self):
        """Test getting device status"""
        self.device_manager.discover_devices()
        
        status = self.device_manager.get_device_status("DEVICE001")
        self.assertIsNotNone(status)
        self.assertEqual(status.device.serial, "DEVICE001")
        self.assertEqual(status.state, DeviceState.CONNECTED)
        
        # Test non-existent device
        status = self.device_manager.get_device_status("NONEXISTENT")
        self.assertIsNone(status)
    
    def test_get_all_device_status(self):
        """Test getting all device statuses"""
        self.device_manager.discover_devices()
        
        all_status = self.device_manager.get_all_device_status()
        self.assertEqual(len(all_status), 2)
        self.assertIn("DEVICE001", all_status)
        self.assertIn("DEVICE002", all_status)
    
    def test_get_available_devices(self):
        """Test getting available devices"""
        self.device_manager.discover_devices()
        
        available = self.device_manager.get_available_devices()
        self.assertEqual(len(available), 2)
        self.assertIn("DEVICE001", available)
        self.assertIn("DEVICE002", available)
        
        # Set one device to error state
        self.device_manager.set_device_state("DEVICE001", DeviceState.ERROR)
        
        available = self.device_manager.get_available_devices()
        self.assertEqual(len(available), 1)
        self.assertIn("DEVICE002", available)
    
    def test_get_devices_by_state(self):
        """Test getting devices by state"""
        self.device_manager.discover_devices()
        
        # Initially both should be connected
        connected = self.device_manager.get_devices_by_state(DeviceState.CONNECTED)
        self.assertEqual(len(connected), 2)
        
        # Set one to busy
        self.device_manager.set_device_state("DEVICE001", DeviceState.BUSY)
        
        busy = self.device_manager.get_devices_by_state(DeviceState.BUSY)
        self.assertEqual(len(busy), 1)
        self.assertIn("DEVICE001", busy)
        
        connected = self.device_manager.get_devices_by_state(DeviceState.CONNECTED)
        self.assertEqual(len(connected), 1)
        self.assertIn("DEVICE002", connected)
    
    def test_set_device_state(self):
        """Test setting device state"""
        self.device_manager.discover_devices()
        
        # Mock callback
        state_callback = Mock()
        self.device_manager.set_device_state_changed_callback(state_callback)
        
        self.device_manager.set_device_state(
            "DEVICE001", 
            DeviceState.BUSY, 
            operation="test_operation",
            error="test_error"
        )
        
        status = self.device_manager.get_device_status("DEVICE001")
        self.assertEqual(status.state, DeviceState.BUSY)
        self.assertEqual(status.current_operation, "test_operation")
        self.assertEqual(status.last_error, "test_error")
        self.assertEqual(status.error_count, 1)
        
        # Check callback was called
        state_callback.assert_called_once_with("DEVICE001", DeviceState.BUSY)
    
    def test_set_device_lockout(self):
        """Test setting device lockout"""
        self.device_manager.discover_devices()
        
        self.device_manager.set_device_lockout("DEVICE001", 300)  # 5 minutes
        
        status = self.device_manager.get_device_status("DEVICE001")
        self.assertEqual(status.state, DeviceState.LOCKED_OUT)
        self.assertIsNotNone(status.lockout_until)
        self.assertFalse(status.is_available)
        
        # Check lockout time is approximately correct
        expected_lockout = datetime.now() + timedelta(seconds=300)
        time_diff = abs((status.lockout_until - expected_lockout).total_seconds())
        self.assertLess(time_diff, 5)  # Within 5 seconds
    
    def test_check_device_connection(self):
        """Test checking device connection"""
        self.device_manager.discover_devices()
        
        # Test successful connection check
        is_connected = self.device_manager.check_device_connection("DEVICE001")
        self.assertTrue(is_connected)
        self.assertEqual(self.handler1.accessible_calls, 1)
        
        # Test failed connection check
        self.handler1.should_fail = True
        is_connected = self.device_manager.check_device_connection("DEVICE001")
        self.assertFalse(is_connected)
        
        status = self.device_manager.get_device_status("DEVICE001")
        self.assertEqual(status.state, DeviceState.DISCONNECTED)
    
    def test_reconnect_device(self):
        """Test device reconnection"""
        self.device_manager.discover_devices()
        
        # Test successful reconnection
        success = self.device_manager.reconnect_device("DEVICE001")
        self.assertTrue(success)
        self.assertEqual(self.handler1.connect_calls, 1)
        
        status = self.device_manager.get_device_status("DEVICE001")
        self.assertEqual(status.state, DeviceState.CONNECTED)
        self.assertEqual(status.connection_attempts, 1)
        
        # Test failed reconnection
        self.handler1.should_fail = True
        success = self.device_manager.reconnect_device("DEVICE001")
        self.assertFalse(success)
        
        status = self.device_manager.get_device_status("DEVICE001")
        self.assertEqual(status.state, DeviceState.DISCONNECTED)
    
    def test_perform_concurrent_operation(self):
        """Test concurrent operation execution"""
        self.device_manager.discover_devices()
        
        # Mock operation function
        operation_results = {"DEVICE001": "result1", "DEVICE002": "result2"}
        
        def mock_operation(device_serial):
            return operation_results[device_serial]
        
        results = self.device_manager.perform_concurrent_operation(
            ["DEVICE001", "DEVICE002"],
            mock_operation,
            "test_operation"
        )
        
        self.assertEqual(len(results), 2)
        self.assertEqual(results["DEVICE001"], "result1")
        self.assertEqual(results["DEVICE002"], "result2")
        
        # Check devices are back to connected state
        for device_serial in ["DEVICE001", "DEVICE002"]:
            status = self.device_manager.get_device_status(device_serial)
            self.assertEqual(status.state, DeviceState.CONNECTED)
    
    def test_perform_concurrent_operation_with_failure(self):
        """Test concurrent operation with failure"""
        self.device_manager.discover_devices()
        
        def failing_operation(device_serial):
            if device_serial == "DEVICE001":
                raise Exception("Operation failed")
            return "success"
        
        results = self.device_manager.perform_concurrent_operation(
            ["DEVICE001", "DEVICE002"],
            failing_operation,
            "test_operation"
        )
        
        self.assertEqual(len(results), 2)
        self.assertIn("error", results["DEVICE001"])
        self.assertEqual(results["DEVICE002"], "success")
        
        # Check device states
        status1 = self.device_manager.get_device_status("DEVICE001")
        self.assertEqual(status1.state, DeviceState.ERROR)
        
        status2 = self.device_manager.get_device_status("DEVICE002")
        self.assertEqual(status2.state, DeviceState.CONNECTED)
    
    def test_perform_concurrent_operation_no_available_devices(self):
        """Test concurrent operation with no available devices"""
        self.device_manager.discover_devices()
        
        # Set all devices to error state
        self.device_manager.set_device_state("DEVICE001", DeviceState.ERROR)
        self.device_manager.set_device_state("DEVICE002", DeviceState.ERROR)
        
        def mock_operation(device_serial):
            return "result"
        
        results = self.device_manager.perform_concurrent_operation(
            ["DEVICE001", "DEVICE002"],
            mock_operation,
            "test_operation"
        )
        
        self.assertEqual(len(results), 0)
    
    def test_health_monitoring(self):
        """Test health monitoring functionality"""
        self.device_manager.discover_devices()
        
        # Mock health callback
        health_callback = Mock()
        self.device_manager.set_device_health_changed_callback(health_callback)
        
        # Simulate device going offline by setting old last_seen time
        status = self.device_manager.get_device_status("DEVICE001")
        status.last_seen = datetime.now() - timedelta(minutes=10)
        
        # Manually trigger health check instead of waiting
        self.device_manager._check_device_health("DEVICE001")
        
        # Check that health status changed to offline
        updated_status = self.device_manager.get_device_status("DEVICE001")
        self.assertEqual(updated_status.health, DeviceHealthStatus.OFFLINE)
        
        # Verify callback was called
        health_callback.assert_called()
    
    def test_health_assessment(self):
        """Test device health assessment"""
        status = DeviceStatus(device=self.device1)
        
        # Test healthy device
        health = self.device_manager._assess_device_health(status)
        self.assertEqual(health, DeviceHealthStatus.HEALTHY)
        
        # Test device with warnings (moderate errors)
        status.error_count = 7
        health = self.device_manager._assess_device_health(status)
        self.assertEqual(health, DeviceHealthStatus.WARNING)
        
        # Test critical device (many errors)
        status.error_count = 15
        health = self.device_manager._assess_device_health(status)
        self.assertEqual(health, DeviceHealthStatus.CRITICAL)
        
        # Test offline device
        status.error_count = 0
        status.last_seen = datetime.now() - timedelta(minutes=10)
        health = self.device_manager._assess_device_health(status)
        self.assertEqual(health, DeviceHealthStatus.OFFLINE)
        
        # Test device in error state
        status.last_seen = datetime.now()
        status.state = DeviceState.ERROR
        health = self.device_manager._assess_device_health(status)
        self.assertEqual(health, DeviceHealthStatus.CRITICAL)
    
    def test_get_health_summary(self):
        """Test health summary generation"""
        self.device_manager.discover_devices()
        
        # Set different states for testing
        self.device_manager.set_device_state("DEVICE001", DeviceState.BUSY, operation="test_op")
        
        status2 = self.device_manager.get_device_status("DEVICE002")
        status2.error_count = 7  # Warning level
        status2.health = DeviceHealthStatus.WARNING
        
        summary = self.device_manager.get_health_summary()
        
        self.assertEqual(summary['total_devices'], 2)
        self.assertEqual(summary['healthy_devices'], 1)
        self.assertEqual(summary['warning_devices'], 1)
        self.assertEqual(summary['critical_devices'], 0)
        self.assertEqual(summary['offline_devices'], 0)
        self.assertEqual(summary['available_devices'], 1)
        self.assertEqual(summary['busy_devices'], 1)
        self.assertEqual(summary['error_devices'], 0)
        
        # Check device details
        self.assertIn("DEVICE001", summary['device_details'])
        self.assertIn("DEVICE002", summary['device_details'])
        
        device1_details = summary['device_details']['DEVICE001']
        self.assertEqual(device1_details['state'], 'busy')
        self.assertEqual(device1_details['current_operation'], 'test_op')
    
    def test_callback_functionality(self):
        """Test callback functionality"""
        self.device_manager.discover_devices()
        
        # Set up callbacks
        state_callback = Mock()
        health_callback = Mock()
        error_callback = Mock()
        
        self.device_manager.set_device_state_changed_callback(state_callback)
        self.device_manager.set_device_health_changed_callback(health_callback)
        self.device_manager.set_device_error_callback(error_callback)
        
        # Trigger state change with error
        self.device_manager.set_device_state("DEVICE001", DeviceState.ERROR, error="test error")
        
        # Check callbacks were called
        state_callback.assert_called_once_with("DEVICE001", DeviceState.ERROR)
        error_callback.assert_called_once_with("DEVICE001", "test error")
    
    def test_context_manager(self):
        """Test context manager functionality"""
        with DeviceManager(self.device_handlers) as dm:
            self.assertIsNotNone(dm._executor)
            self.assertIsNotNone(dm._health_monitor_thread)
        
        # After exiting context, manager should be shut down
        # Note: We can't easily test the shutdown state without accessing private members
    
    def test_shutdown(self):
        """Test device manager shutdown"""
        # Create a new manager for this test
        dm = DeviceManager(self.device_handlers)
        
        # Verify it's running
        self.assertIsNotNone(dm._executor)
        self.assertIsNotNone(dm._health_monitor_thread)
        
        # Shutdown
        dm.shutdown()
        
        # Verify shutdown completed
        self.assertTrue(dm._health_monitor_stop.is_set())


class TestDeviceManagerException(unittest.TestCase):
    """Test DeviceManagerException class"""
    
    def test_exception_creation(self):
        """Test exception creation"""
        exception = DeviceManagerException("Test error", device_serial="DEVICE001")
        
        self.assertEqual(str(exception), "Test error")
        self.assertEqual(exception.device_serial, "DEVICE001")
        self.assertEqual(exception.error_code, "DEVICE_MANAGER_ERROR")
        self.assertFalse(exception.evidence_impact)
        self.assertIsInstance(exception.timestamp, datetime)
    
    def test_exception_without_device_serial(self):
        """Test exception creation without device serial"""
        exception = DeviceManagerException("Test error")
        
        self.assertEqual(str(exception), "Test error")
        self.assertIsNone(exception.device_serial)


if __name__ == '__main__':
    unittest.main()