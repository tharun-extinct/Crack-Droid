"""
Unit tests for AndroidDevice model validation
"""

import pytest
from datetime import datetime
from forensics_toolkit.models.device import AndroidDevice, LockoutPolicy, DeviceValidationError
from forensics_toolkit.interfaces import LockType


class TestAndroidDeviceValidation:
    """Test AndroidDevice validation methods"""
    
    def test_valid_device_creation(self):
        """Test creating a valid AndroidDevice"""
        device = AndroidDevice(
            serial="ABC123DEF456",
            model="Pixel 6",
            brand="Google",
            android_version="13.0",
            imei="490154203237518",  # Valid test IMEI that passes Luhn
            usb_debugging=True,
            root_status=False,
            lock_type=LockType.PIN,
            screen_timeout=60
        )
        
        assert device.serial == "ABC123DEF456"
        assert device.model == "Pixel 6"
        assert device.brand == "Google"
        assert device.android_version == "13.0"
        assert device.imei == "490154203237518"
        assert device.usb_debugging is True
        assert device.root_status is False
        assert device.lock_type == LockType.PIN
        assert device.screen_timeout == 60
        assert len(device.validation_errors) == 0
    
    def test_serial_validation(self):
        """Test serial number validation"""
        # Empty serial should raise exception
        with pytest.raises(DeviceValidationError) as exc_info:
            AndroidDevice(
                serial="",
                model="Test Model",
                brand="Test Brand",
                android_version="11"
            )
        assert "serial cannot be empty" in str(exc_info.value)
        
        # Invalid characters in serial
        device = AndroidDevice(
            serial="ABC-123!@#",
            model="Test Model",
            brand="Test Brand",
            android_version="11"
        )
        assert "Serial contains invalid characters" in device.validation_errors
        
        # Serial too short/long
        device = AndroidDevice(
            serial="AB",
            model="Test Model",
            brand="Test Brand",
            android_version="11"
        )
        assert "Serial length is outside expected range" in device.validation_errors
    
    def test_model_brand_validation(self):
        """Test model and brand validation"""
        # Empty model
        with pytest.raises(DeviceValidationError):
            AndroidDevice(
                serial="ABC123",
                model="",
                brand="Test Brand",
                android_version="11"
            )
        
        # Empty brand
        with pytest.raises(DeviceValidationError):
            AndroidDevice(
                serial="ABC123",
                model="Test Model",
                brand="",
                android_version="11"
            )
        
        # Very long model name
        device = AndroidDevice(
            serial="ABC123",
            model="A" * 150,
            brand="Test Brand",
            android_version="11"
        )
        assert "Model name is unusually long" in device.validation_errors
    
    def test_android_version_validation(self):
        """Test Android version validation"""
        # Empty version
        with pytest.raises(DeviceValidationError):
            AndroidDevice(
                serial="ABC123",
                model="Test Model",
                brand="Test Brand",
                android_version=""
            )
        
        # Invalid version format
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="Android 11"
        )
        assert "Invalid Android version format" in device.validation_errors
        
        # Version outside range
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="2.0"
        )
        assert "Android version outside expected range" in device.validation_errors
        
        # Valid versions
        valid_versions = ["11", "12.0", "13.0.1", "14"]
        for version in valid_versions:
            device = AndroidDevice(
                serial="ABC123",
                model="Test Model",
                brand="Test Brand",
                android_version=version
            )
            version_errors = [e for e in device.validation_errors if "version" in e.lower()]
            assert len(version_errors) == 0
    
    def test_imei_validation(self):
        """Test IMEI validation"""
        # Valid IMEI (using a test IMEI that passes Luhn)
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            imei="490154203237518"  # Valid test IMEI
        )
        imei_errors = [e for e in device.validation_errors if "IMEI" in e]
        assert len(imei_errors) == 0
        
        # Invalid IMEI length
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            imei="12345"
        )
        assert "IMEI must be exactly 15 digits" in device.validation_errors
        
        # Invalid IMEI characters
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            imei="12345678901234A"
        )
        assert "IMEI must be exactly 15 digits" in device.validation_errors
        
        # None IMEI should be valid
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            imei=None
        )
        imei_errors = [e for e in device.validation_errors if "IMEI" in e]
        assert len(imei_errors) == 0
    
    def test_screen_timeout_validation(self):
        """Test screen timeout validation"""
        # Invalid type
        with pytest.raises(DeviceValidationError):
            AndroidDevice(
                serial="ABC123",
                model="Test Model",
                brand="Test Brand",
                android_version="11",
                screen_timeout="30"  # String instead of int
            )
        
        # Out of range values
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            screen_timeout=2000  # Too high
        )
        assert "Screen timeout outside reasonable range (5-1800 seconds)" in device.validation_errors
        
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            screen_timeout=1  # Too low
        )
        assert "Screen timeout outside reasonable range (5-1800 seconds)" in device.validation_errors
    
    def test_lockout_policy_validation(self):
        """Test lockout policy validation"""
        # Valid lockout policy
        policy = LockoutPolicy(
            max_attempts=5,
            lockout_duration=30,
            progressive_lockout=True,
            wipe_after_attempts=10
        )
        
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            lockout_policy=policy
        )
        
        lockout_errors = [e for e in device.validation_errors if "lockout" in e.lower()]
        assert len(lockout_errors) == 0
        
        # Invalid lockout policy values
        policy = LockoutPolicy(
            max_attempts=0,  # Too low
            lockout_duration=-1,  # Negative
            wipe_after_attempts=2000  # Too high
        )
        
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            lockout_policy=policy
        )
        
        assert "Lockout max_attempts outside reasonable range" in device.validation_errors
        assert "Lockout duration outside reasonable range" in device.validation_errors
        assert "Wipe after attempts outside reasonable range" in device.validation_errors
    
    def test_security_patch_validation(self):
        """Test security patch level validation"""
        # Valid format
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            security_patch_level="2023-12-01"
        )
        patch_errors = [e for e in device.validation_errors if "security patch" in e.lower()]
        assert len(patch_errors) == 0
        
        # Invalid format
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            security_patch_level="December 2023"
        )
        assert "Invalid security patch level format (expected YYYY-MM-DD)" in device.validation_errors
        
        # None should be valid
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            security_patch_level=None
        )
        patch_errors = [e for e in device.validation_errors if "security patch" in e.lower()]
        assert len(patch_errors) == 0


class TestAndroidDeviceForensicCapabilities:
    """Test forensic capability assessment"""
    
    def test_forensics_ready_with_usb_debugging(self):
        """Test forensic readiness with USB debugging enabled"""
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            usb_debugging=True,
            lock_type=LockType.PIN
        )
        
        assert device.is_forensics_ready() is True
    
    def test_forensics_ready_with_root(self):
        """Test forensic readiness with root access"""
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            root_status=True,
            lock_type=LockType.PATTERN,
            bootloader_locked=False  # Root access typically means unlocked bootloader
        )
        
        assert device.is_forensics_ready() is True
    
    def test_forensics_not_ready_no_access(self):
        """Test forensic readiness without access methods"""
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            usb_debugging=False,
            root_status=False,
            lock_type=LockType.PIN
        )
        
        assert device.is_forensics_ready() is False
    
    def test_get_forensic_capabilities(self):
        """Test forensic capabilities assessment"""
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            usb_debugging=True,
            root_status=True,
            lock_type=LockType.PATTERN,
            bootloader_locked=False
        )
        
        capabilities = device.get_forensic_capabilities()
        
        assert capabilities['adb_access'] is True
        assert capabilities['root_access'] is True
        assert capabilities['bootloader_unlock'] is True
        assert capabilities['pattern_analysis'] is True
        assert capabilities['brute_force_viable'] is True
        assert capabilities['hash_extraction'] is True
        assert capabilities['edl_mode'] is False  # USB debugging enabled
        assert capabilities['fastboot_access'] is True


class TestAndroidDeviceSerialization:
    """Test device serialization and deserialization"""
    
    def test_to_dict(self):
        """Test converting device to dictionary"""
        policy = LockoutPolicy(max_attempts=5, lockout_duration=30)
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            imei="490154203237518",
            usb_debugging=True,
            root_status=False,
            lock_type=LockType.PIN,
            lockout_policy=policy,
            security_patch_level="2023-12-01"
        )
        
        data = device.to_dict()
        
        assert data['serial'] == "ABC123"
        assert data['model'] == "Test Model"
        assert data['brand'] == "Test Brand"
        assert data['android_version'] == "11"
        assert data['imei'] == "490154203237518"
        assert data['usb_debugging'] is True
        assert data['root_status'] is False
        assert data['lock_type'] == "pin"
        assert data['security_patch_level'] == "2023-12-01"
        assert 'lockout_policy' in data
        assert data['lockout_policy']['max_attempts'] == 5
        assert 'forensic_capabilities' in data
        assert 'discovered_at' in data
    
    def test_from_dict(self):
        """Test creating device from dictionary"""
        data = {
            'serial': 'ABC123',
            'model': 'Test Model',
            'brand': 'Test Brand',
            'android_version': '11',
            'imei': '490154203237518',
            'usb_debugging': True,
            'root_status': False,
            'lock_type': 'pin',
            'security_patch_level': '2023-12-01',
            'lockout_policy': {
                'max_attempts': 5,
                'lockout_duration': 30,
                'progressive_lockout': True,
                'wipe_after_attempts': 10
            },
            'discovered_at': '2023-12-01T10:00:00',
            'validation_errors': []
        }
        
        device = AndroidDevice.from_dict(data)
        
        assert device.serial == "ABC123"
        assert device.model == "Test Model"
        assert device.brand == "Test Brand"
        assert device.android_version == "11"
        assert device.imei == "490154203237518"
        assert device.usb_debugging is True
        assert device.root_status is False
        assert device.lock_type == LockType.PIN
        assert device.security_patch_level == "2023-12-01"
        assert device.lockout_policy is not None
        assert device.lockout_policy.max_attempts == 5
    
    def test_round_trip_serialization(self):
        """Test serialization round trip"""
        original = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            usb_debugging=True,
            lock_type=LockType.PATTERN
        )
        
        data = original.to_dict()
        reconstructed = AndroidDevice.from_dict(data)
        
        assert original.serial == reconstructed.serial
        assert original.model == reconstructed.model
        assert original.brand == reconstructed.brand
        assert original.android_version == reconstructed.android_version
        assert original.usb_debugging == reconstructed.usb_debugging
        assert original.lock_type == reconstructed.lock_type


class TestAndroidDeviceStringRepresentation:
    """Test string representations"""
    
    def test_str_representation(self):
        """Test string representation"""
        device = AndroidDevice(
            serial="ABC123",
            model="Pixel 6",
            brand="Google",
            android_version="13.0"
        )
        
        str_repr = str(device)
        assert "Google Pixel 6" in str_repr
        assert "ABC123" in str_repr
        assert "13.0" in str_repr
    
    def test_repr_representation(self):
        """Test detailed representation"""
        device = AndroidDevice(
            serial="ABC123",
            model="Pixel 6",
            brand="Google",
            android_version="13.0",
            usb_debugging=True
        )
        
        repr_str = repr(device)
        assert "AndroidDevice" in repr_str
        assert "serial='ABC123'" in repr_str
        assert "usb_debugging=True" in repr_str


if __name__ == "__main__":
    pytest.main([__file__])