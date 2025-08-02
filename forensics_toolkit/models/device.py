"""
Android device model with validation
"""

import re
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

from ..interfaces import LockType, ForensicsException


class DeviceValidationError(ForensicsException):
    """Exception raised for device validation errors"""
    
    def __init__(self, message: str, field_name: str = None):
        super().__init__(message, "DEVICE_VALIDATION_ERROR", evidence_impact=False)
        self.field_name = field_name


@dataclass
class LockoutPolicy:
    """Device lockout policy configuration"""
    max_attempts: int = 5
    lockout_duration: int = 30  # seconds
    progressive_lockout: bool = True
    wipe_after_attempts: int = 10


@dataclass
class AndroidDevice:
    """
    Android device profile with comprehensive validation
    
    This model represents an Android device with all necessary metadata
    for forensic analysis, including validation methods for data integrity.
    """
    serial: str
    model: str
    brand: str
    android_version: str
    imei: Optional[str] = None
    usb_debugging: bool = False
    root_status: bool = False
    lock_type: Optional[LockType] = None
    screen_timeout: int = 30  # seconds
    lockout_policy: Optional[LockoutPolicy] = None
    
    # Additional forensic metadata
    build_number: Optional[str] = None
    security_patch_level: Optional[str] = None
    bootloader_locked: bool = True
    encryption_enabled: bool = True
    developer_options_enabled: bool = False
    
    # Fastboot-specific metadata
    bootloader_version: Optional[str] = None
    secure_boot: Optional[bool] = None
    slot_count: int = 0
    current_slot: Optional[str] = None
    
    # Forensic analysis metadata
    discovered_at: datetime = field(default_factory=datetime.now)
    last_validated: Optional[datetime] = None
    validation_errors: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Post-initialization validation"""
        self.validate_all()
    
    def validate_all(self) -> bool:
        """
        Validate all device metadata for integrity
        
        Returns:
            bool: True if all validations pass
            
        Raises:
            DeviceValidationError: If critical validation fails
        """
        self.validation_errors.clear()
        
        try:
            self._validate_serial()
            self._validate_model_brand()
            self._validate_android_version()
            self._validate_imei()
            self._validate_screen_timeout()
            self._validate_lockout_policy()
            self._validate_security_patch()
            
            self.last_validated = datetime.now()
            return len(self.validation_errors) == 0
            
        except DeviceValidationError:
            raise
        except Exception as e:
            raise DeviceValidationError(f"Unexpected validation error: {str(e)}")
    
    def _validate_serial(self):
        """Validate device serial number"""
        if not self.serial or not self.serial.strip():
            raise DeviceValidationError("Device serial cannot be empty", "serial")
        
        # Android serial numbers are typically alphanumeric
        if not re.match(r'^[A-Za-z0-9]+$', self.serial):
            self.validation_errors.append("Serial contains invalid characters")
        
        # Reasonable length check (Android serials are usually 8-20 characters)
        if len(self.serial) < 4 or len(self.serial) > 50:
            self.validation_errors.append("Serial length is outside expected range")
    
    def _validate_model_brand(self):
        """Validate device model and brand"""
        if not self.model or not self.model.strip():
            raise DeviceValidationError("Device model cannot be empty", "model")
        
        if not self.brand or not self.brand.strip():
            raise DeviceValidationError("Device brand cannot be empty", "brand")
        
        # Check for reasonable lengths
        if len(self.model) > 100:
            self.validation_errors.append("Model name is unusually long")
        
        if len(self.brand) > 50:
            self.validation_errors.append("Brand name is unusually long")
    
    def _validate_android_version(self):
        """Validate Android version format"""
        if not self.android_version or not self.android_version.strip():
            raise DeviceValidationError("Android version cannot be empty", "android_version")
        
        # Android version pattern (e.g., "11", "12.0", "13.0.1")
        version_pattern = r'^\d+(\.\d+)*$'
        if not re.match(version_pattern, self.android_version):
            self.validation_errors.append("Invalid Android version format")
        
        # Check for reasonable version numbers (Android 4.0+ for forensics)
        try:
            major_version = int(self.android_version.split('.')[0])
            if major_version < 4 or major_version > 20:
                self.validation_errors.append("Android version outside expected range")
        except (ValueError, IndexError):
            self.validation_errors.append("Cannot parse Android version number")
    
    def _validate_imei(self):
        """Validate IMEI if provided"""
        if self.imei is None:
            return  # IMEI is optional
        
        if not self.imei.strip():
            self.imei = None
            return
        
        # IMEI should be 15 digits
        if not re.match(r'^\d{15}$', self.imei):
            self.validation_errors.append("IMEI must be exactly 15 digits")
            return
        
        # Luhn algorithm validation for IMEI
        if not self._validate_imei_checksum(self.imei):
            self.validation_errors.append("IMEI checksum validation failed")
    
    def _validate_imei_checksum(self, imei: str) -> bool:
        """Validate IMEI using Luhn algorithm"""
        def luhn_checksum(card_num):
            def digits_of(n):
                return [int(d) for d in str(n)]
            
            digits = digits_of(card_num)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d*2))
            return checksum % 10
        
        return luhn_checksum(imei) == 0
    
    def _validate_screen_timeout(self):
        """Validate screen timeout value"""
        if not isinstance(self.screen_timeout, int):
            raise DeviceValidationError("Screen timeout must be an integer", "screen_timeout")
        
        # Reasonable timeout range (5 seconds to 30 minutes)
        if self.screen_timeout < 5 or self.screen_timeout > 1800:
            self.validation_errors.append("Screen timeout outside reasonable range (5-1800 seconds)")
    
    def _validate_lockout_policy(self):
        """Validate lockout policy if provided"""
        if self.lockout_policy is None:
            return
        
        if not isinstance(self.lockout_policy, LockoutPolicy):
            raise DeviceValidationError("Lockout policy must be LockoutPolicy instance", "lockout_policy")
        
        # Validate lockout policy values
        if self.lockout_policy.max_attempts < 1 or self.lockout_policy.max_attempts > 100:
            self.validation_errors.append("Lockout max_attempts outside reasonable range")
        
        if self.lockout_policy.lockout_duration < 0 or self.lockout_policy.lockout_duration > 86400:
            self.validation_errors.append("Lockout duration outside reasonable range")
        
        if self.lockout_policy.wipe_after_attempts < 5 or self.lockout_policy.wipe_after_attempts > 1000:
            self.validation_errors.append("Wipe after attempts outside reasonable range")
    
    def _validate_security_patch(self):
        """Validate security patch level format"""
        if self.security_patch_level is None:
            return
        
        if not self.security_patch_level.strip():
            self.security_patch_level = None
            return
        
        # Security patch format: YYYY-MM-DD
        patch_pattern = r'^\d{4}-\d{2}-\d{2}$'
        if not re.match(patch_pattern, self.security_patch_level):
            self.validation_errors.append("Invalid security patch level format (expected YYYY-MM-DD)")
    
    def is_forensics_ready(self) -> bool:
        """
        Check if device is ready for forensic analysis
        
        Returns:
            bool: True if device meets forensic analysis requirements
        """
        if not self.validate_all():
            return False
        
        # Additional forensic readiness checks
        forensic_issues = []
        
        if not self.usb_debugging and not self.root_status:
            forensic_issues.append("Neither USB debugging nor root access available")
        
        if self.lock_type is None:
            forensic_issues.append("Lock type not determined")
        
        if self.bootloader_locked and not self.usb_debugging:
            forensic_issues.append("Bootloader locked without USB debugging")
        
        return len(forensic_issues) == 0
    
    def get_forensic_capabilities(self) -> Dict[str, bool]:
        """
        Get available forensic capabilities for this device
        
        Returns:
            Dict[str, bool]: Mapping of capability names to availability
        """
        capabilities = {
            'adb_access': self.usb_debugging,
            'root_access': self.root_status,
            'bootloader_unlock': not self.bootloader_locked,
            'pattern_analysis': self.lock_type == LockType.PATTERN,
            'brute_force_viable': self.lock_type in [LockType.PIN, LockType.PASSWORD, LockType.PATTERN],
            'hash_extraction': self.root_status,
            'edl_mode': not self.usb_debugging,
            'fastboot_access': not self.bootloader_locked
        }
        
        return capabilities
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert device to dictionary for serialization
        
        Returns:
            Dict[str, Any]: Device data as dictionary
        """
        data = {
            'serial': self.serial,
            'model': self.model,
            'brand': self.brand,
            'android_version': self.android_version,
            'imei': self.imei,
            'usb_debugging': self.usb_debugging,
            'root_status': self.root_status,
            'lock_type': self.lock_type.value if self.lock_type else None,
            'screen_timeout': self.screen_timeout,
            'build_number': self.build_number,
            'security_patch_level': self.security_patch_level,
            'bootloader_locked': self.bootloader_locked,
            'encryption_enabled': self.encryption_enabled,
            'developer_options_enabled': self.developer_options_enabled,
            'bootloader_version': self.bootloader_version,
            'secure_boot': self.secure_boot,
            'slot_count': self.slot_count,
            'current_slot': self.current_slot,
            'discovered_at': self.discovered_at.isoformat(),
            'last_validated': self.last_validated.isoformat() if self.last_validated else None,
            'validation_errors': self.validation_errors,
            'forensic_capabilities': self.get_forensic_capabilities()
        }
        
        if self.lockout_policy:
            data['lockout_policy'] = {
                'max_attempts': self.lockout_policy.max_attempts,
                'lockout_duration': self.lockout_policy.lockout_duration,
                'progressive_lockout': self.lockout_policy.progressive_lockout,
                'wipe_after_attempts': self.lockout_policy.wipe_after_attempts
            }
        
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AndroidDevice':
        """
        Create AndroidDevice from dictionary
        
        Args:
            data: Device data dictionary
            
        Returns:
            AndroidDevice: Reconstructed device instance
        """
        # Handle lockout policy
        lockout_policy = None
        if 'lockout_policy' in data and data['lockout_policy']:
            lockout_policy = LockoutPolicy(**data['lockout_policy'])
        
        # Handle lock type
        lock_type = None
        if data.get('lock_type'):
            lock_type = LockType(data['lock_type'])
        
        # Handle timestamps
        discovered_at = datetime.fromisoformat(data['discovered_at']) if data.get('discovered_at') else datetime.now()
        last_validated = datetime.fromisoformat(data['last_validated']) if data.get('last_validated') else None
        
        return cls(
            serial=data['serial'],
            model=data['model'],
            brand=data['brand'],
            android_version=data['android_version'],
            imei=data.get('imei'),
            usb_debugging=data.get('usb_debugging', False),
            root_status=data.get('root_status', False),
            lock_type=lock_type,
            screen_timeout=data.get('screen_timeout', 30),
            lockout_policy=lockout_policy,
            build_number=data.get('build_number'),
            security_patch_level=data.get('security_patch_level'),
            bootloader_locked=data.get('bootloader_locked', True),
            encryption_enabled=data.get('encryption_enabled', True),
            developer_options_enabled=data.get('developer_options_enabled', False),
            bootloader_version=data.get('bootloader_version'),
            secure_boot=data.get('secure_boot'),
            slot_count=data.get('slot_count', 0),
            current_slot=data.get('current_slot'),
            discovered_at=discovered_at,
            last_validated=last_validated,
            validation_errors=data.get('validation_errors', [])
        )
    
    def __str__(self) -> str:
        """String representation of device"""
        return f"{self.brand} {self.model} (Serial: {self.serial}, Android: {self.android_version})"
    
    def __repr__(self) -> str:
        """Detailed representation of device"""
        return (f"AndroidDevice(serial='{self.serial}', model='{self.model}', "
                f"brand='{self.brand}', android_version='{self.android_version}', "
                f"usb_debugging={self.usb_debugging}, root_status={self.root_status})")