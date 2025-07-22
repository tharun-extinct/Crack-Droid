"""
Core interfaces and abstract classes for forensics operations
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class LockType(Enum):
    """Android device lock types"""
    PIN = "pin"
    PATTERN = "pattern"
    PASSWORD = "password"
    FINGERPRINT = "fingerprint"
    FACE = "face"
    NONE = "none"


class AttackType(Enum):
    """Types of forensic attacks"""
    BRUTE_FORCE = "brute_force"
    DICTIONARY = "dictionary"
    PATTERN_ANALYSIS = "pattern_analysis"
    HASH_CRACKING = "hash_cracking"
    HYBRID = "hybrid"


@dataclass
class AndroidDevice:
    """Android device profile"""
    serial: str
    model: str
    brand: str
    android_version: str
    imei: Optional[str] = None
    usb_debugging: bool = False
    root_status: bool = False
    lock_type: Optional[LockType] = None
    screen_timeout: int = 30
    lockout_policy: Optional[Dict[str, Any]] = None


@dataclass
class AttackStrategy:
    """Attack strategy configuration"""
    strategy_type: AttackType
    target_device: AndroidDevice
    wordlists: List[str]
    mask_patterns: List[str]
    max_attempts: int
    delay_handling: bool = True
    gpu_acceleration: bool = False


@dataclass
class AttackResult:
    """Result of a forensic attack"""
    success: bool
    attempts: int
    duration: float
    result_data: Optional[str] = None
    error_message: Optional[str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class EvidenceRecord:
    """Evidence record with chain of custody"""
    case_id: str
    timestamp: datetime
    operation_type: str
    device_serial: str
    attempt_number: int
    result: str
    hash_verification: str
    chain_of_custody: List[Dict[str, Any]]


class IDeviceHandler(ABC):
    """Interface for device communication handlers"""
    
    @abstractmethod
    def detect_devices(self) -> List[AndroidDevice]:
        """Detect connected Android devices"""
        pass
    
    @abstractmethod
    def connect_device(self, device: AndroidDevice) -> bool:
        """Connect to a specific device"""
        pass
    
    @abstractmethod
    def get_device_info(self, device: AndroidDevice) -> AndroidDevice:
        """Get detailed device information"""
        pass
    
    @abstractmethod
    def is_device_accessible(self, device: AndroidDevice) -> bool:
        """Check if device is accessible for forensic operations"""
        pass


class IAttackEngine(ABC):
    """Interface for attack engines"""
    
    @abstractmethod
    def execute_attack(self, strategy: AttackStrategy) -> AttackResult:
        """Execute the attack strategy"""
        pass
    
    @abstractmethod
    def validate_strategy(self, strategy: AttackStrategy) -> bool:
        """Validate if strategy is applicable"""
        pass
    
    @abstractmethod
    def estimate_duration(self, strategy: AttackStrategy) -> float:
        """Estimate attack duration in seconds"""
        pass


class IEvidenceManager(ABC):
    """Interface for evidence management"""
    
    @abstractmethod
    def log_operation(self, record: EvidenceRecord) -> bool:
        """Log a forensic operation"""
        pass
    
    @abstractmethod
    def verify_integrity(self, case_id: str) -> bool:
        """Verify evidence integrity"""
        pass
    
    @abstractmethod
    def generate_report(self, case_id: str) -> Dict[str, Any]:
        """Generate evidence report"""
        pass


class IForensicsEngine(ABC):
    """Main forensics engine interface"""
    
    @abstractmethod
    def detect_devices(self) -> List[AndroidDevice]:
        """Detect all available devices"""
        pass
    
    @abstractmethod
    def analyze_device(self, device: AndroidDevice) -> AndroidDevice:
        """Analyze device capabilities and configuration"""
        pass
    
    @abstractmethod
    def execute_attack(self, strategy: AttackStrategy) -> AttackResult:
        """Execute forensic attack strategy"""
        pass
    
    @abstractmethod
    def generate_evidence_report(self, case_id: str) -> Dict[str, Any]:
        """Generate comprehensive evidence report"""
        pass


class ForensicsException(Exception):
    """Base exception for forensics operations"""
    
    def __init__(self, message: str, error_code: str, evidence_impact: bool = False):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.evidence_impact = evidence_impact
        self.timestamp = datetime.now()
    
    def log_error(self):
        """Log error with evidence preservation"""
        # Implementation will be added in evidence management task
        pass