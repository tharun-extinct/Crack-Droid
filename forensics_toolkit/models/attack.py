"""
Attack strategy and evidence record models
"""

import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum

from ..interfaces import AttackType, ForensicsException
from .device import AndroidDevice


class AttackValidationError(ForensicsException):
    """Exception raised for attack strategy validation errors"""
    
    def __init__(self, message: str, field_name: str = None):
        super().__init__(message, "ATTACK_VALIDATION_ERROR", evidence_impact=False)
        self.field_name = field_name


class DelayStrategy(Enum):
    """Delay handling strategies for attacks"""
    WAIT = "wait"  # Wait for lockout to expire
    SKIP = "skip"  # Skip attempts during lockout
    ABORT = "abort"  # Abort attack on lockout


class AttackStatus(Enum):
    """Attack execution status"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


@dataclass
class AttackStrategy:
    """
    Attack strategy configuration with comprehensive validation
    
    This model represents a forensic attack strategy with all necessary
    configuration parameters and validation methods.
    """
    strategy_type: AttackType
    target_device: AndroidDevice
    wordlists: List[str] = field(default_factory=list)
    mask_patterns: List[str] = field(default_factory=list)
    max_attempts: int = 1000
    delay_handling: DelayStrategy = DelayStrategy.WAIT
    gpu_acceleration: bool = False
    
    # Advanced configuration
    thread_count: int = 1
    timeout_seconds: int = 3600  # 1 hour default
    priority_patterns: List[str] = field(default_factory=list)
    custom_parameters: Dict[str, Any] = field(default_factory=dict)
    
    # Execution metadata
    created_at: datetime = field(default_factory=datetime.now)
    last_modified: Optional[datetime] = None
    validation_errors: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Post-initialization validation"""
        self.validate_all()
    
    def validate_all(self) -> bool:
        """
        Validate all attack strategy parameters
        
        Returns:
            bool: True if all validations pass
            
        Raises:
            AttackValidationError: If critical validation fails
        """
        self.validation_errors.clear()
        
        try:
            self._validate_strategy_type()
            self._validate_target_device()
            self._validate_wordlists()
            self._validate_mask_patterns()
            self._validate_max_attempts()
            self._validate_thread_count()
            self._validate_timeout()
            self._validate_strategy_compatibility()
            
            self.last_modified = datetime.now()
            return len(self.validation_errors) == 0
            
        except AttackValidationError:
            raise
        except Exception as e:
            raise AttackValidationError(f"Unexpected validation error: {str(e)}")
    
    def _validate_strategy_type(self):
        """Validate attack strategy type"""
        if not isinstance(self.strategy_type, AttackType):
            raise AttackValidationError("Strategy type must be AttackType enum", "strategy_type")
    
    def _validate_target_device(self):
        """Validate target device"""
        if not isinstance(self.target_device, AndroidDevice):
            raise AttackValidationError("Target device must be AndroidDevice instance", "target_device")
        
        if not self.target_device.validate_all():
            self.validation_errors.append("Target device has validation errors")
    
    def _validate_wordlists(self):
        """Validate wordlist configuration"""
        if not isinstance(self.wordlists, list):
            raise AttackValidationError("Wordlists must be a list", "wordlists")
        
        # Check for dictionary attacks requiring wordlists
        if self.strategy_type in [AttackType.DICTIONARY, AttackType.HYBRID]:
            if not self.wordlists:
                self.validation_errors.append("Dictionary/hybrid attacks require at least one wordlist")
        
        # Validate wordlist paths (basic check)
        for wordlist in self.wordlists:
            if not isinstance(wordlist, str) or not wordlist.strip():
                self.validation_errors.append("Wordlist paths must be non-empty strings")
    
    def _validate_mask_patterns(self):
        """Validate mask patterns"""
        if not isinstance(self.mask_patterns, list):
            raise AttackValidationError("Mask patterns must be a list", "mask_patterns")
        
        # Validate mask pattern format (basic validation)
        for pattern in self.mask_patterns:
            if not isinstance(pattern, str) or not pattern.strip():
                self.validation_errors.append("Mask patterns must be non-empty strings")
    
    def _validate_max_attempts(self):
        """Validate maximum attempts"""
        if not isinstance(self.max_attempts, int):
            raise AttackValidationError("Max attempts must be an integer", "max_attempts")
        
        if self.max_attempts < 1:
            raise AttackValidationError("Max attempts must be positive", "max_attempts")
        
        if self.max_attempts > 1000000:
            self.validation_errors.append("Max attempts is very high, may take excessive time")
    
    def _validate_thread_count(self):
        """Validate thread count"""
        if not isinstance(self.thread_count, int):
            raise AttackValidationError("Thread count must be an integer", "thread_count")
        
        if self.thread_count < 1:
            raise AttackValidationError("Thread count must be positive", "thread_count")
        
        if self.thread_count > 32:
            self.validation_errors.append("High thread count may cause device instability")
    
    def _validate_timeout(self):
        """Validate timeout configuration"""
        if not isinstance(self.timeout_seconds, int):
            raise AttackValidationError("Timeout must be an integer", "timeout_seconds")
        
        if self.timeout_seconds < 60:
            self.validation_errors.append("Very short timeout may prevent attack completion")
        
        if self.timeout_seconds > 86400:  # 24 hours
            self.validation_errors.append("Very long timeout may indicate configuration error")
    
    def _validate_strategy_compatibility(self):
        """Validate strategy compatibility with target device"""
        capabilities = self.target_device.get_forensic_capabilities()
        
        # Check if strategy is compatible with device capabilities
        if self.strategy_type == AttackType.PATTERN_ANALYSIS:
            if not capabilities.get('pattern_analysis', False):
                self.validation_errors.append("Pattern analysis not supported for this lock type")
        
        if self.strategy_type == AttackType.HASH_CRACKING:
            if not capabilities.get('hash_extraction', False):
                self.validation_errors.append("Hash extraction not available without root access")
        
        if self.strategy_type == AttackType.BRUTE_FORCE:
            if not capabilities.get('brute_force_viable', False):
                self.validation_errors.append("Brute force not viable for this lock type")
        
        # Check GPU acceleration compatibility
        if self.gpu_acceleration and self.strategy_type not in [AttackType.HASH_CRACKING, AttackType.HYBRID]:
            self.validation_errors.append("GPU acceleration only supported for hash cracking")
    
    def estimate_duration(self) -> float:
        """
        Estimate attack duration in seconds
        
        Returns:
            float: Estimated duration in seconds
        """
        base_rate = 10  # attempts per second (conservative estimate)
        
        # Adjust rate based on strategy type
        if self.strategy_type == AttackType.HASH_CRACKING and self.gpu_acceleration:
            base_rate = 1000000  # GPU can be much faster
        elif self.strategy_type == AttackType.PATTERN_ANALYSIS:
            base_rate = 100  # Pattern analysis is faster
        elif self.strategy_type == AttackType.BRUTE_FORCE:
            base_rate = 1  # Physical input is slow
        
        # Adjust for threading
        effective_rate = base_rate * min(self.thread_count, 4)  # Diminishing returns
        
        return min(self.max_attempts / effective_rate, self.timeout_seconds)
    
    def get_estimated_complexity(self) -> Dict[str, Any]:
        """
        Get attack complexity estimation
        
        Returns:
            Dict[str, Any]: Complexity metrics
        """
        return {
            'estimated_duration_seconds': self.estimate_duration(),
            'max_attempts': self.max_attempts,
            'thread_count': self.thread_count,
            'strategy_type': self.strategy_type.value,
            'gpu_acceleration': self.gpu_acceleration,
            'wordlist_count': len(self.wordlists),
            'mask_pattern_count': len(self.mask_patterns)
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert attack strategy to dictionary for serialization
        
        Returns:
            Dict[str, Any]: Strategy data as dictionary
        """
        return {
            'strategy_type': self.strategy_type.value,
            'target_device': self.target_device.to_dict(),
            'wordlists': self.wordlists,
            'mask_patterns': self.mask_patterns,
            'max_attempts': self.max_attempts,
            'delay_handling': self.delay_handling.value,
            'gpu_acceleration': self.gpu_acceleration,
            'thread_count': self.thread_count,
            'timeout_seconds': self.timeout_seconds,
            'priority_patterns': self.priority_patterns,
            'custom_parameters': self.custom_parameters,
            'created_at': self.created_at.isoformat(),
            'last_modified': self.last_modified.isoformat() if self.last_modified else None,
            'validation_errors': self.validation_errors,
            'complexity_metrics': self.get_estimated_complexity()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AttackStrategy':
        """
        Create AttackStrategy from dictionary
        
        Args:
            data: Strategy data dictionary
            
        Returns:
            AttackStrategy: Reconstructed strategy instance
        """
        # Reconstruct target device
        target_device = AndroidDevice.from_dict(data['target_device'])
        
        # Handle enums
        strategy_type = AttackType(data['strategy_type'])
        delay_handling = DelayStrategy(data.get('delay_handling', DelayStrategy.WAIT.value))
        
        # Handle timestamps
        created_at = datetime.fromisoformat(data['created_at']) if data.get('created_at') else datetime.now()
        last_modified = datetime.fromisoformat(data['last_modified']) if data.get('last_modified') else None
        
        return cls(
            strategy_type=strategy_type,
            target_device=target_device,
            wordlists=data.get('wordlists', []),
            mask_patterns=data.get('mask_patterns', []),
            max_attempts=data.get('max_attempts', 1000),
            delay_handling=delay_handling,
            gpu_acceleration=data.get('gpu_acceleration', False),
            thread_count=data.get('thread_count', 1),
            timeout_seconds=data.get('timeout_seconds', 3600),
            priority_patterns=data.get('priority_patterns', []),
            custom_parameters=data.get('custom_parameters', {}),
            created_at=created_at,
            last_modified=last_modified,
            validation_errors=data.get('validation_errors', [])
        )
    
    def to_json(self) -> str:
        """
        Convert strategy to JSON string
        
        Returns:
            str: JSON representation
        """
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'AttackStrategy':
        """
        Create AttackStrategy from JSON string
        
        Args:
            json_str: JSON string representation
            
        Returns:
            AttackStrategy: Reconstructed strategy instance
        """
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    def __str__(self) -> str:
        """String representation of attack strategy"""
        return f"{self.strategy_type.value} attack on {self.target_device.brand} {self.target_device.model}"
    
    def __repr__(self) -> str:
        """Detailed representation of attack strategy"""
        return (f"AttackStrategy(strategy_type={self.strategy_type}, "
                f"target_device='{self.target_device.serial}', "
                f"max_attempts={self.max_attempts}, "
                f"gpu_acceleration={self.gpu_acceleration})")


@dataclass
class CustodyEvent:
    """Chain of custody event record"""
    timestamp: datetime
    event_type: str
    user_id: str
    description: str
    hash_before: Optional[str] = None
    hash_after: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'user_id': self.user_id,
            'description': self.description,
            'hash_before': self.hash_before,
            'hash_after': self.hash_after
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CustodyEvent':
        """Create from dictionary"""
        return cls(
            timestamp=datetime.fromisoformat(data['timestamp']),
            event_type=data['event_type'],
            user_id=data['user_id'],
            description=data['description'],
            hash_before=data.get('hash_before'),
            hash_after=data.get('hash_after')
        )


@dataclass
class EvidenceRecord:
    """
    Evidence record with chain of custody tracking
    
    This model represents a forensic evidence record with comprehensive
    chain of custody tracking and integrity verification.
    """
    case_id: str
    timestamp: datetime
    operation_type: str
    device_serial: str
    attempt_number: int
    result: str
    hash_verification: str
    chain_of_custody: List[CustodyEvent] = field(default_factory=list)
    
    # Additional evidence metadata
    evidence_type: str = "forensic_operation"
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    investigator_id: Optional[str] = None
    case_notes: str = ""
    
    # Integrity tracking
    created_at: datetime = field(default_factory=datetime.now)
    last_verified: Optional[datetime] = None
    verification_status: str = "pending"
    validation_errors: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Post-initialization validation"""
        self.validate_all()
    
    def validate_all(self) -> bool:
        """
        Validate all evidence record fields
        
        Returns:
            bool: True if all validations pass
            
        Raises:
            ForensicsException: If critical validation fails
        """
        self.validation_errors.clear()
        
        try:
            self._validate_case_id()
            self._validate_operation_type()
            self._validate_device_serial()
            self._validate_attempt_number()
            self._validate_hash_verification()
            self._validate_chain_of_custody()
            
            self.last_verified = datetime.now()
            self.verification_status = "verified" if len(self.validation_errors) == 0 else "failed"
            return len(self.validation_errors) == 0
            
        except Exception as e:
            raise ForensicsException(f"Evidence validation error: {str(e)}", 
                                   "EVIDENCE_VALIDATION_ERROR", evidence_impact=True)
    
    def _validate_case_id(self):
        """Validate case ID format"""
        if not self.case_id or not self.case_id.strip():
            raise ForensicsException("Case ID cannot be empty", "INVALID_CASE_ID", evidence_impact=True)
        
        # Case ID format validation (alphanumeric with dashes/underscores)
        import re
        if not re.match(r'^[A-Za-z0-9_-]+$', self.case_id):
            self.validation_errors.append("Case ID contains invalid characters")
        
        if len(self.case_id) < 3 or len(self.case_id) > 50:
            self.validation_errors.append("Case ID length outside acceptable range")
    
    def _validate_operation_type(self):
        """Validate operation type"""
        if not self.operation_type or not self.operation_type.strip():
            raise ForensicsException("Operation type cannot be empty", "INVALID_OPERATION_TYPE", evidence_impact=True)
        
        valid_operations = [
            'device_detection', 'device_analysis', 'attack_execution',
            'evidence_collection', 'hash_verification', 'report_generation'
        ]
        
        if self.operation_type not in valid_operations:
            self.validation_errors.append(f"Unknown operation type: {self.operation_type}")
    
    def _validate_device_serial(self):
        """Validate device serial"""
        if not self.device_serial or not self.device_serial.strip():
            raise ForensicsException("Device serial cannot be empty", "INVALID_DEVICE_SERIAL", evidence_impact=True)
    
    def _validate_attempt_number(self):
        """Validate attempt number"""
        if not isinstance(self.attempt_number, int):
            raise ForensicsException("Attempt number must be integer", "INVALID_ATTEMPT_NUMBER", evidence_impact=True)
        
        if self.attempt_number < 0:
            raise ForensicsException("Attempt number cannot be negative", "INVALID_ATTEMPT_NUMBER", evidence_impact=True)
    
    def _validate_hash_verification(self):
        """Validate hash verification"""
        if not self.hash_verification or not self.hash_verification.strip():
            raise ForensicsException("Hash verification cannot be empty", "INVALID_HASH", evidence_impact=True)
        
        # SHA-256 hash format validation
        import re
        if not re.match(r'^[a-fA-F0-9]{64}$', self.hash_verification):
            self.validation_errors.append("Hash verification must be valid SHA-256 hash")
    
    def _validate_chain_of_custody(self):
        """Validate chain of custody events"""
        if not isinstance(self.chain_of_custody, list):
            raise ForensicsException("Chain of custody must be a list", "INVALID_CUSTODY_CHAIN", evidence_impact=True)
        
        # Validate each custody event
        for i, event in enumerate(self.chain_of_custody):
            if not isinstance(event, CustodyEvent):
                self.validation_errors.append(f"Custody event {i} is not a CustodyEvent instance")
        
        # Check chronological order
        if len(self.chain_of_custody) > 1:
            for i in range(1, len(self.chain_of_custody)):
                if self.chain_of_custody[i].timestamp < self.chain_of_custody[i-1].timestamp:
                    self.validation_errors.append("Chain of custody events not in chronological order")
                    break
    
    def add_custody_event(self, event_type: str, user_id: str, description: str, 
                         hash_before: str = None, hash_after: str = None):
        """
        Add a new custody event
        
        Args:
            event_type: Type of custody event
            user_id: ID of user performing the action
            description: Description of the action
            hash_before: Hash before the action
            hash_after: Hash after the action
        """
        event = CustodyEvent(
            timestamp=datetime.now(),
            event_type=event_type,
            user_id=user_id,
            description=description,
            hash_before=hash_before,
            hash_after=hash_after
        )
        
        self.chain_of_custody.append(event)
        self.last_verified = None  # Require re-validation
    
    def verify_integrity(self) -> bool:
        """
        Verify evidence integrity
        
        Returns:
            bool: True if integrity is verified
        """
        # Re-validate all fields
        if not self.validate_all():
            return False
        
        # Additional integrity checks
        if self.file_path and self.file_size is not None:
            # File-based integrity checks would go here
            pass
        
        # Check custody chain integrity
        for event in self.chain_of_custody:
            if event.hash_before and event.hash_after:
                # Hash transition validation would go here
                pass
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert evidence record to dictionary for serialization
        
        Returns:
            Dict[str, Any]: Evidence data as dictionary
        """
        return {
            'case_id': self.case_id,
            'timestamp': self.timestamp.isoformat(),
            'operation_type': self.operation_type,
            'device_serial': self.device_serial,
            'attempt_number': self.attempt_number,
            'result': self.result,
            'hash_verification': self.hash_verification,
            'chain_of_custody': [event.to_dict() for event in self.chain_of_custody],
            'evidence_type': self.evidence_type,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'investigator_id': self.investigator_id,
            'case_notes': self.case_notes,
            'created_at': self.created_at.isoformat(),
            'last_verified': self.last_verified.isoformat() if self.last_verified else None,
            'verification_status': self.verification_status,
            'validation_errors': self.validation_errors
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EvidenceRecord':
        """
        Create EvidenceRecord from dictionary
        
        Args:
            data: Evidence data dictionary
            
        Returns:
            EvidenceRecord: Reconstructed evidence record
        """
        # Reconstruct custody events
        custody_events = [CustodyEvent.from_dict(event_data) 
                         for event_data in data.get('chain_of_custody', [])]
        
        # Handle timestamps
        timestamp = datetime.fromisoformat(data['timestamp'])
        created_at = datetime.fromisoformat(data['created_at']) if data.get('created_at') else datetime.now()
        last_verified = datetime.fromisoformat(data['last_verified']) if data.get('last_verified') else None
        
        return cls(
            case_id=data['case_id'],
            timestamp=timestamp,
            operation_type=data['operation_type'],
            device_serial=data['device_serial'],
            attempt_number=data['attempt_number'],
            result=data['result'],
            hash_verification=data['hash_verification'],
            chain_of_custody=custody_events,
            evidence_type=data.get('evidence_type', 'forensic_operation'),
            file_path=data.get('file_path'),
            file_size=data.get('file_size'),
            investigator_id=data.get('investigator_id'),
            case_notes=data.get('case_notes', ''),
            created_at=created_at,
            last_verified=last_verified,
            verification_status=data.get('verification_status', 'pending'),
            validation_errors=data.get('validation_errors', [])
        )
    
    def to_json(self) -> str:
        """
        Convert evidence record to JSON string
        
        Returns:
            str: JSON representation
        """
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'EvidenceRecord':
        """
        Create EvidenceRecord from JSON string
        
        Args:
            json_str: JSON string representation
            
        Returns:
            EvidenceRecord: Reconstructed evidence record
        """
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    def __str__(self) -> str:
        """String representation of evidence record"""
        return f"Evidence {self.case_id}: {self.operation_type} on {self.device_serial}"
    
    def __repr__(self) -> str:
        """Detailed representation of evidence record"""
        return (f"EvidenceRecord(case_id='{self.case_id}', "
                f"operation_type='{self.operation_type}', "
                f"device_serial='{self.device_serial}', "
                f"attempt_number={self.attempt_number})")