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
            lock_type=LockType.PIN)
    
    def test_valid_attack_strategy_creation(self):
        """Test creating a valid AttackStrategy"""
        device = self.create_test_device()
        strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=device,
            wordlists=["common_pins.txt"],
            mask_patterns=["?d?d?d?d"],
            max_attempts=1000,
            delay_handling=DelayStrategy.WAIT,
            gpu_acceleration=False,
            thread_count=2,
            timeout_seconds=3600
        )
        
        assert strategy.strategy_type == AttackType.BRUTE_FORCE
        assert strategy.target_device == device
        assert strategy.wordlists == ["common_pins.txt"]
        assert strategy.mask_patterns == ["?d?d?d?d"]
        assert strategy.max_attempts == 1000
        assert strategy.delay_handling == DelayStrategy.WAIT
        assert strategy.gpu_acceleration is False
        assert strategy.thread_count == 2
        assert strategy.timeout_seconds == 3600
        assert len(strategy.validation_errors) == 0
    
    def test_strategy_type_validation(self):
        """Test attack strategy type validation"""
        device = self.create_test_device()
        
        # Invalid strategy type should raise exception
        with pytest.raises(AttackValidationError) as exc_info:
            AttackStrategy(
                strategy_type="invalid_type",  # Not an AttackType enum
                target_device=device
            )
        assert "Strategy type must be AttackType enum" in str(exc_info.value)
    
    def test_target_device_validation(self):
        """Test target device validation"""
        # Invalid device type should raise exception
        with pytest.raises(AttackValidationError) as exc_info:
            AttackStrategy(
                strategy_type=AttackType.BRUTE_FORCE,
                target_device="not_a_device"  # Not an AndroidDevice
            )
        assert "Target device must be AndroidDevice instance" in str(exc_info.value)
        
        # Device with validation errors should raise exception during device creation
        with pytest.raises(Exception):  # DeviceValidationError from device creation
            AndroidDevice(
                serial="",  # Invalid empty serial
                model="Test Model",
                brand="Test Brand",
                android_version="11"
            )
    
    def test_wordlist_validation(self):
        """Test wordlist validation"""
        device = self.create_test_device()
        
        # Dictionary attack without wordlists should add validation error
        strategy = AttackStrategy(
            strategy_type=AttackType.DICTIONARY,
            target_device=device,
            wordlists=[]  # Empty wordlists for dictionary attack
        )
        assert "Dictionary/hybrid attacks require at least one wordlist" in strategy.validation_errors
        
        # Invalid wordlist type should raise exception
        with pytest.raises(AttackValidationError):
            AttackStrategy(
                strategy_type=AttackType.BRUTE_FORCE,
                target_device=device,
                wordlists="not_a_list"  # Not a list
            )
        
        # Empty string in wordlists should add validation error
        strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=device,
            wordlists=["valid.txt", ""]  # Empty string
        )
        assert "Wordlist paths must be non-empty strings" in strategy.validation_errors
    
    def test_max_attempts_validation(self):
        """Test max attempts validation"""
        device = self.create_test_device()
        
        # Invalid type should raise exception
        with pytest.raises(AttackValidationError) as exc_info:
            AttackStrategy(
                strategy_type=AttackType.BRUTE_FORCE,
                target_device=device,
                max_attempts="1000"  # String instead of int
            )
        assert "Max attempts must be an integer" in str(exc_info.value)
        
        # Zero or negative attempts should raise exception
        with pytest.raises(AttackValidationError) as exc_info:
            AttackStrategy(
                strategy_type=AttackType.BRUTE_FORCE,
                target_device=device,
                max_attempts=0
            )
        assert "Max attempts must be positive" in str(exc_info.value)
        
        # Very high attempts should add warning
        strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=device,
            max_attempts=2000000
        )
        assert "Max attempts is very high, may take excessive time" in strategy.validation_errors
    
    def test_thread_count_validation(self):
        """Test thread count validation"""
        device = self.create_test_device()
        
        # Invalid type should raise exception
        with pytest.raises(AttackValidationError):
            AttackStrategy(
                strategy_type=AttackType.BRUTE_FORCE,
                target_device=device,
                thread_count="2"  # String instead of int
            )
        
        # Zero or negative threads should raise exception
        with pytest.raises(AttackValidationError):
            AttackStrategy(
                strategy_type=AttackType.BRUTE_FORCE,
                target_device=device,
                thread_count=0
            )
        
        # High thread count should add warning
        strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=device,
            thread_count=64
        )
        assert "High thread count may cause device instability" in strategy.validation_errors
    
    def test_timeout_validation(self):
        """Test timeout validation"""
        device = self.create_test_device()
        
        # Invalid type should raise exception
        with pytest.raises(AttackValidationError):
            AttackStrategy(
                strategy_type=AttackType.BRUTE_FORCE,
                target_device=device,
                timeout_seconds="3600"  # String instead of int
            )
        
        # Very short timeout should add warning
        strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=device,
            timeout_seconds=30
        )
        assert "Very short timeout may prevent attack completion" in strategy.validation_errors
        
        # Very long timeout should add warning
        strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=device,
            timeout_seconds=100000
        )
        assert "Very long timeout may indicate configuration error" in strategy.validation_errors
    
    def test_strategy_compatibility_validation(self):
        """Test strategy compatibility with device capabilities"""
        # Device without pattern lock for pattern analysis
        device = AndroidDevice(
            serial="TEST123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            usb_debugging=True,
            lock_type=LockType.PIN  # Not pattern
        )
        
        strategy = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,
            target_device=device
        )
        assert "Pattern analysis not supported for this lock type" in strategy.validation_errors
        
        # Device without root for hash cracking
        device_no_root = AndroidDevice(
            serial="TEST123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            usb_debugging=True,
            root_status=False,  # No root access
            lock_type=LockType.PIN
        )
        
        strategy = AttackStrategy(
            strategy_type=AttackType.HASH_CRACKING,
            target_device=device_no_root
        )
        assert "Hash extraction not available without root access" in strategy.validation_errors
        
        # GPU acceleration for non-compatible strategy
        strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=device,
            gpu_acceleration=True
        )
        assert "GPU acceleration only supported for hash cracking" in strategy.validation_errors
    
    def test_duration_estimation(self):
        """Test attack duration estimation"""
        device = self.create_test_device()
        
        # Basic brute force estimation
        strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=device,
            max_attempts=1000,
            thread_count=1
        )
        duration = strategy.estimate_duration()
        assert duration > 0
        assert duration <= strategy.timeout_seconds
        
        # GPU-accelerated hash cracking should be faster
        device_rooted = AndroidDevice(
            serial="TEST123",
            model="Test Model",
            brand="Test Brand",
            android_version="11",
            root_status=True,
            lock_type=LockType.PIN
        )
        
        gpu_strategy = AttackStrategy(
            strategy_type=AttackType.HASH_CRACKING,
            target_device=device_rooted,
            max_attempts=1000,
            gpu_acceleration=True
        )
        gpu_duration = gpu_strategy.estimate_duration()
        
        regular_strategy = AttackStrategy(
            strategy_type=AttackType.HASH_CRACKING,
            target_device=device_rooted,
            max_attempts=1000,
            gpu_acceleration=False
        )
        regular_duration = regular_strategy.estimate_duration()
        
        assert gpu_duration <= regular_duration
    
    def test_complexity_metrics(self):
        """Test attack complexity metrics"""
        device = self.create_test_device()
        strategy = AttackStrategy(
            strategy_type=AttackType.HYBRID,
            target_device=device,
            wordlists=["list1.txt", "list2.txt"],
            mask_patterns=["?d?d?d?d", "?l?l?l?l"],
            max_attempts=5000,
            thread_count=4,
            gpu_acceleration=False
        )
        
        metrics = strategy.get_estimated_complexity()
        
        assert 'estimated_duration_seconds' in metrics
        assert metrics['max_attempts'] == 5000
        assert metrics['thread_count'] == 4
        assert metrics['strategy_type'] == 'hybrid'
        assert metrics['gpu_acceleration'] is False
        assert metrics['wordlist_count'] == 2
        assert metrics['mask_pattern_count'] == 2
    
    def test_serialization_to_dict(self):
        """Test AttackStrategy serialization to dictionary"""
        device = self.create_test_device()
        strategy = AttackStrategy(
            strategy_type=AttackType.DICTIONARY,
            target_device=device,
            wordlists=["common.txt"],
            mask_patterns=["?d?d?d?d"],
            max_attempts=1000,
            delay_handling=DelayStrategy.WAIT,
            gpu_acceleration=False,
            priority_patterns=["1234", "0000"]
        )
        
        data = strategy.to_dict()
        
        assert data['strategy_type'] == 'dictionary'
        assert 'target_device' in data
        assert data['wordlists'] == ["common.txt"]
        assert data['mask_patterns'] == ["?d?d?d?d"]
        assert data['max_attempts'] == 1000
        assert data['delay_handling'] == 'wait'
        assert data['gpu_acceleration'] is False
        assert data['priority_patterns'] == ["1234", "0000"]
        assert 'created_at' in data
        assert 'complexity_metrics' in data
    
    def test_serialization_from_dict(self):
        """Test AttackStrategy deserialization from dictionary"""
        device = self.create_test_device()
        original = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=device,
            max_attempts=500
        )
        
        data = original.to_dict()
        reconstructed = AttackStrategy.from_dict(data)
        
        assert reconstructed.strategy_type == original.strategy_type
        assert reconstructed.target_device.serial == original.target_device.serial
        assert reconstructed.max_attempts == original.max_attempts
        assert reconstructed.delay_handling == original.delay_handling
    
    def test_json_serialization(self):
        """Test JSON serialization and deserialization"""
        device = self.create_test_device()
        strategy = AttackStrategy(
            strategy_type=AttackType.HYBRID,
            target_device=device,
            wordlists=["test.txt"],
            max_attempts=1000
        )
        
        # Test to_json
        json_str = strategy.to_json()
        assert isinstance(json_str, str)
        
        # Verify it's valid JSON
        data = json.loads(json_str)
        assert data['strategy_type'] == 'hybrid'
        assert data['max_attempts'] == 1000
        
        # Test from_json
        reconstructed = AttackStrategy.from_json(json_str)
        assert reconstructed.strategy_type == strategy.strategy_type
        assert reconstructed.max_attempts == strategy.max_attempts
    
    def test_string_representations(self):
        """Test string representations"""
        device = self.create_test_device()
        strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=device
        )
        
        # Test __str__
        str_repr = str(strategy)
        assert "brute_force attack" in str_repr
        assert "Test Brand Test Model" in str_repr
        
        # Test __repr__
        repr_str = repr(strategy)
        assert "AttackStrategy" in repr_str
        assert "strategy_type=AttackType.BRUTE_FORCE" in repr_str
        assert "target_device='TEST123'" in repr_str


class TestCustodyEvent:
    """Test CustodyEvent model"""
    
    def test_custody_event_creation(self):
        """Test creating a custody event"""
        event = CustodyEvent(
            timestamp=datetime.now(),
            event_type="evidence_collection",
            user_id="investigator_001",
            description="Collected device evidence",
            hash_before="abc123",
            hash_after="def456"
        )
        
        assert event.event_type == "evidence_collection"
        assert event.user_id == "investigator_001"
        assert event.description == "Collected device evidence"
        assert event.hash_before == "abc123"
        assert event.hash_after == "def456"
    
    def test_custody_event_serialization(self):
        """Test custody event serialization"""
        timestamp = datetime.now()
        event = CustodyEvent(
            timestamp=timestamp,
            event_type="analysis",
            user_id="analyst_001",
            description="Analyzed evidence"
        )
        
        data = event.to_dict()
        assert data['timestamp'] == timestamp.isoformat()
        assert data['event_type'] == "analysis"
        assert data['user_id'] == "analyst_001"
        assert data['description'] == "Analyzed evidence"
        
        # Test round trip
        reconstructed = CustodyEvent.from_dict(data)
        assert reconstructed.timestamp == timestamp
        assert reconstructed.event_type == event.event_type
        assert reconstructed.user_id == event.user_id


class TestEvidenceRecord:
    """Test EvidenceRecord model validation and functionality"""
    
    def create_test_evidence_record(self) -> EvidenceRecord:
        """Create a test evidence record"""
        return EvidenceRecord(
            case_id="CASE_001",
            timestamp=datetime.now(),
            operation_type="device_analysis",
            device_serial="TEST123",
            attempt_number=1,
            result="success",
            hash_verification="a" * 64,  # Valid SHA-256 hash format
            investigator_id="INV_001"
        )
    
    def test_valid_evidence_record_creation(self):
        """Test creating a valid EvidenceRecord"""
        timestamp = datetime.now()
        record = EvidenceRecord(
            case_id="CASE_001",
            timestamp=timestamp,
            operation_type="device_analysis",
            device_serial="TEST123",
            attempt_number=1,
            result="Device successfully analyzed",
            hash_verification="1234567890abcdef" * 4,  # 64 char hex string
            investigator_id="INV_001",
            case_notes="Initial device analysis"
        )
        
        assert record.case_id == "CASE_001"
        assert record.timestamp == timestamp
        assert record.operation_type == "device_analysis"
        assert record.device_serial == "TEST123"
        assert record.attempt_number == 1
        assert record.result == "Device successfully analyzed"
        assert record.investigator_id == "INV_001"
        assert record.case_notes == "Initial device analysis"
        assert len(record.validation_errors) == 0
        assert record.verification_status == "verified"
    
    def test_case_id_validation(self):
        """Test case ID validation"""
        # Empty case ID should raise exception
        with pytest.raises(ForensicsException) as exc_info:
            EvidenceRecord(
                case_id="",
                timestamp=datetime.now(),
                operation_type="device_analysis",
                device_serial="TEST123",
                attempt_number=1,
                result="success",
                hash_verification="a" * 64
            )
        assert "Case ID cannot be empty" in str(exc_info.value)
        assert exc_info.value.evidence_impact is True
        
        # Invalid characters in case ID
        record = EvidenceRecord(
            case_id="CASE@001!",
            timestamp=datetime.now(),
            operation_type="device_analysis",
            device_serial="TEST123",
            attempt_number=1,
            result="success",
            hash_verification="a" * 64
        )
        assert "Case ID contains invalid characters" in record.validation_errors
        
        # Case ID too short/long
        record = EvidenceRecord(
            case_id="AB",
            timestamp=datetime.now(),
            operation_type="device_analysis",
            device_serial="TEST123",
            attempt_number=1,
            result="success",
            hash_verification="a" * 64
        )
        assert "Case ID length outside acceptable range" in record.validation_errors
    
    def test_operation_type_validation(self):
        """Test operation type validation"""
        # Empty operation type should raise exception
        with pytest.raises(ForensicsException):
            EvidenceRecord(
                case_id="CASE_001",
                timestamp=datetime.now(),
                operation_type="",
                device_serial="TEST123",
                attempt_number=1,
                result="success",
                hash_verification="a" * 64
            )
        
        # Invalid operation type should add validation error
        record = EvidenceRecord(
            case_id="CASE_001",
            timestamp=datetime.now(),
            operation_type="invalid_operation",
            device_serial="TEST123",
            attempt_number=1,
            result="success",
            hash_verification="a" * 64
        )
        assert "Unknown operation type: invalid_operation" in record.validation_errors
        
        # Valid operation types should pass
        valid_operations = [
            'device_detection', 'device_analysis', 'attack_execution',
            'evidence_collection', 'hash_verification', 'report_generation'
        ]
        
        for op_type in valid_operations:
            record = EvidenceRecord(
                case_id="CASE_001",
                timestamp=datetime.now(),
                operation_type=op_type,
                device_serial="TEST123",
                attempt_number=1,
                result="success",
                hash_verification="a" * 64
            )
            op_errors = [e for e in record.validation_errors if "operation type" in e.lower()]
            assert len(op_errors) == 0
    
    def test_device_serial_validation(self):
        """Test device serial validation"""
        # Empty device serial should raise exception
        with pytest.raises(ForensicsException):
            EvidenceRecord(
                case_id="CASE_001",
                timestamp=datetime.now(),
                operation_type="device_analysis",
                device_serial="",
                attempt_number=1,
                result="success",
                hash_verification="a" * 64
            )
    
    def test_attempt_number_validation(self):
        """Test attempt number validation"""
        # Invalid type should raise exception
        with pytest.raises(ForensicsException):
            EvidenceRecord(
                case_id="CASE_001",
                timestamp=datetime.now(),
                operation_type="device_analysis",
                device_serial="TEST123",
                attempt_number="1",  # String instead of int
                result="success",
                hash_verification="a" * 64
            )
        
        # Negative attempt number should raise exception
        with pytest.raises(ForensicsException):
            EvidenceRecord(
                case_id="CASE_001",
                timestamp=datetime.now(),
                operation_type="device_analysis",
                device_serial="TEST123",
                attempt_number=-1,
                result="success",
                hash_verification="a" * 64
            )
    
    def test_hash_verification_validation(self):
        """Test hash verification validation"""
        # Empty hash should raise exception
        with pytest.raises(ForensicsException):
            EvidenceRecord(
                case_id="CASE_001",
                timestamp=datetime.now(),
                operation_type="device_analysis",
                device_serial="TEST123",
                attempt_number=1,
                result="success",
                hash_verification=""
            )
        
        # Invalid hash format should add validation error
        record = EvidenceRecord(
            case_id="CASE_001",
            timestamp=datetime.now(),
            operation_type="device_analysis",
            device_serial="TEST123",
            attempt_number=1,
            result="success",
            hash_verification="invalid_hash"
        )
        assert "Hash verification must be valid SHA-256 hash" in record.validation_errors
        
        # Valid SHA-256 hash should pass
        valid_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        record = EvidenceRecord(
            case_id="CASE_001",
            timestamp=datetime.now(),
            operation_type="device_analysis",
            device_serial="TEST123",
            attempt_number=1,
            result="success",
            hash_verification=valid_hash
        )
        hash_errors = [e for e in record.validation_errors if "hash" in e.lower()]
        assert len(hash_errors) == 0
    
    def test_chain_of_custody_validation(self):
        """Test chain of custody validation"""
        record = self.create_test_evidence_record()
        
        # Invalid custody event type should add validation error
        record.chain_of_custody = ["not_a_custody_event"]
        record.validate_all()
        assert any("not a CustodyEvent instance" in error for error in record.validation_errors)
        
        # Test chronological order validation
        record = self.create_test_evidence_record()
        now = datetime.now()
        event1 = CustodyEvent(
            timestamp=now,
            event_type="collection",
            user_id="user1",
            description="First event"
        )
        event2 = CustodyEvent(
            timestamp=now - timedelta(hours=1),  # Earlier timestamp
            event_type="analysis",
            user_id="user2",
            description="Second event"
        )
        
        record.chain_of_custody = [event1, event2]
        record.validate_all()
        assert "Chain of custody events not in chronological order" in record.validation_errors
    
    def test_add_custody_event(self):
        """Test adding custody events"""
        record = self.create_test_evidence_record()
        initial_count = len(record.chain_of_custody)
        
        record.add_custody_event(
            event_type="analysis",
            user_id="analyst_001",
            description="Performed forensic analysis",
            hash_before="abc123",
            hash_after="def456"
        )
        
        assert len(record.chain_of_custody) == initial_count + 1
        new_event = record.chain_of_custody[-1]
        assert new_event.event_type == "analysis"
        assert new_event.user_id == "analyst_001"
        assert new_event.description == "Performed forensic analysis"
        assert new_event.hash_before == "abc123"
        assert new_event.hash_after == "def456"
        assert record.last_verified is None  # Should require re-validation
    
    def test_verify_integrity(self):
        """Test evidence integrity verification"""
        record = self.create_test_evidence_record()
        
        # Valid record should verify successfully
        assert record.verify_integrity() is True
        
        # Record with validation errors should raise exception during verification
        record.case_id = ""  # Make it invalid
        with pytest.raises(ForensicsException):
            record.verify_integrity()
    
    def test_serialization_to_dict(self):
        """Test EvidenceRecord serialization to dictionary"""
        timestamp = datetime.now()
        record = EvidenceRecord(
            case_id="CASE_001",
            timestamp=timestamp,
            operation_type="device_analysis",
            device_serial="TEST123",
            attempt_number=1,
            result="Analysis completed",
            hash_verification="a" * 64,
            investigator_id="INV_001",
            case_notes="Test analysis"
        )
        
        # Add a custody event
        record.add_custody_event(
            event_type="collection",
            user_id="collector_001",
            description="Evidence collected"
        )
        
        data = record.to_dict()
        
        assert data['case_id'] == "CASE_001"
        assert data['timestamp'] == timestamp.isoformat()
        assert data['operation_type'] == "device_analysis"
        assert data['device_serial'] == "TEST123"
        assert data['attempt_number'] == 1
        assert data['result'] == "Analysis completed"
        assert data['hash_verification'] == "a" * 64
        assert data['investigator_id'] == "INV_001"
        assert data['case_notes'] == "Test analysis"
        assert len(data['chain_of_custody']) == 1
        assert data['verification_status'] == "verified"
    
    def test_serialization_from_dict(self):
        """Test EvidenceRecord deserialization from dictionary"""
        timestamp = datetime.now()
        original = self.create_test_evidence_record()
        original.timestamp = timestamp
        
        data = original.to_dict()
        reconstructed = EvidenceRecord.from_dict(data)
        
        assert reconstructed.case_id == original.case_id
        assert reconstructed.timestamp == original.timestamp
        assert reconstructed.operation_type == original.operation_type
        assert reconstructed.device_serial == original.device_serial
        assert reconstructed.attempt_number == original.attempt_number
        assert reconstructed.result == original.result
        assert reconstructed.hash_verification == original.hash_verification
    
    def test_json_serialization(self):
        """Test JSON serialization and deserialization"""
        record = self.create_test_evidence_record()
        
        # Test to_json
        json_str = record.to_json()
        assert isinstance(json_str, str)
        
        # Verify it's valid JSON
        data = json.loads(json_str)
        assert data['case_id'] == "CASE_001"
        assert data['operation_type'] == "device_analysis"
        
        # Test from_json
        reconstructed = EvidenceRecord.from_json(json_str)
        assert reconstructed.case_id == record.case_id
        assert reconstructed.operation_type == record.operation_type
    
    def test_string_representations(self):
        """Test string representations"""
        record = self.create_test_evidence_record()
        
        # Test __str__
        str_repr = str(record)
        assert "Evidence CASE_001" in str_repr
        assert "device_analysis" in str_repr
        assert "TEST123" in str_repr
        
        # Test __repr__
        repr_str = repr(record)
        assert "EvidenceRecord" in repr_str
        assert "case_id='CASE_001'" in repr_str
        assert "operation_type='device_analysis'" in repr_str


if __name__ == "__main__":
    pytest.main([__file__])
