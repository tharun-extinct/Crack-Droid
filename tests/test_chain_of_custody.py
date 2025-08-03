"""
Unit tests for Chain of Custody Manager

Tests comprehensive chain of custody management including:
- Case ID tracking and validation
- Evidence handling documentation
- Tamper detection mechanisms
- Custody event logging with cryptographic verification

Requirements tested:
- 4.3: Chain-of-custody logging with SHA-256 hash verification
- 4.4: Formal case ID input for authorization
"""

import pytest
import json
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

from forensics_toolkit.services.chain_of_custody import (
    ChainOfCustody, CustodyEventType, CustodyValidationError, 
    CaseMetadata
)
from forensics_toolkit.models.attack import EvidenceRecord, CustodyEvent
from forensics_toolkit.models.device import AndroidDevice, LockType


# Global fixtures for all test classes
@pytest.fixture
def temp_storage():
    """Create temporary storage directory"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)

@pytest.fixture
def custody_manager(temp_storage):
    """Create ChainOfCustody instance with temporary storage"""
    return ChainOfCustody(storage_path=temp_storage, secret_key="test_secret_key_12345678901234567890")

@pytest.fixture
def sample_device():
    """Create sample Android device for testing"""
    return AndroidDevice(
        serial="TEST123456",
        model="Pixel 6",
        brand="Google",
        android_version="12",
        imei="123456789012345",
        usb_debugging=True,
        root_status=False,
        lock_type=LockType.PIN,
        screen_timeout=30,
        lockout_policy=None
    )

@pytest.fixture
def sample_evidence(sample_device):
    """Create sample evidence record for testing"""
    return EvidenceRecord(
        case_id="TEST_CASE_001",
        timestamp=datetime.now(),
        operation_type="device_analysis",
        device_serial=sample_device.serial,
        attempt_number=1,
        result="success",
        hash_verification="",  # Will be computed by custody manager
        investigator_id="investigator_001"
    )


class TestCaseManagement:
    """Test case creation and management functionality"""
    
    def test_create_case_success(self, custody_manager):
        """Test successful case creation"""
        case_metadata = custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Forensic Case",
            case_description="Test case for unit testing",
            authorized_users=["investigator_001", "supervisor_001"]
        )
        
        assert case_metadata.case_id == "TEST_CASE_001"
        assert case_metadata.investigator_id == "investigator_001"
        assert case_metadata.case_title == "Test Forensic Case"
        assert case_metadata.case_status == "active"
        assert "investigator_001" in case_metadata.authorized_users
        assert "supervisor_001" in case_metadata.authorized_users
        assert case_metadata.evidence_count == 0
    
    def test_create_case_invalid_id(self, custody_manager):
        """Test case creation with invalid case ID"""
        with pytest.raises(CustodyValidationError) as exc_info:
            custody_manager.create_case(
                case_id="",
                investigator_id="investigator_001",
                case_title="Test Case",
                case_description="Test description"
            )
        assert "Case ID cannot be empty" in str(exc_info.value)
    
    def test_create_case_invalid_characters(self, custody_manager):
        """Test case creation with invalid characters in case ID"""
        with pytest.raises(CustodyValidationError) as exc_info:
            custody_manager.create_case(
                case_id="TEST@CASE#001",
                investigator_id="investigator_001",
                case_title="Test Case",
                case_description="Test description"
            )
        assert "invalid characters" in str(exc_info.value)
    
    def test_create_case_too_short(self, custody_manager):
        """Test case creation with case ID too short"""
        with pytest.raises(CustodyValidationError) as exc_info:
            custody_manager.create_case(
                case_id="AB",
                investigator_id="investigator_001",
                case_title="Test Case",
                case_description="Test description"
            )
        assert "length outside acceptable range" in str(exc_info.value)
    
    def test_create_case_too_long(self, custody_manager):
        """Test case creation with case ID too long"""
        long_case_id = "A" * 51
        with pytest.raises(CustodyValidationError) as exc_info:
            custody_manager.create_case(
                case_id=long_case_id,
                investigator_id="investigator_001",
                case_title="Test Case",
                case_description="Test description"
            )
        assert "length outside acceptable range" in str(exc_info.value)
    
    def test_create_duplicate_case(self, custody_manager):
        """Test creating duplicate case"""
        # Create first case
        custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        # Try to create duplicate
        with pytest.raises(CustodyValidationError) as exc_info:
            custody_manager.create_case(
                case_id="TEST_CASE_001",
                investigator_id="investigator_002",
                case_title="Duplicate Case",
                case_description="Duplicate description"
            )
        assert "already exists" in str(exc_info.value)
    
    def test_get_case_metadata(self, custody_manager):
        """Test retrieving case metadata"""
        # Create case
        original_metadata = custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        # Retrieve metadata
        retrieved_metadata = custody_manager.get_case_metadata("TEST_CASE_001")
        
        assert retrieved_metadata is not None
        assert retrieved_metadata.case_id == original_metadata.case_id
        assert retrieved_metadata.investigator_id == original_metadata.investigator_id
        assert retrieved_metadata.case_title == original_metadata.case_title
    
    def test_get_nonexistent_case(self, custody_manager):
        """Test retrieving nonexistent case metadata"""
        metadata = custody_manager.get_case_metadata("NONEXISTENT_CASE")
        assert metadata is None


class TestUserAuthorization:
    """Test user authorization functionality"""
    
    def test_authorize_user_success(self, custody_manager):
        """Test successful user authorization"""
        # Create case
        custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        # Authorize new user
        custody_manager.authorize_user_for_case(
            case_id="TEST_CASE_001",
            user_id="new_user_001",
            authorizing_user="investigator_001"
        )
        
        # Verify authorization
        case_metadata = custody_manager.get_case_metadata("TEST_CASE_001")
        assert "new_user_001" in case_metadata.authorized_users
    
    def test_authorize_user_nonexistent_case(self, custody_manager):
        """Test authorizing user for nonexistent case"""
        with pytest.raises(CustodyValidationError) as exc_info:
            custody_manager.authorize_user_for_case(
                case_id="NONEXISTENT_CASE",
                user_id="user_001",
                authorizing_user="investigator_001"
            )
        assert "not found" in str(exc_info.value)
    
    def test_authorize_user_unauthorized_authorizer(self, custody_manager):
        """Test authorization by unauthorized user"""
        # Create case
        custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        # Try to authorize with unauthorized user
        with pytest.raises(CustodyValidationError) as exc_info:
            custody_manager.authorize_user_for_case(
                case_id="TEST_CASE_001",
                user_id="new_user_001",
                authorizing_user="unauthorized_user"
            )
        assert "not authorized" in str(exc_info.value)


class TestCustodyEventLogging:
    """Test custody event logging functionality"""
    
    def test_log_custody_event_success(self, custody_manager):
        """Test successful custody event logging"""
        # Create case
        custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        # Log custody event
        event = custody_manager.log_custody_event(
            case_id="TEST_CASE_001",
            event_type=CustodyEventType.EVIDENCE_COLLECTED,
            user_id="investigator_001",
            description="Test evidence collection",
            hash_after="test_hash_123"
        )
        
        assert event.event_type == CustodyEventType.EVIDENCE_COLLECTED.value
        assert event.user_id == "investigator_001"
        assert event.description == "Test evidence collection"
        assert event.hash_after == "test_hash_123"
        assert isinstance(event.timestamp, datetime)
    
    def test_log_custody_event_unauthorized_user(self, custody_manager):
        """Test logging custody event with unauthorized user"""
        # Create case
        custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        # Try to log event with unauthorized user
        with pytest.raises(CustodyValidationError) as exc_info:
            custody_manager.log_custody_event(
                case_id="TEST_CASE_001",
                event_type=CustodyEventType.EVIDENCE_COLLECTED,
                user_id="unauthorized_user",
                description="Unauthorized access attempt"
            )
        assert "not authorized" in str(exc_info.value)
    
    def test_get_custody_chain(self, custody_manager):
        """Test retrieving custody chain"""
        # Create case
        custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        # Log additional events
        custody_manager.log_custody_event(
            case_id="TEST_CASE_001",
            event_type=CustodyEventType.EVIDENCE_COLLECTED,
            user_id="investigator_001",
            description="First evidence collection"
        )
        
        custody_manager.log_custody_event(
            case_id="TEST_CASE_001",
            event_type=CustodyEventType.EVIDENCE_ANALYZED,
            user_id="investigator_001",
            description="Evidence analysis completed"
        )
        
        # Retrieve custody chain
        custody_chain = custody_manager.get_custody_chain("TEST_CASE_001")
        
        # Should have case creation + 2 additional events
        assert len(custody_chain) == 3
        assert custody_chain[0].event_type == CustodyEventType.CASE_CREATED.value
        assert custody_chain[1].event_type == CustodyEventType.EVIDENCE_COLLECTED.value
        assert custody_chain[2].event_type == CustodyEventType.EVIDENCE_ANALYZED.value
        
        # Verify chronological order
        for i in range(1, len(custody_chain)):
            assert custody_chain[i].timestamp >= custody_chain[i-1].timestamp


class TestEvidenceManagement:
    """Test evidence record management functionality"""
    
    def test_add_evidence_record_success(self, custody_manager, sample_evidence):
        """Test successful evidence record addition"""
        # Create case
        custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        # Add evidence record
        evidence_hash = custody_manager.add_evidence_record(
            evidence=sample_evidence,
            user_id="investigator_001"
        )
        
        assert evidence_hash is not None
        assert len(evidence_hash) == 64  # SHA-256 hash length
        assert sample_evidence.hash_verification == evidence_hash
        
        # Verify case metadata updated
        case_metadata = custody_manager.get_case_metadata("TEST_CASE_001")
        assert case_metadata.evidence_count == 1
    
    def test_add_evidence_unauthorized_user(self, custody_manager, sample_evidence):
        """Test adding evidence with unauthorized user"""
        # Create case
        custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        # Try to add evidence with unauthorized user
        with pytest.raises(CustodyValidationError) as exc_info:
            custody_manager.add_evidence_record(
                evidence=sample_evidence,
                user_id="unauthorized_user"
            )
        assert "not authorized" in str(exc_info.value)
    
    def test_get_evidence_records(self, custody_manager, sample_evidence):
        """Test retrieving evidence records"""
        # Create case
        custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        # Add evidence record
        custody_manager.add_evidence_record(
            evidence=sample_evidence,
            user_id="investigator_001"
        )
        
        # Retrieve evidence records
        evidence_records = custody_manager.get_evidence_records("TEST_CASE_001")
        
        assert len(evidence_records) == 1
        assert evidence_records[0].case_id == "TEST_CASE_001"
        assert evidence_records[0].operation_type == "device_analysis"
        assert evidence_records[0].device_serial == sample_evidence.device_serial


class TestIntegrityVerification:
    """Test evidence integrity verification functionality"""
    
    def test_verify_evidence_integrity_success(self, custody_manager, sample_evidence):
        """Test successful evidence integrity verification"""
        # Create case and add evidence
        custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        evidence_hash = custody_manager.add_evidence_record(
            evidence=sample_evidence,
            user_id="investigator_001"
        )
        
        # Verify integrity
        is_valid, errors = custody_manager.verify_evidence_integrity("TEST_CASE_001", evidence_hash)
        
        assert is_valid is True
        assert len(errors) == 0
    
    def test_verify_evidence_integrity_not_found(self, custody_manager):
        """Test integrity verification for nonexistent evidence"""
        # Create case
        custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        # Try to verify nonexistent evidence
        is_valid, errors = custody_manager.verify_evidence_integrity(
            "TEST_CASE_001", 
            "nonexistent_hash_1234567890123456789012345678901234567890123456789012345678901234"
        )
        
        assert is_valid is False
        assert len(errors) > 0
        assert "not found" in errors[0]
    
    def test_detect_tampering_clean_case(self, custody_manager, sample_evidence):
        """Test tampering detection on clean case"""
        # Create case and add evidence
        custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        custody_manager.add_evidence_record(
            evidence=sample_evidence,
            user_id="investigator_001"
        )
        
        # Check for tampering
        tampering_detected, issues = custody_manager.detect_tampering("TEST_CASE_001")
        
        assert tampering_detected is False
        assert len(issues) == 0
    
    def test_detect_tampering_modified_evidence(self, custody_manager, sample_evidence):
        """Test tampering detection with modified evidence"""
        # Create case and add evidence
        custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        evidence_hash = custody_manager.add_evidence_record(
            evidence=sample_evidence,
            user_id="investigator_001"
        )
        
        # Manually modify evidence to simulate tampering
        evidence_records = custody_manager.get_evidence_records("TEST_CASE_001")
        evidence_records[0].result = "modified_result"  # This should break the hash
        
        # Check for tampering
        tampering_detected, issues = custody_manager.detect_tampering("TEST_CASE_001")
        
        assert tampering_detected is True
        assert len(issues) > 0
        assert "tampering detected" in issues[0]


class TestCryptographicVerification:
    """Test cryptographic verification functionality"""
    
    def test_compute_evidence_hash_consistency(self, custody_manager, sample_evidence):
        """Test that evidence hash computation is consistent"""
        hash1 = custody_manager._compute_evidence_hash(sample_evidence)
        hash2 = custody_manager._compute_evidence_hash(sample_evidence)
        
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hash length
    
    def test_compute_evidence_hash_different_evidence(self, custody_manager, sample_evidence, sample_device):
        """Test that different evidence produces different hashes"""
        # Create second evidence record
        evidence2 = EvidenceRecord(
            case_id="TEST_CASE_002",
            timestamp=datetime.now(),
            operation_type="attack_execution",
            device_serial=sample_device.serial,
            attempt_number=2,
            result="failed",
            hash_verification="",
            investigator_id="investigator_002"
        )
        
        hash1 = custody_manager._compute_evidence_hash(sample_evidence)
        hash2 = custody_manager._compute_evidence_hash(evidence2)
        
        assert hash1 != hash2
    
    def test_custody_signature_verification(self, custody_manager):
        """Test custody event signature verification"""
        event = CustodyEvent(
            timestamp=datetime.now(),
            event_type="test_event",
            user_id="test_user",
            description="Test event description"
        )
        
        # Compute signature
        signature = custody_manager._compute_custody_signature(event)
        
        # Verify signature
        is_valid = custody_manager._verify_custody_signature(event, signature)
        assert is_valid is True
        
        # Test with wrong signature
        wrong_signature = "wrong_signature_123"
        is_valid = custody_manager._verify_custody_signature(event, wrong_signature)
        assert is_valid is False
    
    def test_custody_signature_tamper_detection(self, custody_manager):
        """Test that modified events fail signature verification"""
        event = CustodyEvent(
            timestamp=datetime.now(),
            event_type="test_event",
            user_id="test_user",
            description="Original description"
        )
        
        # Compute signature for original event
        signature = custody_manager._compute_custody_signature(event)
        
        # Modify event
        event.description = "Modified description"
        
        # Verify signature should fail
        is_valid = custody_manager._verify_custody_signature(event, signature)
        assert is_valid is False


class TestReportGeneration:
    """Test custody report generation functionality"""
    
    def test_generate_custody_report(self, custody_manager, sample_evidence):
        """Test comprehensive custody report generation"""
        # Create case and add evidence
        custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        custody_manager.add_evidence_record(
            evidence=sample_evidence,
            user_id="investigator_001"
        )
        
        # Generate report
        report = custody_manager.generate_custody_report("TEST_CASE_001")
        
        # Verify report structure
        assert "case_metadata" in report
        assert "custody_chain" in report
        assert "evidence_records" in report
        assert "integrity_verification" in report
        assert "tampering_detection" in report
        assert "report_generated_at" in report
        
        # Verify content
        assert report["case_metadata"]["case_id"] == "TEST_CASE_001"
        assert len(report["custody_chain"]) >= 2  # Case creation + evidence collection
        assert len(report["evidence_records"]) == 1
        assert report["tampering_detection"]["tampering_detected"] is False
        assert report["total_evidence_records"] == 1
    
    def test_generate_report_nonexistent_case(self, custody_manager):
        """Test report generation for nonexistent case"""
        with pytest.raises(CustodyValidationError) as exc_info:
            custody_manager.generate_custody_report("NONEXISTENT_CASE")
        assert "not found" in str(exc_info.value)


class TestPersistence:
    """Test data persistence functionality"""
    
    def test_case_metadata_persistence(self, temp_storage):
        """Test that case metadata persists across instances"""
        # Create first instance and add case
        custody_manager1 = ChainOfCustody(storage_path=temp_storage)
        custody_manager1.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        # Create second instance and verify case exists
        custody_manager2 = ChainOfCustody(storage_path=temp_storage)
        case_metadata = custody_manager2.get_case_metadata("TEST_CASE_001")
        
        assert case_metadata is not None
        assert case_metadata.case_id == "TEST_CASE_001"
        assert case_metadata.investigator_id == "investigator_001"
    
    def test_custody_log_persistence(self, temp_storage):
        """Test that custody logs persist across instances"""
        # Create first instance and log events
        custody_manager1 = ChainOfCustody(storage_path=temp_storage)
        custody_manager1.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        custody_manager1.log_custody_event(
            case_id="TEST_CASE_001",
            event_type=CustodyEventType.EVIDENCE_COLLECTED,
            user_id="investigator_001",
            description="Test evidence collection"
        )
        
        # Create second instance and verify events exist
        custody_manager2 = ChainOfCustody(storage_path=temp_storage)
        custody_chain = custody_manager2.get_custody_chain("TEST_CASE_001")
        
        assert len(custody_chain) == 2  # Case creation + evidence collection
        assert custody_chain[1].event_type == CustodyEventType.EVIDENCE_COLLECTED.value


class TestErrorHandling:
    """Test error handling and edge cases"""
    
    def test_invalid_storage_path_handling(self):
        """Test handling of invalid storage paths"""
        # This should not raise an exception - directory should be created
        import tempfile
        temp_path = tempfile.mkdtemp(prefix="test_forensics_")
        try:
            custody_manager = ChainOfCustody(storage_path=temp_path)
            assert custody_manager.storage_path.exists()
        finally:
            # Clean up
            shutil.rmtree(temp_path, ignore_errors=True)
    
    def test_corrupted_case_metadata_handling(self, temp_storage):
        """Test handling of corrupted case metadata file"""
        # Create corrupted metadata file
        cases_file = Path(temp_storage) / "cases_metadata.json"
        with open(cases_file, 'w') as f:
            f.write("invalid json content")
        
        # Should raise validation error
        with pytest.raises(CustodyValidationError) as exc_info:
            ChainOfCustody(storage_path=temp_storage)
        assert "Failed to load existing cases" in str(exc_info.value)
    
    def test_missing_custody_log_handling(self, custody_manager):
        """Test handling of missing custody log file"""
        # Create case
        custody_manager.create_case(
            case_id="TEST_CASE_001",
            investigator_id="investigator_001",
            case_title="Test Case",
            case_description="Test description"
        )
        
        # Delete custody log file
        case_dir = custody_manager.storage_path / "TEST_CASE_001"
        custody_log_file = case_dir / "custody_log.json"
        if custody_log_file.exists():
            custody_log_file.unlink()
        
        # Should return empty list instead of raising error
        custody_chain = custody_manager.get_custody_chain("TEST_CASE_001")
        assert custody_chain == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])