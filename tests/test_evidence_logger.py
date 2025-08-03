"""
Unit tests for EvidenceLogger class

Tests cover timestamped operation logging, SHA-256 hash verification,
structured evidence collection, and real-time audit trail generation.
"""

import pytest
import json
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

from forensics_toolkit.services.evidence_logger import (
    EvidenceLogger, 
    OperationLog, 
    EvidenceLoggingError
)
from forensics_toolkit.models.attack import EvidenceRecord, CustodyEvent
from forensics_toolkit.models.device import AndroidDevice
from forensics_toolkit.interfaces import LockType


class TestOperationLog:
    """Test cases for OperationLog class"""
    
    def test_operation_log_creation(self):
        """Test basic operation log creation"""
        timestamp = datetime.now()
        metadata = {'test_key': 'test_value'}
        
        log = OperationLog(
            timestamp=timestamp,
            case_id='TEST_CASE_001',
            operation_type='DEVICE_DETECTION',
            device_serial='ABC123',
            user_id='investigator1',
            message='Device detected successfully',
            metadata=metadata
        )
        
        assert log.timestamp == timestamp
        assert log.case_id == 'TEST_CASE_001'
        assert log.operation_type == 'DEVICE_DETECTION'
        assert log.device_serial == 'ABC123'
        assert log.user_id == 'investigator1'
        assert log.message == 'Device detected successfully'
        assert log.metadata == metadata
        assert log.hash_value is not None
        assert len(log.hash_value) == 64  # SHA-256 hash length
    
    def test_operation_log_hash_calculation(self):
        """Test SHA-256 hash calculation"""
        log = OperationLog(
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            case_id='TEST_CASE_001',
            operation_type='TEST_OP',
            device_serial='ABC123',
            user_id='user1',
            message='Test message',
            metadata={'key': 'value'}
        )
        
        # Hash should be consistent
        expected_hash = log._calculate_hash()
        assert log.hash_value == expected_hash
        
        # Same data should produce same hash
        log2 = OperationLog(
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            case_id='TEST_CASE_001',
            operation_type='TEST_OP',
            device_serial='ABC123',
            user_id='user1',
            message='Test message',
            metadata={'key': 'value'}
        )
        
        assert log.hash_value == log2.hash_value
    
    def test_operation_log_integrity_verification(self):
        """Test integrity verification"""
        log = OperationLog(
            timestamp=datetime.now(),
            case_id='TEST_CASE_001',
            operation_type='TEST_OP',
            device_serial='ABC123',
            user_id='user1',
            message='Test message',
            metadata={}
        )
        
        # Should verify successfully
        assert log.verify_integrity() is True
        
        # Tamper with hash
        original_hash = log.hash_value
        log.hash_value = 'tampered_hash'
        assert log.verify_integrity() is False
        
        # Restore hash
        log.hash_value = original_hash
        assert log.verify_integrity() is True
    
    def test_operation_log_serialization(self):
        """Test to_dict and from_dict methods"""
        timestamp = datetime(2024, 1, 1, 12, 0, 0)
        metadata = {'test_key': 'test_value', 'number': 42}
        
        log = OperationLog(
            timestamp=timestamp,
            case_id='TEST_CASE_001',
            operation_type='TEST_OP',
            device_serial='ABC123',
            user_id='user1',
            message='Test message',
            metadata=metadata
        )
        
        # Convert to dict
        log_dict = log.to_dict()
        
        assert log_dict['timestamp'] == timestamp.isoformat()
        assert log_dict['case_id'] == 'TEST_CASE_001'
        assert log_dict['operation_type'] == 'TEST_OP'
        assert log_dict['device_serial'] == 'ABC123'
        assert log_dict['user_id'] == 'user1'
        assert log_dict['message'] == 'Test message'
        assert log_dict['metadata'] == metadata
        assert log_dict['hash_value'] == log.hash_value
        
        # Convert back from dict
        log2 = OperationLog.from_dict(log_dict)
        
        assert log2.timestamp == log.timestamp
        assert log2.case_id == log.case_id
        assert log2.operation_type == log.operation_type
        assert log2.device_serial == log.device_serial
        assert log2.user_id == log.user_id
        assert log2.message == log.message
        assert log2.metadata == log.metadata
        assert log2.hash_value == log.hash_value


class TestEvidenceLogger:
    """Test cases for EvidenceLogger class"""
    
    @pytest.fixture
    def temp_log_dir(self):
        """Create temporary directory for test logs"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def evidence_logger(self, temp_log_dir):
        """Create EvidenceLogger instance for testing"""
        return EvidenceLogger(
            log_directory=temp_log_dir,
            encrypt_logs=False,  # Disable encryption for easier testing
            auto_backup=False
        )
    
    @pytest.fixture
    def encrypted_evidence_logger(self, temp_log_dir):
        """Create EvidenceLogger with encryption for testing"""
        return EvidenceLogger(
            log_directory=temp_log_dir,
            encrypt_logs=True,
            auto_backup=False
        )
    
    def test_evidence_logger_initialization(self, temp_log_dir):
        """Test evidence logger initialization"""
        logger = EvidenceLogger(
            log_directory=temp_log_dir,
            encrypt_logs=False
        )
        
        assert logger.log_directory == Path(temp_log_dir)
        assert logger.encrypt_logs is False
        assert logger.operations_log_file.exists()
        assert logger.evidence_log_file.exists()
        assert logger.integrity_log_file.exists()
        assert logger.audit_log_file.exists()
    
    def test_evidence_logger_encryption_initialization(self, temp_log_dir):
        """Test evidence logger initialization with encryption"""
        logger = EvidenceLogger(
            log_directory=temp_log_dir,
            encrypt_logs=True
        )
        
        assert logger.encrypt_logs is True
        assert hasattr(logger, 'cipher')
        assert hasattr(logger, 'encryption_key')
        
        # Check encryption key file exists
        key_file = Path(temp_log_dir) / ".encryption_key"
        assert key_file.exists()
    
    def test_log_operation_basic(self, evidence_logger):
        """Test basic operation logging"""
        operation_log = evidence_logger.log_operation(
            case_id='TEST_CASE_001',
            operation_type='DEVICE_DETECTION',
            message='Device detected successfully',
            device_serial='ABC123',
            user_id='investigator1',
            metadata={'device_type': 'Android'}
        )
        
        assert operation_log.case_id == 'TEST_CASE_001'
        assert operation_log.operation_type == 'DEVICE_DETECTION'
        assert operation_log.message == 'Device detected successfully'
        assert operation_log.device_serial == 'ABC123'
        assert operation_log.user_id == 'investigator1'
        assert 'device_type' in operation_log.metadata
        assert operation_log.hash_value is not None
        assert operation_log.verify_integrity() is True
    
    def test_log_operation_validation(self, evidence_logger):
        """Test operation logging validation"""
        # Test empty case_id
        with pytest.raises(EvidenceLoggingError) as exc_info:
            evidence_logger.log_operation(
                case_id='',
                operation_type='TEST_OP',
                message='Test message'
            )
        assert "Case ID cannot be empty" in str(exc_info.value)
        
        # Test empty operation_type
        with pytest.raises(EvidenceLoggingError) as exc_info:
            evidence_logger.log_operation(
                case_id='TEST_CASE_001',
                operation_type='',
                message='Test message'
            )
        assert "Operation type cannot be empty" in str(exc_info.value)
        
        # Test empty message
        with pytest.raises(EvidenceLoggingError) as exc_info:
            evidence_logger.log_operation(
                case_id='TEST_CASE_001',
                operation_type='TEST_OP',
                message=''
            )
        assert "Message cannot be empty" in str(exc_info.value)
    
    def test_log_operation_file_writing(self, evidence_logger):
        """Test that operations are written to log files"""
        evidence_logger.log_operation(
            case_id='TEST_CASE_001',
            operation_type='TEST_OP',
            message='Test message'
        )
        
        # Check operations log file
        assert evidence_logger.operations_log_file.exists()
        with open(evidence_logger.operations_log_file, 'r') as f:
            content = f.read()
            assert 'TEST_CASE_001' in content
            assert 'TEST_OP' in content
            assert 'Test message' in content
        
        # Check integrity log file
        assert evidence_logger.integrity_log_file.exists()
        with open(evidence_logger.integrity_log_file, 'r') as f:
            content = f.read()
            assert 'TEST_CASE_001' in content
            assert 'TEST_OP' in content
        
        # Check audit log file
        assert evidence_logger.audit_log_file.exists()
        with open(evidence_logger.audit_log_file, 'r') as f:
            content = f.read()
            assert 'TEST_CASE_001' in content
    
    def test_log_operation_encrypted(self, encrypted_evidence_logger):
        """Test operation logging with encryption"""
        operation_log = encrypted_evidence_logger.log_operation(
            case_id='TEST_CASE_001',
            operation_type='SENSITIVE_OP',
            message='Sensitive operation performed',
            metadata={'sensitive_data': 'classified'}
        )
        
        assert operation_log.verify_integrity() is True
        
        # Check that file content is encrypted (not readable as plain text)
        with open(encrypted_evidence_logger.operations_log_file, 'rb') as f:
            content = f.read()
            # Should not contain plain text
            assert b'TEST_CASE_001' not in content
            assert b'SENSITIVE_OP' not in content
    
    def test_log_evidence_record(self, evidence_logger):
        """Test logging evidence records"""
        # Create test device
        device = AndroidDevice(
            serial='ABC123',
            model='Test Model',
            brand='Test Brand',
            android_version='11.0'
        )
        
        # Create custody event
        custody_event = CustodyEvent(
            timestamp=datetime.now(),
            event_type='EVIDENCE_COLLECTION',
            user_id='investigator1',
            description='Evidence collected from device'
        )
        
        # Create evidence record
        evidence_record = EvidenceRecord(
            case_id='TEST_CASE_001',
            timestamp=datetime.now(),
            operation_type='evidence_collection',  # Use valid operation type
            device_serial='ABC123',
            attempt_number=1,
            result='Success',
            hash_verification='a' * 64,  # Valid SHA-256 hash format
            chain_of_custody=[custody_event],
            investigator_id='investigator1'
        )
        
        # Log the evidence record
        operation_log = evidence_logger.log_evidence_record(evidence_record)
        
        assert operation_log.case_id == 'TEST_CASE_001'
        assert operation_log.operation_type == 'evidence_collection'
        assert 'evidence_type' in operation_log.metadata
        assert 'chain_of_custody' in operation_log.metadata
        assert operation_log.verify_integrity() is True
    
    def test_get_operations_filtering(self, evidence_logger):
        """Test operation retrieval with filtering"""
        # Log multiple operations
        evidence_logger.log_operation(
            case_id='CASE_001',
            operation_type='DEVICE_DETECTION',
            message='Device 1 detected'
        )
        
        evidence_logger.log_operation(
            case_id='CASE_002',
            operation_type='DEVICE_DETECTION',
            message='Device 2 detected'
        )
        
        evidence_logger.log_operation(
            case_id='CASE_001',
            operation_type='ATTACK_EXECUTION',
            message='Attack executed'
        )
        
        # Test case_id filtering
        case1_ops = evidence_logger.get_operations(case_id='CASE_001')
        assert len(case1_ops) == 2
        assert all(op.case_id == 'CASE_001' for op in case1_ops)
        
        # Test operation_type filtering
        detection_ops = evidence_logger.get_operations(operation_type='DEVICE_DETECTION')
        assert len(detection_ops) == 2
        assert all(op.operation_type == 'DEVICE_DETECTION' for op in detection_ops)
        
        # Test combined filtering
        case1_detection = evidence_logger.get_operations(
            case_id='CASE_001',
            operation_type='DEVICE_DETECTION'
        )
        assert len(case1_detection) == 1
        assert case1_detection[0].case_id == 'CASE_001'
        assert case1_detection[0].operation_type == 'DEVICE_DETECTION'
    
    def test_get_operations_time_filtering(self, evidence_logger):
        """Test operation retrieval with time filtering"""
        start_time = datetime.now()
        
        # Log operation
        evidence_logger.log_operation(
            case_id='TEST_CASE_001',
            operation_type='TEST_OP',
            message='Test message'
        )
        
        end_time = datetime.now()
        
        # Test time range filtering
        ops_in_range = evidence_logger.get_operations(
            start_time=start_time,
            end_time=end_time
        )
        assert len(ops_in_range) >= 1
        
        # Test operations before start time
        future_time = datetime.now() + timedelta(hours=1)
        ops_before = evidence_logger.get_operations(start_time=future_time)
        assert len(ops_before) == 0
    
    def test_verify_integrity(self, evidence_logger):
        """Test integrity verification"""
        # Log some operations
        evidence_logger.log_operation(
            case_id='TEST_CASE_001',
            operation_type='TEST_OP_1',
            message='Test message 1'
        )
        
        evidence_logger.log_operation(
            case_id='TEST_CASE_001',
            operation_type='TEST_OP_2',
            message='Test message 2'
        )
        
        # Verify integrity
        verification_result = evidence_logger.verify_integrity(case_id='TEST_CASE_001')
        
        assert verification_result['case_id'] == 'TEST_CASE_001'
        assert verification_result['total_operations'] >= 2
        assert verification_result['verified_operations'] >= 2
        assert verification_result['failed_operations'] == 0
        assert verification_result['integrity_status'] == 'verified'
        assert len(verification_result['corrupted_entries']) == 0
    
    def test_verify_integrity_with_corruption(self, evidence_logger):
        """Test integrity verification with corrupted data"""
        # Log operation
        operation_log = evidence_logger.log_operation(
            case_id='TEST_CASE_001',
            operation_type='TEST_OP',
            message='Test message'
        )
        
        # Simulate corruption by modifying cached operation
        if evidence_logger._operation_cache:
            evidence_logger._operation_cache[0].hash_value = 'corrupted_hash'
        
        # Verify integrity
        verification_result = evidence_logger.verify_integrity(case_id='TEST_CASE_001')
        
        assert verification_result['failed_operations'] > 0
        assert verification_result['integrity_status'] in ['partial', 'failed']
        assert len(verification_result['corrupted_entries']) > 0
    
    def test_generate_audit_trail(self, evidence_logger):
        """Test audit trail generation"""
        # Log multiple operations
        evidence_logger.log_operation(
            case_id='TEST_CASE_001',
            operation_type='DEVICE_DETECTION',
            message='Device detected',
            device_serial='ABC123',
            user_id='investigator1'
        )
        
        evidence_logger.log_operation(
            case_id='TEST_CASE_001',
            operation_type='ATTACK_EXECUTION',
            message='Attack executed',
            device_serial='ABC123',
            user_id='investigator1'
        )
        
        evidence_logger.log_operation(
            case_id='TEST_CASE_001',
            operation_type='EVIDENCE_COLLECTION',
            message='Evidence collected',
            device_serial='DEF456',
            user_id='investigator2'
        )
        
        # Generate audit trail
        audit_trail = evidence_logger.generate_audit_trail('TEST_CASE_001')
        
        assert audit_trail['case_id'] == 'TEST_CASE_001'
        assert audit_trail['total_operations'] >= 3
        assert 'DEVICE_DETECTION' in audit_trail['operations_by_type']
        assert 'ATTACK_EXECUTION' in audit_trail['operations_by_type']
        assert 'EVIDENCE_COLLECTION' in audit_trail['operations_by_type']
        assert 'ABC123' in audit_trail['devices_involved']
        assert 'DEF456' in audit_trail['devices_involved']
        assert 'investigator1' in audit_trail['users_involved']
        assert 'investigator2' in audit_trail['users_involved']
        assert len(audit_trail['timeline']) >= 3
        assert 'integrity_verification' in audit_trail
    
    def test_export_case_logs(self, evidence_logger, temp_log_dir):
        """Test case log export"""
        # Log some operations
        evidence_logger.log_operation(
            case_id='TEST_CASE_001',
            operation_type='TEST_OP_1',
            message='Test message 1',
            metadata={'key1': 'value1'}
        )
        
        evidence_logger.log_operation(
            case_id='TEST_CASE_001',
            operation_type='TEST_OP_2',
            message='Test message 2',
            metadata={'key2': 'value2'}
        )
        
        # Export logs
        export_path = Path(temp_log_dir) / 'export' / 'case_export.json'
        success = evidence_logger.export_case_logs(
            case_id='TEST_CASE_001',
            export_path=str(export_path),
            include_metadata=True
        )
        
        assert success is True
        assert export_path.exists()
        
        # Verify export content
        with open(export_path, 'r') as f:
            export_data = json.load(f)
        
        assert export_data['export_info']['case_id'] == 'TEST_CASE_001'
        assert export_data['export_info']['include_metadata'] is True
        assert 'audit_trail' in export_data
        assert 'operations' in export_data
        assert len(export_data['operations']) >= 2
        
        # Check that metadata is included
        for operation in export_data['operations']:
            if operation['operation_type'] in ['TEST_OP_1', 'TEST_OP_2']:
                assert 'metadata' in operation
    
    def test_export_case_logs_without_metadata(self, evidence_logger, temp_log_dir):
        """Test case log export without metadata"""
        # Log operation with metadata
        evidence_logger.log_operation(
            case_id='TEST_CASE_001',
            operation_type='TEST_OP',
            message='Test message',
            metadata={'sensitive_key': 'sensitive_value'}
        )
        
        # Export without metadata
        export_path = Path(temp_log_dir) / 'export_no_meta.json'
        success = evidence_logger.export_case_logs(
            case_id='TEST_CASE_001',
            export_path=str(export_path),
            include_metadata=False
        )
        
        assert success is True
        
        # Verify metadata is excluded
        with open(export_path, 'r') as f:
            export_data = json.load(f)
        
        for operation in export_data['operations']:
            if operation['operation_type'] == 'TEST_OP':
                assert 'metadata' not in operation
    
    def test_operation_cache_management(self, evidence_logger):
        """Test operation cache size management"""
        # Set small cache size for testing
        evidence_logger._cache_max_size = 3
        
        # Log more operations than cache size
        for i in range(5):
            evidence_logger.log_operation(
                case_id='TEST_CASE_001',
                operation_type=f'TEST_OP_{i}',
                message=f'Test message {i}'
            )
        
        # Cache should be limited to max size
        assert len(evidence_logger._operation_cache) == 3
        
        # Should contain the most recent operations
        cached_ops = [op.operation_type for op in evidence_logger._operation_cache]
        assert 'TEST_OP_2' in cached_ops
        assert 'TEST_OP_3' in cached_ops
        assert 'TEST_OP_4' in cached_ops
        assert 'TEST_OP_0' not in cached_ops
        assert 'TEST_OP_1' not in cached_ops
    
    def test_concurrent_logging(self, evidence_logger):
        """Test thread-safe concurrent logging"""
        import threading
        import time
        
        results = []
        errors = []
        
        def log_operations(thread_id):
            try:
                for i in range(10):
                    operation_log = evidence_logger.log_operation(
                        case_id=f'CASE_{thread_id}',
                        operation_type='CONCURRENT_TEST',
                        message=f'Thread {thread_id} operation {i}',
                        user_id=f'user_{thread_id}'
                    )
                    results.append(operation_log)
                    time.sleep(0.001)  # Small delay to increase chance of race conditions
            except Exception as e:
                errors.append(e)
        
        # Start multiple threads
        threads = []
        for i in range(3):
            thread = threading.Thread(target=log_operations, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Check results
        assert len(errors) == 0, f"Concurrent logging errors: {errors}"
        assert len(results) == 30  # 3 threads * 10 operations each
        
        # Verify all operations have valid hashes
        for operation_log in results:
            assert operation_log.verify_integrity() is True
    
    def test_error_handling_file_permissions(self, temp_log_dir):
        """Test error handling for file permission issues"""
        # Create logger
        logger = EvidenceLogger(log_directory=temp_log_dir, encrypt_logs=False)
        
        # Make operations log file read-only to simulate permission error
        logger.operations_log_file.chmod(0o444)
        
        try:
            # This should raise an EvidenceLoggingError
            with pytest.raises(EvidenceLoggingError) as exc_info:
                logger.log_operation(
                    case_id='TEST_CASE_001',
                    operation_type='TEST_OP',
                    message='Test message'
                )
            
            assert "Failed to log operation" in str(exc_info.value)
        
        finally:
            # Restore permissions for cleanup
            logger.operations_log_file.chmod(0o644)
    
    def test_cleanup_old_logs(self, evidence_logger):
        """Test log cleanup functionality"""
        # Log some operations
        evidence_logger.log_operation(
            case_id='TEST_CASE_001',
            operation_type='OLD_OP',
            message='Old operation'
        )
        
        # Test cleanup (this is mostly a placeholder test since actual cleanup
        # would require more complex implementation)
        cleanup_results = evidence_logger.cleanup_old_logs(days_to_keep=30)
        
        assert 'cutoff_date' in cleanup_results
        assert 'operations_before_cleanup' in cleanup_results
        assert 'operations_after_cleanup' in cleanup_results
        assert 'operations_archived' in cleanup_results


if __name__ == '__main__':
    pytest.main([__file__])