"""
Evidence Integrity Validation Tests

This module provides comprehensive tests for evidence integrity validation
throughout the forensic workflow, ensuring chain of custody and data integrity.
"""

import pytest
import tempfile
import shutil
import hashlib
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from forensics_toolkit.services.evidence_logger import EvidenceLogger
from forensics_toolkit.services.chain_of_custody import ChainOfCustody
from forensics_toolkit.services.data_encryption import DataEncryption
from forensics_toolkit.models.attack import EvidenceRecord
from forensics_toolkit.interfaces import AttackResult, LockType


@dataclass
class IntegrityTestCase:
    """Test case for integrity validation"""
    name: str
    description: str
    test_data: Dict[str, Any]
    expected_hash: str
    should_pass: bool = True
    tamper_function: Optional[callable] = None


class EvidenceIntegrityValidator:
    """Validator for evidence integrity testing"""
    
    def __init__(self, temp_dir: str):
        self.temp_dir = Path(temp_dir)
        self.evidence_dir = self.temp_dir / "evidence"
        self.logs_dir = self.temp_dir / "logs"
        self.reports_dir = self.temp_dir / "reports"
        
        # Create directories
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        self.integrity_log = []
        
    def create_evidence_file(self, filename: str, data: Dict[str, Any]) -> Path:
        """Create evidence file with data"""
        file_path = self.evidence_dir / filename
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return file_path
    
    def calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file"""
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    
    def create_hash_manifest(self, files: List[Path]) -> Path:
        """Create hash manifest for multiple files"""
        manifest = {}
        for file_path in files:
            relative_path = file_path.relative_to(self.temp_dir)
            manifest[str(relative_path)] = self.calculate_file_hash(file_path)
        
        manifest_path = self.evidence_dir / "integrity_manifest.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        return manifest_path
    
    def verify_file_integrity(self, file_path: Path, expected_hash: str) -> bool:
        """Verify file integrity against expected hash"""
        if not file_path.exists():
            self.integrity_log.append(f"File not found: {file_path}")
            return False
        
        actual_hash = self.calculate_file_hash(file_path)
        if actual_hash != expected_hash:
            self.integrity_log.append(
                f"Hash mismatch for {file_path}: expected {expected_hash}, got {actual_hash}"
            )
            return False
        
        return True
    
    def verify_manifest_integrity(self, manifest_path: Path) -> Dict[str, bool]:
        """Verify integrity of all files in manifest"""
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        results = {}
        for relative_path, expected_hash in manifest.items():
            file_path = self.temp_dir / relative_path
            results[relative_path] = self.verify_file_integrity(file_path, expected_hash)
        
        return results
    
    def tamper_with_file(self, file_path: Path, tamper_function: callable):
        """Apply tampering function to file"""
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        tampered_data = tamper_function(data)
        
        with open(file_path, 'w') as f:
            json.dump(tampered_data, f, indent=2, default=str)
    
    def create_chain_of_custody_record(self, case_id: str, events: List[Dict[str, Any]]) -> Path:
        """Create chain of custody record"""
        custody_record = {
            "case_id": case_id,
            "created_at": datetime.now().isoformat(),
            "events": events,
            "integrity_hash": None
        }
        
        # Calculate integrity hash
        temp_record = custody_record.copy()
        temp_record.pop("integrity_hash")
        record_json = json.dumps(temp_record, sort_keys=True, default=str)
        custody_record["integrity_hash"] = hashlib.sha256(record_json.encode()).hexdigest()
        
        custody_path = self.logs_dir / f"custody_{case_id}.json"
        with open(custody_path, 'w') as f:
            json.dump(custody_record, f, indent=2, default=str)
        
        return custody_path
    
    def verify_custody_chain_integrity(self, custody_path: Path) -> bool:
        """Verify chain of custody integrity"""
        with open(custody_path, 'r') as f:
            custody_record = json.load(f)
        
        stored_hash = custody_record.pop("integrity_hash")
        record_json = json.dumps(custody_record, sort_keys=True, default=str)
        calculated_hash = hashlib.sha256(record_json.encode()).hexdigest()
        
        return stored_hash == calculated_hash


class TestEvidenceIntegrityValidation:
    """Test evidence integrity validation"""
    
    @pytest.fixture
    def integrity_validator(self):
        """Create integrity validator"""
        temp_dir = tempfile.mkdtemp()
        validator = EvidenceIntegrityValidator(temp_dir)
        yield validator
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def sample_evidence_data(self):
        """Create sample evidence data"""
        return {
            "case_id": "INTEGRITY_TEST_001",
            "timestamp": datetime.now().isoformat(),
            "device_serial": "TEST_DEVICE_001",
            "operation_type": "brute_force_attack",
            "attack_strategy": {
                "type": "brute_force",
                "target_lock_type": "pin",
                "max_attempts": 10000,
                "wordlists": ["common_pins.txt"]
            },
            "result": {
                "success": True,
                "attempts": 42,
                "duration_seconds": 120.5,
                "successful_value": "1234",
                "unlock_timestamp": datetime.now().isoformat()
            },
            "evidence_metadata": {
                "investigator": "test_investigator",
                "case_officer": "test_officer",
                "location": "forensic_lab_001",
                "equipment_used": ["adb", "custom_brute_force_tool"]
            }
        }
    
    def test_basic_file_integrity_validation(self, integrity_validator, sample_evidence_data):
        """Test basic file integrity validation"""
        # Create evidence file
        evidence_file = integrity_validator.create_evidence_file(
            "test_evidence.json", sample_evidence_data
        )
        
        # Calculate expected hash
        expected_hash = integrity_validator.calculate_file_hash(evidence_file)
        
        # Verify integrity
        assert integrity_validator.verify_file_integrity(evidence_file, expected_hash)
        
        # Tamper with file
        def tamper_result(data):
            data["result"]["successful_value"] = "modified"
            return data
        
        integrity_validator.tamper_with_file(evidence_file, tamper_result)
        
        # Verify tampering is detected
        assert not integrity_validator.verify_file_integrity(evidence_file, expected_hash)
        assert len(integrity_validator.integrity_log) > 0
    
    def test_manifest_based_integrity_validation(self, integrity_validator, sample_evidence_data):
        """Test manifest-based integrity validation"""
        # Create multiple evidence files
        evidence_files = []
        for i in range(5):
            data = sample_evidence_data.copy()
            data["operation_sequence"] = i
            data["timestamp"] = (datetime.now() + timedelta(minutes=i)).isoformat()
            
            file_path = integrity_validator.create_evidence_file(
                f"evidence_{i:03d}.json", data
            )
            evidence_files.append(file_path)
        
        # Create manifest
        manifest_path = integrity_validator.create_hash_manifest(evidence_files)
        
        # Verify all files are intact
        results = integrity_validator.verify_manifest_integrity(manifest_path)
        assert all(results.values())
        
        # Tamper with one file
        def tamper_timestamp(data):
            data["timestamp"] = datetime.now().isoformat()
            return data
        
        integrity_validator.tamper_with_file(evidence_files[2], tamper_timestamp)
        
        # Verify tampering is detected
        results = integrity_validator.verify_manifest_integrity(manifest_path)
        assert not results[str(evidence_files[2].relative_to(integrity_validator.temp_dir))]
        assert sum(results.values()) == 4  # 4 out of 5 files should still be valid
    
    def test_chain_of_custody_integrity(self, integrity_validator):
        """Test chain of custody integrity validation"""
        case_id = "CUSTODY_TEST_001"
        
        # Create custody events
        custody_events = [
            {
                "timestamp": datetime.now().isoformat(),
                "event_type": "evidence_collected",
                "user": "investigator_001",
                "action": "Device seized from suspect",
                "location": "crime_scene_001",
                "witness": "officer_002",
                "evidence_hash": "abc123def456"
            },
            {
                "timestamp": (datetime.now() + timedelta(minutes=30)).isoformat(),
                "event_type": "evidence_transferred",
                "user": "investigator_001",
                "action": "Transferred to forensic lab",
                "location": "forensic_lab_001",
                "witness": "lab_technician_001",
                "evidence_hash": "abc123def456"
            },
            {
                "timestamp": (datetime.now() + timedelta(hours=1)).isoformat(),
                "event_type": "analysis_started",
                "user": "forensic_analyst_001",
                "action": "Started forensic analysis",
                "location": "forensic_lab_001",
                "tools_used": ["adb", "custom_tools"],
                "evidence_hash": "abc123def456"
            }
        ]
        
        # Create custody record
        custody_path = integrity_validator.create_chain_of_custody_record(
            case_id, custody_events
        )
        
        # Verify integrity
        assert integrity_validator.verify_custody_chain_integrity(custody_path)
        
        # Tamper with custody record
        with open(custody_path, 'r') as f:
            custody_data = json.load(f)
        
        # Modify an event
        custody_data["events"][1]["action"] = "Modified action"
        
        with open(custody_path, 'w') as f:
            json.dump(custody_data, f, indent=2, default=str)
        
        # Verify tampering is detected
        assert not integrity_validator.verify_custody_chain_integrity(custody_path)
    
    def test_evidence_logger_integrity_integration(self, integrity_validator):
        """Test integration with EvidenceLogger for integrity validation"""
        with patch('forensics_toolkit.services.evidence_logger.EvidenceLogger') as mock_logger:
            logger = mock_logger.return_value
            
            # Mock evidence logging with integrity checks
            def mock_log_operation(record):
                # Simulate creating evidence file with hash
                evidence_data = {
                    "case_id": record.case_id,
                    "timestamp": record.timestamp.isoformat(),
                    "operation_type": record.operation_type,
                    "device_serial": record.device_serial,
                    "result": record.result
                }
                
                file_path = integrity_validator.create_evidence_file(
                    f"evidence_{record.case_id}_{int(record.timestamp.timestamp())}.json",
                    evidence_data
                )
                
                # Calculate and store hash
                file_hash = integrity_validator.calculate_file_hash(file_path)
                return file_hash
            
            logger.log_operation.side_effect = mock_log_operation
            
            # Create evidence record
            evidence_record = EvidenceRecord(
                case_id="LOGGER_TEST_001",
                timestamp=datetime.now(),
                operation_type="brute_force_attack",
                device_serial="TEST_DEVICE_001",
                attempt_number=42,
                result="success",
                hash_verification="",
                chain_of_custody=[]
            )
            
            # Log operation
            file_hash = logger.log_operation(evidence_record)
            
            # Verify hash was generated
            assert file_hash is not None
            assert len(file_hash) == 64  # SHA-256 hash length
    
    def test_encrypted_evidence_integrity(self, integrity_validator):
        """Test integrity validation of encrypted evidence"""
        with patch('forensics_toolkit.services.data_encryption.DataEncryption') as mock_encryption:
            encryption_service = mock_encryption.return_value
            
            # Mock encryption with integrity verification
            original_data = json.dumps({
                "sensitive_data": "recovered_password_123",
                "device_serial": "ENCRYPTED_TEST_001",
                "timestamp": datetime.now().isoformat()
            })
            
            # Simulate encryption
            encrypted_data = b"encrypted_mock_data_with_integrity_check"
            integrity_tag = "integrity_tag_abc123"
            
            encryption_service.encrypt_with_integrity.return_value = {
                "encrypted_data": encrypted_data,
                "integrity_tag": integrity_tag,
                "encryption_timestamp": datetime.now().isoformat()
            }
            
            encryption_service.verify_encrypted_integrity.return_value = True
            encryption_service.decrypt_with_verification.return_value = original_data.encode()
            
            # Test encryption with integrity
            encrypted_result = encryption_service.encrypt_with_integrity(original_data.encode())
            
            # Verify integrity of encrypted data
            integrity_valid = encryption_service.verify_encrypted_integrity(
                encrypted_result["encrypted_data"],
                encrypted_result["integrity_tag"]
            )
            
            assert integrity_valid is True
            
            # Test decryption with verification
            decrypted_data = encryption_service.decrypt_with_verification(
                encrypted_result["encrypted_data"],
                encrypted_result["integrity_tag"]
            )
            
            assert decrypted_data.decode() == original_data
    
    def test_concurrent_evidence_integrity(self, integrity_validator):
        """Test integrity validation under concurrent operations"""
        import threading
        import time
        
        results = []
        errors = []
        
        def create_and_verify_evidence(thread_id):
            try:
                # Create evidence data
                evidence_data = {
                    "thread_id": thread_id,
                    "timestamp": datetime.now().isoformat(),
                    "operation": f"concurrent_test_{thread_id}",
                    "data": f"test_data_{thread_id}"
                }
                
                # Create file
                file_path = integrity_validator.create_evidence_file(
                    f"concurrent_{thread_id}.json", evidence_data
                )
                
                # Calculate hash
                file_hash = integrity_validator.calculate_file_hash(file_path)
                
                # Small delay to simulate processing
                time.sleep(0.1)
                
                # Verify integrity
                integrity_valid = integrity_validator.verify_file_integrity(file_path, file_hash)
                
                results.append({
                    "thread_id": thread_id,
                    "file_path": str(file_path),
                    "hash": file_hash,
                    "integrity_valid": integrity_valid
                })
                
            except Exception as e:
                errors.append(f"Thread {thread_id}: {str(e)}")
        
        # Create multiple threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=create_and_verify_evidence, args=(i,))
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify results
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 10
        assert all(r["integrity_valid"] for r in results)
    
    def test_integrity_validation_performance(self, integrity_validator):
        """Test performance of integrity validation operations"""
        import time
        
        # Create large evidence dataset
        large_dataset = []
        for i in range(100):
            evidence_data = {
                "sequence": i,
                "timestamp": (datetime.now() + timedelta(seconds=i)).isoformat(),
                "operation": f"performance_test_{i}",
                "data": "x" * 1000,  # 1KB of data per record
                "metadata": {
                    "device_serial": f"PERF_DEVICE_{i:03d}",
                    "investigator": f"investigator_{i % 5}",
                    "location": f"lab_{i % 3}"
                }
            }
            large_dataset.append(evidence_data)
        
        # Test file creation performance
        start_time = time.time()
        evidence_files = []
        for i, data in enumerate(large_dataset):
            file_path = integrity_validator.create_evidence_file(
                f"perf_evidence_{i:03d}.json", data
            )
            evidence_files.append(file_path)
        
        creation_time = time.time() - start_time
        
        # Test manifest creation performance
        start_time = time.time()
        manifest_path = integrity_validator.create_hash_manifest(evidence_files)
        manifest_time = time.time() - start_time
        
        # Test integrity verification performance
        start_time = time.time()
        verification_results = integrity_validator.verify_manifest_integrity(manifest_path)
        verification_time = time.time() - start_time
        
        # Performance assertions
        assert creation_time < 10.0  # Should create 100 files in under 10 seconds
        assert manifest_time < 5.0   # Should create manifest in under 5 seconds
        assert verification_time < 5.0  # Should verify all files in under 5 seconds
        assert all(verification_results.values())  # All files should be valid
        
        # Log performance metrics
        print(f"Performance metrics:")
        print(f"  File creation: {creation_time:.2f}s for {len(large_dataset)} files")
        print(f"  Manifest creation: {manifest_time:.2f}s")
        print(f"  Integrity verification: {verification_time:.2f}s")
    
    def test_integrity_validation_edge_cases(self, integrity_validator):
        """Test edge cases in integrity validation"""
        # Test empty file
        empty_file = integrity_validator.evidence_dir / "empty.json"
        empty_file.touch()
        empty_hash = integrity_validator.calculate_file_hash(empty_file)
        assert integrity_validator.verify_file_integrity(empty_file, empty_hash)
        
        # Test non-existent file
        non_existent = integrity_validator.evidence_dir / "non_existent.json"
        assert not integrity_validator.verify_file_integrity(non_existent, "dummy_hash")
        
        # Test file with special characters
        special_data = {
            "unicode_test": "测试数据",
            "special_chars": "!@#$%^&*()_+-=[]{}|;':\",./<>?",
            "newlines": "line1\nline2\nline3",
            "tabs": "col1\tcol2\tcol3"
        }
        
        special_file = integrity_validator.create_evidence_file(
            "special_chars.json", special_data
        )
        special_hash = integrity_validator.calculate_file_hash(special_file)
        assert integrity_validator.verify_file_integrity(special_file, special_hash)
        
        # Test very large file (simulated)
        large_data = {
            "large_field": "x" * 10000,  # 10KB field
            "timestamp": datetime.now().isoformat()
        }
        
        large_file = integrity_validator.create_evidence_file(
            "large_file.json", large_data
        )
        large_hash = integrity_validator.calculate_file_hash(large_file)
        assert integrity_validator.verify_file_integrity(large_file, large_hash)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])