"""
Unit tests for DataEncryption module

Tests the DataEncryption class for recovered data protection, secure key management,
encrypted storage for sensitive evidence, and secure data disposal protocols.
"""

import os
import json
import tempfile
import shutil
import pytest
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from forensics_toolkit.services.data_encryption import (
    DataEncryption, 
    DataEncryptionError, 
    EncryptionKey, 
    EncryptedData
)


class TestEncryptionKey:
    """Test cases for EncryptionKey dataclass"""
    
    def test_encryption_key_creation(self):
        """Test creating an encryption key with all fields"""
        created_at = datetime.now()
        expires_at = created_at + timedelta(days=90)
        
        key = EncryptionKey(
            key_id="test_key_001",
            key_type="symmetric",
            algorithm="AES-256",
            created_at=created_at,
            expires_at=expires_at,
            case_id="CASE_001",
            purpose="evidence_encryption"
        )
        
        assert key.key_id == "test_key_001"
        assert key.key_type == "symmetric"
        assert key.algorithm == "AES-256"
        assert key.created_at == created_at
        assert key.expires_at == expires_at
        assert key.case_id == "CASE_001"
        assert key.purpose == "evidence_encryption"
        assert key.is_active is True
        assert key.key_hash is not None
        assert len(key.key_hash) == 64  # SHA-256 hash length
    
    def test_encryption_key_hash_calculation(self):
        """Test that key hash is calculated correctly"""
        key1 = EncryptionKey(
            key_id="test_key_001",
            key_type="symmetric",
            algorithm="AES-256",
            created_at=datetime(2024, 1, 1, 12, 0, 0),
            case_id="CASE_001"
        )
        
        key2 = EncryptionKey(
            key_id="test_key_001",
            key_type="symmetric",
            algorithm="AES-256",
            created_at=datetime(2024, 1, 1, 12, 0, 0),
            case_id="CASE_001"
        )
        
        # Same parameters should produce same hash
        assert key1.key_hash == key2.key_hash
        
        # Different parameters should produce different hash
        key3 = EncryptionKey(
            key_id="test_key_002",
            key_type="symmetric",
            algorithm="AES-256",
            created_at=datetime(2024, 1, 1, 12, 0, 0),
            case_id="CASE_001"
        )
        
        assert key1.key_hash != key3.key_hash
    
    def test_encryption_key_expiration(self):
        """Test key expiration logic"""
        # Non-expiring key
        key1 = EncryptionKey(
            key_id="test_key_001",
            key_type="symmetric",
            algorithm="AES-256",
            created_at=datetime.now(),
            expires_at=None
        )
        assert not key1.is_expired()
        
        # Future expiration
        key2 = EncryptionKey(
            key_id="test_key_002",
            key_type="symmetric",
            algorithm="AES-256",
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(days=30)
        )
        assert not key2.is_expired()
        
        # Past expiration
        key3 = EncryptionKey(
            key_id="test_key_003",
            key_type="symmetric",
            algorithm="AES-256",
            created_at=datetime.now() - timedelta(days=100),
            expires_at=datetime.now() - timedelta(days=10)
        )
        assert key3.is_expired()
    
    def test_encryption_key_serialization(self):
        """Test key serialization to dictionary"""
        created_at = datetime(2024, 1, 1, 12, 0, 0)
        expires_at = created_at + timedelta(days=90)
        
        key = EncryptionKey(
            key_id="test_key_001",
            key_type="symmetric",
            algorithm="AES-256",
            created_at=created_at,
            expires_at=expires_at,
            case_id="CASE_001"
        )
        
        key_dict = key.to_dict()
        
        assert key_dict['key_id'] == "test_key_001"
        assert key_dict['key_type'] == "symmetric"
        assert key_dict['algorithm'] == "AES-256"
        assert key_dict['created_at'] == created_at.isoformat()
        assert key_dict['expires_at'] == expires_at.isoformat()
        assert key_dict['case_id'] == "CASE_001"
        assert key_dict['is_active'] is True
        assert 'key_hash' in key_dict


class TestEncryptedData:
    """Test cases for EncryptedData dataclass"""
    
    def test_encrypted_data_creation(self):
        """Test creating encrypted data container"""
        encrypted_content = b"encrypted_test_data"
        timestamp = datetime.now()
        
        data = EncryptedData(
            data_id="data_001",
            encrypted_content=encrypted_content,
            key_id="key_001",
            algorithm="AES-256",
            iv=b"test_iv_16bytes_",
            salt=b"test_salt_32bytes_long_enough__",
            timestamp=timestamp,
            case_id="CASE_001",
            original_filename="test.txt",
            original_size=100
        )
        
        assert data.data_id == "data_001"
        assert data.encrypted_content == encrypted_content
        assert data.key_id == "key_001"
        assert data.algorithm == "AES-256"
        assert data.iv == b"test_iv_16bytes_"
        assert data.salt == b"test_salt_32bytes_long_enough__"
        assert data.timestamp == timestamp
        assert data.case_id == "CASE_001"
        assert data.original_filename == "test.txt"
        assert data.original_size == 100
        assert data.content_hash is not None
    
    def test_encrypted_data_integrity_verification(self):
        """Test integrity verification of encrypted data"""
        encrypted_content = b"encrypted_test_data"
        
        data = EncryptedData(
            data_id="data_001",
            encrypted_content=encrypted_content,
            key_id="key_001",
            algorithm="AES-256"
        )
        
        # Should verify correctly initially
        assert data.verify_integrity()
        
        # Modify content and verify it fails
        data.encrypted_content = b"modified_content"
        assert not data.verify_integrity()
    
    def test_encrypted_data_serialization(self):
        """Test encrypted data serialization"""
        encrypted_content = b"encrypted_test_data"
        iv = b"test_iv_16bytes_"
        salt = b"test_salt_32bytes_long_enough__"
        timestamp = datetime(2024, 1, 1, 12, 0, 0)
        
        data = EncryptedData(
            data_id="data_001",
            encrypted_content=encrypted_content,
            key_id="key_001",
            algorithm="AES-256",
            iv=iv,
            salt=salt,
            timestamp=timestamp,
            case_id="CASE_001",
            original_filename="test.txt",
            original_size=100
        )
        
        data_dict = data.to_dict()
        
        assert data_dict['data_id'] == "data_001"
        assert data_dict['encrypted_content'] == encrypted_content.hex()
        assert data_dict['key_id'] == "key_001"
        assert data_dict['algorithm'] == "AES-256"
        assert data_dict['iv'] == iv.hex()
        assert data_dict['salt'] == salt.hex()
        assert data_dict['timestamp'] == timestamp.isoformat()
        assert data_dict['case_id'] == "CASE_001"
        assert data_dict['original_filename'] == "test.txt"
        assert data_dict['original_size'] == 100
        assert 'content_hash' in data_dict


class TestDataEncryption:
    """Test cases for DataEncryption class"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def encryption_service(self, temp_dir):
        """Create DataEncryption service for testing"""
        key_storage = os.path.join(temp_dir, "keys")
        encrypted_storage = os.path.join(temp_dir, "encrypted")
        
        return DataEncryption(
            key_storage_path=key_storage,
            encrypted_storage_path=encrypted_storage,
            key_rotation_days=30
        )
    
    def test_initialization(self, encryption_service, temp_dir):
        """Test DataEncryption initialization"""
        assert encryption_service.key_storage_path.exists()
        assert encryption_service.encrypted_storage_path.exists()
        assert encryption_service.key_rotation_days == 30
        
        # Check that master key was created
        master_key_file = encryption_service.key_storage_path / ".master_key"
        assert master_key_file.exists()
        
        # Check secure permissions (skip on Windows)
        import platform
        if platform.system() != 'Windows':
            assert oct(encryption_service.key_storage_path.stat().st_mode)[-3:] == '700'
            assert oct(encryption_service.encrypted_storage_path.stat().st_mode)[-3:] == '700'
    
    def test_generate_symmetric_key(self, encryption_service):
        """Test generating symmetric encryption keys"""
        case_id = "TEST_CASE_001"
        
        # Test AES-256 key generation
        key_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="symmetric",
            algorithm="AES-256",
            expires_in_days=90
        )
        
        assert key_id is not None
        assert case_id in key_id
        assert "AES-256" in key_id
        
        # Verify key metadata
        key_info = encryption_service.get_key_info(key_id)
        assert key_info is not None
        assert key_info.case_id == case_id
        assert key_info.key_type == "symmetric"
        assert key_info.algorithm == "AES-256"
        assert key_info.is_active
        assert not key_info.is_expired()
        
        # Test Fernet key generation
        fernet_key_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="symmetric",
            algorithm="Fernet"
        )
        
        assert fernet_key_id is not None
        fernet_key_info = encryption_service.get_key_info(fernet_key_id)
        assert fernet_key_info.algorithm == "Fernet"
    
    def test_generate_asymmetric_key(self, encryption_service):
        """Test generating asymmetric encryption keys"""
        case_id = "TEST_CASE_002"
        
        key_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="asymmetric",
            algorithm="RSA-2048"
        )
        
        assert key_id is not None
        
        # Verify key metadata
        key_info = encryption_service.get_key_info(key_id)
        assert key_info.key_type == "asymmetric"
        assert key_info.algorithm == "RSA-2048"
        
        # Verify both public and private keys exist
        private_key_file = encryption_service.key_storage_path / f"{key_id}_private.key"
        public_key_file = encryption_service.key_storage_path / f"{key_id}_public.key"
        assert private_key_file.exists()
        assert public_key_file.exists()
    
    def test_generate_key_validation(self, encryption_service):
        """Test key generation validation"""
        # Test empty case ID
        with pytest.raises(DataEncryptionError) as exc_info:
            encryption_service.generate_encryption_key(
                case_id="",
                key_type="symmetric",
                algorithm="AES-256"
            )
        assert "Case ID cannot be empty" in str(exc_info.value)
        
        # Test unsupported algorithm
        with pytest.raises(DataEncryptionError) as exc_info:
            encryption_service.generate_encryption_key(
                case_id="TEST_CASE",
                key_type="symmetric",
                algorithm="UNSUPPORTED"
            )
        assert "Unsupported symmetric algorithm" in str(exc_info.value)
        
        # Test unsupported key type
        with pytest.raises(DataEncryptionError) as exc_info:
            encryption_service.generate_encryption_key(
                case_id="TEST_CASE",
                key_type="unsupported",
                algorithm="AES-256"
            )
        assert "Unsupported key type" in str(exc_info.value)
    
    def test_encrypt_decrypt_fernet(self, encryption_service):
        """Test encryption and decryption with Fernet"""
        case_id = "TEST_CASE_003"
        test_data = "This is sensitive forensic evidence data"
        
        # Generate key
        key_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="symmetric",
            algorithm="Fernet"
        )
        
        # Encrypt data
        encrypted_data = encryption_service.encrypt_data(
            data=test_data,
            key_id=key_id,
            case_id=case_id,
            original_filename="evidence.txt"
        )
        
        assert encrypted_data.data_id is not None
        assert encrypted_data.key_id == key_id
        assert encrypted_data.algorithm == "Fernet"
        assert encrypted_data.case_id == case_id
        assert encrypted_data.original_filename == "evidence.txt"
        assert encrypted_data.original_size == len(test_data.encode('utf-8'))
        assert encrypted_data.verify_integrity()
        
        # Decrypt data
        decrypted_data = encryption_service.decrypt_data(encrypted_data)
        assert decrypted_data.decode('utf-8') == test_data
    
    def test_encrypt_decrypt_aes256(self, encryption_service):
        """Test encryption and decryption with AES-256"""
        case_id = "TEST_CASE_004"
        test_data = b"Binary forensic evidence data"
        
        # Generate key
        key_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="symmetric",
            algorithm="AES-256"
        )
        
        # Encrypt data
        encrypted_data = encryption_service.encrypt_data(
            data=test_data,
            key_id=key_id,
            case_id=case_id
        )
        
        assert encrypted_data.algorithm == "AES-256"
        assert encrypted_data.iv is not None
        assert encrypted_data.salt is not None
        assert len(encrypted_data.iv) == 16  # AES block size
        assert len(encrypted_data.salt) == 32  # Salt size
        
        # Decrypt data
        decrypted_data = encryption_service.decrypt_data(encrypted_data)
        assert decrypted_data == test_data
    
    def test_encrypt_decrypt_rsa2048(self, encryption_service):
        """Test encryption and decryption with RSA-2048 (hybrid)"""
        case_id = "TEST_CASE_005"
        test_data = "RSA hybrid encryption test data"
        
        # Generate key
        key_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="asymmetric",
            algorithm="RSA-2048"
        )
        
        # Encrypt data
        encrypted_data = encryption_service.encrypt_data(
            data=test_data,
            key_id=key_id,
            case_id=case_id
        )
        
        assert encrypted_data.algorithm == "RSA-2048"
        assert encrypted_data.salt is None  # RSA doesn't use salt
        
        # Decrypt data
        decrypted_data = encryption_service.decrypt_data(encrypted_data)
        assert decrypted_data.decode('utf-8') == test_data
    
    def test_encryption_validation(self, encryption_service):
        """Test encryption validation"""
        # Test invalid key ID
        with pytest.raises(DataEncryptionError) as exc_info:
            encryption_service.encrypt_data(
                data="test",
                key_id="nonexistent_key"
            )
        assert "Invalid or unknown key ID" in str(exc_info.value)
        
        # Test expired key
        case_id = "TEST_CASE_006"
        key_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="symmetric",
            algorithm="Fernet",
            expires_in_days=1
        )
        
        # Manually expire the key
        key_info = encryption_service.get_key_info(key_id)
        key_info.expires_at = datetime.now() - timedelta(days=1)
        
        with pytest.raises(DataEncryptionError) as exc_info:
            encryption_service.encrypt_data(
                data="test",
                key_id=key_id
            )
        assert "has expired" in str(exc_info.value)
        
        # Test inactive key
        key_info.is_active = False
        key_info.expires_at = datetime.now() + timedelta(days=30)  # Reset expiration
        
        with pytest.raises(DataEncryptionError) as exc_info:
            encryption_service.encrypt_data(
                data="test",
                key_id=key_id
            )
        assert "is not active" in str(exc_info.value)
    
    def test_store_load_encrypted_data(self, encryption_service):
        """Test storing and loading encrypted data"""
        case_id = "TEST_CASE_007"
        test_data = "Data to be stored and loaded"
        
        # Generate key and encrypt data
        key_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="symmetric",
            algorithm="Fernet"
        )
        
        encrypted_data = encryption_service.encrypt_data(
            data=test_data,
            key_id=key_id,
            case_id=case_id,
            original_filename="stored_evidence.txt"
        )
        
        # Store encrypted data
        storage_path = encryption_service.store_encrypted_data(encrypted_data)
        assert storage_path is not None
        assert Path(storage_path).exists()
        
        # Load encrypted data
        loaded_data = encryption_service.load_encrypted_data(
            data_id=encrypted_data.data_id,
            case_id=case_id
        )
        
        assert loaded_data.data_id == encrypted_data.data_id
        assert loaded_data.key_id == encrypted_data.key_id
        assert loaded_data.algorithm == encrypted_data.algorithm
        assert loaded_data.case_id == encrypted_data.case_id
        assert loaded_data.original_filename == encrypted_data.original_filename
        assert loaded_data.verify_integrity()
        
        # Decrypt loaded data
        decrypted_data = encryption_service.decrypt_data(loaded_data)
        assert decrypted_data.decode('utf-8') == test_data
    
    def test_secure_delete_data(self, encryption_service):
        """Test secure deletion of encrypted data"""
        case_id = "TEST_CASE_008"
        test_data = "Data to be securely deleted"
        
        # Generate key, encrypt, and store data
        key_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="symmetric",
            algorithm="Fernet"
        )
        
        encrypted_data = encryption_service.encrypt_data(
            data=test_data,
            key_id=key_id,
            case_id=case_id
        )
        
        storage_path = encryption_service.store_encrypted_data(encrypted_data)
        assert Path(storage_path).exists()
        
        # Securely delete data
        result = encryption_service.secure_delete_data(
            data_id=encrypted_data.data_id,
            case_id=case_id
        )
        
        assert result is True
        assert not Path(storage_path).exists()
        
        # Verify data cannot be loaded
        with pytest.raises(DataEncryptionError) as exc_info:
            encryption_service.load_encrypted_data(
                data_id=encrypted_data.data_id,
                case_id=case_id
            )
        assert "not found" in str(exc_info.value)
    
    def test_key_rotation(self, encryption_service):
        """Test key rotation functionality"""
        case_id = "TEST_CASE_009"
        
        # Generate initial keys
        key1_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="symmetric",
            algorithm="AES-256"
        )
        
        key2_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="symmetric",
            algorithm="Fernet"
        )
        
        # Manually age the keys to trigger rotation
        key1_info = encryption_service.get_key_info(key1_id)
        key2_info = encryption_service.get_key_info(key2_id)
        
        old_date = datetime.now() - timedelta(days=100)
        key1_info.created_at = old_date
        key2_info.created_at = old_date
        
        # Rotate keys
        new_key_ids = encryption_service.rotate_keys(case_id)
        
        assert len(new_key_ids) == 2
        
        # Verify old keys are deactivated
        assert not key1_info.is_active
        assert not key2_info.is_active
        
        # Verify new keys are active
        for new_key_id in new_key_ids:
            new_key_info = encryption_service.get_key_info(new_key_id)
            assert new_key_info.is_active
            assert new_key_info.case_id == case_id
    
    def test_list_keys(self, encryption_service):
        """Test listing encryption keys"""
        case_id1 = "TEST_CASE_010"
        case_id2 = "TEST_CASE_011"
        
        # Generate keys for different cases
        key1_id = encryption_service.generate_encryption_key(
            case_id=case_id1,
            key_type="symmetric",
            algorithm="AES-256"
        )
        
        key2_id = encryption_service.generate_encryption_key(
            case_id=case_id2,
            key_type="symmetric",
            algorithm="Fernet"
        )
        
        key3_id = encryption_service.generate_encryption_key(
            case_id=case_id1,
            key_type="asymmetric",
            algorithm="RSA-2048"
        )
        
        # List all keys
        all_keys = encryption_service.list_keys()
        assert len(all_keys) >= 3
        
        # List keys for specific case
        case1_keys = encryption_service.list_keys(case_id=case_id1)
        assert len(case1_keys) == 2
        
        case2_keys = encryption_service.list_keys(case_id=case_id2)
        assert len(case2_keys) == 1
        
        # Deactivate a key and test active_only filter
        key1_info = encryption_service.get_key_info(key1_id)
        key1_info.is_active = False
        
        active_keys = encryption_service.list_keys(case_id=case_id1, active_only=True)
        assert len(active_keys) == 1
        
        all_keys_including_inactive = encryption_service.list_keys(case_id=case_id1, active_only=False)
        assert len(all_keys_including_inactive) == 2
    
    def test_cleanup_expired_keys(self, encryption_service):
        """Test cleanup of expired keys"""
        case_id = "TEST_CASE_012"
        
        # Generate keys
        key1_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="symmetric",
            algorithm="AES-256"
        )
        
        key2_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="asymmetric",
            algorithm="RSA-2048"
        )
        
        # Manually expire and deactivate keys
        key1_info = encryption_service.get_key_info(key1_id)
        key2_info = encryption_service.get_key_info(key2_id)
        
        key1_info.is_active = False
        key1_info.expires_at = datetime.now() - timedelta(days=1)
        
        key2_info.is_active = False
        key2_info.expires_at = datetime.now() - timedelta(days=1)
        
        # Verify key files exist
        key1_file = encryption_service.key_storage_path / f"{key1_id}.key"
        key2_private_file = encryption_service.key_storage_path / f"{key2_id}_private.key"
        key2_public_file = encryption_service.key_storage_path / f"{key2_id}_public.key"
        
        assert key1_file.exists()
        assert key2_private_file.exists()
        assert key2_public_file.exists()
        
        # Cleanup expired keys
        cleaned_count = encryption_service.cleanup_expired_keys()
        
        assert cleaned_count == 2
        
        # Verify key files are deleted
        assert not key1_file.exists()
        assert not key2_private_file.exists()
        assert not key2_public_file.exists()
        
        # Verify keys are removed from cache
        assert encryption_service.get_key_info(key1_id) is None
        assert encryption_service.get_key_info(key2_id) is None
    
    def test_error_handling(self, encryption_service):
        """Test error handling in various scenarios"""
        # Test decryption with corrupted data
        case_id = "TEST_CASE_013"
        key_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="symmetric",
            algorithm="Fernet"
        )
        
        encrypted_data = encryption_service.encrypt_data(
            data="test data",
            key_id=key_id,
            case_id=case_id
        )
        
        # Corrupt the encrypted content
        encrypted_data.encrypted_content = b"corrupted_data"
        
        with pytest.raises(DataEncryptionError) as exc_info:
            encryption_service.decrypt_data(encrypted_data)
        assert "integrity check failed" in str(exc_info.value).lower()
        
        # Test loading non-existent data
        with pytest.raises(DataEncryptionError) as exc_info:
            encryption_service.load_encrypted_data("nonexistent_data_id")
        assert "not found" in str(exc_info.value)


if __name__ == "__main__":
    pytest.main([__file__])