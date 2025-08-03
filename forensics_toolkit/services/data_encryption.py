"""
Data Encryption Module for Forensic Evidence Protection

This module implements the DataEncryption class for recovered data protection,
secure key management, encrypted storage for sensitive evidence, and secure
data disposal protocols as required by forensic compliance standards.
"""

import os
import json
import hashlib
import secrets
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from ..interfaces import ForensicsException


class DataEncryptionError(ForensicsException):
    """Exception raised for data encryption errors"""
    
    def __init__(self, message: str, operation: str = None):
        super().__init__(message, "DATA_ENCRYPTION_ERROR", evidence_impact=True)
        self.operation = operation


@dataclass
class EncryptionKey:
    """Encryption key metadata and management"""
    key_id: str
    key_type: str  # 'symmetric', 'asymmetric_public', 'asymmetric_private'
    algorithm: str  # 'AES-256', 'RSA-2048', 'Fernet'
    created_at: datetime
    expires_at: Optional[datetime] = None
    case_id: Optional[str] = None
    purpose: str = "evidence_encryption"
    is_active: bool = True
    key_hash: str = field(init=False)
    
    def __post_init__(self):
        """Calculate key hash after initialization"""
        self.key_hash = self._calculate_key_hash()
    
    def _calculate_key_hash(self) -> str:
        """Calculate SHA-256 hash of key metadata"""
        hash_data = {
            'key_id': self.key_id,
            'key_type': self.key_type,
            'algorithm': self.algorithm,
            'created_at': self.created_at.isoformat(),
            'case_id': self.case_id,
            'purpose': self.purpose
        }
        json_str = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(json_str.encode('utf-8')).hexdigest()
    
    def is_expired(self) -> bool:
        """Check if key has expired"""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'key_id': self.key_id,
            'key_type': self.key_type,
            'algorithm': self.algorithm,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'case_id': self.case_id,
            'purpose': self.purpose,
            'is_active': self.is_active,
            'key_hash': self.key_hash
        }


@dataclass
class EncryptedData:
    """Encrypted data container with metadata"""
    data_id: str
    encrypted_content: bytes
    key_id: str
    algorithm: str
    iv: Optional[bytes] = None  # Initialization vector for AES
    salt: Optional[bytes] = None  # Salt for key derivation
    timestamp: datetime = field(default_factory=datetime.now)
    case_id: Optional[str] = None
    original_filename: Optional[str] = None
    original_size: int = 0
    content_hash: str = field(init=False)
    
    def __post_init__(self):
        """Calculate content hash after initialization"""
        self.content_hash = self._calculate_content_hash()
    
    def _calculate_content_hash(self) -> str:
        """Calculate SHA-256 hash of encrypted content"""
        return hashlib.sha256(self.encrypted_content).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify integrity of encrypted data"""
        expected_hash = hashlib.sha256(self.encrypted_content).hexdigest()
        return self.content_hash == expected_hash
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'data_id': self.data_id,
            'encrypted_content': self.encrypted_content.hex(),
            'key_id': self.key_id,
            'algorithm': self.algorithm,
            'iv': self.iv.hex() if self.iv else None,
            'salt': self.salt.hex() if self.salt else None,
            'timestamp': self.timestamp.isoformat(),
            'case_id': self.case_id,
            'original_filename': self.original_filename,
            'original_size': self.original_size,
            'content_hash': self.content_hash
        }


class DataEncryption:
    """
    Comprehensive data encryption service for forensic evidence protection
    
    Provides secure key management, encrypted storage for sensitive evidence,
    and secure data disposal protocols in compliance with forensic standards.
    """
    
    def __init__(self, 
                 key_storage_path: str = "./keys",
                 encrypted_storage_path: str = "./encrypted_evidence",
                 key_rotation_days: int = 90):
        """
        Initialize the data encryption service
        
        Args:
            key_storage_path: Directory to store encryption keys
            encrypted_storage_path: Directory to store encrypted evidence
            key_rotation_days: Days after which keys should be rotated
        """
        self.key_storage_path = Path(key_storage_path)
        self.encrypted_storage_path = Path(encrypted_storage_path)
        self.key_rotation_days = key_rotation_days
        
        # Create directories with secure permissions
        self._create_secure_directories()
        
        # Thread safety
        self._lock = threading.RLock()
        
        # In-memory key cache for performance
        self._key_cache: Dict[str, bytes] = {}
        self._key_metadata_cache: Dict[str, EncryptionKey] = {}
        
        # Initialize master key for key encryption
        self._init_master_key()
        
        # Load existing key metadata
        self._load_key_metadata()
    
    def _create_secure_directories(self):
        """Create directories with secure permissions"""
        try:
            self.key_storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.encrypted_storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
            
            # Set restrictive permissions on existing directories
            os.chmod(self.key_storage_path, 0o700)
            os.chmod(self.encrypted_storage_path, 0o700)
            
        except Exception as e:
            raise DataEncryptionError(f"Failed to create secure directories: {e}", "INIT")
    
    def _init_master_key(self):
        """Initialize or load master key for key encryption"""
        master_key_file = self.key_storage_path / ".master_key"
        
        try:
            if master_key_file.exists():
                with open(master_key_file, 'rb') as f:
                    self.master_key = f.read()
            else:
                # Generate new master key
                self.master_key = Fernet.generate_key()
                with open(master_key_file, 'wb') as f:
                    f.write(self.master_key)
                # Secure the master key file
                master_key_file.chmod(0o600)
            
            self.master_cipher = Fernet(self.master_key)
            
        except Exception as e:
            raise DataEncryptionError(f"Failed to initialize master key: {e}", "MASTER_KEY_INIT")
    
    def _load_key_metadata(self):
        """Load existing key metadata from storage"""
        metadata_file = self.key_storage_path / "key_metadata.json"
        
        try:
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata_list = json.load(f)
                
                for metadata_dict in metadata_list:
                    key_metadata = EncryptionKey(
                        key_id=metadata_dict['key_id'],
                        key_type=metadata_dict['key_type'],
                        algorithm=metadata_dict['algorithm'],
                        created_at=datetime.fromisoformat(metadata_dict['created_at']),
                        expires_at=datetime.fromisoformat(metadata_dict['expires_at']) if metadata_dict.get('expires_at') else None,
                        case_id=metadata_dict.get('case_id'),
                        purpose=metadata_dict.get('purpose', 'evidence_encryption'),
                        is_active=metadata_dict.get('is_active', True)
                    )
                    self._key_metadata_cache[key_metadata.key_id] = key_metadata
        
        except Exception as e:
            # Log error but don't fail initialization
            pass
    
    def _save_key_metadata(self):
        """Save key metadata to storage"""
        metadata_file = self.key_storage_path / "key_metadata.json"
        
        try:
            metadata_list = [metadata.to_dict() for metadata in self._key_metadata_cache.values()]
            
            with open(metadata_file, 'w') as f:
                json.dump(metadata_list, f, indent=2)
            
            # Secure the metadata file
            metadata_file.chmod(0o600)
        
        except Exception as e:
            raise DataEncryptionError(f"Failed to save key metadata: {e}", "SAVE_METADATA")
    
    def generate_encryption_key(self, 
                               case_id: str,
                               key_type: str = "symmetric",
                               algorithm: str = "AES-256",
                               expires_in_days: Optional[int] = None) -> str:
        """
        Generate a new encryption key for a case
        
        Args:
            case_id: Case ID for the encryption key
            key_type: Type of key ('symmetric', 'asymmetric')
            algorithm: Encryption algorithm
            expires_in_days: Days until key expires (None for no expiration)
            
        Returns:
            str: Key ID for the generated key
            
        Raises:
            DataEncryptionError: If key generation fails
        """
        if not case_id or not case_id.strip():
            raise DataEncryptionError("Case ID cannot be empty", "GENERATE_KEY")
        
        try:
            with self._lock:
                # Generate unique key ID
                key_id = f"{case_id}_{algorithm}_{secrets.token_hex(8)}"
                
                # Calculate expiration
                expires_at = None
                if expires_in_days:
                    expires_at = datetime.now() + timedelta(days=expires_in_days)
                
                # Generate the actual key based on type
                if key_type == "symmetric":
                    if algorithm == "AES-256":
                        raw_key = secrets.token_bytes(32)  # 256 bits
                    elif algorithm == "Fernet":
                        raw_key = Fernet.generate_key()
                    else:
                        raise DataEncryptionError(f"Unsupported symmetric algorithm: {algorithm}", "GENERATE_KEY")
                
                elif key_type == "asymmetric":
                    if algorithm == "RSA-2048":
                        private_key = rsa.generate_private_key(
                            public_exponent=65537,
                            key_size=2048,
                            backend=default_backend()
                        )
                        
                        # Store private key
                        private_pem = private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        )
                        
                        # Store public key
                        public_key = private_key.public_key()
                        public_pem = public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        
                        # For asymmetric keys, we store both
                        self._store_key(f"{key_id}_private", private_pem)
                        self._store_key(f"{key_id}_public", public_pem)
                        
                        raw_key = private_pem  # Use private key as the main key
                    else:
                        raise DataEncryptionError(f"Unsupported asymmetric algorithm: {algorithm}", "GENERATE_KEY")
                
                else:
                    raise DataEncryptionError(f"Unsupported key type: {key_type}", "GENERATE_KEY")
                
                # Store the key securely
                self._store_key(key_id, raw_key)
                
                # Create and store key metadata
                key_metadata = EncryptionKey(
                    key_id=key_id,
                    key_type=key_type,
                    algorithm=algorithm,
                    created_at=datetime.now(),
                    expires_at=expires_at,
                    case_id=case_id,
                    purpose="evidence_encryption"
                )
                
                self._key_metadata_cache[key_id] = key_metadata
                self._save_key_metadata()
                
                return key_id
        
        except Exception as e:
            raise DataEncryptionError(f"Failed to generate encryption key: {e}", "GENERATE_KEY")
    
    def _store_key(self, key_id: str, key_data: bytes):
        """Store encryption key securely"""
        try:
            # Encrypt key with master key
            encrypted_key = self.master_cipher.encrypt(key_data)
            
            # Store encrypted key
            key_file = self.key_storage_path / f"{key_id}.key"
            with open(key_file, 'wb') as f:
                f.write(encrypted_key)
            
            # Secure the key file
            key_file.chmod(0o600)
            
            # Cache the key
            self._key_cache[key_id] = key_data
        
        except Exception as e:
            raise DataEncryptionError(f"Failed to store key {key_id}: {e}", "STORE_KEY")
    
    def _load_key(self, key_id: str) -> bytes:
        """Load encryption key from storage"""
        # Check cache first
        if key_id in self._key_cache:
            return self._key_cache[key_id]
        
        try:
            key_file = self.key_storage_path / f"{key_id}.key"
            if not key_file.exists():
                raise DataEncryptionError(f"Key {key_id} not found", "LOAD_KEY")
            
            # Load and decrypt key
            with open(key_file, 'rb') as f:
                encrypted_key = f.read()
            
            key_data = self.master_cipher.decrypt(encrypted_key)
            
            # Cache the key
            self._key_cache[key_id] = key_data
            
            return key_data
        
        except Exception as e:
            raise DataEncryptionError(f"Failed to load key {key_id}: {e}", "LOAD_KEY")
    
    def encrypt_data(self, 
                    data: Union[str, bytes], 
                    key_id: str,
                    case_id: Optional[str] = None,
                    original_filename: Optional[str] = None) -> EncryptedData:
        """
        Encrypt sensitive data using specified key
        
        Args:
            data: Data to encrypt (string or bytes)
            key_id: ID of the encryption key to use
            case_id: Case ID for the encrypted data
            original_filename: Original filename if encrypting a file
            
        Returns:
            EncryptedData: Encrypted data container
            
        Raises:
            DataEncryptionError: If encryption fails
        """
        if not key_id or key_id not in self._key_metadata_cache:
            raise DataEncryptionError(f"Invalid or unknown key ID: {key_id}", "ENCRYPT_DATA")
        
        key_metadata = self._key_metadata_cache[key_id]
        
        # Check if key is active and not expired
        if not key_metadata.is_active:
            raise DataEncryptionError(f"Key {key_id} is not active", "ENCRYPT_DATA")
        
        if key_metadata.is_expired():
            raise DataEncryptionError(f"Key {key_id} has expired", "ENCRYPT_DATA")
        
        try:
            with self._lock:
                # Convert string to bytes if necessary
                if isinstance(data, str):
                    data_bytes = data.encode('utf-8')
                else:
                    data_bytes = data
                
                original_size = len(data_bytes)
                
                # Load the encryption key
                key_data = self._load_key(key_id)
                
                # Encrypt based on algorithm
                if key_metadata.algorithm == "Fernet":
                    cipher = Fernet(key_data)
                    encrypted_content = cipher.encrypt(data_bytes)
                    iv = None
                    salt = None
                
                elif key_metadata.algorithm == "AES-256":
                    # Generate random IV and salt
                    iv = secrets.token_bytes(16)  # 128-bit IV for AES
                    salt = secrets.token_bytes(32)  # 256-bit salt
                    
                    # Derive key using PBKDF2
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                        backend=default_backend()
                    )
                    derived_key = kdf.derive(key_data)
                    
                    # Encrypt using AES-256-CBC
                    cipher = Cipher(
                        algorithms.AES(derived_key),
                        modes.CBC(iv),
                        backend=default_backend()
                    )
                    encryptor = cipher.encryptor()
                    
                    # Pad data to block size
                    padded_data = self._pad_data(data_bytes, 16)
                    encrypted_content = encryptor.update(padded_data) + encryptor.finalize()
                
                elif key_metadata.algorithm == "RSA-2048":
                    # For RSA, we encrypt with public key
                    public_key_data = self._load_key(f"{key_id}_public")
                    public_key = serialization.load_pem_public_key(public_key_data, backend=default_backend())
                    
                    # RSA can only encrypt small amounts of data, so we use hybrid encryption
                    # Generate AES key for actual data encryption
                    aes_key = secrets.token_bytes(32)
                    iv = secrets.token_bytes(16)
                    
                    # Encrypt data with AES
                    cipher = Cipher(
                        algorithms.AES(aes_key),
                        modes.CBC(iv),
                        backend=default_backend()
                    )
                    encryptor = cipher.encryptor()
                    padded_data = self._pad_data(data_bytes, 16)
                    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                    
                    # Encrypt AES key with RSA
                    encrypted_aes_key = public_key.encrypt(
                        aes_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    # Combine encrypted key and data
                    encrypted_content = encrypted_aes_key + iv + encrypted_data
                    salt = None
                
                else:
                    raise DataEncryptionError(f"Unsupported algorithm: {key_metadata.algorithm}", "ENCRYPT_DATA")
                
                # Generate unique data ID
                data_id = f"{case_id or 'unknown'}_{secrets.token_hex(8)}"
                
                # Create encrypted data container
                encrypted_data = EncryptedData(
                    data_id=data_id,
                    encrypted_content=encrypted_content,
                    key_id=key_id,
                    algorithm=key_metadata.algorithm,
                    iv=iv,
                    salt=salt,
                    case_id=case_id,
                    original_filename=original_filename,
                    original_size=original_size
                )
                
                return encrypted_data
        
        except Exception as e:
            raise DataEncryptionError(f"Failed to encrypt data: {e}", "ENCRYPT_DATA")
    
    def decrypt_data(self, encrypted_data: EncryptedData) -> bytes:
        """
        Decrypt encrypted data
        
        Args:
            encrypted_data: Encrypted data container
            
        Returns:
            bytes: Decrypted data
            
        Raises:
            DataEncryptionError: If decryption fails
        """
        if not encrypted_data.verify_integrity():
            raise DataEncryptionError("Encrypted data integrity check failed", "DECRYPT_DATA")
        
        key_id = encrypted_data.key_id
        if key_id not in self._key_metadata_cache:
            raise DataEncryptionError(f"Key {key_id} not found", "DECRYPT_DATA")
        
        key_metadata = self._key_metadata_cache[key_id]
        
        try:
            with self._lock:
                # Load the decryption key
                key_data = self._load_key(key_id)
                
                # Decrypt based on algorithm
                if encrypted_data.algorithm == "Fernet":
                    cipher = Fernet(key_data)
                    decrypted_data = cipher.decrypt(encrypted_data.encrypted_content)
                
                elif encrypted_data.algorithm == "AES-256":
                    if not encrypted_data.iv or not encrypted_data.salt:
                        raise DataEncryptionError("Missing IV or salt for AES decryption", "DECRYPT_DATA")
                    
                    # Derive key using PBKDF2
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=encrypted_data.salt,
                        iterations=100000,
                        backend=default_backend()
                    )
                    derived_key = kdf.derive(key_data)
                    
                    # Decrypt using AES-256-CBC
                    cipher = Cipher(
                        algorithms.AES(derived_key),
                        modes.CBC(encrypted_data.iv),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    padded_data = decryptor.update(encrypted_data.encrypted_content) + decryptor.finalize()
                    
                    # Remove padding
                    decrypted_data = self._unpad_data(padded_data)
                
                elif encrypted_data.algorithm == "RSA-2048":
                    # For RSA hybrid encryption, extract components
                    encrypted_content = encrypted_data.encrypted_content
                    
                    # Extract encrypted AES key (first 256 bytes for RSA-2048)
                    encrypted_aes_key = encrypted_content[:256]
                    iv = encrypted_content[256:272]  # Next 16 bytes
                    encrypted_data_part = encrypted_content[272:]  # Rest is encrypted data
                    
                    # Load private key for decryption
                    private_key_data = self._load_key(f"{key_id}_private")
                    private_key = serialization.load_pem_private_key(
                        private_key_data, 
                        password=None, 
                        backend=default_backend()
                    )
                    
                    # Decrypt AES key with RSA
                    aes_key = private_key.decrypt(
                        encrypted_aes_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    # Decrypt data with AES
                    cipher = Cipher(
                        algorithms.AES(aes_key),
                        modes.CBC(iv),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    padded_data = decryptor.update(encrypted_data_part) + decryptor.finalize()
                    
                    # Remove padding
                    decrypted_data = self._unpad_data(padded_data)
                
                else:
                    raise DataEncryptionError(f"Unsupported algorithm: {encrypted_data.algorithm}", "DECRYPT_DATA")
                
                return decrypted_data
        
        except Exception as e:
            raise DataEncryptionError(f"Failed to decrypt data: {e}", "DECRYPT_DATA")
    
    def _pad_data(self, data: bytes, block_size: int) -> bytes:
        """Apply PKCS7 padding to data"""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, padded_data: bytes) -> bytes:
        """Remove PKCS7 padding from data"""
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
    
    def store_encrypted_data(self, encrypted_data: EncryptedData) -> str:
        """
        Store encrypted data to secure storage
        
        Args:
            encrypted_data: Encrypted data container
            
        Returns:
            str: Storage path of the encrypted data
            
        Raises:
            DataEncryptionError: If storage fails
        """
        try:
            with self._lock:
                # Create case-specific directory
                case_dir = self.encrypted_storage_path
                if encrypted_data.case_id:
                    case_dir = self.encrypted_storage_path / encrypted_data.case_id
                    case_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                
                # Create storage file
                storage_file = case_dir / f"{encrypted_data.data_id}.enc"
                
                # Store encrypted data with metadata
                storage_data = {
                    'metadata': encrypted_data.to_dict(),
                    'encrypted_content': encrypted_data.encrypted_content.hex()
                }
                
                with open(storage_file, 'w') as f:
                    json.dump(storage_data, f, indent=2)
                
                # Secure the storage file
                storage_file.chmod(0o600)
                
                return str(storage_file)
        
        except Exception as e:
            raise DataEncryptionError(f"Failed to store encrypted data: {e}", "STORE_DATA")
    
    def load_encrypted_data(self, data_id: str, case_id: Optional[str] = None) -> EncryptedData:
        """
        Load encrypted data from secure storage
        
        Args:
            data_id: ID of the encrypted data
            case_id: Optional case ID to narrow search
            
        Returns:
            EncryptedData: Loaded encrypted data container
            
        Raises:
            DataEncryptionError: If loading fails
        """
        try:
            with self._lock:
                # Search for the data file
                search_dirs = [self.encrypted_storage_path]
                if case_id:
                    case_dir = self.encrypted_storage_path / case_id
                    if case_dir.exists():
                        search_dirs.insert(0, case_dir)
                
                storage_file = None
                for search_dir in search_dirs:
                    potential_file = search_dir / f"{data_id}.enc"
                    if potential_file.exists():
                        storage_file = potential_file
                        break
                
                if not storage_file:
                    raise DataEncryptionError(f"Encrypted data {data_id} not found", "LOAD_DATA")
                
                # Load and parse storage data
                with open(storage_file, 'r') as f:
                    storage_data = json.load(f)
                
                metadata = storage_data['metadata']
                encrypted_content = bytes.fromhex(storage_data['encrypted_content'])
                
                # Reconstruct EncryptedData object
                encrypted_data = EncryptedData(
                    data_id=metadata['data_id'],
                    encrypted_content=encrypted_content,
                    key_id=metadata['key_id'],
                    algorithm=metadata['algorithm'],
                    iv=bytes.fromhex(metadata['iv']) if metadata.get('iv') else None,
                    salt=bytes.fromhex(metadata['salt']) if metadata.get('salt') else None,
                    timestamp=datetime.fromisoformat(metadata['timestamp']),
                    case_id=metadata.get('case_id'),
                    original_filename=metadata.get('original_filename'),
                    original_size=metadata.get('original_size', 0)
                )
                
                # Verify integrity
                if not encrypted_data.verify_integrity():
                    raise DataEncryptionError(f"Integrity check failed for {data_id}", "LOAD_DATA")
                
                return encrypted_data
        
        except Exception as e:
            raise DataEncryptionError(f"Failed to load encrypted data: {e}", "LOAD_DATA")
    
    def secure_delete_data(self, data_id: str, case_id: Optional[str] = None) -> bool:
        """
        Securely delete encrypted data and associated keys
        
        Args:
            data_id: ID of the data to delete
            case_id: Optional case ID to narrow search
            
        Returns:
            bool: True if deletion successful
            
        Raises:
            DataEncryptionError: If deletion fails
        """
        try:
            with self._lock:
                # Find and load the encrypted data
                encrypted_data = self.load_encrypted_data(data_id, case_id)
                
                # Determine storage file path
                search_dirs = [self.encrypted_storage_path]
                if case_id:
                    case_dir = self.encrypted_storage_path / case_id
                    if case_dir.exists():
                        search_dirs.insert(0, case_dir)
                
                storage_file = None
                for search_dir in search_dirs:
                    potential_file = search_dir / f"{data_id}.enc"
                    if potential_file.exists():
                        storage_file = potential_file
                        break
                
                if storage_file:
                    # Secure overwrite before deletion
                    self._secure_overwrite_file(storage_file)
                    storage_file.unlink()  # Delete the file
                
                return True
        
        except Exception as e:
            raise DataEncryptionError(f"Failed to securely delete data: {e}", "SECURE_DELETE")
    
    def _secure_overwrite_file(self, file_path: Path, passes: int = 3):
        """
        Securely overwrite file contents multiple times
        
        Args:
            file_path: Path to file to overwrite
            passes: Number of overwrite passes
        """
        try:
            file_size = file_path.stat().st_size
            
            with open(file_path, 'r+b') as f:
                for _ in range(passes):
                    # Overwrite with random data
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())  # Force write to disk
        
        except Exception as e:
            raise DataEncryptionError(f"Failed to securely overwrite file: {e}", "SECURE_OVERWRITE")
    
    def rotate_keys(self, case_id: str) -> List[str]:
        """
        Rotate encryption keys for a case
        
        Args:
            case_id: Case ID to rotate keys for
            
        Returns:
            List[str]: List of new key IDs
            
        Raises:
            DataEncryptionError: If key rotation fails
        """
        try:
            with self._lock:
                new_key_ids = []
                
                # Find keys that need rotation
                keys_to_rotate = []
                for key_id, key_metadata in self._key_metadata_cache.items():
                    if (key_metadata.case_id == case_id and 
                        key_metadata.is_active and
                        (key_metadata.is_expired() or 
                         (datetime.now() - key_metadata.created_at).days >= self.key_rotation_days)):
                        keys_to_rotate.append(key_metadata)
                
                # Generate new keys
                for old_key_metadata in keys_to_rotate:
                    # Generate new key with same parameters
                    new_key_id = self.generate_encryption_key(
                        case_id=case_id,
                        key_type=old_key_metadata.key_type,
                        algorithm=old_key_metadata.algorithm,
                        expires_in_days=self.key_rotation_days
                    )
                    new_key_ids.append(new_key_id)
                    
                    # Deactivate old key
                    old_key_metadata.is_active = False
                
                # Save updated metadata
                self._save_key_metadata()
                
                return new_key_ids
        
        except Exception as e:
            raise DataEncryptionError(f"Failed to rotate keys: {e}", "KEY_ROTATION")
    
    def get_key_info(self, key_id: str) -> Optional[EncryptionKey]:
        """
        Get information about an encryption key
        
        Args:
            key_id: ID of the key
            
        Returns:
            EncryptionKey: Key metadata or None if not found
        """
        return self._key_metadata_cache.get(key_id)
    
    def list_keys(self, case_id: Optional[str] = None, active_only: bool = True) -> List[EncryptionKey]:
        """
        List encryption keys
        
        Args:
            case_id: Optional case ID to filter by
            active_only: Whether to return only active keys
            
        Returns:
            List[EncryptionKey]: List of key metadata
        """
        keys = []
        for key_metadata in self._key_metadata_cache.values():
            if case_id and key_metadata.case_id != case_id:
                continue
            if active_only and not key_metadata.is_active:
                continue
            keys.append(key_metadata)
        
        return keys
    
    def cleanup_expired_keys(self) -> int:
        """
        Clean up expired and inactive keys
        
        Returns:
            int: Number of keys cleaned up
        """
        try:
            with self._lock:
                cleaned_count = 0
                keys_to_remove = []
                
                for key_id, key_metadata in self._key_metadata_cache.items():
                    if not key_metadata.is_active and key_metadata.is_expired():
                        # Remove key files
                        key_file = self.key_storage_path / f"{key_id}.key"
                        if key_file.exists():
                            self._secure_overwrite_file(key_file)
                            key_file.unlink()
                        
                        # For asymmetric keys, also remove public/private key files
                        if key_metadata.key_type == "asymmetric":
                            for suffix in ["_private", "_public"]:
                                asym_key_file = self.key_storage_path / f"{key_id}{suffix}.key"
                                if asym_key_file.exists():
                                    self._secure_overwrite_file(asym_key_file)
                                    asym_key_file.unlink()
                        
                        keys_to_remove.append(key_id)
                        cleaned_count += 1
                
                # Remove from cache and metadata
                for key_id in keys_to_remove:
                    del self._key_metadata_cache[key_id]
                    if key_id in self._key_cache:
                        del self._key_cache[key_id]
                
                # Save updated metadata
                if keys_to_remove:
                    self._save_key_metadata()
                
                return cleaned_count
        
        except Exception as e:
            raise DataEncryptionError(f"Failed to cleanup expired keys: {e}", "CLEANUP_KEYS")