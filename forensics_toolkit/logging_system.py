"""
Logging infrastructure with evidence integrity features
"""

import logging
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
import threading


@dataclass
class LogEntry:
    """Structured log entry with integrity verification"""
    timestamp: datetime
    level: str
    operation: str
    case_id: Optional[str]
    device_serial: Optional[str]
    message: str
    metadata: Dict[str, Any]
    hash_value: Optional[str] = None
    
    def __post_init__(self):
        if self.hash_value is None:
            self.hash_value = self._calculate_hash()
    
    def _calculate_hash(self) -> str:
        """Calculate SHA-256 hash of log entry"""
        # Create a copy without hash_value for hashing
        data = {
            'timestamp': self.timestamp.isoformat(),
            'level': self.level,
            'operation': self.operation,
            'case_id': self.case_id,
            'device_serial': self.device_serial,
            'message': self.message,
            'metadata': self.metadata
        }
        
        json_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify log entry integrity"""
        expected_hash = self._calculate_hash()
        return self.hash_value == expected_hash


class EvidenceLogger:
    """Logger with evidence integrity and chain of custody features"""
    
    def __init__(self, log_directory: str = "./logs", encrypt_logs: bool = True):
        self.log_directory = Path(log_directory)
        self.log_directory.mkdir(parents=True, exist_ok=True)
        
        self.encrypt_logs = encrypt_logs
        self._lock = threading.Lock()
        
        # Initialize encryption key if needed
        if encrypt_logs:
            self._init_encryption()
        
        # Set up standard logging
        self._setup_standard_logging()
        
        # Initialize evidence log file
        self.evidence_log_file = self.log_directory / "evidence.log"
        self.integrity_log_file = self.log_directory / "integrity.log"
    
    def _init_encryption(self):
        """Initialize encryption for sensitive logs"""
        key_file = self.log_directory / ".encryption_key"
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                self.encryption_key = f.read()
        else:
            self.encryption_key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.encryption_key)
            # Secure the key file
            key_file.chmod(0o600)
        
        self.cipher = Fernet(self.encryption_key)
    
    def _setup_standard_logging(self):
        """Set up standard Python logging"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # Create formatter
        formatter = logging.Formatter(log_format)
        
        # File handler
        file_handler = logging.FileHandler(self.log_directory / "forensics.log")
        file_handler.setFormatter(formatter)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        # Configure logger
        self.logger = logging.getLogger('ForensicsToolkit')
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def log_operation(self, 
                     level: str,
                     operation: str,
                     message: str,
                     case_id: Optional[str] = None,
                     device_serial: Optional[str] = None,
                     metadata: Optional[Dict[str, Any]] = None) -> LogEntry:
        """Log a forensic operation with integrity verification"""
        
        if metadata is None:
            metadata = {}
        
        # Create log entry
        log_entry = LogEntry(
            timestamp=datetime.now(),
            level=level,
            operation=operation,
            case_id=case_id,
            device_serial=device_serial,
            message=message,
            metadata=metadata
        )
        
        # Write to evidence log
        self._write_evidence_log(log_entry)
        
        # Write to standard log
        getattr(self.logger, level.lower())(
            f"[{operation}] {message} - Case: {case_id}, Device: {device_serial}"
        )
        
        return log_entry
    
    def _write_evidence_log(self, log_entry: LogEntry):
        """Write log entry to evidence log file"""
        with self._lock:
            try:
                # Convert to JSON
                log_data = asdict(log_entry)
                log_data['timestamp'] = log_entry.timestamp.isoformat()
                json_line = json.dumps(log_data) + '\n'
                
                # Encrypt if required
                if self.encrypt_logs:
                    encrypted_data = self.cipher.encrypt(json_line.encode())
                    with open(self.evidence_log_file, 'ab') as f:
                        f.write(encrypted_data + b'\n')
                else:
                    with open(self.evidence_log_file, 'a') as f:
                        f.write(json_line)
                
                # Log integrity hash
                self._log_integrity_hash(log_entry)
                
            except Exception as e:
                self.logger.error(f"Failed to write evidence log: {e}")
    
    def _log_integrity_hash(self, log_entry: LogEntry):
        """Log integrity hash for verification"""
        integrity_entry = {
            'timestamp': log_entry.timestamp.isoformat(),
            'operation': log_entry.operation,
            'hash': log_entry.hash_value
        }
        
        with open(self.integrity_log_file, 'a') as f:
            f.write(json.dumps(integrity_entry) + '\n')
    
    def verify_log_integrity(self, case_id: Optional[str] = None) -> Dict[str, Any]:
        """Verify integrity of logged evidence"""
        verification_results = {
            'total_entries': 0,
            'verified_entries': 0,
            'failed_entries': 0,
            'corrupted_entries': [],
            'case_id': case_id
        }
        
        try:
            log_entries = self.read_evidence_logs(case_id)
            
            for entry in log_entries:
                verification_results['total_entries'] += 1
                
                if entry.verify_integrity():
                    verification_results['verified_entries'] += 1
                else:
                    verification_results['failed_entries'] += 1
                    verification_results['corrupted_entries'].append({
                        'timestamp': entry.timestamp.isoformat(),
                        'operation': entry.operation,
                        'expected_hash': entry._calculate_hash(),
                        'actual_hash': entry.hash_value
                    })
        
        except Exception as e:
            self.logger.error(f"Error verifying log integrity: {e}")
            verification_results['error'] = str(e)
        
        return verification_results
    
    def read_evidence_logs(self, case_id: Optional[str] = None) -> List[LogEntry]:
        """Read evidence logs, optionally filtered by case ID"""
        log_entries = []
        
        try:
            if not self.evidence_log_file.exists():
                return log_entries
            
            with open(self.evidence_log_file, 'rb' if self.encrypt_logs else 'r') as f:
                for line in f:
                    try:
                        if self.encrypt_logs:
                            # Decrypt line
                            decrypted_data = self.cipher.decrypt(line.strip())
                            json_data = json.loads(decrypted_data.decode())
                        else:
                            json_data = json.loads(line.strip())
                        
                        # Convert timestamp back to datetime
                        json_data['timestamp'] = datetime.fromisoformat(json_data['timestamp'])
                        
                        # Create LogEntry
                        log_entry = LogEntry(**json_data)
                        
                        # Filter by case_id if specified
                        if case_id is None or log_entry.case_id == case_id:
                            log_entries.append(log_entry)
                    
                    except Exception as e:
                        self.logger.error(f"Error parsing log entry: {e}")
                        continue
        
        except Exception as e:
            self.logger.error(f"Error reading evidence logs: {e}")
        
        return log_entries
    
    def create_audit_trail(self, case_id: str) -> Dict[str, Any]:
        """Create comprehensive audit trail for a case"""
        case_logs = self.read_evidence_logs(case_id)
        
        audit_trail = {
            'case_id': case_id,
            'generated_at': datetime.now().isoformat(),
            'total_operations': len(case_logs),
            'operations_by_type': {},
            'timeline': [],
            'integrity_status': self.verify_log_integrity(case_id)
        }
        
        # Analyze operations
        for log_entry in case_logs:
            # Count by operation type
            op_type = log_entry.operation
            if op_type not in audit_trail['operations_by_type']:
                audit_trail['operations_by_type'][op_type] = 0
            audit_trail['operations_by_type'][op_type] += 1
            
            # Add to timeline
            audit_trail['timeline'].append({
                'timestamp': log_entry.timestamp.isoformat(),
                'operation': log_entry.operation,
                'level': log_entry.level,
                'message': log_entry.message,
                'device_serial': log_entry.device_serial,
                'hash': log_entry.hash_value
            })
        
        # Sort timeline by timestamp
        audit_trail['timeline'].sort(key=lambda x: x['timestamp'])
        
        return audit_trail
    
    def export_case_evidence(self, case_id: str, export_path: str) -> bool:
        """Export all evidence for a case to a secure file"""
        try:
            audit_trail = self.create_audit_trail(case_id)
            
            export_file = Path(export_path)
            export_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(export_file, 'w') as f:
                json.dump(audit_trail, f, indent=2)
            
            self.log_operation(
                level='INFO',
                operation='EVIDENCE_EXPORT',
                message=f'Evidence exported for case {case_id}',
                case_id=case_id,
                metadata={'export_path': str(export_file)}
            )
            
            return True
        
        except Exception as e:
            self.logger.error(f"Error exporting case evidence: {e}")
            return False


# Global evidence logger instance
evidence_logger = EvidenceLogger()