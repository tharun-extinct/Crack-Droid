"""
Evidence Logger with comprehensive forensic logging capabilities

This module implements the EvidenceLogger class with timestamped operation logging,
SHA-256 hash verification, structured evidence collection, and real-time audit trails.
"""

import json
import hashlib
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict, field
from cryptography.fernet import Fernet

from ..models.attack import EvidenceRecord, CustodyEvent
from ..models.device import AndroidDevice
from ..interfaces import ForensicsException


class EvidenceLoggingError(ForensicsException):
    """Exception raised for evidence logging errors"""
    
    def __init__(self, message: str, operation: str = None):
        super().__init__(message, "EVIDENCE_LOGGING_ERROR", evidence_impact=True)
        self.operation = operation


@dataclass
class OperationLog:
    """Individual operation log entry with integrity verification"""
    timestamp: datetime
    case_id: str
    operation_type: str
    device_serial: Optional[str]
    user_id: Optional[str]
    message: str
    metadata: Dict[str, Any]
    hash_value: str = field(init=False)
    
    def __post_init__(self):
        """Calculate hash after initialization"""
        self.hash_value = self._calculate_hash()
    
    def _calculate_hash(self) -> str:
        """Calculate SHA-256 hash of operation data"""
        # Create hashable data structure
        hash_data = {
            'timestamp': self.timestamp.isoformat(),
            'case_id': self.case_id,
            'operation_type': self.operation_type,
            'device_serial': self.device_serial,
            'user_id': self.user_id,
            'message': self.message,
            'metadata': self.metadata
        }
        
        # Convert to JSON string with sorted keys for consistent hashing
        json_str = json.dumps(hash_data, sort_keys=True, default=str)
        return hashlib.sha256(json_str.encode('utf-8')).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify the integrity of this operation log"""
        expected_hash = self._calculate_hash()
        return self.hash_value == expected_hash
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'case_id': self.case_id,
            'operation_type': self.operation_type,
            'device_serial': self.device_serial,
            'user_id': self.user_id,
            'message': self.message,
            'metadata': self.metadata,
            'hash_value': self.hash_value
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OperationLog':
        """Create OperationLog from dictionary"""
        timestamp = datetime.fromisoformat(data['timestamp'])
        
        # Create instance without hash_value first
        log = cls(
            timestamp=timestamp,
            case_id=data['case_id'],
            operation_type=data['operation_type'],
            device_serial=data.get('device_serial'),
            user_id=data.get('user_id'),
            message=data['message'],
            metadata=data.get('metadata', {})
        )
        
        # Set the stored hash value
        log.hash_value = data['hash_value']
        return log


class EvidenceLogger:
    """
    Comprehensive evidence logger with forensic integrity features
    
    Provides timestamped operation logging, SHA-256 hash verification,
    structured evidence collection, and real-time audit trail generation.
    """
    
    def __init__(self, 
                 log_directory: str = "./logs",
                 encrypt_logs: bool = True,
                 auto_backup: bool = True):
        """
        Initialize the evidence logger
        
        Args:
            log_directory: Directory to store log files
            encrypt_logs: Whether to encrypt sensitive log data
            auto_backup: Whether to automatically backup logs
        """
        self.log_directory = Path(log_directory)
        self.log_directory.mkdir(parents=True, exist_ok=True)
        
        self.encrypt_logs = encrypt_logs
        self.auto_backup = auto_backup
        self._lock = threading.RLock()  # Reentrant lock for nested calls
        
        # Initialize encryption if enabled
        if encrypt_logs:
            self._init_encryption()
        
        # Log file paths
        self.operations_log_file = self.log_directory / "operations.log"
        self.evidence_log_file = self.log_directory / "evidence.log"
        self.integrity_log_file = self.log_directory / "integrity.log"
        self.audit_log_file = self.log_directory / "audit.log"
        
        # In-memory cache for recent operations (for performance)
        self._operation_cache: List[OperationLog] = []
        self._cache_max_size = 1000
        
        # Initialize log files with headers if they don't exist
        self._initialize_log_files()
    
    def _init_encryption(self):
        """Initialize encryption for sensitive logs"""
        key_file = self.log_directory / ".encryption_key"
        
        try:
            if key_file.exists():
                with open(key_file, 'rb') as f:
                    self.encryption_key = f.read()
            else:
                self.encryption_key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(self.encryption_key)
                # Secure the key file permissions
                key_file.chmod(0o600)
            
            self.cipher = Fernet(self.encryption_key)
            
        except Exception as e:
            raise EvidenceLoggingError(f"Failed to initialize encryption: {e}", "ENCRYPTION_INIT")
    
    def _initialize_log_files(self):
        """Initialize log files with proper headers"""
        try:
            # Create log files if they don't exist
            for log_file in [self.operations_log_file, self.evidence_log_file, 
                           self.integrity_log_file, self.audit_log_file]:
                if not log_file.exists():
                    log_file.touch()
                    
                    # Add header for JSON-lines format
                    if log_file == self.operations_log_file:
                        self._log_system_event("SYSTEM_INIT", "Operations log initialized")
                    elif log_file == self.evidence_log_file:
                        self._log_system_event("SYSTEM_INIT", "Evidence log initialized")
                    elif log_file == self.integrity_log_file:
                        self._log_system_event("SYSTEM_INIT", "Integrity log initialized")
                    elif log_file == self.audit_log_file:
                        self._log_system_event("SYSTEM_INIT", "Audit log initialized")
        
        except Exception as e:
            raise EvidenceLoggingError(f"Failed to initialize log files: {e}", "LOG_INIT")
    
    def _log_system_event(self, event_type: str, message: str):
        """Log system-level events"""
        system_log = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'message': message,
            'system': 'EvidenceLogger'
        }
        
        # Write directly to avoid recursion
        with open(self.audit_log_file, 'a') as f:
            f.write(json.dumps(system_log) + '\n')
    
    def log_operation(self,
                     case_id: str,
                     operation_type: str,
                     message: str,
                     device_serial: Optional[str] = None,
                     user_id: Optional[str] = None,
                     metadata: Optional[Dict[str, Any]] = None) -> OperationLog:
        """
        Log a forensic operation with timestamped integrity verification
        
        Args:
            case_id: Case identifier for the operation
            operation_type: Type of operation being performed
            message: Human-readable description of the operation
            device_serial: Serial number of the device involved
            user_id: ID of the user performing the operation
            metadata: Additional structured data about the operation
            
        Returns:
            OperationLog: The created operation log entry
            
        Raises:
            EvidenceLoggingError: If logging fails
        """
        if not case_id or not case_id.strip():
            raise EvidenceLoggingError("Case ID cannot be empty", "LOG_OPERATION")
        
        if not operation_type or not operation_type.strip():
            raise EvidenceLoggingError("Operation type cannot be empty", "LOG_OPERATION")
        
        if not message or not message.strip():
            raise EvidenceLoggingError("Message cannot be empty", "LOG_OPERATION")
        
        if metadata is None:
            metadata = {}
        
        # Add system metadata
        metadata.update({
            'logger_version': '1.0',
            'log_timestamp': datetime.now().isoformat(),
            'thread_id': threading.get_ident()
        })
        
        try:
            with self._lock:
                # Create operation log entry
                operation_log = OperationLog(
                    timestamp=datetime.now(),
                    case_id=case_id,
                    operation_type=operation_type,
                    device_serial=device_serial,
                    user_id=user_id,
                    message=message,
                    metadata=metadata
                )
                
                # Write to operations log file
                self._write_operation_log(operation_log)
                
                # Add to cache
                self._add_to_cache(operation_log)
                
                # Log integrity hash
                self._log_integrity_hash(operation_log)
                
                # Create audit trail entry
                self._create_audit_entry(operation_log)
                
                return operation_log
        
        except Exception as e:
            raise EvidenceLoggingError(f"Failed to log operation: {e}", "LOG_OPERATION")
    
    def _write_operation_log(self, operation_log: OperationLog):
        """Write operation log to file"""
        try:
            log_data = operation_log.to_dict()
            json_line = json.dumps(log_data) + '\n'
            
            if self.encrypt_logs:
                # Encrypt the log line
                encrypted_data = self.cipher.encrypt(json_line.encode('utf-8'))
                with open(self.operations_log_file, 'ab') as f:
                    f.write(encrypted_data + b'\n')
            else:
                with open(self.operations_log_file, 'a', encoding='utf-8') as f:
                    f.write(json_line)
        
        except Exception as e:
            raise EvidenceLoggingError(f"Failed to write operation log: {e}", "WRITE_LOG")
    
    def _add_to_cache(self, operation_log: OperationLog):
        """Add operation log to in-memory cache"""
        self._operation_cache.append(operation_log)
        
        # Maintain cache size limit
        if len(self._operation_cache) > self._cache_max_size:
            self._operation_cache.pop(0)  # Remove oldest entry
    
    def _log_integrity_hash(self, operation_log: OperationLog):
        """Log integrity hash for verification"""
        integrity_entry = {
            'timestamp': operation_log.timestamp.isoformat(),
            'case_id': operation_log.case_id,
            'operation_type': operation_log.operation_type,
            'hash_value': operation_log.hash_value,
            'verification_timestamp': datetime.now().isoformat()
        }
        
        with open(self.integrity_log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(integrity_entry) + '\n')
    
    def _create_audit_entry(self, operation_log: OperationLog):
        """Create audit trail entry"""
        audit_entry = {
            'timestamp': datetime.now().isoformat(),
            'case_id': operation_log.case_id,
            'operation_type': operation_log.operation_type,
            'user_id': operation_log.user_id,
            'device_serial': operation_log.device_serial,
            'message': operation_log.message,
            'hash_reference': operation_log.hash_value
        }
        
        with open(self.audit_log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(audit_entry) + '\n')
    
    def log_evidence_record(self, evidence_record: EvidenceRecord) -> OperationLog:
        """
        Log an evidence record with full chain of custody
        
        Args:
            evidence_record: The evidence record to log
            
        Returns:
            OperationLog: The created operation log entry
        """
        try:
            # Validate evidence record
            if not evidence_record.validate_all():
                raise EvidenceLoggingError(
                    f"Evidence record validation failed: {evidence_record.validation_errors}",
                    "LOG_EVIDENCE"
                )
            
            # Create metadata from evidence record
            metadata = {
                'evidence_type': evidence_record.evidence_type,
                'attempt_number': evidence_record.attempt_number,
                'result': evidence_record.result,
                'file_path': evidence_record.file_path,
                'file_size': evidence_record.file_size,
                'investigator_id': evidence_record.investigator_id,
                'case_notes': evidence_record.case_notes,
                'chain_of_custody': [event.to_dict() for event in evidence_record.chain_of_custody],
                'evidence_hash': evidence_record.hash_verification
            }
            
            # Log the evidence record
            operation_log = self.log_operation(
                case_id=evidence_record.case_id,
                operation_type=evidence_record.operation_type,
                message=f"Evidence recorded: {evidence_record.result}",
                device_serial=evidence_record.device_serial,
                user_id=evidence_record.investigator_id,
                metadata=metadata
            )
            
            # Also write to evidence-specific log
            self._write_evidence_log(evidence_record, operation_log)
            
            return operation_log
        
        except Exception as e:
            raise EvidenceLoggingError(f"Failed to log evidence record: {e}", "LOG_EVIDENCE")
    
    def _write_evidence_log(self, evidence_record: EvidenceRecord, operation_log: OperationLog):
        """Write evidence record to evidence-specific log"""
        evidence_entry = {
            'timestamp': datetime.now().isoformat(),
            'evidence_record': evidence_record.to_dict(),
            'operation_log_hash': operation_log.hash_value,
            'integrity_verified': evidence_record.verify_integrity()
        }
        
        json_line = json.dumps(evidence_entry) + '\n'
        
        if self.encrypt_logs:
            encrypted_data = self.cipher.encrypt(json_line.encode('utf-8'))
            with open(self.evidence_log_file, 'ab') as f:
                f.write(encrypted_data + b'\n')
        else:
            with open(self.evidence_log_file, 'a', encoding='utf-8') as f:
                f.write(json_line)
    
    def verify_integrity(self, case_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Verify SHA-256 hash integrity of all logged evidence
        
        Args:
            case_id: Optional case ID to filter verification
            
        Returns:
            Dict containing verification results
        """
        verification_results = {
            'timestamp': datetime.now().isoformat(),
            'case_id': case_id,
            'total_operations': 0,
            'verified_operations': 0,
            'failed_operations': 0,
            'corrupted_entries': [],
            'integrity_status': 'unknown'
        }
        
        try:
            with self._lock:
                # Get operations to verify
                operations = self.get_operations(case_id=case_id)
                
                verification_results['total_operations'] = len(operations)
                
                for operation in operations:
                    if operation.verify_integrity():
                        verification_results['verified_operations'] += 1
                    else:
                        verification_results['failed_operations'] += 1
                        verification_results['corrupted_entries'].append({
                            'timestamp': operation.timestamp.isoformat(),
                            'case_id': operation.case_id,
                            'operation_type': operation.operation_type,
                            'expected_hash': operation._calculate_hash(),
                            'stored_hash': operation.hash_value
                        })
                
                # Determine overall integrity status
                if verification_results['failed_operations'] == 0:
                    verification_results['integrity_status'] = 'verified'
                elif verification_results['verified_operations'] > 0:
                    verification_results['integrity_status'] = 'partial'
                else:
                    verification_results['integrity_status'] = 'failed'
                
                # Log the verification operation
                self.log_operation(
                    case_id=case_id or "SYSTEM",
                    operation_type="INTEGRITY_VERIFICATION",
                    message=f"Integrity verification completed: {verification_results['integrity_status']}",
                    metadata=verification_results
                )
        
        except Exception as e:
            verification_results['error'] = str(e)
            verification_results['integrity_status'] = 'error'
        
        return verification_results
    
    def get_operations(self, 
                      case_id: Optional[str] = None,
                      operation_type: Optional[str] = None,
                      start_time: Optional[datetime] = None,
                      end_time: Optional[datetime] = None) -> List[OperationLog]:
        """
        Retrieve operation logs with optional filtering
        
        Args:
            case_id: Filter by case ID
            operation_type: Filter by operation type
            start_time: Filter operations after this time
            end_time: Filter operations before this time
            
        Returns:
            List of matching operation logs
        """
        operations = []
        
        try:
            with self._lock:
                # First check cache for recent operations
                for operation in self._operation_cache:
                    if self._matches_filter(operation, case_id, operation_type, start_time, end_time):
                        operations.append(operation)
                
                # Read from file for complete history
                if self.operations_log_file.exists():
                    file_operations = self._read_operations_from_file()
                    
                    for operation in file_operations:
                        if self._matches_filter(operation, case_id, operation_type, start_time, end_time):
                            # Avoid duplicates from cache
                            if not any(op.hash_value == operation.hash_value for op in operations):
                                operations.append(operation)
                
                # Sort by timestamp
                operations.sort(key=lambda op: op.timestamp)
        
        except Exception as e:
            raise EvidenceLoggingError(f"Failed to retrieve operations: {e}", "GET_OPERATIONS")
        
        return operations
    
    def _matches_filter(self, 
                       operation: OperationLog,
                       case_id: Optional[str],
                       operation_type: Optional[str],
                       start_time: Optional[datetime],
                       end_time: Optional[datetime]) -> bool:
        """Check if operation matches filter criteria"""
        if case_id and operation.case_id != case_id:
            return False
        
        if operation_type and operation.operation_type != operation_type:
            return False
        
        if start_time and operation.timestamp < start_time:
            return False
        
        if end_time and operation.timestamp > end_time:
            return False
        
        return True
    
    def _read_operations_from_file(self) -> List[OperationLog]:
        """Read all operations from the log file"""
        operations = []
        
        try:
            with open(self.operations_log_file, 'rb' if self.encrypt_logs else 'r') as f:
                for line in f:
                    try:
                        if self.encrypt_logs:
                            # Skip empty lines
                            if not line.strip():
                                continue
                            # Decrypt line
                            decrypted_data = self.cipher.decrypt(line.strip())
                            json_data = json.loads(decrypted_data.decode('utf-8'))
                        else:
                            if not line.strip():
                                continue
                            json_data = json.loads(line.strip())
                        
                        # Create OperationLog from data
                        operation = OperationLog.from_dict(json_data)
                        operations.append(operation)
                    
                    except Exception as e:
                        # Log parsing error but continue
                        self._log_system_event("PARSE_ERROR", f"Failed to parse log line: {e}")
                        continue
        
        except Exception as e:
            raise EvidenceLoggingError(f"Failed to read operations file: {e}", "READ_FILE")
        
        return operations
    
    def generate_audit_trail(self, case_id: str) -> Dict[str, Any]:
        """
        Generate real-time audit trail for a case
        
        Args:
            case_id: Case ID to generate audit trail for
            
        Returns:
            Dict containing comprehensive audit trail
        """
        try:
            operations = self.get_operations(case_id=case_id)
            
            audit_trail = {
                'case_id': case_id,
                'generated_at': datetime.now().isoformat(),
                'total_operations': len(operations),
                'operations_by_type': {},
                'devices_involved': set(),
                'users_involved': set(),
                'timeline': [],
                'integrity_verification': self.verify_integrity(case_id),
                'chain_of_custody_events': []
            }
            
            # Analyze operations
            for operation in operations:
                # Count by operation type
                op_type = operation.operation_type
                if op_type not in audit_trail['operations_by_type']:
                    audit_trail['operations_by_type'][op_type] = 0
                audit_trail['operations_by_type'][op_type] += 1
                
                # Track devices and users
                if operation.device_serial:
                    audit_trail['devices_involved'].add(operation.device_serial)
                if operation.user_id:
                    audit_trail['users_involved'].add(operation.user_id)
                
                # Add to timeline
                timeline_entry = {
                    'timestamp': operation.timestamp.isoformat(),
                    'operation_type': operation.operation_type,
                    'message': operation.message,
                    'device_serial': operation.device_serial,
                    'user_id': operation.user_id,
                    'hash_value': operation.hash_value,
                    'integrity_verified': operation.verify_integrity()
                }
                audit_trail['timeline'].append(timeline_entry)
                
                # Extract chain of custody events from metadata
                if 'chain_of_custody' in operation.metadata:
                    audit_trail['chain_of_custody_events'].extend(
                        operation.metadata['chain_of_custody']
                    )
            
            # Convert sets to lists for JSON serialization
            audit_trail['devices_involved'] = list(audit_trail['devices_involved'])
            audit_trail['users_involved'] = list(audit_trail['users_involved'])
            
            # Sort timeline by timestamp
            audit_trail['timeline'].sort(key=lambda x: x['timestamp'])
            
            # Log audit trail generation
            self.log_operation(
                case_id=case_id,
                operation_type="AUDIT_TRAIL_GENERATION",
                message=f"Audit trail generated with {len(operations)} operations",
                metadata={
                    'operations_count': len(operations),
                    'devices_count': len(audit_trail['devices_involved']),
                    'users_count': len(audit_trail['users_involved'])
                }
            )
            
            return audit_trail
        
        except Exception as e:
            raise EvidenceLoggingError(f"Failed to generate audit trail: {e}", "AUDIT_TRAIL")
    
    def export_case_logs(self, case_id: str, export_path: str, include_metadata: bool = True) -> bool:
        """
        Export all logs for a case to a file
        
        Args:
            case_id: Case ID to export
            export_path: Path to export file
            include_metadata: Whether to include full metadata
            
        Returns:
            bool: True if export successful
        """
        try:
            export_file = Path(export_path)
            export_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Generate comprehensive export data
            export_data = {
                'export_info': {
                    'case_id': case_id,
                    'exported_at': datetime.now().isoformat(),
                    'exported_by': 'EvidenceLogger',
                    'include_metadata': include_metadata
                },
                'audit_trail': self.generate_audit_trail(case_id),
                'operations': []
            }
            
            # Add operation details
            operations = self.get_operations(case_id=case_id)
            for operation in operations:
                op_data = operation.to_dict()
                if not include_metadata:
                    # Remove sensitive metadata if requested
                    op_data.pop('metadata', None)
                export_data['operations'].append(op_data)
            
            # Write export file
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            # Log the export operation
            self.log_operation(
                case_id=case_id,
                operation_type="CASE_EXPORT",
                message=f"Case logs exported to {export_path}",
                metadata={
                    'export_path': str(export_file),
                    'operations_count': len(operations),
                    'include_metadata': include_metadata
                }
            )
            
            return True
        
        except Exception as e:
            raise EvidenceLoggingError(f"Failed to export case logs: {e}", "EXPORT_LOGS")
    
    def cleanup_old_logs(self, days_to_keep: int = 90) -> Dict[str, Any]:
        """
        Clean up old log entries while preserving integrity
        
        Args:
            days_to_keep: Number of days of logs to keep
            
        Returns:
            Dict with cleanup results
        """
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        cleanup_results = {
            'cutoff_date': cutoff_date.isoformat(),
            'operations_before_cleanup': 0,
            'operations_after_cleanup': 0,
            'operations_archived': 0,
            'files_processed': []
        }
        
        try:
            with self._lock:
                # This is a placeholder for log cleanup logic
                # In a production system, you'd want to archive rather than delete
                # to maintain forensic integrity
                
                self.log_operation(
                    case_id="SYSTEM",
                    operation_type="LOG_CLEANUP",
                    message=f"Log cleanup initiated for logs older than {days_to_keep} days",
                    metadata=cleanup_results
                )
        
        except Exception as e:
            raise EvidenceLoggingError(f"Failed to cleanup logs: {e}", "CLEANUP_LOGS")
        
        return cleanup_results