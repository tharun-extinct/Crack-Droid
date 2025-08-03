"""
Chain of Custody Manager for forensic evidence tracking

This module implements comprehensive chain of custody management with case ID tracking,
evidence handling documentation, tamper detection, and cryptographic verification.

Requirements implemented:
- 4.3: Chain-of-custody logging with SHA-256 hash verification
- 4.4: Formal case ID input for authorization
"""

import json
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

from ..interfaces import ForensicsException
from ..models.attack import EvidenceRecord, CustodyEvent


class CustodyEventType(Enum):
    """Types of chain of custody events"""
    CASE_CREATED = "case_created"
    EVIDENCE_COLLECTED = "evidence_collected"
    EVIDENCE_ACCESSED = "evidence_accessed"
    EVIDENCE_MODIFIED = "evidence_modified"
    EVIDENCE_TRANSFERRED = "evidence_transferred"
    EVIDENCE_ANALYZED = "evidence_analyzed"
    EVIDENCE_EXPORTED = "evidence_exported"
    EVIDENCE_ARCHIVED = "evidence_archived"
    EVIDENCE_DESTROYED = "evidence_destroyed"
    INTEGRITY_VERIFIED = "integrity_verified"
    TAMPER_DETECTED = "tamper_detected"


class CustodyValidationError(ForensicsException):
    """Exception raised for chain of custody validation errors"""
    
    def __init__(self, message: str, case_id: str = None):
        super().__init__(message, "CUSTODY_VALIDATION_ERROR", evidence_impact=True)
        self.case_id = case_id


@dataclass
class CaseMetadata:
    """Metadata for a forensic case"""
    case_id: str
    investigator_id: str
    case_title: str
    case_description: str
    created_at: datetime
    authorized_users: List[str] = field(default_factory=list)
    case_status: str = "active"
    evidence_count: int = 0
    last_activity: Optional[datetime] = None
    case_notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'case_id': self.case_id,
            'investigator_id': self.investigator_id,
            'case_title': self.case_title,
            'case_description': self.case_description,
            'created_at': self.created_at.isoformat(),
            'authorized_users': self.authorized_users,
            'case_status': self.case_status,
            'evidence_count': self.evidence_count,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None,
            'case_notes': self.case_notes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CaseMetadata':
        """Create from dictionary"""
        return cls(
            case_id=data['case_id'],
            investigator_id=data['investigator_id'],
            case_title=data['case_title'],
            case_description=data['case_description'],
            created_at=datetime.fromisoformat(data['created_at']),
            authorized_users=data.get('authorized_users', []),
            case_status=data.get('case_status', 'active'),
            evidence_count=data.get('evidence_count', 0),
            last_activity=datetime.fromisoformat(data['last_activity']) if data.get('last_activity') else None,
            case_notes=data.get('case_notes', '')
        )


class ChainOfCustody:
    """
    Chain of Custody Manager for forensic evidence tracking
    
    This class implements comprehensive chain of custody management with:
    - Case ID tracking and validation
    - Evidence handling documentation
    - Tamper detection mechanisms
    - Custody event logging with cryptographic verification
    
    Requirements:
    - 4.3: Chain-of-custody logging with SHA-256 hash verification
    - 4.4: Formal case ID input for authorization
    """
    
    def __init__(self, storage_path: str = "evidence", secret_key: Optional[str] = None):
        """
        Initialize Chain of Custody manager
        
        Args:
            storage_path: Path to evidence storage directory
            secret_key: Secret key for HMAC verification (generated if None)
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        
        # Initialize cryptographic key for tamper detection
        self.secret_key = secret_key or self._generate_secret_key()
        
        # In-memory cache for active cases
        self._case_cache: Dict[str, CaseMetadata] = {}
        self._evidence_cache: Dict[str, List[EvidenceRecord]] = {}
        
        # Load existing cases
        self._load_existing_cases()
    
    def _generate_secret_key(self) -> str:
        """Generate a secure secret key for HMAC operations"""
        return secrets.token_hex(32)
    
    def _load_existing_cases(self):
        """Load existing cases from storage"""
        cases_file = self.storage_path / "cases_metadata.json"
        if cases_file.exists():
            try:
                with open(cases_file, 'r') as f:
                    cases_data = json.load(f)
                    for case_data in cases_data:
                        case_metadata = CaseMetadata.from_dict(case_data)
                        self._case_cache[case_metadata.case_id] = case_metadata
            except Exception as e:
                raise CustodyValidationError(f"Failed to load existing cases: {str(e)}")
    
    def _save_cases_metadata(self):
        """Save cases metadata to storage"""
        cases_file = self.storage_path / "cases_metadata.json"
        try:
            cases_data = [case.to_dict() for case in self._case_cache.values()]
            with open(cases_file, 'w') as f:
                json.dump(cases_data, f, indent=2)
        except Exception as e:
            raise CustodyValidationError(f"Failed to save cases metadata: {str(e)}")
    
    def _compute_evidence_hash(self, evidence: EvidenceRecord) -> str:
        """
        Compute SHA-256 hash of evidence record for integrity verification
        
        Args:
            evidence: Evidence record to hash
            
        Returns:
            str: SHA-256 hash of evidence
        """
        # Create a canonical representation for hashing
        hash_data = {
            'case_id': evidence.case_id,
            'timestamp': evidence.timestamp.isoformat(),
            'operation_type': evidence.operation_type,
            'device_serial': evidence.device_serial,
            'attempt_number': evidence.attempt_number,
            'result': evidence.result,
            'evidence_type': evidence.evidence_type,
            'file_path': evidence.file_path,
            'file_size': evidence.file_size,
            'investigator_id': evidence.investigator_id
        }
        
        # Convert to JSON and compute hash
        json_str = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()
    
    def _compute_custody_signature(self, event: CustodyEvent) -> str:
        """
        Compute HMAC signature for custody event to prevent tampering
        
        Args:
            event: Custody event to sign
            
        Returns:
            str: HMAC signature
        """
        event_data = f"{event.timestamp.isoformat()}|{event.event_type}|{event.user_id}|{event.description}"
        return hmac.new(
            self.secret_key.encode(),
            event_data.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def _verify_custody_signature(self, event: CustodyEvent, signature: str) -> bool:
        """
        Verify HMAC signature for custody event
        
        Args:
            event: Custody event to verify
            signature: Expected signature
            
        Returns:
            bool: True if signature is valid
        """
        expected_signature = self._compute_custody_signature(event)
        return hmac.compare_digest(expected_signature, signature)
    
    def validate_case_id(self, case_id: str) -> bool:
        """
        Validate case ID format and authorization
        
        Args:
            case_id: Case ID to validate
            
        Returns:
            bool: True if case ID is valid
            
        Raises:
            CustodyValidationError: If case ID is invalid
        """
        if not case_id or not case_id.strip():
            raise CustodyValidationError("Case ID cannot be empty")
        
        # Case ID format validation (alphanumeric with dashes/underscores)
        import re
        if not re.match(r'^[A-Za-z0-9_-]+$', case_id):
            raise CustodyValidationError("Case ID contains invalid characters", case_id)
        
        if len(case_id) < 3 or len(case_id) > 50:
            raise CustodyValidationError("Case ID length outside acceptable range (3-50 characters)", case_id)
        
        return True
    
    def create_case(self, case_id: str, investigator_id: str, case_title: str, 
                   case_description: str, authorized_users: List[str] = None) -> CaseMetadata:
        """
        Create a new forensic case with formal case ID
        
        Args:
            case_id: Unique case identifier
            investigator_id: ID of primary investigator
            case_title: Title of the case
            case_description: Description of the case
            authorized_users: List of authorized user IDs
            
        Returns:
            CaseMetadata: Created case metadata
            
        Raises:
            CustodyValidationError: If case creation fails
        """
        # Validate case ID
        self.validate_case_id(case_id)
        
        # Check if case already exists
        if case_id in self._case_cache:
            raise CustodyValidationError(f"Case {case_id} already exists", case_id)
        
        # Create case metadata
        case_metadata = CaseMetadata(
            case_id=case_id,
            investigator_id=investigator_id,
            case_title=case_title,
            case_description=case_description,
            created_at=datetime.now(),
            authorized_users=authorized_users or [investigator_id],
            case_status="active"
        )
        
        # Store in cache and persist
        self._case_cache[case_id] = case_metadata
        self._evidence_cache[case_id] = []
        self._save_cases_metadata()
        
        # Create initial custody event
        self.log_custody_event(
            case_id=case_id,
            event_type=CustodyEventType.CASE_CREATED,
            user_id=investigator_id,
            description=f"Case created: {case_title}"
        )
        
        return case_metadata
    
    def get_case_metadata(self, case_id: str) -> Optional[CaseMetadata]:
        """
        Get case metadata by case ID
        
        Args:
            case_id: Case ID to retrieve
            
        Returns:
            CaseMetadata: Case metadata if found, None otherwise
        """
        return self._case_cache.get(case_id)
    
    def authorize_user_for_case(self, case_id: str, user_id: str, authorizing_user: str):
        """
        Authorize a user for case access
        
        Args:
            case_id: Case ID
            user_id: User to authorize
            authorizing_user: User performing the authorization
            
        Raises:
            CustodyValidationError: If authorization fails
        """
        case_metadata = self.get_case_metadata(case_id)
        if not case_metadata:
            raise CustodyValidationError(f"Case {case_id} not found", case_id)
        
        # Check if authorizing user has permission
        if authorizing_user not in case_metadata.authorized_users:
            raise CustodyValidationError(f"User {authorizing_user} not authorized for case {case_id}", case_id)
        
        # Add user to authorized list
        if user_id not in case_metadata.authorized_users:
            case_metadata.authorized_users.append(user_id)
            self._save_cases_metadata()
            
            # Log custody event
            self.log_custody_event(
                case_id=case_id,
                event_type=CustodyEventType.EVIDENCE_ACCESSED,
                user_id=authorizing_user,
                description=f"Authorized user {user_id} for case access"
            )
    
    def log_custody_event(self, case_id: str, event_type: CustodyEventType, 
                         user_id: str, description: str, 
                         hash_before: str = None, hash_after: str = None) -> CustodyEvent:
        """
        Log a chain of custody event with cryptographic verification
        
        Args:
            case_id: Case ID
            event_type: Type of custody event
            user_id: User performing the action
            description: Description of the action
            hash_before: Hash before the action
            hash_after: Hash after the action
            
        Returns:
            CustodyEvent: Created custody event
            
        Raises:
            CustodyValidationError: If logging fails
        """
        # Validate case exists
        case_metadata = self.get_case_metadata(case_id)
        if not case_metadata:
            raise CustodyValidationError(f"Case {case_id} not found", case_id)
        
        # Check user authorization (allow system operations)
        if user_id != "system" and user_id not in case_metadata.authorized_users:
            raise CustodyValidationError(f"User {user_id} not authorized for case {case_id}", case_id)
        
        # Create custody event
        event = CustodyEvent(
            timestamp=datetime.now(),
            event_type=event_type.value,
            user_id=user_id,
            description=description,
            hash_before=hash_before,
            hash_after=hash_after
        )
        
        # Update case metadata
        case_metadata.last_activity = event.timestamp
        self._save_cases_metadata()
        
        # Save custody event to case log
        self._save_custody_event(case_id, event)
        
        return event
    
    def _save_custody_event(self, case_id: str, event: CustodyEvent):
        """
        Save custody event to case log file
        
        Args:
            case_id: Case ID
            event: Custody event to save
        """
        case_dir = self.storage_path / case_id
        case_dir.mkdir(exist_ok=True)
        
        custody_log_file = case_dir / "custody_log.json"
        
        # Load existing events
        events = []
        if custody_log_file.exists():
            try:
                with open(custody_log_file, 'r') as f:
                    events_data = json.load(f)
                    events = [CustodyEvent.from_dict(event_data) for event_data in events_data]
            except Exception as e:
                raise CustodyValidationError(f"Failed to load custody log: {str(e)}", case_id)
        
        # Add new event with signature
        events.append(event)
        
        # Save with cryptographic signature
        events_data = []
        for e in events:
            event_dict = e.to_dict()
            event_dict['signature'] = self._compute_custody_signature(e)
            events_data.append(event_dict)
        
        try:
            with open(custody_log_file, 'w') as f:
                json.dump(events_data, f, indent=2)
        except Exception as e:
            raise CustodyValidationError(f"Failed to save custody event: {str(e)}", case_id)
    
    def add_evidence_record(self, evidence: EvidenceRecord, user_id: str) -> str:
        """
        Add evidence record with chain of custody tracking
        
        Args:
            evidence: Evidence record to add
            user_id: User adding the evidence
            
        Returns:
            str: Evidence hash for verification
            
        Raises:
            CustodyValidationError: If evidence addition fails
        """
        # Validate case exists and user is authorized
        case_metadata = self.get_case_metadata(evidence.case_id)
        if not case_metadata:
            raise CustodyValidationError(f"Case {evidence.case_id} not found", evidence.case_id)
        
        if user_id not in case_metadata.authorized_users:
            raise CustodyValidationError(f"User {user_id} not authorized for case {evidence.case_id}", evidence.case_id)
        
        # Compute evidence hash
        evidence_hash = self._compute_evidence_hash(evidence)
        evidence.hash_verification = evidence_hash
        
        # Add to cache
        if evidence.case_id not in self._evidence_cache:
            self._evidence_cache[evidence.case_id] = []
        self._evidence_cache[evidence.case_id].append(evidence)
        
        # Update case metadata
        case_metadata.evidence_count += 1
        case_metadata.last_activity = datetime.now()
        self._save_cases_metadata()
        
        # Save evidence record
        self._save_evidence_record(evidence)
        
        # Log custody event
        self.log_custody_event(
            case_id=evidence.case_id,
            event_type=CustodyEventType.EVIDENCE_COLLECTED,
            user_id=user_id,
            description=f"Evidence collected: {evidence.operation_type} on {evidence.device_serial}",
            hash_after=evidence_hash
        )
        
        return evidence_hash
    
    def _save_evidence_record(self, evidence: EvidenceRecord):
        """
        Save evidence record to storage
        
        Args:
            evidence: Evidence record to save
        """
        case_dir = self.storage_path / evidence.case_id
        case_dir.mkdir(exist_ok=True)
        
        evidence_file = case_dir / f"evidence_{evidence.timestamp.strftime('%Y%m%d_%H%M%S')}_{evidence.attempt_number}.json"
        
        try:
            with open(evidence_file, 'w') as f:
                json.dump(evidence.to_dict(), f, indent=2)
        except Exception as e:
            raise CustodyValidationError(f"Failed to save evidence record: {str(e)}", evidence.case_id)
    
    def verify_evidence_integrity(self, case_id: str, evidence_hash: str) -> Tuple[bool, List[str]]:
        """
        Verify evidence integrity using hash verification
        
        Args:
            case_id: Case ID
            evidence_hash: Expected evidence hash
            
        Returns:
            Tuple[bool, List[str]]: (integrity_valid, error_messages)
        """
        errors = []
        
        # Find evidence record
        evidence_records = self._evidence_cache.get(case_id, [])
        target_evidence = None
        
        for evidence in evidence_records:
            if evidence.hash_verification == evidence_hash:
                target_evidence = evidence
                break
        
        if not target_evidence:
            errors.append(f"Evidence with hash {evidence_hash} not found in case {case_id}")
            return False, errors
        
        # Recompute hash and compare
        computed_hash = self._compute_evidence_hash(target_evidence)
        if computed_hash != evidence_hash:
            errors.append(f"Evidence hash mismatch: expected {evidence_hash}, computed {computed_hash}")
            
            # Log tamper detection
            self.log_custody_event(
                case_id=case_id,
                event_type=CustodyEventType.TAMPER_DETECTED,
                user_id="system",
                description=f"Evidence integrity verification failed for hash {evidence_hash}",
                hash_before=evidence_hash,
                hash_after=computed_hash
            )
            
            return False, errors
        
        # Verify custody chain integrity
        custody_errors = self._verify_custody_chain_integrity(case_id)
        if custody_errors:
            errors.extend(custody_errors)
            return False, errors
        
        # Log successful verification
        self.log_custody_event(
            case_id=case_id,
            event_type=CustodyEventType.INTEGRITY_VERIFIED,
            user_id="system",
            description=f"Evidence integrity verified for hash {evidence_hash}",
            hash_after=evidence_hash
        )
        
        return True, []
    
    def _verify_custody_chain_integrity(self, case_id: str) -> List[str]:
        """
        Verify custody chain integrity using cryptographic signatures
        
        Args:
            case_id: Case ID to verify
            
        Returns:
            List[str]: List of integrity errors
        """
        errors = []
        
        case_dir = self.storage_path / case_id
        custody_log_file = case_dir / "custody_log.json"
        
        if not custody_log_file.exists():
            errors.append(f"Custody log not found for case {case_id}")
            return errors
        
        try:
            with open(custody_log_file, 'r') as f:
                events_data = json.load(f)
            
            for i, event_data in enumerate(events_data):
                # Reconstruct event
                event = CustodyEvent.from_dict(event_data)
                expected_signature = event_data.get('signature')
                
                if not expected_signature:
                    errors.append(f"Missing signature for custody event {i}")
                    continue
                
                # Verify signature
                if not self._verify_custody_signature(event, expected_signature):
                    errors.append(f"Invalid signature for custody event {i}: {event.description}")
                
                # Check chronological order
                if i > 0:
                    prev_event = CustodyEvent.from_dict(events_data[i-1])
                    if event.timestamp < prev_event.timestamp:
                        errors.append(f"Custody events not in chronological order at position {i}")
        
        except Exception as e:
            errors.append(f"Failed to verify custody chain: {str(e)}")
        
        return errors
    
    def get_custody_chain(self, case_id: str) -> List[CustodyEvent]:
        """
        Get complete custody chain for a case
        
        Args:
            case_id: Case ID
            
        Returns:
            List[CustodyEvent]: List of custody events
            
        Raises:
            CustodyValidationError: If case not found
        """
        if case_id not in self._case_cache:
            raise CustodyValidationError(f"Case {case_id} not found", case_id)
        
        case_dir = self.storage_path / case_id
        custody_log_file = case_dir / "custody_log.json"
        
        if not custody_log_file.exists():
            return []
        
        try:
            with open(custody_log_file, 'r') as f:
                events_data = json.load(f)
                return [CustodyEvent.from_dict(event_data) for event_data in events_data]
        except Exception as e:
            raise CustodyValidationError(f"Failed to load custody chain: {str(e)}", case_id)
    
    def get_evidence_records(self, case_id: str) -> List[EvidenceRecord]:
        """
        Get all evidence records for a case
        
        Args:
            case_id: Case ID
            
        Returns:
            List[EvidenceRecord]: List of evidence records
            
        Raises:
            CustodyValidationError: If case not found
        """
        if case_id not in self._case_cache:
            raise CustodyValidationError(f"Case {case_id} not found", case_id)
        
        return self._evidence_cache.get(case_id, [])
    
    def detect_tampering(self, case_id: str) -> Tuple[bool, List[str]]:
        """
        Detect potential tampering in case evidence and custody chain
        
        Args:
            case_id: Case ID to check
            
        Returns:
            Tuple[bool, List[str]]: (tampering_detected, issues_found)
        """
        issues = []
        
        # Verify custody chain integrity
        custody_errors = self._verify_custody_chain_integrity(case_id)
        if custody_errors:
            issues.extend(custody_errors)
        
        # Verify all evidence records
        evidence_records = self.get_evidence_records(case_id)
        for evidence in evidence_records:
            computed_hash = self._compute_evidence_hash(evidence)
            if computed_hash != evidence.hash_verification:
                issues.append(f"Evidence tampering detected: {evidence.operation_type} on {evidence.device_serial}")
        
        # Check for gaps in custody chain
        custody_events = self.get_custody_chain(case_id)
        if len(custody_events) < 2:  # Should have at least case creation + one evidence event
            issues.append("Insufficient custody events - possible gap in chain")
        
        # Check for suspicious time gaps
        for i in range(1, len(custody_events)):
            time_gap = custody_events[i].timestamp - custody_events[i-1].timestamp
            if time_gap > timedelta(hours=24):
                issues.append(f"Large time gap in custody chain: {time_gap} between events")
        
        tampering_detected = len(issues) > 0
        
        if tampering_detected:
            # Log tamper detection
            self.log_custody_event(
                case_id=case_id,
                event_type=CustodyEventType.TAMPER_DETECTED,
                user_id="system",
                description=f"Tampering detection scan found {len(issues)} issues"
            )
        
        return tampering_detected, issues
    
    def generate_custody_report(self, case_id: str) -> Dict[str, Any]:
        """
        Generate comprehensive custody report for a case
        
        Args:
            case_id: Case ID
            
        Returns:
            Dict[str, Any]: Custody report data
            
        Raises:
            CustodyValidationError: If case not found
        """
        case_metadata = self.get_case_metadata(case_id)
        if not case_metadata:
            raise CustodyValidationError(f"Case {case_id} not found", case_id)
        
        custody_events = self.get_custody_chain(case_id)
        evidence_records = self.get_evidence_records(case_id)
        tampering_detected, tampering_issues = self.detect_tampering(case_id)
        
        # Generate integrity verification results
        integrity_results = []
        for evidence in evidence_records:
            is_valid, errors = self.verify_evidence_integrity(case_id, evidence.hash_verification)
            integrity_results.append({
                'evidence_hash': evidence.hash_verification,
                'operation_type': evidence.operation_type,
                'device_serial': evidence.device_serial,
                'integrity_valid': is_valid,
                'errors': errors
            })
        
        report = {
            'case_metadata': case_metadata.to_dict(),
            'custody_chain': [event.to_dict() for event in custody_events],
            'evidence_records': [evidence.to_dict() for evidence in evidence_records],
            'integrity_verification': integrity_results,
            'tampering_detection': {
                'tampering_detected': tampering_detected,
                'issues_found': tampering_issues
            },
            'report_generated_at': datetime.now().isoformat(),
            'total_custody_events': len(custody_events),
            'total_evidence_records': len(evidence_records)
        }
        
        # Log report generation
        self.log_custody_event(
            case_id=case_id,
            event_type=CustodyEventType.EVIDENCE_EXPORTED,
            user_id="system",
            description="Custody report generated"
        )
        
        return report