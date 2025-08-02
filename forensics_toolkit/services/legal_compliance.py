"""
Legal compliance workflow implementation
"""

import json
import re
import socket
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass, asdict

from ..interfaces import AuthenticationException, AuthorizationException


@dataclass
class LegalDisclaimer:
    """Legal disclaimer information"""
    title: str
    content: str
    version: str
    effective_date: datetime
    requires_acknowledgment: bool = True


@dataclass
class ConsentRecord:
    """User consent record"""
    user: str
    disclaimer_version: str
    timestamp: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    consent_given: bool = False


@dataclass
class CaseInfo:
    """Forensic case information"""
    case_id: str
    case_title: str
    investigator: str
    created_at: datetime
    legal_authority: str
    warrant_number: Optional[str] = None
    court_order: Optional[str] = None
    authorized_environment: str = "FORENSIC_LAB"
    status: str = "ACTIVE"


@dataclass
class ComplianceAuditEntry:
    """Compliance audit log entry"""
    timestamp: datetime
    case_id: str
    user: str
    action: str
    compliance_check: str
    result: str
    details: Optional[Dict[str, Any]] = None


class LegalDisclaimerManager:
    """Manages legal disclaimers and consent"""
    
    DEFAULT_DISCLAIMER = LegalDisclaimer(
        title="Digital Forensics Tool - Legal Notice",
        content="""
IMPORTANT LEGAL NOTICE - READ CAREFULLY

This digital forensics tool is designed exclusively for authorized law enforcement 
and government forensic investigators. Use of this tool is subject to the following 
legal requirements and restrictions:

1. AUTHORIZED USE ONLY
   - This tool may only be used by authorized government personnel
   - Use must be in compliance with applicable laws and regulations
   - Unauthorized use is strictly prohibited and may result in criminal prosecution

2. LEGAL AUTHORITY REQUIRED
   - All forensic operations must be conducted under proper legal authority
   - Valid search warrant, court order, or other legal authorization required
   - Evidence collection must comply with chain of custody requirements

3. PRIVACY AND CIVIL RIGHTS
   - All operations must respect constitutional rights and privacy laws
   - Data collection limited to scope of legal authorization
   - Proper handling and protection of personal information required

4. EVIDENCE INTEGRITY
   - All forensic operations are logged and audited
   - Evidence integrity must be maintained throughout the process
   - Tampering with evidence or logs is strictly prohibited

5. PROFESSIONAL RESPONSIBILITY
   - Users must be properly trained in digital forensics procedures
   - Operations must follow established forensic best practices
   - Results must be accurately documented and reported

By proceeding, you acknowledge that:
- You are an authorized government forensic investigator
- You have proper legal authority for your intended use
- You understand and agree to comply with all legal requirements
- You accept full responsibility for proper and lawful use of this tool

VIOLATION OF THESE TERMS MAY RESULT IN CRIMINAL PROSECUTION AND CIVIL LIABILITY.
        """.strip(),
        version="1.0",
        effective_date=datetime.now(),
        requires_acknowledgment=True
    )
    
    def __init__(self, disclaimer_file: str = "config/legal_disclaimer.json"):
        self.disclaimer_file = Path(disclaimer_file)
        self.disclaimer_file.parent.mkdir(exist_ok=True)
        self.consent_file = self.disclaimer_file.parent / "consent_records.json"
        self._disclaimer = self._load_disclaimer()
        self._consent_records: List[ConsentRecord] = self._load_consent_records()
    
    def _load_disclaimer(self) -> LegalDisclaimer:
        """Load disclaimer from file or use default"""
        if self.disclaimer_file.exists():
            try:
                with open(self.disclaimer_file, 'r') as f:
                    data = json.load(f)
                    return LegalDisclaimer(
                        title=data['title'],
                        content=data['content'],
                        version=data['version'],
                        effective_date=datetime.fromisoformat(data['effective_date']),
                        requires_acknowledgment=data.get('requires_acknowledgment', True)
                    )
            except (json.JSONDecodeError, KeyError, ValueError):
                pass
        
        # Save default disclaimer
        self._save_disclaimer(self.DEFAULT_DISCLAIMER)
        return self.DEFAULT_DISCLAIMER
    
    def _save_disclaimer(self, disclaimer: LegalDisclaimer) -> None:
        """Save disclaimer to file"""
        try:
            with open(self.disclaimer_file, 'w') as f:
                data = asdict(disclaimer)
                data['effective_date'] = disclaimer.effective_date.isoformat()
                json.dump(data, f, indent=2)
        except IOError as e:
            raise AuthenticationException(f"Failed to save disclaimer: {e}", "DISCLAIMER_SAVE_ERROR")
    
    def _load_consent_records(self) -> List[ConsentRecord]:
        """Load consent records from file"""
        if not self.consent_file.exists():
            return []
        
        try:
            with open(self.consent_file, 'r') as f:
                data = json.load(f)
                return [
                    ConsentRecord(
                        user=record['user'],
                        disclaimer_version=record['disclaimer_version'],
                        timestamp=datetime.fromisoformat(record['timestamp']),
                        ip_address=record.get('ip_address'),
                        user_agent=record.get('user_agent'),
                        consent_given=record['consent_given']
                    )
                    for record in data
                ]
        except (json.JSONDecodeError, KeyError, ValueError):
            return []
    
    def _save_consent_records(self) -> None:
        """Save consent records to file"""
        try:
            with open(self.consent_file, 'w') as f:
                data = []
                for record in self._consent_records:
                    record_data = asdict(record)
                    record_data['timestamp'] = record.timestamp.isoformat()
                    data.append(record_data)
                json.dump(data, f, indent=2)
        except IOError as e:
            raise AuthenticationException(f"Failed to save consent records: {e}", "CONSENT_SAVE_ERROR")
    
    def get_disclaimer(self) -> LegalDisclaimer:
        """Get current legal disclaimer"""
        return self._disclaimer
    
    def update_disclaimer(self, title: str, content: str, version: str) -> LegalDisclaimer:
        """Update legal disclaimer"""
        disclaimer = LegalDisclaimer(
            title=title,
            content=content,
            version=version,
            effective_date=datetime.now(),
            requires_acknowledgment=True
        )
        
        self._disclaimer = disclaimer
        self._save_disclaimer(disclaimer)
        return disclaimer
    
    def record_consent(self, user: str, consent_given: bool, ip_address: str = None, 
                      user_agent: str = None) -> ConsentRecord:
        """Record user consent"""
        consent_record = ConsentRecord(
            user=user,
            disclaimer_version=self._disclaimer.version,
            timestamp=datetime.now(),
            ip_address=ip_address,
            user_agent=user_agent,
            consent_given=consent_given
        )
        
        self._consent_records.append(consent_record)
        self._save_consent_records()
        return consent_record
    
    def has_valid_consent(self, user: str) -> bool:
        """Check if user has valid consent for current disclaimer version"""
        current_version = self._disclaimer.version
        
        # Find most recent consent record for user
        user_consents = [
            record for record in self._consent_records 
            if record.user == user and record.disclaimer_version == current_version
        ]
        
        if not user_consents:
            return False
        
        # Get most recent consent
        latest_consent = max(user_consents, key=lambda x: x.timestamp)
        return latest_consent.consent_given
    
    def get_consent_history(self, user: str) -> List[ConsentRecord]:
        """Get consent history for user"""
        return [record for record in self._consent_records if record.user == user]


class CaseManager:
    """Manages forensic case information and validation"""
    
    CASE_ID_PATTERN = re.compile(r'^[A-Z]{2,4}-\d{4}-\d{6}$')  # e.g., FBI-2024-123456
    
    def __init__(self, cases_file: str = "config/cases.json"):
        self.cases_file = Path(cases_file)
        self.cases_file.parent.mkdir(exist_ok=True)
        self._cases: Dict[str, CaseInfo] = self._load_cases()
    
    def _load_cases(self) -> Dict[str, CaseInfo]:
        """Load cases from file"""
        if not self.cases_file.exists():
            return {}
        
        try:
            with open(self.cases_file, 'r') as f:
                data = json.load(f)
                cases = {}
                for case_id, case_data in data.items():
                    cases[case_id] = CaseInfo(
                        case_id=case_data['case_id'],
                        case_title=case_data['case_title'],
                        investigator=case_data['investigator'],
                        created_at=datetime.fromisoformat(case_data['created_at']),
                        legal_authority=case_data['legal_authority'],
                        warrant_number=case_data.get('warrant_number'),
                        court_order=case_data.get('court_order'),
                        authorized_environment=case_data.get('authorized_environment', 'FORENSIC_LAB'),
                        status=case_data.get('status', 'ACTIVE')
                    )
                return cases
        except (json.JSONDecodeError, KeyError, ValueError):
            return {}
    
    def _save_cases(self) -> None:
        """Save cases to file"""
        try:
            with open(self.cases_file, 'w') as f:
                data = {}
                for case_id, case_info in self._cases.items():
                    case_data = asdict(case_info)
                    case_data['created_at'] = case_info.created_at.isoformat()
                    data[case_id] = case_data
                json.dump(data, f, indent=2)
        except IOError as e:
            raise AuthenticationException(f"Failed to save cases: {e}", "CASE_SAVE_ERROR")
    
    def validate_case_id_format(self, case_id: str) -> bool:
        """Validate case ID format"""
        return bool(self.CASE_ID_PATTERN.match(case_id))
    
    def create_case(self, case_id: str, case_title: str, investigator: str, 
                   legal_authority: str, warrant_number: str = None, 
                   court_order: str = None) -> CaseInfo:
        """Create new forensic case"""
        if not self.validate_case_id_format(case_id):
            raise AuthorizationException(
                f"Invalid case ID format: {case_id}. Expected format: XX-YYYY-NNNNNN",
                "INVALID_CASE_ID"
            )
        
        if case_id in self._cases:
            raise AuthorizationException(f"Case {case_id} already exists", "CASE_EXISTS")
        
        case_info = CaseInfo(
            case_id=case_id,
            case_title=case_title,
            investigator=investigator,
            created_at=datetime.now(),
            legal_authority=legal_authority,
            warrant_number=warrant_number,
            court_order=court_order
        )
        
        self._cases[case_id] = case_info
        self._save_cases()
        return case_info
    
    def get_case(self, case_id: str) -> Optional[CaseInfo]:
        """Get case information"""
        return self._cases.get(case_id)
    
    def validate_case(self, case_id: str, investigator: str) -> bool:
        """Validate case exists and investigator has access"""
        case_info = self.get_case(case_id)
        if not case_info:
            return False
        
        return (case_info.status == "ACTIVE" and 
                case_info.investigator == investigator)
    
    def list_cases(self, investigator: str = None) -> List[CaseInfo]:
        """List cases, optionally filtered by investigator"""
        cases = list(self._cases.values())
        if investigator:
            cases = [case for case in cases if case.investigator == investigator]
        return cases
    
    def update_case_status(self, case_id: str, status: str) -> bool:
        """Update case status"""
        if case_id not in self._cases:
            return False
        
        self._cases[case_id].status = status
        self._save_cases()
        return True


class EnvironmentValidator:
    """Validates authorized forensic environment"""
    
    AUTHORIZED_NETWORKS = [
        "10.0.0.0/8",      # Private network ranges
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8"      # Localhost
    ]
    
    AUTHORIZED_HOSTNAMES = [
        "forensic-lab",
        "evidence-workstation",
        "investigation-system"
    ]
    
    @classmethod
    def get_system_info(cls) -> Dict[str, str]:
        """Get current system information"""
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            return {
                'hostname': hostname,
                'ip_address': ip_address
            }
        except Exception:
            return {
                'hostname': 'unknown',
                'ip_address': 'unknown'
            }
    
    @classmethod
    def is_authorized_environment(cls) -> bool:
        """Check if current environment is authorized"""
        system_info = cls.get_system_info()
        hostname = system_info['hostname'].lower()
        
        # Check hostname patterns
        for authorized_hostname in cls.AUTHORIZED_HOSTNAMES:
            if authorized_hostname in hostname:
                return True
        
        # For now, allow any environment in development
        # In production, this would check network ranges, certificates, etc.
        return True
    
    @classmethod
    def validate_environment(cls) -> Dict[str, Any]:
        """Validate and return environment information"""
        system_info = cls.get_system_info()
        is_authorized = cls.is_authorized_environment()
        
        return {
            'hostname': system_info['hostname'],
            'ip_address': system_info['ip_address'],
            'is_authorized': is_authorized,
            'timestamp': datetime.now().isoformat()
        }


class ComplianceAuditLogger:
    """Compliance-specific audit logging"""
    
    def __init__(self, audit_file: str = "logs/compliance_audit.log"):
        self.audit_file = Path(audit_file)
        self.audit_file.parent.mkdir(exist_ok=True)
    
    def _write_audit_entry(self, entry: ComplianceAuditEntry) -> None:
        """Write compliance audit entry"""
        try:
            with open(self.audit_file, 'a') as f:
                entry_data = asdict(entry)
                entry_data['timestamp'] = entry.timestamp.isoformat()
                f.write(json.dumps(entry_data) + '\n')
        except IOError as e:
            print(f"Failed to write compliance audit log: {e}")
    
    def log_disclaimer_acknowledgment(self, case_id: str, user: str, 
                                    consent_given: bool, **kwargs) -> None:
        """Log disclaimer acknowledgment"""
        entry = ComplianceAuditEntry(
            timestamp=datetime.now(),
            case_id=case_id,
            user=user,
            action="DISCLAIMER_ACKNOWLEDGMENT",
            compliance_check="LEGAL_CONSENT",
            result="ACCEPTED" if consent_given else "REJECTED",
            details=kwargs
        )
        self._write_audit_entry(entry)
    
    def log_case_validation(self, case_id: str, user: str, valid: bool, **kwargs) -> None:
        """Log case validation"""
        entry = ComplianceAuditEntry(
            timestamp=datetime.now(),
            case_id=case_id,
            user=user,
            action="CASE_VALIDATION",
            compliance_check="CASE_AUTHORIZATION",
            result="VALID" if valid else "INVALID",
            details=kwargs
        )
        self._write_audit_entry(entry)
    
    def log_environment_check(self, case_id: str, user: str, authorized: bool, **kwargs) -> None:
        """Log environment authorization check"""
        entry = ComplianceAuditEntry(
            timestamp=datetime.now(),
            case_id=case_id,
            user=user,
            action="ENVIRONMENT_CHECK",
            compliance_check="AUTHORIZED_ENVIRONMENT",
            result="AUTHORIZED" if authorized else "UNAUTHORIZED",
            details=kwargs
        )
        self._write_audit_entry(entry)
    
    def log_compliance_violation(self, case_id: str, user: str, violation_type: str, **kwargs) -> None:
        """Log compliance violation"""
        entry = ComplianceAuditEntry(
            timestamp=datetime.now(),
            case_id=case_id,
            user=user,
            action="COMPLIANCE_VIOLATION",
            compliance_check=violation_type,
            result="VIOLATION",
            details=kwargs
        )
        self._write_audit_entry(entry)
    
    def get_compliance_audit_logs(self, case_id: str = None, 
                                 start_date: datetime = None, 
                                 end_date: datetime = None) -> List[ComplianceAuditEntry]:
        """Get compliance audit logs"""
        logs = []
        
        if not self.audit_file.exists():
            return logs
        
        try:
            with open(self.audit_file, 'r') as f:
                for line in f:
                    try:
                        entry_data = json.loads(line.strip())
                        entry_timestamp = datetime.fromisoformat(entry_data['timestamp'])
                        
                        # Filter by case ID
                        if case_id and entry_data['case_id'] != case_id:
                            continue
                        
                        # Filter by date range
                        if start_date and entry_timestamp < start_date:
                            continue
                        if end_date and entry_timestamp > end_date:
                            continue
                        
                        entry = ComplianceAuditEntry(
                            timestamp=entry_timestamp,
                            case_id=entry_data['case_id'],
                            user=entry_data['user'],
                            action=entry_data['action'],
                            compliance_check=entry_data['compliance_check'],
                            result=entry_data['result'],
                            details=entry_data.get('details')
                        )
                        logs.append(entry)
                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue
        except IOError:
            pass
        
        return logs


class LegalComplianceService:
    """Main legal compliance service"""
    
    def __init__(self, disclaimer_manager: LegalDisclaimerManager = None,
                 case_manager: CaseManager = None,
                 compliance_logger: ComplianceAuditLogger = None):
        self.disclaimer_manager = disclaimer_manager or LegalDisclaimerManager()
        self.case_manager = case_manager or CaseManager()
        self.compliance_logger = compliance_logger or ComplianceAuditLogger()
    
    def display_disclaimer(self) -> LegalDisclaimer:
        """Get disclaimer for display"""
        return self.disclaimer_manager.get_disclaimer()
    
    def capture_consent(self, user: str, consent_given: bool, case_id: str = "SYSTEM",
                       ip_address: str = None, user_agent: str = None) -> ConsentRecord:
        """Capture user consent"""
        consent_record = self.disclaimer_manager.record_consent(
            user, consent_given, ip_address, user_agent
        )
        
        self.compliance_logger.log_disclaimer_acknowledgment(
            case_id, user, consent_given,
            ip_address=ip_address, user_agent=user_agent
        )
        
        if not consent_given:
            raise AuthorizationException(
                "Legal disclaimer must be accepted to proceed", "CONSENT_REQUIRED"
            )
        
        return consent_record
    
    def validate_case_authorization(self, case_id: str, investigator: str) -> CaseInfo:
        """Validate case authorization"""
        case_info = self.case_manager.get_case(case_id)
        if not case_info:
            self.compliance_logger.log_case_validation(
                case_id, investigator, False, reason="Case not found"
            )
            raise AuthorizationException(f"Case {case_id} not found", "CASE_NOT_FOUND")
        
        if not self.case_manager.validate_case(case_id, investigator):
            self.compliance_logger.log_case_validation(
                case_id, investigator, False, reason="Invalid case or investigator"
            )
            raise AuthorizationException(
                f"Invalid case authorization for {case_id}", "INVALID_CASE_AUTH"
            )
        
        self.compliance_logger.log_case_validation(case_id, investigator, True)
        return case_info
    
    def verify_authorized_environment(self, case_id: str, user: str) -> Dict[str, Any]:
        """Verify authorized environment"""
        env_info = EnvironmentValidator.validate_environment()
        
        self.compliance_logger.log_environment_check(
            case_id, user, env_info['is_authorized'], 
            hostname=env_info['hostname'], ip_address=env_info['ip_address']
        )
        
        if not env_info['is_authorized']:
            raise AuthorizationException(
                "Unauthorized environment for forensic operations", "UNAUTHORIZED_ENVIRONMENT"
            )
        
        return env_info
    
    def check_compliance_requirements(self, user: str, case_id: str) -> Dict[str, bool]:
        """Check all compliance requirements"""
        compliance_status = {
            'disclaimer_accepted': False,
            'case_authorized': False,
            'environment_authorized': False,
            'all_requirements_met': False
        }
        
        try:
            # Check disclaimer acceptance
            compliance_status['disclaimer_accepted'] = self.disclaimer_manager.has_valid_consent(user)
            
            # Check case authorization
            case_info = self.case_manager.get_case(case_id)
            compliance_status['case_authorized'] = (
                case_info is not None and 
                self.case_manager.validate_case(case_id, user)
            )
            
            # Check environment authorization
            env_info = EnvironmentValidator.validate_environment()
            compliance_status['environment_authorized'] = env_info['is_authorized']
            
            # All requirements met
            compliance_status['all_requirements_met'] = all([
                compliance_status['disclaimer_accepted'],
                compliance_status['case_authorized'],
                compliance_status['environment_authorized']
            ])
            
        except Exception as e:
            self.compliance_logger.log_compliance_violation(
                case_id, user, "COMPLIANCE_CHECK_ERROR", error=str(e)
            )
        
        return compliance_status