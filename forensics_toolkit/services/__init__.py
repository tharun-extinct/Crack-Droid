"""
Services package for forensics toolkit
"""

from .authentication import (
    RolePermissionManager,
    UserManager,
    AuditLogger,
    AuthenticationService
)
from .auth_decorators import (
    require_permission,
    require_authentication,
    AuthenticationMixin
)
from .legal_compliance import (
    LegalDisclaimerManager,
    CaseManager,
    EnvironmentValidator,
    ComplianceAuditLogger,
    LegalComplianceService,
    LegalDisclaimer,
    ConsentRecord,
    CaseInfo,
    ComplianceAuditEntry
)
from .evidence_logger import (
    EvidenceLogger,
    OperationLog,
    EvidenceLoggingError
)
from .chain_of_custody import (
    ChainOfCustody,
    CaseMetadata,
    CustodyValidationError,
    CustodyEventType
)
from .report_generator import (
    ReportGenerator,
    ReportMetadata,
    ReportGenerationError
)
from .data_encryption import (
    DataEncryption,
    DataEncryptionError,
    EncryptionKey,
    EncryptedData
)
from .forensics_orchestrator import (
    ForensicsOrchestrator,
    ForensicsOrchestratorException,
    DeviceAnalysisResult,
    ForensicWorkflowState
)
from .device_manager import (
    DeviceManager,
    DeviceManagerException,
    DeviceState,
    DeviceHealthStatus,
    DeviceStatus
)

__all__ = [
    'RolePermissionManager',
    'UserManager',
    'AuditLogger',
    'AuthenticationService',
    'require_permission',
    'require_authentication',
    'AuthenticationMixin',
    'LegalDisclaimerManager',
    'CaseManager',
    'EnvironmentValidator',
    'ComplianceAuditLogger',
    'LegalComplianceService',
    'LegalDisclaimer',
    'ConsentRecord',
    'CaseInfo',
    'ComplianceAuditEntry',
    'EvidenceLogger',
    'OperationLog',
    'EvidenceLoggingError',
    'ChainOfCustody',
    'CaseMetadata',
    'CustodyValidationError',
    'CustodyEventType',
    'ReportGenerator',
    'ReportMetadata',
    'ReportGenerationError',
    'DataEncryption',
    'DataEncryptionError',
    'EncryptionKey',
    'EncryptedData',
    'ForensicsOrchestrator',
    'ForensicsOrchestratorException',
    'DeviceAnalysisResult',
    'ForensicWorkflowState',
    'DeviceManager',
    'DeviceManagerException',
    'DeviceState',
    'DeviceHealthStatus',
    'DeviceStatus'
]