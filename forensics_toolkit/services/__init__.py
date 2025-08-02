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
    'ComplianceAuditEntry'
]