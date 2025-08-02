#!/usr/bin/env python3
"""
Demo script showing authentication and legal compliance workflow
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from forensics_toolkit.services import (
    AuthenticationService, LegalComplianceService,
    UserManager, LegalDisclaimerManager, CaseManager
)
from forensics_toolkit.interfaces import UserRole, Permission


def main():
    """Demonstrate authentication and legal compliance workflow"""
    print("=== ForenCrack Droid Authentication & Legal Compliance Demo ===\n")
    
    # Initialize services
    auth_service = AuthenticationService()
    compliance_service = LegalComplianceService()
    
    print("1. Creating test users...")
    user_manager = auth_service.user_manager
    
    # Create test users (admin already exists by default)
    try:
        investigator = user_manager.create_user("investigator1", "secure123", UserRole.INVESTIGATOR)
        analyst = user_manager.create_user("analyst1", "secure456", UserRole.ANALYST)
        print(f"   ✓ Created investigator: {investigator.username}")
        print(f"   ✓ Created analyst: {analyst.username}")
    except Exception as e:
        print(f"   Users may already exist: {e}")
    
    print("\n2. Demonstrating authentication...")
    
    # Authenticate investigator
    user = auth_service.authenticate_user("investigator1", "secure123")
    if user:
        print(f"   ✓ Authenticated user: {user.username} (Role: {user.role.value})")
        session = auth_service.create_session(user)
        print(f"   ✓ Created session: {session.session_id[:16]}...")
        
        # Check permissions
        has_device_access = auth_service.check_permission(session.session_id, Permission.DEVICE_ACCESS)
        has_user_mgmt = auth_service.check_permission(session.session_id, Permission.USER_MANAGEMENT)
        print(f"   ✓ Device access permission: {has_device_access}")
        print(f"   ✓ User management permission: {has_user_mgmt}")
    else:
        print("   ✗ Authentication failed")
        return
    
    print("\n3. Legal compliance workflow...")
    
    # Display disclaimer
    disclaimer = compliance_service.display_disclaimer()
    print(f"   ✓ Legal disclaimer loaded (Version: {disclaimer.version})")
    print(f"   ✓ Disclaimer title: {disclaimer.title}")
    
    # Create a test case
    case_manager = compliance_service.case_manager
    try:
        case_info = case_manager.create_case(
            "FBI-2024-123456",
            "Test Mobile Device Investigation",
            "investigator1",
            "Search Warrant #SW-2024-001",
            warrant_number="SW-2024-001"
        )
        print(f"   ✓ Created case: {case_info.case_id}")
        print(f"   ✓ Case title: {case_info.case_title}")
    except Exception as e:
        print(f"   Case may already exist: {e}")
        case_info = case_manager.get_case("FBI-2024-123456")
    
    # Capture consent
    try:
        consent_record = compliance_service.capture_consent(
            "investigator1", True, "FBI-2024-123456", "192.168.1.100"
        )
        print(f"   ✓ Consent captured for user: {consent_record.user}")
    except Exception as e:
        print(f"   Consent capture: {e}")
    
    # Validate case authorization
    try:
        validated_case = compliance_service.validate_case_authorization(
            "FBI-2024-123456", "investigator1"
        )
        print(f"   ✓ Case authorization validated: {validated_case.case_id}")
    except Exception as e:
        print(f"   ✗ Case authorization failed: {e}")
    
    # Verify environment
    try:
        env_info = compliance_service.verify_authorized_environment(
            "FBI-2024-123456", "investigator1"
        )
        print(f"   ✓ Environment authorized: {env_info['hostname']}")
    except Exception as e:
        print(f"   ✗ Environment check failed: {e}")
    
    # Check all compliance requirements
    compliance_status = compliance_service.check_compliance_requirements(
        "investigator1", "FBI-2024-123456"
    )
    
    print("\n4. Compliance status summary:")
    print(f"   Disclaimer accepted: {compliance_status['disclaimer_accepted']}")
    print(f"   Case authorized: {compliance_status['case_authorized']}")
    print(f"   Environment authorized: {compliance_status['environment_authorized']}")
    print(f"   All requirements met: {compliance_status['all_requirements_met']}")
    
    if compliance_status['all_requirements_met']:
        print("\n   ✅ SYSTEM READY FOR FORENSIC OPERATIONS")
    else:
        print("\n   ❌ COMPLIANCE REQUIREMENTS NOT MET")
    
    # Cleanup session
    auth_service.logout_user(session.session_id)
    print(f"\n5. Session logged out successfully")
    
    print("\n=== Demo completed ===")


if __name__ == "__main__":
    main()