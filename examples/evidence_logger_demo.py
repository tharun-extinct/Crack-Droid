#!/usr/bin/env python3
"""
Evidence Logger Demonstration

This script demonstrates the key features of the EvidenceLogger class:
- Timestamped operation logging
- SHA-256 hash verification
- Structured evidence collection
- Real-time audit trail generation
"""

import sys
import os
from datetime import datetime
from pathlib import Path

# Add the parent directory to the path so we can import the forensics toolkit
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from forensics_toolkit.services.evidence_logger import EvidenceLogger, EvidenceLoggingError
from forensics_toolkit.models.attack import EvidenceRecord, CustodyEvent
from forensics_toolkit.models.device import AndroidDevice
from forensics_toolkit.interfaces import LockType


def demonstrate_basic_logging():
    """Demonstrate basic operation logging"""
    print("=== Basic Operation Logging ===")
    
    # Create evidence logger
    logger = EvidenceLogger(
        log_directory="./demo_logs",
        encrypt_logs=False,  # Disable encryption for demo
        auto_backup=False
    )
    
    # Log various forensic operations
    operations = [
        ("CASE_001", "device_detection", "Android device detected via ADB", "ABC123", "investigator1"),
        ("CASE_001", "device_analysis", "Device analysis completed", "ABC123", "investigator1"),
        ("CASE_001", "attack_execution", "Brute force attack initiated", "ABC123", "investigator1"),
        ("CASE_001", "evidence_collection", "Evidence successfully collected", "ABC123", "investigator1"),
    ]
    
    logged_operations = []
    for case_id, op_type, message, device_serial, user_id in operations:
        try:
            operation_log = logger.log_operation(
                case_id=case_id,
                operation_type=op_type,
                message=message,
                device_serial=device_serial,
                user_id=user_id,
                metadata={
                    "demo": True,
                    "operation_sequence": len(logged_operations) + 1
                }
            )
            logged_operations.append(operation_log)
            print(f"✓ Logged: {op_type} - {message}")
            print(f"  Hash: {operation_log.hash_value[:16]}...")
            print(f"  Integrity: {'✓ Verified' if operation_log.verify_integrity() else '✗ Failed'}")
            
        except EvidenceLoggingError as e:
            print(f"✗ Failed to log operation: {e}")
    
    return logger, logged_operations


def demonstrate_evidence_record_logging(logger):
    """Demonstrate evidence record logging with chain of custody"""
    print("\n=== Evidence Record Logging ===")
    
    # Create a test Android device
    device = AndroidDevice(
        serial="ABC123",
        model="Galaxy S21",
        brand="Samsung",
        android_version="11.0",
        usb_debugging=True,
        lock_type=LockType.PIN
    )
    
    # Create chain of custody events
    custody_events = [
        CustodyEvent(
            timestamp=datetime.now(),
            event_type="DEVICE_SEIZED",
            user_id="investigator1",
            description="Device seized from suspect",
            hash_before=None,
            hash_after="initial_device_hash_123"
        ),
        CustodyEvent(
            timestamp=datetime.now(),
            event_type="EVIDENCE_EXTRACTED",
            user_id="investigator1",
            description="PIN successfully cracked and data extracted",
            hash_before="initial_device_hash_123",
            hash_after="extracted_data_hash_456"
        )
    ]
    
    # Create evidence record
    evidence_record = EvidenceRecord(
        case_id="CASE_001",
        timestamp=datetime.now(),
        operation_type="evidence_collection",
        device_serial="ABC123",
        attempt_number=1,
        result="PIN cracked: 1234",
        hash_verification="a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
        chain_of_custody=custody_events,
        evidence_type="device_unlock",
        investigator_id="investigator1",
        case_notes="Device unlocked using brute force attack on PIN lock"
    )
    
    try:
        # Log the evidence record
        operation_log = logger.log_evidence_record(evidence_record)
        print(f"✓ Evidence record logged successfully")
        print(f"  Case ID: {evidence_record.case_id}")
        print(f"  Result: {evidence_record.result}")
        print(f"  Chain of custody events: {len(evidence_record.chain_of_custody)}")
        print(f"  Operation hash: {operation_log.hash_value[:16]}...")
        print(f"  Integrity: {'✓ Verified' if operation_log.verify_integrity() else '✗ Failed'}")
        
    except EvidenceLoggingError as e:
        print(f"✗ Failed to log evidence record: {e}")


def demonstrate_integrity_verification(logger):
    """Demonstrate integrity verification"""
    print("\n=== Integrity Verification ===")
    
    # Verify integrity of all operations for CASE_001
    verification_result = logger.verify_integrity(case_id="CASE_001")
    
    print(f"Case ID: {verification_result['case_id']}")
    print(f"Total operations: {verification_result['total_operations']}")
    print(f"Verified operations: {verification_result['verified_operations']}")
    print(f"Failed operations: {verification_result['failed_operations']}")
    print(f"Overall status: {verification_result['integrity_status']}")
    
    if verification_result['corrupted_entries']:
        print("⚠️  Corrupted entries detected:")
        for entry in verification_result['corrupted_entries']:
            print(f"  - {entry['timestamp']}: {entry['operation_type']}")
    else:
        print("✓ All entries verified successfully")


def demonstrate_audit_trail_generation(logger):
    """Demonstrate audit trail generation"""
    print("\n=== Audit Trail Generation ===")
    
    # Generate audit trail for CASE_001
    audit_trail = logger.generate_audit_trail("CASE_001")
    
    print(f"Case ID: {audit_trail['case_id']}")
    print(f"Generated at: {audit_trail['generated_at']}")
    print(f"Total operations: {audit_trail['total_operations']}")
    print(f"Devices involved: {', '.join(audit_trail['devices_involved'])}")
    print(f"Users involved: {', '.join(audit_trail['users_involved'])}")
    
    print("\nOperations by type:")
    for op_type, count in audit_trail['operations_by_type'].items():
        print(f"  {op_type}: {count}")
    
    print(f"\nTimeline entries: {len(audit_trail['timeline'])}")
    print("Recent timeline entries:")
    for entry in audit_trail['timeline'][-3:]:  # Show last 3 entries
        print(f"  {entry['timestamp'][:19]}: {entry['operation_type']} - {entry['message'][:50]}...")


def demonstrate_case_export(logger):
    """Demonstrate case log export"""
    print("\n=== Case Log Export ===")
    
    export_path = "./demo_logs/case_001_export.json"
    
    try:
        success = logger.export_case_logs(
            case_id="CASE_001",
            export_path=export_path,
            include_metadata=True
        )
        
        if success:
            print(f"✓ Case logs exported successfully to: {export_path}")
            
            # Check file size
            export_file = Path(export_path)
            if export_file.exists():
                file_size = export_file.stat().st_size
                print(f"  Export file size: {file_size} bytes")
            
        else:
            print("✗ Failed to export case logs")
            
    except EvidenceLoggingError as e:
        print(f"✗ Export failed: {e}")


def demonstrate_operation_filtering(logger):
    """Demonstrate operation filtering and retrieval"""
    print("\n=== Operation Filtering ===")
    
    # Get all operations for CASE_001
    all_operations = logger.get_operations(case_id="CASE_001")
    print(f"Total operations for CASE_001: {len(all_operations)}")
    
    # Filter by operation type
    detection_operations = logger.get_operations(
        case_id="CASE_001",
        operation_type="device_detection"
    )
    print(f"Device detection operations: {len(detection_operations)}")
    
    # Filter by time range (last hour)
    from datetime import timedelta
    recent_operations = logger.get_operations(
        case_id="CASE_001",
        start_time=datetime.now() - timedelta(hours=1)
    )
    print(f"Operations in last hour: {len(recent_operations)}")


def main():
    """Main demonstration function"""
    print("Evidence Logger Demonstration")
    print("=" * 50)
    
    try:
        # Demonstrate basic logging
        logger, operations = demonstrate_basic_logging()
        
        # Demonstrate evidence record logging
        demonstrate_evidence_record_logging(logger)
        
        # Demonstrate integrity verification
        demonstrate_integrity_verification(logger)
        
        # Demonstrate audit trail generation
        demonstrate_audit_trail_generation(logger)
        
        # Demonstrate case export
        demonstrate_case_export(logger)
        
        # Demonstrate operation filtering
        demonstrate_operation_filtering(logger)
        
        print("\n" + "=" * 50)
        print("✓ Evidence Logger demonstration completed successfully!")
        print(f"Demo logs saved to: {logger.log_directory}")
        
    except Exception as e:
        print(f"\n✗ Demonstration failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()