#!/usr/bin/env python3
"""
Report Generator Demo

This script demonstrates the ReportGenerator functionality including:
- JSON report generation
- Evidence visualization and formatting
- Court-admissible documentation templates
- Report integrity verification

Requirements implemented:
- 4.2: Generate both JSON and PDF format outputs
"""

import sys
import os
from datetime import datetime, timedelta
from pathlib import Path

# Add the parent directory to the path so we can import the forensics toolkit
sys.path.insert(0, str(Path(__file__).parent.parent))

from forensics_toolkit.services.report_generator import ReportGenerator, ReportGenerationError
from forensics_toolkit.services.evidence_logger import EvidenceLogger
from forensics_toolkit.services.chain_of_custody import ChainOfCustody
from forensics_toolkit.models.attack import EvidenceRecord, CustodyEvent
from forensics_toolkit.models.device import AndroidDevice, LockType


def create_sample_case_data():
    """Create sample case data for demonstration"""
    print("Creating sample case data...")
    
    # Initialize services
    evidence_logger = EvidenceLogger(log_directory="./demo_logs")
    custody_manager = ChainOfCustody(storage_path="./demo_evidence")
    
    # Create a test case
    case_id = "DEMO_CASE_001"
    case_metadata = custody_manager.create_case(
        case_id=case_id,
        investigator_id="demo_investigator",
        case_title="Android Device Forensic Analysis Demo",
        case_description="Demonstration of report generation capabilities for Android forensic analysis",
        authorized_users=["demo_investigator", "supervisor"]
    )
    
    print(f"Created case: {case_metadata.case_id}")
    
    # Create sample evidence records
    device_serial = "DEMO_DEVICE_123"
    
    # Device detection evidence
    evidence1 = EvidenceRecord(
        case_id=case_id,
        timestamp=datetime.now() - timedelta(hours=2),
        operation_type="device_detection",
        device_serial=device_serial,
        attempt_number=1,
        result="Samsung Galaxy S21 detected with Android 12, USB debugging enabled",
        hash_verification="",  # Will be computed by custody manager
        evidence_type="device_metadata",
        investigator_id="demo_investigator",
        case_notes="Initial device detection and metadata collection"
    )
    
    # Attack execution evidence
    evidence2 = EvidenceRecord(
        case_id=case_id,
        timestamp=datetime.now() - timedelta(hours=1),
        operation_type="attack_execution",
        device_serial=device_serial,
        attempt_number=1,
        result="Brute force attack completed - PIN cracked: 1234",
        hash_verification="",  # Will be computed by custody manager
        evidence_type="attack_result",
        investigator_id="demo_investigator",
        case_notes="Successful PIN brute force attack"
    )
    
    # Data extraction evidence
    evidence3 = EvidenceRecord(
        case_id=case_id,
        timestamp=datetime.now() - timedelta(minutes=30),
        operation_type="data_extraction",
        device_serial=device_serial,
        attempt_number=1,
        result="Extracted 1,247 contacts, 5,832 messages, 2,156 photos",
        hash_verification="",  # Will be computed by custody manager
        evidence_type="extracted_data",
        investigator_id="demo_investigator",
        case_notes="Complete data extraction after successful unlock"
    )
    
    # Add evidence to custody manager
    custody_manager.add_evidence_record(evidence1, "demo_investigator")
    custody_manager.add_evidence_record(evidence2, "demo_investigator")
    custody_manager.add_evidence_record(evidence3, "demo_investigator")
    
    # Log some operations
    evidence_logger.log_operation(
        case_id=case_id,
        operation_type="DEVICE_DETECTION",
        message="Android device detected and analyzed",
        device_serial=device_serial,
        user_id="demo_investigator",
        metadata={
            'device_model': 'Samsung Galaxy S21',
            'android_version': '12',
            'usb_debugging': True,
            'root_status': False
        }
    )
    
    evidence_logger.log_operation(
        case_id=case_id,
        operation_type="ATTACK_EXECUTION",
        message="Brute force attack initiated",
        device_serial=device_serial,
        user_id="demo_investigator",
        metadata={
            'strategy_type': 'brute_force',
            'attack_target': 'PIN',
            'max_attempts': 10000,
            'success': True,
            'attempts_used': 1234
        }
    )
    
    evidence_logger.log_operation(
        case_id=case_id,
        operation_type="DATA_EXTRACTION",
        message="Data extraction completed successfully",
        device_serial=device_serial,
        user_id="demo_investigator",
        metadata={
            'extraction_type': 'logical',
            'contacts_count': 1247,
            'messages_count': 5832,
            'photos_count': 2156,
            'total_size_mb': 2847
        }
    )
    
    print(f"Created {len([evidence1, evidence2, evidence3])} evidence records")
    print("Sample case data creation completed!")
    
    return evidence_logger, custody_manager, case_id


def demonstrate_json_report_generation(report_generator, case_id):
    """Demonstrate JSON report generation"""
    print("\n" + "="*60)
    print("JSON REPORT GENERATION DEMONSTRATION")
    print("="*60)
    
    try:
        # Generate comprehensive JSON report
        print("Generating comprehensive JSON report...")
        file_path, metadata = report_generator.generate_json_report(
            case_id=case_id,
            include_raw_data=True,
            include_visualizations=True
        )
        
        print(f"✓ JSON report generated successfully!")
        print(f"  File: {file_path}")
        print(f"  Size: {metadata.file_size} bytes")
        print(f"  Hash: {metadata.integrity_hash[:16]}...")
        
        # Generate summary report
        print("\nGenerating summary report...")
        summary_path, summary_metadata = report_generator.generate_summary_report(case_id)
        
        print(f"✓ Summary report generated successfully!")
        print(f"  File: {summary_path}")
        print(f"  Size: {summary_metadata.file_size} bytes")
        
        return [metadata, summary_metadata]
        
    except ReportGenerationError as e:
        print(f"✗ Report generation failed: {e}")
        return []


def demonstrate_pdf_report_generation(report_generator, case_id):
    """Demonstrate PDF report generation"""
    print("\n" + "="*60)
    print("PDF REPORT GENERATION DEMONSTRATION")
    print("="*60)
    
    try:
        # Generate court-admissible PDF report
        print("Generating court-admissible PDF report...")
        file_path, metadata = report_generator.generate_pdf_report(
            case_id=case_id,
            include_charts=True,
            court_format=True
        )
        
        print(f"✓ PDF report generated successfully!")
        print(f"  File: {file_path}")
        print(f"  Size: {metadata.file_size} bytes")
        print(f"  Hash: {metadata.integrity_hash[:16]}...")
        
        return metadata
        
    except ReportGenerationError as e:
        print(f"✗ PDF report generation failed: {e}")
        print("  Note: PDF generation requires reportlab library")
        print("  Install with: pip install reportlab")
        return None


def demonstrate_report_integrity_verification(report_generator, report_metadatas):
    """Demonstrate report integrity verification"""
    print("\n" + "="*60)
    print("REPORT INTEGRITY VERIFICATION DEMONSTRATION")
    print("="*60)
    
    for metadata in report_metadatas:
        if metadata is None:
            continue
            
        print(f"\nVerifying integrity of report: {metadata.report_id}")
        
        # Verify report integrity
        is_valid, results = report_generator.verify_report_integrity(metadata.report_id)
        
        if is_valid:
            print(f"✓ Report integrity verified successfully!")
            print(f"  Original hash: {results['original_hash'][:16]}...")
            print(f"  Current hash:  {results['current_hash'][:16]}...")
            print(f"  Size match: {results['size_match']}")
        else:
            print(f"✗ Report integrity verification failed!")
            print(f"  Error: {results.get('error', 'Unknown error')}")


def demonstrate_report_listing(report_generator, case_id):
    """Demonstrate report listing functionality"""
    print("\n" + "="*60)
    print("REPORT LISTING DEMONSTRATION")
    print("="*60)
    
    # List all reports for the case
    reports = report_generator.list_generated_reports(case_id=case_id)
    
    print(f"Found {len(reports)} reports for case {case_id}:")
    
    for i, report in enumerate(reports, 1):
        print(f"\n{i}. Report ID: {report.report_id}")
        print(f"   Type: {report.report_type}")
        print(f"   Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Size: {report.file_size} bytes")
        print(f"   File: {report.file_path}")


def demonstrate_evidence_visualization(report_generator, case_id):
    """Demonstrate evidence visualization capabilities"""
    print("\n" + "="*60)
    print("EVIDENCE VISUALIZATION DEMONSTRATION")
    print("="*60)
    
    try:
        # Collect case data to show what's available for visualization
        case_data = report_generator._collect_case_data(case_id)
        
        print("Case Statistics:")
        stats = case_data['statistics']
        print(f"  Total Operations: {stats['total_operations']}")
        print(f"  Evidence Records: {stats['total_evidence_records']}")
        print(f"  Unique Devices: {stats['unique_devices']}")
        print(f"  Unique Users: {stats['unique_users']}")
        print(f"  Case Duration: {stats['case_duration_hours']} hours")
        
        print("\nOperations by Type:")
        for op_type, count in stats['operations_by_type'].items():
            print(f"  {op_type}: {count}")
        
        print("\nEvidence by Type:")
        for ev_type, count in stats['evidence_by_type'].items():
            print(f"  {ev_type}: {count}")
        
        print("\nTimeline Events:")
        timeline = case_data['timeline']
        for i, event in enumerate(timeline[:5]):  # Show first 5 events
            print(f"  {i+1}. {event['timestamp'][:19]} - {event['operation_type']}")
        
        if len(timeline) > 5:
            print(f"  ... and {len(timeline) - 5} more events")
        
        # Generate visualization data
        viz_data = report_generator._generate_visualization_data(case_data)
        
        if viz_data:
            print(f"\n✓ Visualization data generated with {len(viz_data)} chart types")
            for chart_type in viz_data.keys():
                print(f"  - {chart_type}")
        else:
            print("\n! Visualization data generation skipped (matplotlib not available)")
        
    except Exception as e:
        print(f"✗ Evidence visualization failed: {e}")


def main():
    """Main demonstration function"""
    print("FORENSIC REPORT GENERATOR DEMONSTRATION")
    print("="*60)
    print("This demo shows the comprehensive report generation capabilities")
    print("of the ForenCrack Droid forensics toolkit.")
    print()
    
    try:
        # Create sample case data
        evidence_logger, custody_manager, case_id = create_sample_case_data()
        
        # Initialize report generator
        report_generator = ReportGenerator(
            output_directory="./demo_reports",
            evidence_logger=evidence_logger,
            custody_manager=custody_manager
        )
        
        print(f"Report generator initialized with output directory: ./demo_reports")
        
        # Demonstrate various report generation features
        json_reports = demonstrate_json_report_generation(report_generator, case_id)
        pdf_report = demonstrate_pdf_report_generation(report_generator, case_id)
        
        # Collect all generated reports for integrity verification
        all_reports = json_reports + ([pdf_report] if pdf_report else [])
        
        demonstrate_report_integrity_verification(report_generator, all_reports)
        demonstrate_report_listing(report_generator, case_id)
        demonstrate_evidence_visualization(report_generator, case_id)
        
        print("\n" + "="*60)
        print("DEMONSTRATION COMPLETED SUCCESSFULLY!")
        print("="*60)
        print("Key features demonstrated:")
        print("✓ JSON report generation with comprehensive case data")
        print("✓ Summary report generation for quick overview")
        print("✓ PDF report generation (court-admissible format)")
        print("✓ Report integrity verification with SHA-256 hashing")
        print("✓ Report metadata management and listing")
        print("✓ Evidence visualization and statistical analysis")
        print("✓ Timeline generation and case data analysis")
        print()
        print("Generated reports can be found in the ./demo_reports directory")
        print("Evidence data is stored in the ./demo_evidence directory")
        print("Operation logs are stored in the ./demo_logs directory")
        
    except Exception as e:
        print(f"\n✗ Demonstration failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())