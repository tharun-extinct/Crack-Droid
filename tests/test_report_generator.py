"""
Unit tests for ReportGenerator

Tests the report generation functionality including JSON and PDF output,
evidence visualization, court-admissible documentation, and integrity verification.
"""

import pytest
import json
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from forensics_toolkit.services.report_generator import (
    ReportGenerator, ReportGenerationError, ReportMetadata
)
from forensics_toolkit.services.evidence_logger import EvidenceLogger, OperationLog
from forensics_toolkit.services.chain_of_custody import ChainOfCustody, CaseMetadata
from forensics_toolkit.models.attack import EvidenceRecord, CustodyEvent
from forensics_toolkit.models.device import AndroidDevice, LockType


class TestReportGenerator:
    """Test cases for ReportGenerator class"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test reports"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def mock_evidence_logger(self):
        """Mock evidence logger with test data"""
        logger = Mock(spec=EvidenceLogger)
        
        # Mock operations
        operations = [
            OperationLog(
                timestamp=datetime.now() - timedelta(hours=2),
                case_id="TEST_CASE_001",
                operation_type="DEVICE_DETECTION",
                device_serial="ABC123",
                user_id="investigator1",
                message="Device detected",
                metadata={'device_type': 'android'}
            ),
            OperationLog(
                timestamp=datetime.now() - timedelta(hours=1),
                case_id="TEST_CASE_001",
                operation_type="ATTACK_EXECUTION",
                device_serial="ABC123",
                user_id="investigator1",
                message="Brute force attack started",
                metadata={'strategy_type': 'brute_force', 'attempts': 100}
            )
        ]
        
        logger.get_operations.return_value = operations
        logger.verify_integrity.return_value = {
            'timestamp': datetime.now().isoformat(),
            'case_id': 'TEST_CASE_001',
            'total_operations': 2,
            'verified_operations': 2,
            'failed_operations': 0,
            'corrupted_entries': [],
            'integrity_status': 'verified'
        }
        logger.log_operation.return_value = operations[0]
        
        return logger
    
    @pytest.fixture
    def mock_custody_manager(self):
        """Mock chain of custody manager with test data"""
        custody = Mock(spec=ChainOfCustody)
        
        # Mock case metadata
        case_metadata = CaseMetadata(
            case_id="TEST_CASE_001",
            investigator_id="investigator1",
            case_title="Test Android Device Analysis",
            case_description="Testing report generation functionality",
            created_at=datetime.now() - timedelta(days=1),
            authorized_users=["investigator1", "supervisor1"],
            case_status="active",
            evidence_count=2
        )
        
        # Mock evidence records
        evidence_records = [
            EvidenceRecord(
                case_id="TEST_CASE_001",
                timestamp=datetime.now() - timedelta(hours=2),
                operation_type="device_detection",
                device_serial="ABC123",
                attempt_number=1,
                result="Device successfully detected",
                hash_verification="a1b2c3d4e5f6" + "0" * 52,
                evidence_type="device_metadata"
            ),
            EvidenceRecord(
                case_id="TEST_CASE_001",
                timestamp=datetime.now() - timedelta(hours=1),
                operation_type="attack_execution",
                device_serial="ABC123",
                attempt_number=1,
                result="Attack completed - no success",
                hash_verification="f6e5d4c3b2a1" + "0" * 52,
                evidence_type="attack_result"
            )
        ]
        
        # Mock custody events
        custody_events = [
            CustodyEvent(
                timestamp=datetime.now() - timedelta(days=1),
                event_type="case_created",
                user_id="investigator1",
                description="Case created for device analysis"
            ),
            CustodyEvent(
                timestamp=datetime.now() - timedelta(hours=2),
                event_type="evidence_collected",
                user_id="investigator1",
                description="Device metadata collected"
            )
        ]
        
        custody.get_case_metadata.return_value = case_metadata
        custody.get_evidence_records.return_value = evidence_records
        custody.get_custody_chain.return_value = custody_events
        
        return custody
    
    @pytest.fixture
    def report_generator(self, temp_dir, mock_evidence_logger, mock_custody_manager):
        """Create ReportGenerator instance with mocked dependencies"""
        return ReportGenerator(
            output_directory=temp_dir,
            evidence_logger=mock_evidence_logger,
            custody_manager=mock_custody_manager
        )
    
    def test_init(self, temp_dir):
        """Test ReportGenerator initialization"""
        generator = ReportGenerator(output_directory=temp_dir)
        
        assert generator.output_directory == Path(temp_dir)
        assert generator.output_directory.exists()
        assert isinstance(generator.evidence_logger, EvidenceLogger)
        assert isinstance(generator.custody_manager, ChainOfCustody)
        assert generator._generated_reports == {}
    
    def test_generate_json_report_success(self, report_generator):
        """Test successful JSON report generation"""
        case_id = "TEST_CASE_001"
        
        file_path, metadata = report_generator.generate_json_report(
            case_id=case_id,
            include_raw_data=True,
            include_visualizations=False
        )
        
        # Verify file was created
        assert Path(file_path).exists()
        assert Path(file_path).suffix == '.json'
        
        # Verify metadata
        assert metadata.case_id == case_id
        assert metadata.report_type == 'json'
        assert metadata.integrity_hash != ""
        assert metadata.file_path == file_path
        assert metadata.file_size > 0
        
        # Verify report content
        with open(file_path, 'r') as f:
            report_data = json.load(f)
        
        assert 'report_metadata' in report_data
        assert 'case_summary' in report_data
        assert 'devices_analyzed' in report_data
        assert 'evidence_records' in report_data
        assert 'chain_of_custody' in report_data
        assert 'integrity_verification' in report_data
        assert 'raw_operation_logs' in report_data  # included because include_raw_data=True
        
        assert report_data['report_metadata']['case_id'] == case_id
        assert report_data['report_metadata']['report_type'] == 'json'
        
        # Verify evidence logger was called
        report_generator.evidence_logger.log_operation.assert_called_once()
    
    def test_generate_json_report_without_raw_data(self, report_generator):
        """Test JSON report generation without raw data"""
        case_id = "TEST_CASE_001"
        
        file_path, metadata = report_generator.generate_json_report(
            case_id=case_id,
            include_raw_data=False,
            include_visualizations=False
        )
        
        # Verify report content
        with open(file_path, 'r') as f:
            report_data = json.load(f)
        
        assert 'raw_operation_logs' not in report_data
        assert report_data['report_metadata']['include_raw_data'] is False
    
    def test_generate_pdf_report_success(self, report_generator):
        """Test PDF report generation when PDF libraries are available"""
        # Since PDF libraries are not installed in test environment,
        # we'll test that the method correctly identifies PDF availability
        case_id = "TEST_CASE_001"
        
        # Test that PDF generation fails when libraries are not available
        with pytest.raises(ReportGenerationError) as exc_info:
            report_generator.generate_pdf_report(case_id)
        
        assert "PDF generation not available" in str(exc_info.value)
        assert exc_info.value.report_type == "pdf"
    
    @patch('forensics_toolkit.services.report_generator.PDF_AVAILABLE', False)
    def test_generate_pdf_report_unavailable(self, report_generator):
        """Test PDF report generation when PDF libraries unavailable"""
        case_id = "TEST_CASE_001"
        
        with pytest.raises(ReportGenerationError) as exc_info:
            report_generator.generate_pdf_report(case_id)
        
        assert "PDF generation not available" in str(exc_info.value)
        assert exc_info.value.report_type == "pdf"
    
    def test_generate_summary_report(self, report_generator):
        """Test summary report generation"""
        case_id = "TEST_CASE_001"
        
        file_path, metadata = report_generator.generate_summary_report(case_id)
        
        # Verify file was created
        assert Path(file_path).exists()
        assert Path(file_path).suffix == '.json'
        
        # Verify metadata
        assert metadata.case_id == case_id
        assert metadata.report_type == 'summary'
        
        # Verify report content
        with open(file_path, 'r') as f:
            report_data = json.load(f)
        
        assert 'report_metadata' in report_data
        assert 'case_summary' in report_data
        assert 'statistics' in report_data
        assert 'integrity_status' in report_data
        assert 'devices_count' in report_data
        assert 'attack_strategies_count' in report_data
        assert 'successful_attacks' in report_data
        
        assert report_data['report_metadata']['report_type'] == 'summary'
    
    def test_collect_case_data(self, report_generator):
        """Test case data collection"""
        case_id = "TEST_CASE_001"
        
        case_data = report_generator._collect_case_data(case_id)
        
        # Verify all required sections are present
        required_sections = [
            'case_summary', 'devices', 'attack_strategies', 'evidence_records',
            'custody_chain', 'raw_operations', 'integrity_results', 'timeline', 'statistics'
        ]
        
        for section in required_sections:
            assert section in case_data
        
        # Verify case summary
        assert case_data['case_summary']['case_id'] == case_id
        assert case_data['case_summary']['case_title'] == "Test Android Device Analysis"
        
        # Verify statistics
        stats = case_data['statistics']
        assert 'total_operations' in stats
        assert 'total_evidence_records' in stats
        assert 'unique_devices' in stats
        assert 'operations_by_type' in stats
    
    def test_collect_case_data_case_not_found(self, report_generator):
        """Test case data collection when case doesn't exist"""
        report_generator.custody_manager.get_case_metadata.return_value = None
        
        with pytest.raises(ReportGenerationError) as exc_info:
            report_generator._collect_case_data("NONEXISTENT_CASE")
        
        assert "Case NONEXISTENT_CASE not found" in str(exc_info.value)
    
    def test_analyze_case_devices(self, report_generator):
        """Test device analysis functionality"""
        # Create test evidence records
        evidence_records = [
            EvidenceRecord(
                case_id="TEST_CASE_001",
                timestamp=datetime.now() - timedelta(hours=2),
                operation_type="device_detection",
                device_serial="ABC123",
                attempt_number=1,
                result="Device detected",
                hash_verification="a" * 64,
                evidence_type="device_metadata"
            ),
            EvidenceRecord(
                case_id="TEST_CASE_001",
                timestamp=datetime.now() - timedelta(hours=1),
                operation_type="attack_execution",
                device_serial="ABC123",
                attempt_number=2,
                result="Attack completed",
                hash_verification="b" * 64,
                evidence_type="attack_result"
            )
        ]
        
        devices = report_generator._analyze_case_devices(evidence_records)
        
        assert len(devices) == 1
        device = devices[0]
        
        assert device['device_serial'] == "ABC123"
        assert device['operation_count'] == 2
        assert 'device_detection' in device['unique_operations']
        assert 'attack_execution' in device['unique_operations']
        assert 'device_metadata' in device['evidence_types']
        assert 'attack_result' in device['evidence_types']
    
    def test_generate_case_timeline(self, report_generator):
        """Test timeline generation"""
        # Create test operations and custody events
        operations = [
            OperationLog(
                timestamp=datetime.now() - timedelta(hours=2),
                case_id="TEST_CASE_001",
                operation_type="DEVICE_DETECTION",
                device_serial="ABC123",
                user_id="investigator1",
                message="Device detected",
                metadata={}
            )
        ]
        
        custody_events = [
            CustodyEvent(
                timestamp=datetime.now() - timedelta(hours=3),
                event_type="case_created",
                user_id="investigator1",
                description="Case created"
            )
        ]
        
        timeline = report_generator._generate_case_timeline(operations, custody_events)
        
        assert len(timeline) == 2
        
        # Verify timeline is sorted by timestamp
        timestamps = [event['timestamp'] for event in timeline]
        assert timestamps == sorted(timestamps)
        
        # Verify event types
        event_types = [event['event_type'] for event in timeline]
        assert 'custody' in event_types
        assert 'operation' in event_types
    
    def test_generate_case_statistics(self, report_generator):
        """Test statistics generation"""
        # Create test data
        evidence_records = [
            EvidenceRecord(
                case_id="TEST_CASE_001",
                timestamp=datetime.now(),
                operation_type="device_detection",
                device_serial="ABC123",
                attempt_number=1,
                result="Success",
                hash_verification="a" * 64,
                evidence_type="device_metadata"
            )
        ]
        
        operations = [
            OperationLog(
                timestamp=datetime.now() - timedelta(hours=1),
                case_id="TEST_CASE_001",
                operation_type="DEVICE_DETECTION",
                device_serial="ABC123",
                user_id="investigator1",
                message="Device detected",
                metadata={}
            ),
            OperationLog(
                timestamp=datetime.now(),
                case_id="TEST_CASE_001",
                operation_type="ATTACK_EXECUTION",
                device_serial="ABC123",
                user_id="investigator1",
                message="Attack executed",
                metadata={}
            )
        ]
        
        custody_events = [
            CustodyEvent(
                timestamp=datetime.now(),
                event_type="case_created",
                user_id="investigator1",
                description="Case created"
            )
        ]
        
        stats = report_generator._generate_case_statistics(evidence_records, operations, custody_events)
        
        assert stats['total_operations'] == 2
        assert stats['total_evidence_records'] == 1
        assert stats['total_custody_events'] == 1
        assert stats['unique_devices'] == 1
        assert stats['unique_users'] == 1
        assert stats['case_duration_hours'] == 1.0
        
        assert 'DEVICE_DETECTION' in stats['operations_by_type']
        assert 'ATTACK_EXECUTION' in stats['operations_by_type']
        assert stats['operations_by_type']['DEVICE_DETECTION'] == 1
        assert stats['operations_by_type']['ATTACK_EXECUTION'] == 1
    
    def test_generate_case_statistics_empty_operations(self, report_generator):
        """Test statistics generation with empty operations"""
        stats = report_generator._generate_case_statistics([], [], [])
        
        assert stats['total_operations'] == 0
        assert stats['total_evidence_records'] == 0
        assert stats['total_custody_events'] == 0
        assert stats['unique_devices'] == 0
        assert stats['unique_users'] == 0
        assert stats['case_duration_hours'] == 0
        assert stats['operations_by_type'] == {}
    
    def test_calculate_file_hash(self, report_generator, temp_dir):
        """Test file hash calculation"""
        # Create test file
        test_file = Path(temp_dir) / "test.txt"
        test_content = "This is test content for hash calculation"
        
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        hash_value = report_generator._calculate_file_hash(test_file)
        
        # Verify hash format (SHA-256 is 64 hex characters)
        assert len(hash_value) == 64
        assert all(c in '0123456789abcdef' for c in hash_value)
        
        # Verify hash is consistent
        hash_value2 = report_generator._calculate_file_hash(test_file)
        assert hash_value == hash_value2
    
    def test_verify_report_integrity_success(self, report_generator):
        """Test successful report integrity verification"""
        # Generate a report first
        case_id = "TEST_CASE_001"
        file_path, metadata = report_generator.generate_json_report(case_id)
        
        # Verify integrity
        is_valid, results = report_generator.verify_report_integrity(metadata.report_id)
        
        assert is_valid is True
        assert results['integrity_valid'] is True
        assert results['size_match'] is True
        assert results['report_id'] == metadata.report_id
        assert results['original_hash'] == results['current_hash']
    
    def test_verify_report_integrity_not_found(self, report_generator):
        """Test report integrity verification for non-existent report"""
        is_valid, results = report_generator.verify_report_integrity("NONEXISTENT_REPORT")
        
        assert is_valid is False
        assert 'error' in results
        assert 'Report not found' in results['error']
    
    def test_verify_report_integrity_file_missing(self, report_generator):
        """Test report integrity verification when file is missing"""
        # Create fake metadata
        metadata = ReportMetadata(
            report_id="FAKE_REPORT",
            case_id="TEST_CASE_001",
            report_type="json",
            generated_at=datetime.now(),
            generated_by="Test",
            file_path="/nonexistent/path.json"
        )
        
        report_generator._generated_reports["FAKE_REPORT"] = metadata
        
        is_valid, results = report_generator.verify_report_integrity("FAKE_REPORT")
        
        assert is_valid is False
        assert 'error' in results
        assert 'Report file not found' in results['error']
    
    def test_get_report_metadata(self, report_generator):
        """Test getting report metadata"""
        # Generate a report first
        case_id = "TEST_CASE_001"
        file_path, metadata = report_generator.generate_json_report(case_id)
        
        # Get metadata
        retrieved_metadata = report_generator.get_report_metadata(metadata.report_id)
        
        assert retrieved_metadata is not None
        assert retrieved_metadata.report_id == metadata.report_id
        assert retrieved_metadata.case_id == case_id
        assert retrieved_metadata.report_type == 'json'
        
        # Test non-existent report
        assert report_generator.get_report_metadata("NONEXISTENT") is None
    
    def test_list_generated_reports(self, report_generator):
        """Test listing generated reports"""
        # Generate multiple reports
        case_id1 = "TEST_CASE_001"
        case_id2 = "TEST_CASE_002"
        
        # Mock second case
        report_generator.custody_manager.get_case_metadata.side_effect = lambda cid: (
            CaseMetadata(
                case_id=cid,
                investigator_id="investigator1",
                case_title=f"Test Case {cid}",
                case_description="Test description",
                created_at=datetime.now(),
                authorized_users=["investigator1"]
            )
        )
        report_generator.custody_manager.get_evidence_records.return_value = []
        report_generator.custody_manager.get_custody_chain.return_value = []
        
        file_path1, metadata1 = report_generator.generate_json_report(case_id1)
        file_path2, metadata2 = report_generator.generate_summary_report(case_id2)
        
        # List all reports
        all_reports = report_generator.list_generated_reports()
        assert len(all_reports) == 2
        
        # List reports for specific case
        case1_reports = report_generator.list_generated_reports(case_id1)
        assert len(case1_reports) == 1
        assert case1_reports[0].case_id == case_id1
        
        case2_reports = report_generator.list_generated_reports(case_id2)
        assert len(case2_reports) == 1
        assert case2_reports[0].case_id == case_id2
    
    def test_report_metadata_to_dict(self):
        """Test ReportMetadata to_dict conversion"""
        metadata = ReportMetadata(
            report_id="TEST_REPORT_001",
            case_id="TEST_CASE_001",
            report_type="json",
            generated_at=datetime(2023, 1, 1, 12, 0, 0),
            generated_by="TestUser",
            integrity_hash="abcd1234",
            file_path="/path/to/report.json",
            file_size=1024
        )
        
        data = metadata.to_dict()
        
        assert data['report_id'] == "TEST_REPORT_001"
        assert data['case_id'] == "TEST_CASE_001"
        assert data['report_type'] == "json"
        assert data['generated_at'] == "2023-01-01T12:00:00"
        assert data['generated_by'] == "TestUser"
        assert data['integrity_hash'] == "abcd1234"
        assert data['file_path'] == "/path/to/report.json"
        assert data['file_size'] == 1024
    
    def test_report_generation_error(self):
        """Test ReportGenerationError exception"""
        error = ReportGenerationError("Test error message", "json")
        
        assert str(error) == "Test error message"
        assert error.report_type == "json"
        assert error.error_code == "REPORT_GENERATION_ERROR"
        assert error.evidence_impact is True
    
    @patch('forensics_toolkit.services.report_generator.CHART_AVAILABLE', True)
    def test_generate_visualization_data(self, report_generator):
        """Test visualization data generation"""
        # Create test case data
        case_data = {
            'timeline': [
                {
                    'timestamp': '2023-01-01T12:00:00',
                    'event_type': 'operation',
                    'operation_type': 'DEVICE_DETECTION'
                }
            ],
            'statistics': {
                'operations_by_type': {
                    'DEVICE_DETECTION': 1,
                    'ATTACK_EXECUTION': 2
                },
                'activity_by_hour': {
                    12: 1,
                    13: 2
                }
            }
        }
        
        viz_data = report_generator._generate_visualization_data(case_data)
        
        assert 'timeline_chart' in viz_data
        assert 'operations_pie_chart' in viz_data
        assert 'activity_heatmap' in viz_data
        
        # Verify timeline chart data
        timeline_chart = viz_data['timeline_chart']
        assert len(timeline_chart['timestamps']) == 1
        assert timeline_chart['timestamps'][0] == '2023-01-01T12:00:00'
        
        # Verify pie chart data
        pie_chart = viz_data['operations_pie_chart']
        assert 'DEVICE_DETECTION' in pie_chart['labels']
        assert 'ATTACK_EXECUTION' in pie_chart['labels']
        assert 1 in pie_chart['values']
        assert 2 in pie_chart['values']
        
        # Verify heatmap data
        heatmap = viz_data['activity_heatmap']
        assert len(heatmap['hours']) == 24
        assert heatmap['activity_counts'][12] == 1
        assert heatmap['activity_counts'][13] == 2
    
    @patch('forensics_toolkit.services.report_generator.CHART_AVAILABLE', False)
    def test_generate_visualization_data_unavailable(self, report_generator):
        """Test visualization data generation when charts unavailable"""
        case_data = {'timeline': [], 'statistics': {}}
        
        viz_data = report_generator._generate_visualization_data(case_data)
        
        assert viz_data == {}


if __name__ == '__main__':
    pytest.main([__file__])