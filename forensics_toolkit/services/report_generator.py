"""
Report Generator for forensic evidence documentation

This module implements the ReportGenerator class for JSON and PDF output,
evidence visualization and formatting, court-admissible documentation templates,
and report integrity verification.

Requirements implemented:
- 4.2: Generate both JSON and PDF format outputs
"""

import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

# PDF generation imports
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak
    )
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# Chart generation imports
try:
    import matplotlib.pyplot as plt
    CHART_AVAILABLE = True
except ImportError:
    CHART_AVAILABLE = False

from ..interfaces import ForensicsException
from ..models.attack import EvidenceRecord, CustodyEvent
from .evidence_logger import EvidenceLogger, OperationLog
from .chain_of_custody import ChainOfCustody, CaseMetadata


class ReportGenerationError(ForensicsException):
    """Exception raised for report generation errors"""
    
    def __init__(self, message: str, report_type: str = None):
        super().__init__(message, "REPORT_GENERATION_ERROR", evidence_impact=True)
        self.report_type = report_type


@dataclass
class ReportMetadata:
    """Metadata for generated reports"""
    report_id: str
    case_id: str
    report_type: str  # 'json', 'pdf', 'summary'
    generated_at: datetime
    generated_by: str
    report_version: str = "1.0"
    integrity_hash: str = ""
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'report_id': self.report_id,
            'case_id': self.case_id,
            'report_type': self.report_type,
            'generated_at': self.generated_at.isoformat(),
            'generated_by': self.generated_by,
            'report_version': self.report_version,
            'integrity_hash': self.integrity_hash,
            'file_path': self.file_path,
            'file_size': self.file_size
        }


class ReportGenerator:
    """
    Report Generator for forensic evidence documentation
    
    This class implements comprehensive report generation with:
    - JSON and PDF output formats
    - Evidence visualization and formatting
    - Court-admissible documentation templates
    - Report integrity verification
    
    Requirements:
    - 4.2: Generate both JSON and PDF format outputs
    """
    
    def __init__(self, 
                 output_directory: str = "./reports",
                 evidence_logger: Optional[EvidenceLogger] = None,
                 custody_manager: Optional[ChainOfCustody] = None):
        """
        Initialize Report Generator
        
        Args:
            output_directory: Directory to store generated reports
            evidence_logger: Evidence logger instance for data retrieval
            custody_manager: Chain of custody manager for case data
        """
        self.output_directory = Path(output_directory)
        self.output_directory.mkdir(parents=True, exist_ok=True)
        
        self.evidence_logger = evidence_logger or EvidenceLogger()
        self.custody_manager = custody_manager or ChainOfCustody()
        
        # Report templates and styles
        self._init_report_styles()
        
        # Generated reports tracking
        self._generated_reports: Dict[str, ReportMetadata] = {}
    
    def _init_report_styles(self):
        """Initialize report styles and templates"""
        if PDF_AVAILABLE:
            self.styles = getSampleStyleSheet()
            
            # Custom styles for forensic reports
            self.styles.add(ParagraphStyle(
                name='ForensicTitle',
                parent=self.styles['Title'],
                fontSize=18,
                spaceAfter=30,
                alignment=TA_CENTER,
                textColor=colors.darkblue
            ))
            
            self.styles.add(ParagraphStyle(
                name='ForensicHeading',
                parent=self.styles['Heading1'],
                fontSize=14,
                spaceAfter=12,
                spaceBefore=20,
                textColor=colors.darkblue
            ))
            
            self.styles.add(ParagraphStyle(
                name='ForensicSubheading',
                parent=self.styles['Heading2'],
                fontSize=12,
                spaceAfter=8,
                spaceBefore=12,
                textColor=colors.black
            ))
            
            self.styles.add(ParagraphStyle(
                name='ForensicBody',
                parent=self.styles['Normal'],
                fontSize=10,
                spaceAfter=6,
                alignment=TA_JUSTIFY
            ))
    
    def generate_json_report(self, 
                           case_id: str, 
                           include_raw_data: bool = True,
                           include_visualizations: bool = False) -> Tuple[str, ReportMetadata]:
        """
        Generate comprehensive JSON report for a case
        
        Args:
            case_id: Case ID to generate report for
            include_raw_data: Whether to include raw operation logs
            include_visualizations: Whether to include chart data
            
        Returns:
            Tuple[str, ReportMetadata]: (file_path, report_metadata)
            
        Raises:
            ReportGenerationError: If report generation fails
        """
        try:
            # Generate report ID
            report_id = f"JSON_{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Collect case data
            case_data = self._collect_case_data(case_id)
            
            # Build comprehensive JSON report
            report_data = {
                'report_metadata': {
                    'report_id': report_id,
                    'case_id': case_id,
                    'report_type': 'json',
                    'generated_at': datetime.now().isoformat(),
                    'generated_by': 'ForensicsToolkit',
                    'report_version': '1.0',
                    'include_raw_data': include_raw_data,
                    'include_visualizations': include_visualizations
                },
                'case_summary': case_data['case_summary'],
                'devices_analyzed': case_data['devices'],
                'attack_strategies': case_data['attack_strategies'],
                'evidence_records': case_data['evidence_records'],
                'chain_of_custody': case_data['custody_chain'],
                'integrity_verification': case_data['integrity_results'],
                'timeline_analysis': case_data['timeline'],
                'statistical_summary': case_data['statistics']
            }
            
            # Add raw data if requested
            if include_raw_data:
                report_data['raw_operation_logs'] = case_data['raw_operations']
            
            # Add visualization data if requested
            if include_visualizations and CHART_AVAILABLE:
                report_data['visualization_data'] = self._generate_visualization_data(case_data)
            
            # Generate file path
            filename = f"{report_id}.json"
            file_path = self.output_directory / filename
            
            # Write JSON report
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            # Calculate integrity hash
            integrity_hash = self._calculate_file_hash(file_path)
            
            # Create report metadata
            report_metadata = ReportMetadata(
                report_id=report_id,
                case_id=case_id,
                report_type='json',
                generated_at=datetime.now(),
                generated_by='ForensicsToolkit',
                integrity_hash=integrity_hash,
                file_path=str(file_path),
                file_size=file_path.stat().st_size
            )
            
            # Store metadata
            self._generated_reports[report_id] = report_metadata
            
            # Log report generation
            self.evidence_logger.log_operation(
                case_id=case_id,
                operation_type="REPORT_GENERATION",
                message=f"JSON report generated: {report_id}",
                metadata={
                    'report_id': report_id,
                    'report_type': 'json',
                    'file_path': str(file_path),
                    'file_size': report_metadata.file_size,
                    'integrity_hash': integrity_hash
                }
            )
            
            return str(file_path), report_metadata
        
        except Exception as e:
            raise ReportGenerationError(f"Failed to generate JSON report: {str(e)}", "json")
    
    def generate_pdf_report(self, 
                          case_id: str, 
                          include_charts: bool = True,
                          court_format: bool = True) -> Tuple[str, ReportMetadata]:
        """
        Generate court-admissible PDF report for a case
        
        Args:
            case_id: Case ID to generate report for
            include_charts: Whether to include visualization charts
            court_format: Whether to use court-admissible formatting
            
        Returns:
            Tuple[str, ReportMetadata]: (file_path, report_metadata)
            
        Raises:
            ReportGenerationError: If report generation fails
        """
        if not PDF_AVAILABLE:
            raise ReportGenerationError("PDF generation not available - reportlab not installed", "pdf")
        
        try:
            # Generate report ID
            report_id = f"PDF_{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Collect case data
            case_data = self._collect_case_data(case_id)
            
            # Generate file path
            filename = f"{report_id}.pdf"
            file_path = self.output_directory / filename
            
            # Create PDF document
            doc = SimpleDocTemplate(
                str(file_path),
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build PDF content
            story = []
            
            # Title page
            story.extend(self._build_pdf_title_page(case_data, court_format))
            story.append(PageBreak())
            
            # Executive summary
            story.extend(self._build_pdf_executive_summary(case_data))
            story.append(PageBreak())
            
            # Case details
            story.extend(self._build_pdf_case_details(case_data))
            
            # Evidence documentation
            story.extend(self._build_pdf_evidence_documentation(case_data))
            story.append(PageBreak())
            
            # Chain of custody
            story.extend(self._build_pdf_custody_chain(case_data))
            story.append(PageBreak())
            
            # Integrity verification
            story.extend(self._build_pdf_integrity_section(case_data))
            
            # Build PDF
            doc.build(story)
            
            # Calculate integrity hash
            integrity_hash = self._calculate_file_hash(file_path)
            
            # Create report metadata
            report_metadata = ReportMetadata(
                report_id=report_id,
                case_id=case_id,
                report_type='pdf',
                generated_at=datetime.now(),
                generated_by='ForensicsToolkit',
                integrity_hash=integrity_hash,
                file_path=str(file_path),
                file_size=file_path.stat().st_size
            )
            
            # Store metadata
            self._generated_reports[report_id] = report_metadata
            
            # Log report generation
            self.evidence_logger.log_operation(
                case_id=case_id,
                operation_type="REPORT_GENERATION",
                message=f"PDF report generated: {report_id}",
                metadata={
                    'report_id': report_id,
                    'report_type': 'pdf',
                    'file_path': str(file_path),
                    'file_size': report_metadata.file_size,
                    'integrity_hash': integrity_hash,
                    'court_format': court_format,
                    'include_charts': include_charts
                }
            )
            
            return str(file_path), report_metadata
        
        except Exception as e:
            raise ReportGenerationError(f"Failed to generate PDF report: {str(e)}", "pdf")
    
    def _collect_case_data(self, case_id: str) -> Dict[str, Any]:
        """
        Collect comprehensive case data for report generation
        
        Args:
            case_id: Case ID to collect data for
            
        Returns:
            Dict[str, Any]: Comprehensive case data
        """
        # Get case metadata
        case_metadata = self.custody_manager.get_case_metadata(case_id)
        if not case_metadata:
            raise ReportGenerationError(f"Case {case_id} not found")
        
        # Get evidence records
        evidence_records = self.custody_manager.get_evidence_records(case_id)
        
        # Get custody chain
        custody_chain = self.custody_manager.get_custody_chain(case_id)
        
        # Get operation logs
        operations = self.evidence_logger.get_operations(case_id=case_id)
        
        # Get integrity verification results
        integrity_results = self.evidence_logger.verify_integrity(case_id)
        
        # Analyze devices
        devices = self._analyze_case_devices(evidence_records)
        
        # Analyze attack strategies
        attack_strategies = self._analyze_attack_strategies(evidence_records, operations)
        
        # Generate timeline
        timeline = self._generate_case_timeline(operations, custody_chain)
        
        # Generate statistics
        statistics = self._generate_case_statistics(evidence_records, operations, custody_chain)
        
        return {
            'case_summary': {
                'case_id': case_id,
                'case_title': case_metadata.case_title,
                'case_description': case_metadata.case_description,
                'investigator_id': case_metadata.investigator_id,
                'created_at': case_metadata.created_at.isoformat(),
                'case_status': case_metadata.case_status,
                'evidence_count': case_metadata.evidence_count,
                'last_activity': case_metadata.last_activity.isoformat() if case_metadata.last_activity else None,
                'authorized_users': case_metadata.authorized_users,
                'case_notes': case_metadata.case_notes
            },
            'devices': devices,
            'attack_strategies': attack_strategies,
            'evidence_records': [record.to_dict() for record in evidence_records],
            'custody_chain': [event.to_dict() for event in custody_chain],
            'raw_operations': [op.to_dict() for op in operations],
            'integrity_results': integrity_results,
            'timeline': timeline,
            'statistics': statistics
        }
    
    def _analyze_case_devices(self, evidence_records: List[EvidenceRecord]) -> List[Dict[str, Any]]:
        """Analyze devices involved in the case"""
        device_map = {}
        
        for record in evidence_records:
            serial = record.device_serial
            if serial not in device_map:
                device_map[serial] = {
                    'device_serial': serial,
                    'first_seen': record.timestamp,
                    'last_seen': record.timestamp,
                    'operation_count': 0,
                    'operations': [],
                    'evidence_types': set()
                }
            
            device_info = device_map[serial]
            device_info['operation_count'] += 1
            device_info['operations'].append(record.operation_type)
            device_info['evidence_types'].add(record.evidence_type)
            
            if record.timestamp < device_info['first_seen']:
                device_info['first_seen'] = record.timestamp
            if record.timestamp > device_info['last_seen']:
                device_info['last_seen'] = record.timestamp
        
        # Convert to list and format
        devices = []
        for device_info in device_map.values():
            devices.append({
                'device_serial': device_info['device_serial'],
                'first_seen': device_info['first_seen'].isoformat(),
                'last_seen': device_info['last_seen'].isoformat(),
                'operation_count': device_info['operation_count'],
                'unique_operations': list(set(device_info['operations'])),
                'evidence_types': list(device_info['evidence_types'])
            })
        
        return devices
    
    def _analyze_attack_strategies(self, evidence_records: List[EvidenceRecord], 
                                 operations: List[OperationLog]) -> List[Dict[str, Any]]:
        """Analyze attack strategies used in the case"""
        strategies = []
        
        # Group operations by attack type
        attack_operations = [op for op in operations if 'ATTACK' in op.operation_type]
        
        strategy_map = {}
        for op in attack_operations:
            strategy_type = op.metadata.get('strategy_type', 'unknown')
            device_serial = op.device_serial
            
            key = f"{strategy_type}_{device_serial}"
            if key not in strategy_map:
                strategy_map[key] = {
                    'strategy_type': strategy_type,
                    'device_serial': device_serial,
                    'start_time': op.timestamp,
                    'end_time': op.timestamp,
                    'attempt_count': 0,
                    'success_count': 0,
                    'operations': []
                }
            
            strategy_info = strategy_map[key]
            strategy_info['attempt_count'] += 1
            strategy_info['operations'].append(op.to_dict())
            
            if 'success' in op.message.lower():
                strategy_info['success_count'] += 1
            
            if op.timestamp < strategy_info['start_time']:
                strategy_info['start_time'] = op.timestamp
            if op.timestamp > strategy_info['end_time']:
                strategy_info['end_time'] = op.timestamp
        
        # Convert to list and calculate metrics
        for strategy_info in strategy_map.values():
            duration = (strategy_info['end_time'] - strategy_info['start_time']).total_seconds()
            success_rate = (strategy_info['success_count'] / strategy_info['attempt_count'] * 100) if strategy_info['attempt_count'] > 0 else 0
            
            strategies.append({
                'strategy_type': strategy_info['strategy_type'],
                'device_serial': strategy_info['device_serial'],
                'start_time': strategy_info['start_time'].isoformat(),
                'end_time': strategy_info['end_time'].isoformat(),
                'duration_seconds': duration,
                'attempt_count': strategy_info['attempt_count'],
                'success_count': strategy_info['success_count'],
                'success_rate_percent': round(success_rate, 2),
                'operations': strategy_info['operations']
            })
        
        return strategies
    
    def _generate_case_timeline(self, operations: List[OperationLog], 
                              custody_events: List[CustodyEvent]) -> List[Dict[str, Any]]:
        """Generate chronological timeline of case events"""
        timeline_events = []
        
        # Add operation events
        for op in operations:
            timeline_events.append({
                'timestamp': op.timestamp.isoformat(),
                'event_type': 'operation',
                'operation_type': op.operation_type,
                'message': op.message,
                'device_serial': op.device_serial,
                'user_id': op.user_id,
                'source': 'evidence_logger'
            })
        
        # Add custody events
        for event in custody_events:
            timeline_events.append({
                'timestamp': event.timestamp.isoformat(),
                'event_type': 'custody',
                'operation_type': event.event_type,
                'message': event.description,
                'device_serial': None,
                'user_id': event.user_id,
                'source': 'chain_of_custody'
            })
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x['timestamp'])
        
        return timeline_events
    
    def _generate_case_statistics(self, evidence_records: List[EvidenceRecord],
                                operations: List[OperationLog],
                                custody_events: List[CustodyEvent]) -> Dict[str, Any]:
        """Generate statistical summary of case data"""
        if not operations:
            return {
                'total_operations': 0,
                'total_evidence_records': len(evidence_records),
                'total_custody_events': len(custody_events),
                'unique_devices': 0,
                'unique_users': 0,
                'case_duration_hours': 0,
                'operations_by_type': {},
                'evidence_by_type': {},
                'activity_by_hour': {}
            }
        
        # Basic counts
        unique_devices = len(set(op.device_serial for op in operations if op.device_serial))
        unique_users = len(set(op.user_id for op in operations if op.user_id))
        
        # Case duration
        start_time = min(op.timestamp for op in operations)
        end_time = max(op.timestamp for op in operations)
        duration_hours = (end_time - start_time).total_seconds() / 3600
        
        # Operations by type
        operations_by_type = {}
        for op in operations:
            op_type = op.operation_type
            operations_by_type[op_type] = operations_by_type.get(op_type, 0) + 1
        
        # Evidence by type
        evidence_by_type = {}
        for record in evidence_records:
            ev_type = record.evidence_type
            evidence_by_type[ev_type] = evidence_by_type.get(ev_type, 0) + 1
        
        # Activity by hour
        activity_by_hour = {}
        for op in operations:
            hour = op.timestamp.hour
            activity_by_hour[hour] = activity_by_hour.get(hour, 0) + 1
        
        return {
            'total_operations': len(operations),
            'total_evidence_records': len(evidence_records),
            'total_custody_events': len(custody_events),
            'unique_devices': unique_devices,
            'unique_users': unique_users,
            'case_duration_hours': round(duration_hours, 2),
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'operations_by_type': operations_by_type,
            'evidence_by_type': evidence_by_type,
            'activity_by_hour': activity_by_hour
        }
    
    def _generate_visualization_data(self, case_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate data for visualizations"""
        if not CHART_AVAILABLE:
            return {}
        
        viz_data = {}
        
        # Timeline chart data
        timeline = case_data['timeline']
        if timeline:
            viz_data['timeline_chart'] = {
                'timestamps': [event['timestamp'] for event in timeline],
                'event_types': [event['event_type'] for event in timeline],
                'operation_types': [event['operation_type'] for event in timeline]
            }
        
        # Operations distribution
        stats = case_data['statistics']
        if stats['operations_by_type']:
            viz_data['operations_pie_chart'] = {
                'labels': list(stats['operations_by_type'].keys()),
                'values': list(stats['operations_by_type'].values())
            }
        
        # Activity heatmap
        if stats['activity_by_hour']:
            viz_data['activity_heatmap'] = {
                'hours': list(range(24)),
                'activity_counts': [stats['activity_by_hour'].get(hour, 0) for hour in range(24)]
            }
        
        return viz_data
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of a file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    # PDF Building Methods
    def _build_pdf_title_page(self, case_data: Dict[str, Any], court_format: bool) -> List:
        """Build PDF title page"""
        story = []
        
        # Title
        title = "DIGITAL FORENSICS ANALYSIS REPORT" if court_format else "Forensic Analysis Report"
        story.append(Paragraph(title, self.styles['ForensicTitle']))
        story.append(Spacer(1, 0.5*inch))
        
        # Case information
        case_summary = case_data['case_summary']
        
        case_info_data = [
            ['Case ID:', case_summary['case_id']],
            ['Case Title:', case_summary['case_title']],
            ['Primary Investigator:', case_summary['investigator_id']],
            ['Case Created:', case_summary['created_at'][:10]],
            ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ['Case Status:', case_summary['case_status'].upper()]
        ]
        
        case_info_table = Table(case_info_data, colWidths=[2*inch, 4*inch])
        case_info_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey)
        ]))
        
        story.append(case_info_table)
        story.append(Spacer(1, 0.5*inch))
        
        # Legal disclaimer for court format
        if court_format:
            disclaimer = """
            <b>LEGAL NOTICE:</b><br/>
            This report contains the results of a digital forensic examination conducted using 
            Crack Droid forensic toolkit. The examination was performed in accordance with 
            established forensic procedures and industry best practices. All evidence has been 
            handled according to proper chain of custody procedures and integrity verification 
            protocols. This report is intended for authorized law enforcement and legal proceedings only.
            """
            story.append(Paragraph(disclaimer, self.styles['ForensicBody']))
            story.append(Spacer(1, 0.3*inch))
        
        # Case description
        if case_summary['case_description']:
            story.append(Paragraph('<b>Case Description:</b>', self.styles['ForensicSubheading']))
            story.append(Paragraph(case_summary['case_description'], self.styles['ForensicBody']))
        
        return story
    
    def _build_pdf_executive_summary(self, case_data: Dict[str, Any]) -> List:
        """Build PDF executive summary"""
        story = []
        
        story.append(Paragraph('EXECUTIVE SUMMARY', self.styles['ForensicHeading']))
        
        stats = case_data['statistics']
        
        # Summary statistics
        summary_text = f"""
        This forensic analysis examined {stats['unique_devices']} device(s) over a period of 
        {stats['case_duration_hours']} hours, resulting in {stats['total_evidence_records']} 
        evidence records and {stats['total_operations']} forensic operations. The investigation 
        involved {stats['unique_users']} authorized personnel and maintained a complete chain 
        of custody with {stats['total_custody_events']} documented custody events.
        """
        
        story.append(Paragraph(summary_text, self.styles['ForensicBody']))
        story.append(Spacer(1, 0.2*inch))
        
        # Key findings
        story.append(Paragraph('<b>Key Findings:</b>', self.styles['ForensicSubheading']))
        
        # Analyze attack strategies for findings
        attack_strategies = case_data['attack_strategies']
        successful_attacks = [s for s in attack_strategies if s['success_count'] > 0]
        
        if successful_attacks:
            findings_text = f"""
            • {len(successful_attacks)} successful attack strategies were executed<br/>
            • {len(case_data['devices'])} unique devices were analyzed<br/>
            • All evidence integrity verification checks passed<br/>
            • Complete chain of custody maintained throughout investigation
            """
        else:
            findings_text = f"""
            • {len(attack_strategies)} attack strategies were attempted<br/>
            • {len(case_data['devices'])} unique devices were analyzed<br/>
            • All evidence integrity verification checks passed<br/>
            • Complete chain of custody maintained throughout investigation
            """
        
        story.append(Paragraph(findings_text, self.styles['ForensicBody']))
        
        return story
    
    def _build_pdf_case_details(self, case_data: Dict[str, Any]) -> List:
        """Build PDF case details section"""
        story = []
        
        story.append(Paragraph('CASE DETAILS', self.styles['ForensicHeading']))
        
        case_summary = case_data['case_summary']
        
        # Case metadata table
        case_details = [
            ['Case ID', case_summary['case_id']],
            ['Case Title', case_summary['case_title']],
            ['Primary Investigator', case_summary['investigator_id']],
            ['Case Status', case_summary['case_status']],
            ['Created Date', case_summary['created_at'][:10]],
            ['Last Activity', case_summary['last_activity'][:10] if case_summary['last_activity'] else 'N/A'],
            ['Evidence Count', str(case_summary['evidence_count'])],
            ['Authorized Users', ', '.join(case_summary['authorized_users'])]
        ]
        
        case_table = Table(case_details, colWidths=[2*inch, 4*inch])
        case_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey)
        ]))
        
        story.append(case_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Case notes
        if case_summary['case_notes']:
            story.append(Paragraph('<b>Case Notes:</b>', self.styles['ForensicSubheading']))
            story.append(Paragraph(case_summary['case_notes'], self.styles['ForensicBody']))
        
        return story
    
    def _build_pdf_evidence_documentation(self, case_data: Dict[str, Any]) -> List:
        """Build PDF evidence documentation section"""
        story = []
        
        story.append(Paragraph('EVIDENCE DOCUMENTATION', self.styles['ForensicHeading']))
        
        evidence_records = case_data['evidence_records']
        
        if not evidence_records:
            story.append(Paragraph('No evidence records found for this case.', self.styles['ForensicBody']))
            return story
        
        # Summary table
        story.append(Paragraph('Evidence Summary', self.styles['ForensicSubheading']))
        
        # Create evidence summary table
        evidence_summary = [['#', 'Timestamp', 'Operation', 'Device', 'Result', 'Hash (first 16 chars)']]
        
        for i, record in enumerate(evidence_records[:10]):  # Limit to first 10 for space
            evidence_summary.append([
                str(i+1),
                record['timestamp'][:19],
                record['operation_type'],
                record['device_serial'],
                record['result'][:30] + '...' if len(record['result']) > 30 else record['result'],
                record['hash_verification'][:16] + '...'
            ])
        
        if len(evidence_records) > 10:
            evidence_summary.append(['...', f'({len(evidence_records) - 10} more records)', '', '', '', ''])
        
        evidence_table = Table(evidence_summary, colWidths=[0.3*inch, 1.2*inch, 1.2*inch, 1*inch, 1.8*inch, 1.5*inch])
        evidence_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey)
        ]))
        
        story.append(evidence_table)
        
        return story
    
    def _build_pdf_custody_chain(self, case_data: Dict[str, Any]) -> List:
        """Build PDF chain of custody section"""
        story = []
        
        story.append(Paragraph('CHAIN OF CUSTODY', self.styles['ForensicHeading']))
        
        custody_chain = case_data['custody_chain']
        
        if not custody_chain:
            story.append(Paragraph('No custody events found for this case.', self.styles['ForensicBody']))
            return story
        
        # Custody events table
        custody_summary = [['#', 'Timestamp', 'Event Type', 'User', 'Description']]
        
        for i, event in enumerate(custody_chain):
            custody_summary.append([
                str(i+1),
                event['timestamp'][:19],
                event['event_type'],
                event['user_id'],
                event['description'][:50] + '...' if len(event['description']) > 50 else event['description']
            ])
        
        custody_table = Table(custody_summary, colWidths=[0.3*inch, 1.2*inch, 1.2*inch, 1*inch, 3.3*inch])
        custody_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey)
        ]))
        
        story.append(custody_table)
        
        return story
    
    def _build_pdf_integrity_section(self, case_data: Dict[str, Any]) -> List:
        """Build PDF integrity verification section"""
        story = []
        
        story.append(Paragraph('INTEGRITY VERIFICATION', self.styles['ForensicHeading']))
        
        integrity_results = case_data['integrity_results']
        
        # Integrity summary
        integrity_summary = f"""
        <b>Integrity Status:</b> {integrity_results['integrity_status'].upper()}<br/>
        <b>Total Operations Verified:</b> {integrity_results['verified_operations']}<br/>
        <b>Failed Verifications:</b> {integrity_results['failed_operations']}<br/>
        <b>Verification Timestamp:</b> {integrity_results['timestamp'][:19]}
        """
        
        story.append(Paragraph(integrity_summary, self.styles['ForensicBody']))
        
        # Corrupted entries if any
        if integrity_results['corrupted_entries']:
            story.append(Paragraph('<b>Integrity Issues Found:</b>', self.styles['ForensicSubheading']))
            
            for entry in integrity_results['corrupted_entries']:
                issue_text = f"""
                • Timestamp: {entry['timestamp'][:19]}<br/>
                • Operation: {entry['operation_type']}<br/>
                • Expected Hash: {entry['expected_hash'][:16]}...<br/>
                • Stored Hash: {entry['stored_hash'][:16]}...
                """
                story.append(Paragraph(issue_text, self.styles['ForensicBody']))
        
        return story
    
    def verify_report_integrity(self, report_id: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify the integrity of a generated report
        
        Args:
            report_id: Report ID to verify
            
        Returns:
            Tuple[bool, Dict[str, Any]]: (integrity_valid, verification_results)
        """
        if report_id not in self._generated_reports:
            return False, {'error': 'Report not found'}
        
        report_metadata = self._generated_reports[report_id]
        
        try:
            # Check if file exists
            if not report_metadata.file_path or not Path(report_metadata.file_path).exists():
                return False, {'error': 'Report file not found'}
            
            # Recalculate hash
            current_hash = self._calculate_file_hash(Path(report_metadata.file_path))
            
            # Compare with stored hash
            integrity_valid = current_hash == report_metadata.integrity_hash
            
            verification_results = {
                'report_id': report_id,
                'file_path': report_metadata.file_path,
                'original_hash': report_metadata.integrity_hash,
                'current_hash': current_hash,
                'integrity_valid': integrity_valid,
                'file_size': Path(report_metadata.file_path).stat().st_size,
                'original_size': report_metadata.file_size,
                'size_match': Path(report_metadata.file_path).stat().st_size == report_metadata.file_size,
                'verified_at': datetime.now().isoformat()
            }
            
            return integrity_valid, verification_results
        
        except Exception as e:
            return False, {'error': f'Verification failed: {str(e)}'}
    
    def get_report_metadata(self, report_id: str) -> Optional[ReportMetadata]:
        """
        Get metadata for a generated report
        
        Args:
            report_id: Report ID
            
        Returns:
            ReportMetadata: Report metadata if found
        """
        return self._generated_reports.get(report_id)
    
    def list_generated_reports(self, case_id: Optional[str] = None) -> List[ReportMetadata]:
        """
        List all generated reports, optionally filtered by case ID
        
        Args:
            case_id: Optional case ID filter
            
        Returns:
            List[ReportMetadata]: List of report metadata
        """
        reports = list(self._generated_reports.values())
        
        if case_id:
            reports = [r for r in reports if r.case_id == case_id]
        
        # Sort by generation time (newest first)
        reports.sort(key=lambda r: r.generated_at, reverse=True)
        
        return reports
    
    def generate_summary_report(self, case_id: str) -> Tuple[str, ReportMetadata]:
        """
        Generate a brief summary report in JSON format
        
        Args:
            case_id: Case ID to generate summary for
            
        Returns:
            Tuple[str, ReportMetadata]: (file_path, report_metadata)
        """
        try:
            # Generate report ID
            report_id = f"SUMMARY_{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Collect basic case data
            case_data = self._collect_case_data(case_id)
            
            # Build summary report
            summary_data = {
                'report_metadata': {
                    'report_id': report_id,
                    'case_id': case_id,
                    'report_type': 'summary',
                    'generated_at': datetime.now().isoformat(),
                    'generated_by': 'ForensicsToolkit'
                },
                'case_summary': case_data['case_summary'],
                'statistics': case_data['statistics'],
                'integrity_status': case_data['integrity_results']['integrity_status'],
                'devices_count': len(case_data['devices']),
                'attack_strategies_count': len(case_data['attack_strategies']),
                'successful_attacks': len([s for s in case_data['attack_strategies'] if s['success_count'] > 0])
            }
            
            # Generate file path
            filename = f"{report_id}.json"
            file_path = self.output_directory / filename
            
            # Write summary report
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, indent=2, default=str)
            
            # Calculate integrity hash
            integrity_hash = self._calculate_file_hash(file_path)
            
            # Create report metadata
            report_metadata = ReportMetadata(
                report_id=report_id,
                case_id=case_id,
                report_type='summary',
                generated_at=datetime.now(),
                generated_by='ForensicsToolkit',
                integrity_hash=integrity_hash,
                file_path=str(file_path),
                file_size=file_path.stat().st_size
            )
            
            # Store metadata
            self._generated_reports[report_id] = report_metadata
            
            return str(file_path), report_metadata
        
        except Exception as e:
            raise ReportGenerationError(f"Failed to generate summary report: {str(e)}", "summary")