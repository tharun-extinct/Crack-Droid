"""
Forensics Orchestrator - Main workflow controller for forensic operations

This module implements the ForensicsOrchestrator class as the central coordinator
for all forensic operations, managing device detection, analysis coordination,
attack strategy selection and execution, and evidence collection orchestration.
"""

import logging
import threading
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field

from ..interfaces import (
    IForensicsEngine, IDeviceHandler, IAttackEngine, IEvidenceManager,
    AndroidDevice, AttackStrategy, AttackResult, AttackType, LockType,
    ForensicsException
)
from ..models.device import AndroidDevice as DeviceModel, LockoutPolicy
from ..models.attack import AttackStrategy as StrategyModel, EvidenceRecord, AttackStatus
from ..config import config_manager
from .adb_handler import ADBHandler
from .evidence_logger import EvidenceLogger
from .chain_of_custody import ChainOfCustody
from ..attack_engines.brute_force import BruteForceEngine
from ..attack_engines.dictionary_attack import DictionaryAttack
from ..attack_engines.hash_cracking import HashCracking
from ..attack_engines.pattern_analysis import PatternAnalysis
from unittest.mock import Mock


class ForensicsOrchestratorException(ForensicsException):
    """Exception raised during forensics orchestration"""
    
    def __init__(self, message: str, error_code: str = "ORCHESTRATOR_ERROR"):
        super().__init__(message, error_code, evidence_impact=True)


@dataclass
class DeviceAnalysisResult:
    """Result of device analysis"""
    device: AndroidDevice
    capabilities: Dict[str, bool]
    recommended_strategies: List[AttackType]
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    analysis_notes: str = ""


@dataclass
class ForensicWorkflowState:
    """State tracking for forensic workflow"""
    case_id: str
    devices: List[AndroidDevice] = field(default_factory=list)
    analysis_results: Dict[str, DeviceAnalysisResult] = field(default_factory=dict)
    active_attacks: Dict[str, Future] = field(default_factory=dict)
    completed_attacks: Dict[str, AttackResult] = field(default_factory=dict)
    evidence_records: List[EvidenceRecord] = field(default_factory=list)
    workflow_status: str = "initialized"
    start_time: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)


class ForensicsOrchestrator(IForensicsEngine):
    """
    Main workflow controller for forensic operations
    
    This class coordinates all aspects of forensic analysis including:
    - Device detection and analysis coordination
    - Attack strategy selection and execution management
    - Evidence collection orchestration
    - Workflow state management and monitoring
    """
    
    def __init__(self, 
                 case_id: str,
                 user_session: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        """
        Initialize forensics orchestrator
        
        Args:
            case_id: Case identifier for this forensic session
            user_session: User session ID for authentication
            logger: Optional logger instance
        """
        self.case_id = case_id
        self.user_session = user_session
        self.logger = logger or logging.getLogger(__name__)
        
        # Initialize workflow state
        self.workflow_state = ForensicWorkflowState(case_id=case_id)
        self._lock = threading.RLock()
        
        # Initialize services
        self._initialize_services()
        
        # Initialize device handlers
        self._initialize_device_handlers()
        
        # Initialize attack engines
        self._initialize_attack_engines()
        
        # Thread pool for concurrent operations
        self._executor = ThreadPoolExecutor(
            max_workers=config_manager.forensics_settings.max_concurrent_attacks
        )
        
        # Callbacks for workflow events
        self._device_detected_callback: Optional[Callable[[AndroidDevice], None]] = None
        self._analysis_completed_callback: Optional[Callable[[DeviceAnalysisResult], None]] = None
        self._attack_progress_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None
        self._evidence_collected_callback: Optional[Callable[[EvidenceRecord], None]] = None
        
        self.logger.info(f"ForensicsOrchestrator initialized for case: {case_id}")
    
    def _initialize_services(self):
        """Initialize core services"""
        try:
            # Evidence management
            self.evidence_logger = EvidenceLogger(
                log_directory=str(config_manager.get_evidence_path(self.case_id) / "logs"),
                encrypt_logs=config_manager.security_settings.encrypt_evidence
            )
            
            self.chain_of_custody = ChainOfCustody(
                storage_path=str(config_manager.get_evidence_path(self.case_id))
            )
            
            # Authentication and compliance removed - simplified mode
            self.auth_service = None
            self.legal_compliance = None
            
            self.logger.info("Core services initialized successfully")
            
        except Exception as e:
            raise ForensicsOrchestratorException(f"Failed to initialize services: {e}")
    
    def _initialize_device_handlers(self):
        """Initialize device communication handlers"""
        try:
            self.device_handlers: Dict[str, IDeviceHandler] = {}
            
            # ADB Handler for USB debugging enabled devices
            self.device_handlers['adb'] = ADBHandler(
                adb_path=config_manager.tool_paths.adb_path,
                timeout=config_manager.forensics_settings.default_timeout
            )
            
            # EDL Handler for USB debugging disabled devices (mock for now)
            self.device_handlers['edl'] = Mock()
            
            # Fastboot Handler for bootloader access (mock for now)
            self.device_handlers['fastboot'] = Mock()
            
            self.logger.info("Device handlers initialized successfully")
            
        except Exception as e:
            raise ForensicsOrchestratorException(f"Failed to initialize device handlers: {e}")
    
    def _initialize_attack_engines(self):
        """Initialize attack engines"""
        try:
            self.attack_engines: Dict[AttackType, IAttackEngine] = {}
            
            # Brute force engine
            self.attack_engines[AttackType.BRUTE_FORCE] = BruteForceEngine(logger=self.logger)
            
            # Dictionary attack engine
            self.attack_engines[AttackType.DICTIONARY] = DictionaryAttack(logger=self.logger)
            
            # Hash cracking engine
            self.attack_engines[AttackType.HASH_CRACKING] = HashCracking(logger=self.logger)
            
            # Pattern analysis engine (mock for now)
            self.attack_engines[AttackType.PATTERN_ANALYSIS] = Mock()
            
            # Hybrid engine uses brute force as base
            self.attack_engines[AttackType.HYBRID] = self.attack_engines[AttackType.BRUTE_FORCE]
            
            self.logger.info("Attack engines initialized successfully")
            
        except Exception as e:
            raise ForensicsOrchestratorException(f"Failed to initialize attack engines: {e}")
    
    def set_device_detected_callback(self, callback: Callable[[AndroidDevice], None]):
        """Set callback for device detection events"""
        self._device_detected_callback = callback
    
    def set_analysis_completed_callback(self, callback: Callable[[DeviceAnalysisResult], None]):
        """Set callback for analysis completion events"""
        self._analysis_completed_callback = callback
    
    def set_attack_progress_callback(self, callback: Callable[[str, Dict[str, Any]], None]):
        """Set callback for attack progress events"""
        self._attack_progress_callback = callback
    
    def set_evidence_collected_callback(self, callback: Callable[[EvidenceRecord], None]):
        """Set callback for evidence collection events"""
        self._evidence_collected_callback = callback
    
    def detect_devices(self) -> List[AndroidDevice]:
        """
        Detect all available Android devices using multiple handlers
        
        Returns:
            List[AndroidDevice]: List of detected devices
        """
        self.logger.info("Starting device detection across all handlers")
        
        try:
            with self._lock:
                detected_devices = []
                detection_errors = []
                
                # Try each device handler
                for handler_name, handler in self.device_handlers.items():
                    try:
                        self.logger.debug(f"Detecting devices with {handler_name} handler")
                        devices = handler.detect_devices()
                        
                        for device in devices:
                            # Avoid duplicates based on serial number
                            if not any(d.serial == device.serial for d in detected_devices):
                                detected_devices.append(device)
                                
                                # Log device detection
                                self._log_device_detection(device, handler_name)
                                
                                # Trigger callback
                                if self._device_detected_callback:
                                    self._device_detected_callback(device)
                        
                        self.logger.info(f"{handler_name} handler detected {len(devices)} devices")
                        
                    except Exception as e:
                        error_msg = f"Device detection failed for {handler_name}: {e}"
                        self.logger.warning(error_msg)
                        detection_errors.append(error_msg)
                
                # Update workflow state
                self.workflow_state.devices = detected_devices
                self.workflow_state.last_activity = datetime.now()
                
                # Log overall detection results
                self.evidence_logger.log_operation(
                    case_id=self.case_id,
                    operation_type="device_detection",
                    message=f"Detected {len(detected_devices)} devices",
                    metadata={
                        'devices_detected': len(detected_devices),
                        'handlers_used': list(self.device_handlers.keys()),
                        'detection_errors': detection_errors,
                        'device_serials': [d.serial for d in detected_devices]
                    }
                )
                
                self.logger.info(f"Device detection completed: {len(detected_devices)} devices found")
                return detected_devices
                
        except Exception as e:
            raise ForensicsOrchestratorException(f"Device detection failed: {e}")
    
    def _log_device_detection(self, device: AndroidDevice, handler_name: str):
        """Log individual device detection"""
        self.evidence_logger.log_operation(
            case_id=self.case_id,
            operation_type="device_detected",
            message=f"Device detected: {device.brand} {device.model}",
            device_serial=device.serial,
            user_id=self.user_session,
            metadata={
                'handler_used': handler_name,
                'device_info': device.to_dict(),
                'detection_timestamp': datetime.now().isoformat()
            }
        )
    
    def analyze_device(self, device: AndroidDevice) -> AndroidDevice:
        """
        Analyze device capabilities and configuration
        
        Args:
            device: Device to analyze
            
        Returns:
            AndroidDevice: Enhanced device information
        """
        self.logger.info(f"Starting analysis of device: {device.serial}")
        
        try:
            with self._lock:
                # Determine appropriate handler for analysis
                handler = self._select_device_handler(device)
                
                # Get detailed device information
                enhanced_device = handler.get_device_info(device)
                
                # Analyze forensic capabilities
                capabilities = enhanced_device.get_forensic_capabilities()
                
                # Determine recommended attack strategies
                recommended_strategies = self._recommend_attack_strategies(enhanced_device, capabilities)
                
                # Create analysis result
                analysis_result = DeviceAnalysisResult(
                    device=enhanced_device,
                    capabilities=capabilities,
                    recommended_strategies=recommended_strategies,
                    analysis_notes=self._generate_analysis_notes(enhanced_device, capabilities)
                )
                
                # Store analysis result
                self.workflow_state.analysis_results[device.serial] = analysis_result
                self.workflow_state.last_activity = datetime.now()
                
                # Log analysis
                self._log_device_analysis(analysis_result)
                
                # Trigger callback
                if self._analysis_completed_callback:
                    self._analysis_completed_callback(analysis_result)
                
                self.logger.info(f"Device analysis completed for: {device.serial}")
                return enhanced_device
                
        except Exception as e:
            raise ForensicsOrchestratorException(f"Device analysis failed for {device.serial}: {e}")
    
    def _select_device_handler(self, device: AndroidDevice) -> IDeviceHandler:
        """Select appropriate device handler based on device capabilities"""
        if device.usb_debugging:
            return self.device_handlers['adb']
        elif hasattr(device, 'bootloader_locked') and not device.bootloader_locked:
            return self.device_handlers['fastboot']
        else:
            return self.device_handlers['adb']  # Default to ADB for now
    
    def _recommend_attack_strategies(self, device: AndroidDevice, capabilities: Dict[str, bool]) -> List[AttackType]:
        """Recommend attack strategies based on device capabilities"""
        strategies = []
        
        # Pattern analysis for pattern locks
        if capabilities.get('pattern_analysis', False):
            strategies.append(AttackType.PATTERN_ANALYSIS)
        
        # Hash cracking for rooted devices
        if capabilities.get('hash_extraction', False):
            strategies.append(AttackType.HASH_CRACKING)
        
        # Brute force for viable lock types
        if capabilities.get('brute_force_viable', False):
            strategies.append(AttackType.BRUTE_FORCE)
            strategies.append(AttackType.DICTIONARY)
        
        # Hybrid approach for complex scenarios
        if len(strategies) > 1:
            strategies.append(AttackType.HYBRID)
        
        return strategies
    
    def _generate_analysis_notes(self, device: AndroidDevice, capabilities: Dict[str, bool]) -> str:
        """Generate analysis notes for the device"""
        notes = []
        
        if device.usb_debugging:
            notes.append("USB debugging enabled - ADB access available")
        
        if device.root_status:
            notes.append("Device is rooted - direct file system access possible")
        
        if device.lock_type:
            notes.append(f"Lock type: {device.lock_type.value}")
        
        if device.lockout_policy:
            notes.append(f"Lockout policy: {device.lockout_policy.max_attempts} attempts, {device.lockout_policy.lockout_duration}s lockout")
        
        # Capability-based notes
        viable_capabilities = [cap for cap, available in capabilities.items() if available]
        if viable_capabilities:
            notes.append(f"Available capabilities: {', '.join(viable_capabilities)}")
        
        return "; ".join(notes)
    
    def _log_device_analysis(self, analysis_result: DeviceAnalysisResult):
        """Log device analysis results"""
        self.evidence_logger.log_operation(
            case_id=self.case_id,
            operation_type="device_analysis",
            message=f"Device analysis completed: {analysis_result.device.brand} {analysis_result.device.model}",
            device_serial=analysis_result.device.serial,
            user_id=self.user_session,
            metadata={
                'capabilities': analysis_result.capabilities,
                'recommended_strategies': [s.value for s in analysis_result.recommended_strategies],
                'analysis_notes': analysis_result.analysis_notes,
                'device_forensics_ready': analysis_result.device.is_forensics_ready(),
                'analysis_timestamp': analysis_result.analysis_timestamp.isoformat()
            }
        )
    
    def execute_attack(self, strategy: AttackStrategy) -> AttackResult:
        """
        Execute forensic attack strategy
        
        Args:
            strategy: Attack strategy to execute
            
        Returns:
            AttackResult: Attack execution results
        """
        self.logger.info(f"Executing {strategy.strategy_type.value} attack on device: {strategy.target_device.serial}")
        
        try:
            with self._lock:
                # Validate strategy
                if not self._validate_attack_strategy(strategy):
                    raise ForensicsOrchestratorException("Invalid attack strategy")
                
                # Get appropriate attack engine
                engine = self.attack_engines.get(strategy.strategy_type)
                if not engine:
                    raise ForensicsOrchestratorException(f"No engine available for {strategy.strategy_type.value}")
                
                # Validate strategy with engine
                if not engine.validate_strategy(strategy):
                    raise ForensicsOrchestratorException("Strategy validation failed with attack engine")
                
                # Log attack initiation
                self._log_attack_initiation(strategy)
                
                # Execute attack (this may be long-running)
                attack_result = engine.execute_attack(strategy)
                
                # Process attack results
                processed_result = self._process_attack_result(strategy, attack_result)
                
                # Store completed attack
                self.workflow_state.completed_attacks[strategy.target_device.serial] = processed_result
                self.workflow_state.last_activity = datetime.now()
                
                # Log attack completion
                self._log_attack_completion(strategy, processed_result)
                
                self.logger.info(f"Attack execution completed for device: {strategy.target_device.serial}")
                return processed_result
                
        except Exception as e:
            # Log attack failure
            self._log_attack_failure(strategy, str(e))
            raise ForensicsOrchestratorException(f"Attack execution failed: {e}")
    
    def execute_attack_async(self, strategy: AttackStrategy) -> Future[AttackResult]:
        """
        Execute attack strategy asynchronously
        
        Args:
            strategy: Attack strategy to execute
            
        Returns:
            Future[AttackResult]: Future for attack results
        """
        self.logger.info(f"Starting async attack on device: {strategy.target_device.serial}")
        
        # Submit attack to thread pool
        future = self._executor.submit(self.execute_attack, strategy)
        
        # Store active attack
        with self._lock:
            self.workflow_state.active_attacks[strategy.target_device.serial] = future
        
        return future
    
    def _validate_attack_strategy(self, strategy: AttackStrategy) -> bool:
        """Validate attack strategy before execution"""
        try:
            # Basic strategy validation
            if not strategy.validate_all():
                self.logger.error(f"Strategy validation failed: {strategy.validation_errors}")
                return False
            
            # Check if device has been analyzed
            if strategy.target_device.serial not in self.workflow_state.analysis_results:
                self.logger.error("Device must be analyzed before attack execution")
                return False
            
            # Check strategy compatibility with device
            analysis_result = self.workflow_state.analysis_results[strategy.target_device.serial]
            if strategy.strategy_type not in analysis_result.recommended_strategies:
                self.logger.warning(f"Strategy {strategy.strategy_type.value} not recommended for this device")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Strategy validation error: {e}")
            return False
    
    def _process_attack_result(self, strategy: AttackStrategy, raw_result: Dict[str, Any]) -> AttackResult:
        """Process raw attack results into standardized format"""
        # Convert raw result to AttackResult
        attack_result = AttackResult(
            success=raw_result.get('success', False),
            attempts=raw_result.get('total_attempts', 0),
            duration=raw_result.get('duration_seconds', 0.0),
            result_data=raw_result.get('successful_pattern'),
            error_message=raw_result.get('error_message'),
            timestamp=datetime.now()
        )
        
        # Create evidence record if successful
        if attack_result.success:
            self._create_success_evidence_record(strategy, attack_result)
        
        return attack_result
    
    def _create_success_evidence_record(self, strategy: AttackStrategy, result: AttackResult):
        """Create evidence record for successful attack"""
        evidence_record = EvidenceRecord(
            case_id=self.case_id,
            timestamp=datetime.now(),
            operation_type="attack_success",
            device_serial=strategy.target_device.serial,
            attempt_number=result.attempts,
            result=f"Successfully unlocked device using {strategy.strategy_type.value} attack",
            hash_verification="",  # Will be computed by chain of custody
            evidence_type="unlock_credential",
            investigator_id=self.user_session,
            case_notes=f"Device unlocked with credential: {result.result_data}"
        )
        
        # Add to chain of custody
        self.chain_of_custody.add_evidence(evidence_record)
        
        # Store in workflow state
        self.workflow_state.evidence_records.append(evidence_record)
        
        # Trigger callback
        if self._evidence_collected_callback:
            self._evidence_collected_callback(evidence_record)
    
    def _log_attack_initiation(self, strategy: AttackStrategy):
        """Log attack initiation"""
        self.evidence_logger.log_operation(
            case_id=self.case_id,
            operation_type="attack_initiated",
            message=f"Attack initiated: {strategy.strategy_type.value}",
            device_serial=strategy.target_device.serial,
            user_id=self.user_session,
            metadata={
                'strategy_type': strategy.strategy_type.value,
                'max_attempts': strategy.max_attempts,
                'timeout_seconds': strategy.timeout_seconds,
                'gpu_acceleration': strategy.gpu_acceleration,
                'thread_count': strategy.thread_count,
                'estimated_duration': strategy.estimate_duration()
            }
        )
    
    def _log_attack_completion(self, strategy: AttackStrategy, result: AttackResult):
        """Log attack completion"""
        self.evidence_logger.log_operation(
            case_id=self.case_id,
            operation_type="attack_completed",
            message=f"Attack completed: {'SUCCESS' if result.success else 'FAILED'}",
            device_serial=strategy.target_device.serial,
            user_id=self.user_session,
            metadata={
                'strategy_type': strategy.strategy_type.value,
                'success': result.success,
                'attempts': result.attempts,
                'duration_seconds': result.duration,
                'result_data': result.result_data if result.success else None,
                'error_message': result.error_message
            }
        )
    
    def _log_attack_failure(self, strategy: AttackStrategy, error_message: str):
        """Log attack failure"""
        self.evidence_logger.log_operation(
            case_id=self.case_id,
            operation_type="attack_failed",
            message=f"Attack failed: {error_message}",
            device_serial=strategy.target_device.serial,
            user_id=self.user_session,
            metadata={
                'strategy_type': strategy.strategy_type.value,
                'error_message': error_message,
                'failure_timestamp': datetime.now().isoformat()
            }
        )
    
    def generate_evidence_report(self, case_id: str) -> Dict[str, Any]:
        """
        Generate comprehensive evidence report
        
        Args:
            case_id: Case ID to generate report for
            
        Returns:
            Dict[str, Any]: Comprehensive evidence report
        """
        self.logger.info(f"Generating evidence report for case: {case_id}")
        
        try:
            with self._lock:
                # Generate audit trail
                audit_trail = self.evidence_logger.generate_audit_trail(case_id)
                
                # Compile workflow summary
                workflow_summary = self._generate_workflow_summary()
                
                # Generate device analysis summary
                device_summary = self._generate_device_summary()
                
                # Generate attack results summary
                attack_summary = self._generate_attack_summary()
                
                # Compile comprehensive report
                evidence_report = {
                    'case_id': case_id,
                    'report_generated_at': datetime.now().isoformat(),
                    'generated_by': self.user_session,
                    'workflow_summary': workflow_summary,
                    'device_summary': device_summary,
                    'attack_summary': attack_summary,
                    'audit_trail': audit_trail,
                    'evidence_records': [record.to_dict() for record in self.workflow_state.evidence_records],
                    'integrity_verification': self.evidence_logger.verify_integrity(case_id),
                    'chain_of_custody': self.chain_of_custody.get_case_metadata().to_dict()
                }
                
                # Log report generation
                self.evidence_logger.log_operation(
                    case_id=case_id,
                    operation_type="report_generation",
                    message="Comprehensive evidence report generated",
                    user_id=self.user_session,
                    metadata={
                        'devices_analyzed': len(self.workflow_state.devices),
                        'attacks_executed': len(self.workflow_state.completed_attacks),
                        'evidence_records': len(self.workflow_state.evidence_records),
                        'report_sections': list(evidence_report.keys())
                    }
                )
                
                self.logger.info(f"Evidence report generated successfully for case: {case_id}")
                return evidence_report
                
        except Exception as e:
            raise ForensicsOrchestratorException(f"Evidence report generation failed: {e}")
    
    def _generate_workflow_summary(self) -> Dict[str, Any]:
        """Generate workflow summary"""
        return {
            'case_id': self.workflow_state.case_id,
            'workflow_status': self.workflow_state.workflow_status,
            'start_time': self.workflow_state.start_time.isoformat(),
            'last_activity': self.workflow_state.last_activity.isoformat(),
            'total_duration_seconds': (self.workflow_state.last_activity - self.workflow_state.start_time).total_seconds(),
            'devices_detected': len(self.workflow_state.devices),
            'devices_analyzed': len(self.workflow_state.analysis_results),
            'attacks_executed': len(self.workflow_state.completed_attacks),
            'evidence_records_created': len(self.workflow_state.evidence_records)
        }
    
    def _generate_device_summary(self) -> Dict[str, Any]:
        """Generate device analysis summary"""
        device_summary = {
            'total_devices': len(self.workflow_state.devices),
            'devices': [],
            'capabilities_summary': {},
            'lock_types': {}
        }
        
        for device in self.workflow_state.devices:
            device_info = {
                'serial': device.serial,
                'brand': device.brand,
                'model': device.model,
                'android_version': device.android_version,
                'usb_debugging': device.usb_debugging,
                'root_status': device.root_status,
                'lock_type': device.lock_type.value if device.lock_type else None,
                'forensics_ready': device.is_forensics_ready()
            }
            
            # Add analysis results if available
            if device.serial in self.workflow_state.analysis_results:
                analysis = self.workflow_state.analysis_results[device.serial]
                device_info['capabilities'] = analysis.capabilities
                device_info['recommended_strategies'] = [s.value for s in analysis.recommended_strategies]
                device_info['analysis_notes'] = analysis.analysis_notes
            
            device_summary['devices'].append(device_info)
            
            # Aggregate statistics
            if device.lock_type:
                lock_type = device.lock_type.value
                device_summary['lock_types'][lock_type] = device_summary['lock_types'].get(lock_type, 0) + 1
        
        return device_summary
    
    def _generate_attack_summary(self) -> Dict[str, Any]:
        """Generate attack results summary"""
        attack_summary = {
            'total_attacks': len(self.workflow_state.completed_attacks),
            'successful_attacks': 0,
            'failed_attacks': 0,
            'attack_results': [],
            'strategy_effectiveness': {}
        }
        
        for device_serial, result in self.workflow_state.completed_attacks.items():
            attack_info = {
                'device_serial': device_serial,
                'success': result.success,
                'attempts': result.attempts,
                'duration_seconds': result.duration,
                'timestamp': result.timestamp.isoformat()
            }
            
            if result.success:
                attack_summary['successful_attacks'] += 1
                attack_info['result_data'] = result.result_data
            else:
                attack_summary['failed_attacks'] += 1
                attack_info['error_message'] = result.error_message
            
            attack_summary['attack_results'].append(attack_info)
        
        return attack_summary
    
    def get_workflow_status(self) -> Dict[str, Any]:
        """Get current workflow status"""
        with self._lock:
            return {
                'case_id': self.workflow_state.case_id,
                'status': self.workflow_state.workflow_status,
                'devices_detected': len(self.workflow_state.devices),
                'devices_analyzed': len(self.workflow_state.analysis_results),
                'active_attacks': len(self.workflow_state.active_attacks),
                'completed_attacks': len(self.workflow_state.completed_attacks),
                'evidence_records': len(self.workflow_state.evidence_records),
                'start_time': self.workflow_state.start_time.isoformat(),
                'last_activity': self.workflow_state.last_activity.isoformat()
            }
    
    def stop_all_attacks(self):
        """Stop all active attacks"""
        self.logger.info("Stopping all active attacks")
        
        with self._lock:
            for device_serial, future in self.workflow_state.active_attacks.items():
                try:
                    future.cancel()
                    self.logger.info(f"Cancelled attack for device: {device_serial}")
                except Exception as e:
                    self.logger.warning(f"Failed to cancel attack for {device_serial}: {e}")
            
            self.workflow_state.active_attacks.clear()
            self.workflow_state.workflow_status = "stopped"
    
    def cleanup(self):
        """Clean up orchestrator resources"""
        self.logger.info("Cleaning up ForensicsOrchestrator resources")
        
        try:
            # Stop all active attacks
            self.stop_all_attacks()
            
            # Shutdown thread pool
            if self._executor:
                self._executor.shutdown(wait=True)
            
            # Final workflow log
            self.evidence_logger.log_operation(
                case_id=self.case_id,
                operation_type="workflow_cleanup",
                message="Forensics workflow cleanup completed",
                user_id=self.user_session,
                metadata=self.get_workflow_status()
            )
            
            self.logger.info("ForensicsOrchestrator cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.cleanup()