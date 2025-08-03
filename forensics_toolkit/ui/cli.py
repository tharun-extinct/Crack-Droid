"""
Command Line Interface for ForenCrack Droid

This module implements the CLI interface for forensic operations including:
- Interactive prompts for case setup
- Progress display and status reporting
- Command validation and help system
- Forensic workflow management
"""

import argparse
import sys
import os
import getpass
import time
import threading
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
from pathlib import Path

from ..interfaces import (
    AndroidDevice, AttackStrategy, AttackResult, AttackType, LockType,
    UserRole, Permission, ForensicsException
)
from ..services.forensics_orchestrator import ForensicsOrchestrator
from ..services.authentication import AuthenticationService, UserManager
from ..services.legal_compliance import LegalComplianceService
from ..config import config_manager


class CLIColors:
    """ANSI color codes for CLI output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class ProgressDisplay:
    """Progress display for long-running operations"""
    
    def __init__(self, description: str = "Processing"):
        self.description = description
        self.is_running = False
        self._thread = None
        self._progress_data = {}
    
    def start(self):
        """Start progress display"""
        self.is_running = True
        self._thread = threading.Thread(target=self._display_progress)
        self._thread.daemon = True
        self._thread.start()
    
    def stop(self):
        """Stop progress display"""
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=1)
        print()  # New line after progress
    
    def update(self, **kwargs):
        """Update progress data"""
        self._progress_data.update(kwargs)
    
    def _display_progress(self):
        """Display animated progress"""
        spinner = ['|', '/', '-', '\\']
        i = 0
        while self.is_running:
            status = f"\r{self.description} {spinner[i % len(spinner)]}"
            if self._progress_data:
                status += f" - {self._format_progress_data()}"
            print(status, end='', flush=True)
            time.sleep(0.1)
            i += 1
    
    def _format_progress_data(self) -> str:
        """Format progress data for display"""
        parts = []
        for key, value in self._progress_data.items():
            if key == 'attempts':
                parts.append(f"Attempts: {value}")
            elif key == 'duration':
                parts.append(f"Duration: {value:.1f}s")
            elif key == 'status':
                parts.append(f"Status: {value}")
        return " | ".join(parts)


class ForensicsCLI:
    """
    Command Line Interface for ForenCrack Droid
    
    Provides interactive forensic operations with:
    - Case setup and management
    - Device detection and analysis
    - Attack execution and monitoring
    - Evidence reporting
    """
    
    def __init__(self):
        self.auth_service = AuthenticationService()
        self.user_manager = UserManager()
        self.legal_compliance = LegalComplianceService()
        self.current_session = None
        self.current_orchestrator = None
        self.progress_display = None
        
        # Setup argument parser
        self.parser = self._setup_argument_parser()
    
    def _setup_argument_parser(self) -> argparse.ArgumentParser:
        """Setup command line argument parser"""
        parser = argparse.ArgumentParser(
            prog='forencracks',
            description='ForenCrack Droid - Android Forensics Toolkit',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  forencracks interactive          # Start interactive mode
  forencracks detect              # Detect connected devices
  forencracks analyze --device SERIAL  # Analyze specific device
  forencracks attack --case CASE_ID --device SERIAL --type brute_force
  forencracks report --case CASE_ID    # Generate case report
  forencracks config --validate        # Validate tool configuration
            """
        )
        
        # Global options
        parser.add_argument('--version', action='version', version='ForenCrack Droid 1.0.0')
        parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
        parser.add_argument('--config', help='Configuration file path')
        
        # Subcommands
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Interactive mode
        subparsers.add_parser('interactive', help='Start interactive mode')
        
        # Authentication commands
        auth_parser = subparsers.add_parser('auth', help='Authentication commands')
        auth_subparsers = auth_parser.add_subparsers(dest='auth_command')
        auth_subparsers.add_parser('login', help='Login to system')
        auth_subparsers.add_parser('logout', help='Logout from system')
        auth_subparsers.add_parser('whoami', help='Show current user')
        
        # Device commands
        device_parser = subparsers.add_parser('detect', help='Detect connected devices')
        
        analyze_parser = subparsers.add_parser('analyze', help='Analyze device')
        analyze_parser.add_argument('--device', required=True, help='Device serial number')
        
        # Attack commands
        attack_parser = subparsers.add_parser('attack', help='Execute forensic attack')
        attack_parser.add_argument('--case', required=True, help='Case ID')
        attack_parser.add_argument('--device', required=True, help='Device serial number')
        attack_parser.add_argument('--type', required=True, 
                                 choices=['brute_force', 'dictionary', 'pattern_analysis', 'hash_cracking', 'hybrid'],
                                 help='Attack type')
        attack_parser.add_argument('--wordlist', help='Wordlist file path')
        attack_parser.add_argument('--max-attempts', type=int, default=10000, help='Maximum attempts')
        attack_parser.add_argument('--threads', type=int, default=4, help='Number of threads')
        attack_parser.add_argument('--gpu', action='store_true', help='Enable GPU acceleration')
        
        # Report commands
        report_parser = subparsers.add_parser('report', help='Generate case report')
        report_parser.add_argument('--case', required=True, help='Case ID')
        report_parser.add_argument('--format', choices=['json', 'pdf'], default='json', help='Report format')
        report_parser.add_argument('--output', help='Output file path')
        
        # Configuration commands
        config_parser = subparsers.add_parser('config', help='Configuration management')
        config_subparsers = config_parser.add_subparsers(dest='config_command')
        config_subparsers.add_parser('show', help='Show current configuration')
        config_subparsers.add_parser('validate', help='Validate tool paths')
        
        set_parser = config_subparsers.add_parser('set', help='Set configuration value')
        set_parser.add_argument('key', help='Configuration key')
        set_parser.add_argument('value', help='Configuration value')
        
        return parser
    
    def run(self, args: List[str] = None) -> int:
        """
        Run CLI with provided arguments
        
        Args:
            args: Command line arguments (defaults to sys.argv)
            
        Returns:
            int: Exit code (0 for success, non-zero for error)
        """
        try:
            parsed_args = self.parser.parse_args(args)
            
            # Handle no command (show help)
            if not parsed_args.command:
                self.parser.print_help()
                return 0
            
            # Route to appropriate handler
            if parsed_args.command == 'interactive':
                return self._run_interactive_mode()
            elif parsed_args.command == 'auth':
                return self._handle_auth_command(parsed_args)
            elif parsed_args.command == 'detect':
                return self._handle_detect_command(parsed_args)
            elif parsed_args.command == 'analyze':
                return self._handle_analyze_command(parsed_args)
            elif parsed_args.command == 'attack':
                return self._handle_attack_command(parsed_args)
            elif parsed_args.command == 'report':
                return self._handle_report_command(parsed_args)
            elif parsed_args.command == 'config':
                return self._handle_config_command(parsed_args)
            else:
                self._print_error(f"Unknown command: {parsed_args.command}")
                return 1
                
        except KeyboardInterrupt:
            self._print_warning("\nOperation cancelled by user")
            return 130
        except ForensicsException as e:
            self._print_error(f"Forensics error: {e.message}")
            return 1
        except Exception as e:
            self._print_error(f"Unexpected error: {e}")
            return 1
    
    def _run_interactive_mode(self) -> int:
        """Run interactive mode"""
        self._print_header("ForenCrack Droid - Interactive Mode")
        
        # Authentication
        if not self._authenticate_user():
            return 1
        
        # Legal compliance
        if not self._handle_legal_compliance():
            return 1
        
        # Main interactive loop
        while True:
            try:
                self._print_menu()
                choice = input(f"{CLIColors.OKBLUE}Enter choice: {CLIColors.ENDC}").strip()
                
                if choice == '1':
                    self._interactive_case_setup()
                elif choice == '2':
                    self._interactive_device_detection()
                elif choice == '3':
                    self._interactive_device_analysis()
                elif choice == '4':
                    self._interactive_attack_execution()
                elif choice == '5':
                    self._interactive_report_generation()
                elif choice == '6':
                    self._interactive_configuration()
                elif choice.lower() in ['q', 'quit', 'exit']:
                    break
                else:
                    self._print_warning("Invalid choice. Please try again.")
                    
            except KeyboardInterrupt:
                self._print_warning("\nUse 'quit' to exit")
            except Exception as e:
                self._print_error(f"Error: {e}")
        
        self._print_success("Goodbye!")
        return 0
    
    def _print_menu(self):
        """Print main menu"""
        print(f"\n{CLIColors.HEADER}=== ForenCrack Droid - Main Menu ==={CLIColors.ENDC}")
        print("1. Case Setup")
        print("2. Device Detection")
        print("3. Device Analysis")
        print("4. Attack Execution")
        print("5. Report Generation")
        print("6. Configuration")
        print("Q. Quit")
    
    def _authenticate_user(self) -> bool:
        """Authenticate user"""
        self._print_info("Authentication required")
        
        max_attempts = 3
        for attempt in range(max_attempts):
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            
            try:
                user = self.auth_service.authenticate_user(username, password)
                if user:
                    self.current_session = self.auth_service.create_session(user)
                    self._print_success(f"Welcome, {user.username}! Role: {user.role.value}")
                    return True
                else:
                    self._print_error("Invalid credentials")
            except Exception as e:
                self._print_error(f"Authentication error: {e}")
            
            if attempt < max_attempts - 1:
                self._print_warning(f"Attempts remaining: {max_attempts - attempt - 1}")
        
        self._print_error("Authentication failed. Access denied.")
        return False
    
    def _handle_legal_compliance(self) -> bool:
        """Handle legal compliance workflow"""
        try:
            # Display legal disclaimer
            disclaimer = self.legal_compliance.get_legal_disclaimer()
            self._print_warning("LEGAL DISCLAIMER")
            print(disclaimer['content'])
            
            # Get consent
            consent = input(f"\n{CLIColors.WARNING}Do you agree to the terms? (yes/no): {CLIColors.ENDC}").strip().lower()
            if consent not in ['yes', 'y']:
                self._print_error("Legal consent required. Access denied.")
                return False
            
            # Record consent
            self.legal_compliance.record_consent(
                user_id=self.current_session.user.username,
                consent_type="legal_disclaimer",
                consent_given=True
            )
            
            self._print_success("Legal compliance confirmed")
            return True
            
        except Exception as e:
            self._print_error(f"Legal compliance error: {e}")
            return False
    
    def _interactive_case_setup(self):
        """Interactive case setup"""
        self._print_header("Case Setup")
        
        # Get case information
        case_id = input("Enter Case ID: ").strip()
        if not case_id:
            self._print_error("Case ID is required")
            return
        
        # Validate case ID format
        if not self._validate_case_id(case_id):
            self._print_error("Invalid case ID format")
            return
        
        # Initialize orchestrator
        try:
            self.current_orchestrator = ForensicsOrchestrator(
                case_id=case_id,
                user_session=self.current_session.session_id
            )
            
            # Setup callbacks for progress monitoring
            self._setup_orchestrator_callbacks()
            
            self._print_success(f"Case '{case_id}' initialized successfully")
            
        except Exception as e:
            self._print_error(f"Case setup failed: {e}")
    
    def _interactive_device_detection(self):
        """Interactive device detection"""
        if not self._check_orchestrator():
            return
        
        self._print_header("Device Detection")
        
        # Start progress display
        progress = ProgressDisplay("Detecting devices")
        progress.start()
        
        try:
            devices = self.current_orchestrator.detect_devices()
            progress.stop()
            
            if not devices:
                self._print_warning("No devices detected")
                return
            
            # Display detected devices
            self._print_success(f"Detected {len(devices)} device(s):")
            for i, device in enumerate(devices, 1):
                print(f"{i}. {device.brand} {device.model} (Serial: {device.serial})")
                print(f"   Android: {device.android_version}, USB Debug: {device.usb_debugging}")
                if device.lock_type:
                    print(f"   Lock Type: {device.lock_type.value}")
                print()
            
        except Exception as e:
            progress.stop()
            self._print_error(f"Device detection failed: {e}")
    
    def _interactive_device_analysis(self):
        """Interactive device analysis"""
        if not self._check_orchestrator():
            return
        
        self._print_header("Device Analysis")
        
        # Get available devices
        devices = self.current_orchestrator.workflow_state.devices
        if not devices:
            self._print_warning("No devices available. Run device detection first.")
            return
        
        # Select device
        device = self._select_device(devices)
        if not device:
            return
        
        # Analyze device
        progress = ProgressDisplay(f"Analyzing device {device.serial}")
        progress.start()
        
        try:
            analyzed_device = self.current_orchestrator.analyze_device(device)
            progress.stop()
            
            # Display analysis results
            analysis_result = self.current_orchestrator.workflow_state.analysis_results[device.serial]
            self._display_analysis_results(analysis_result)
            
        except Exception as e:
            progress.stop()
            self._print_error(f"Device analysis failed: {e}")
    
    def _interactive_attack_execution(self):
        """Interactive attack execution"""
        if not self._check_orchestrator():
            return
        
        self._print_header("Attack Execution")
        
        # Get analyzed devices
        analyzed_devices = list(self.current_orchestrator.workflow_state.analysis_results.keys())
        if not analyzed_devices:
            self._print_warning("No analyzed devices available. Run device analysis first.")
            return
        
        # Select device
        device_serial = self._select_analyzed_device(analyzed_devices)
        if not device_serial:
            return
        
        analysis_result = self.current_orchestrator.workflow_state.analysis_results[device_serial]
        
        # Select attack strategy
        strategy = self._select_attack_strategy(analysis_result)
        if not strategy:
            return
        
        # Execute attack
        self._execute_attack_with_progress(strategy)
    
    def _interactive_report_generation(self):
        """Interactive report generation"""
        if not self._check_orchestrator():
            return
        
        self._print_header("Report Generation")
        
        case_id = self.current_orchestrator.case_id
        
        # Generate report
        progress = ProgressDisplay("Generating report")
        progress.start()
        
        try:
            report = self.current_orchestrator.generate_evidence_report(case_id)
            progress.stop()
            
            # Display report summary
            self._display_report_summary(report)
            
            # Ask for export
            export = input(f"\n{CLIColors.OKBLUE}Export report to file? (y/n): {CLIColors.ENDC}").strip().lower()
            if export in ['y', 'yes']:
                self._export_report(report, case_id)
            
        except Exception as e:
            progress.stop()
            self._print_error(f"Report generation failed: {e}")
    
    def _interactive_configuration(self):
        """Interactive configuration management"""
        self._print_header("Configuration Management")
        
        print("1. Show current configuration")
        print("2. Validate tool paths")
        print("3. Update tool path")
        print("4. Back to main menu")
        
        choice = input(f"{CLIColors.OKBLUE}Enter choice: {CLIColors.ENDC}").strip()
        
        if choice == '1':
            self._show_configuration()
        elif choice == '2':
            self._validate_tool_paths()
        elif choice == '3':
            self._update_tool_path()
        elif choice == '4':
            return
        else:
            self._print_warning("Invalid choice")
    
    def _check_orchestrator(self) -> bool:
        """Check if orchestrator is initialized"""
        if not self.current_orchestrator:
            self._print_error("No active case. Please setup a case first.")
            return False
        return True
    
    def _validate_case_id(self, case_id: str) -> bool:
        """Validate case ID format"""
        # Basic validation - alphanumeric with underscores and hyphens
        import re
        return bool(re.match(r'^[A-Za-z0-9_-]+$', case_id))
    
    def _setup_orchestrator_callbacks(self):
        """Setup callbacks for orchestrator events"""
        if not self.current_orchestrator:
            return
        
        def on_device_detected(device: AndroidDevice):
            if self.progress_display:
                self.progress_display.update(status=f"Found {device.brand} {device.model}")
        
        def on_attack_progress(device_serial: str, progress_data: Dict[str, Any]):
            if self.progress_display:
                self.progress_display.update(**progress_data)
        
        self.current_orchestrator.set_device_detected_callback(on_device_detected)
        self.current_orchestrator.set_attack_progress_callback(on_attack_progress)
    
    def _select_device(self, devices: List[AndroidDevice]) -> Optional[AndroidDevice]:
        """Select device from list"""
        print("Available devices:")
        for i, device in enumerate(devices, 1):
            print(f"{i}. {device.brand} {device.model} (Serial: {device.serial})")
        
        try:
            choice = int(input(f"{CLIColors.OKBLUE}Select device (1-{len(devices)}): {CLIColors.ENDC}"))
            if 1 <= choice <= len(devices):
                return devices[choice - 1]
        except ValueError:
            pass
        
        self._print_error("Invalid selection")
        return None
    
    def _select_analyzed_device(self, device_serials: List[str]) -> Optional[str]:
        """Select analyzed device"""
        print("Analyzed devices:")
        for i, serial in enumerate(device_serials, 1):
            analysis = self.current_orchestrator.workflow_state.analysis_results[serial]
            device = analysis.device
            print(f"{i}. {device.brand} {device.model} (Serial: {serial})")
        
        try:
            choice = int(input(f"{CLIColors.OKBLUE}Select device (1-{len(device_serials)}): {CLIColors.ENDC}"))
            if 1 <= choice <= len(device_serials):
                return device_serials[choice - 1]
        except ValueError:
            pass
        
        self._print_error("Invalid selection")
        return None
    
    def _select_attack_strategy(self, analysis_result) -> Optional[AttackStrategy]:
        """Select attack strategy"""
        strategies = analysis_result.recommended_strategies
        
        if not strategies:
            self._print_warning("No recommended attack strategies for this device")
            return None
        
        print("Recommended attack strategies:")
        for i, strategy_type in enumerate(strategies, 1):
            print(f"{i}. {strategy_type.value}")
        
        try:
            choice = int(input(f"{CLIColors.OKBLUE}Select strategy (1-{len(strategies)}): {CLIColors.ENDC}"))
            if 1 <= choice <= len(strategies):
                selected_type = strategies[choice - 1]
                return self._create_attack_strategy(analysis_result.device, selected_type)
        except ValueError:
            pass
        
        self._print_error("Invalid selection")
        return None
    
    def _create_attack_strategy(self, device: AndroidDevice, attack_type: AttackType) -> AttackStrategy:
        """Create attack strategy with user input"""
        # Get strategy parameters
        max_attempts = self._get_int_input("Maximum attempts", 10000)
        threads = self._get_int_input("Number of threads", 4)
        
        wordlists = []
        if attack_type in [AttackType.DICTIONARY, AttackType.HYBRID]:
            wordlist = input("Wordlist file path (optional): ").strip()
            if wordlist:
                wordlists.append(wordlist)
        
        # Create strategy
        from ..models.attack import AttackStrategy as StrategyModel
        strategy = StrategyModel(
            strategy_type=attack_type,
            target_device=device,
            max_attempts=max_attempts,
            thread_count=threads,
            wordlists=wordlists,
            gpu_acceleration=config_manager.forensics_settings.gpu_acceleration
        )
        
        return strategy
    
    def _get_int_input(self, prompt: str, default: int) -> int:
        """Get integer input with default"""
        try:
            value = input(f"{prompt} [{default}]: ").strip()
            return int(value) if value else default
        except ValueError:
            return default
    
    def _execute_attack_with_progress(self, strategy: AttackStrategy):
        """Execute attack with progress display"""
        self.progress_display = ProgressDisplay(f"Executing {strategy.strategy_type.value} attack")
        self.progress_display.start()
        
        try:
            # Execute attack asynchronously
            future = self.current_orchestrator.execute_attack_async(strategy)
            
            # Monitor progress
            while not future.done():
                time.sleep(1)
                # Progress updates come through callbacks
            
            # Get result
            result = future.result()
            self.progress_display.stop()
            self.progress_display = None
            
            # Display results
            self._display_attack_results(result)
            
        except Exception as e:
            if self.progress_display:
                self.progress_display.stop()
                self.progress_display = None
            self._print_error(f"Attack execution failed: {e}")
    
    def _display_analysis_results(self, analysis_result):
        """Display device analysis results"""
        device = analysis_result.device
        
        print(f"\n{CLIColors.OKGREEN}Device Analysis Results:{CLIColors.ENDC}")
        print(f"Device: {device.brand} {device.model}")
        print(f"Serial: {device.serial}")
        print(f"Android Version: {device.android_version}")
        print(f"USB Debugging: {device.usb_debugging}")
        print(f"Root Status: {device.root_status}")
        if device.lock_type:
            print(f"Lock Type: {device.lock_type.value}")
        
        print(f"\n{CLIColors.OKBLUE}Capabilities:{CLIColors.ENDC}")
        for capability, available in analysis_result.capabilities.items():
            status = "[OK]" if available else "[FAIL]"
            color = CLIColors.OKGREEN if available else CLIColors.FAIL
            print(f"  {color}{status} {capability}{CLIColors.ENDC}")
        
        print(f"\n{CLIColors.OKBLUE}Recommended Strategies:{CLIColors.ENDC}")
        for strategy in analysis_result.recommended_strategies:
            print(f"  - {strategy.value}")
        
        if analysis_result.analysis_notes:
            print(f"\n{CLIColors.WARNING}Notes:{CLIColors.ENDC}")
            print(f"  {analysis_result.analysis_notes}")
    
    def _display_attack_results(self, result: AttackResult):
        """Display attack results"""
        if result.success:
            self._print_success("Attack completed successfully!")
            print(f"Attempts: {result.attempts}")
            print(f"Duration: {result.duration:.2f} seconds")
            if result.result_data:
                print(f"Result: {result.result_data}")
        else:
            self._print_error("Attack failed")
            print(f"Attempts: {result.attempts}")
            print(f"Duration: {result.duration:.2f} seconds")
            if result.error_message:
                print(f"Error: {result.error_message}")
    
    def _display_report_summary(self, report: Dict[str, Any]):
        """Display report summary"""
        print(f"\n{CLIColors.OKGREEN}Evidence Report Summary:{CLIColors.ENDC}")
        print(f"Case ID: {report['case_id']}")
        print(f"Generated: {report['report_generated_at']}")
        print(f"Generated by: {report['generated_by']}")
        
        workflow = report['workflow_summary']
        print(f"\nWorkflow Status: {workflow['workflow_status']}")
        print(f"Devices Detected: {workflow['devices_detected']}")
        print(f"Devices Analyzed: {workflow['devices_analyzed']}")
        
        print(f"\nEvidence Records: {len(report['evidence_records'])}")
        print(f"Integrity Verified: {report['integrity_verification']}")
    
    def _export_report(self, report: Dict[str, Any], case_id: str):
        """Export report to file"""
        import json
        
        filename = f"report_{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = Path(filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            self._print_success(f"Report exported to: {filepath.absolute()}")
            
        except Exception as e:
            self._print_error(f"Export failed: {e}")
    
    def _show_configuration(self):
        """Show current configuration"""
        print(f"\n{CLIColors.OKBLUE}Tool Paths:{CLIColors.ENDC}")
        print(f"ADB: {config_manager.tool_paths.adb_path}")
        print(f"Fastboot: {config_manager.tool_paths.fastboot_path}")
        print(f"Hashcat: {config_manager.tool_paths.hashcat_path}")
        print(f"John: {config_manager.tool_paths.john_path}")
        
        print(f"\n{CLIColors.OKBLUE}Forensics Settings:{CLIColors.ENDC}")
        print(f"Max Concurrent Attacks: {config_manager.forensics_settings.max_concurrent_attacks}")
        print(f"Default Timeout: {config_manager.forensics_settings.default_timeout}")
        print(f"GPU Acceleration: {config_manager.forensics_settings.gpu_acceleration}")
        
        print(f"\n{CLIColors.OKBLUE}Security Settings:{CLIColors.ENDC}")
        print(f"Require Case ID: {config_manager.security_settings.require_case_id}")
        print(f"Encrypt Evidence: {config_manager.security_settings.encrypt_evidence}")
        print(f"Session Timeout: {config_manager.security_settings.session_timeout}")
    
    def _validate_tool_paths(self):
        """Validate tool paths"""
        print(f"\n{CLIColors.OKBLUE}Validating tool paths...{CLIColors.ENDC}")
        
        validation_results = config_manager.validate_tool_paths()
        
        for tool, is_valid in validation_results.items():
            status = "[OK]" if is_valid else "[FAIL]"
            color = CLIColors.OKGREEN if is_valid else CLIColors.FAIL
            print(f"  {color}{status} {tool}{CLIColors.ENDC}")
    
    def _update_tool_path(self):
        """Update tool path"""
        tools = ['adb', 'fastboot', 'hashcat', 'john']
        
        print("Available tools:")
        for i, tool in enumerate(tools, 1):
            print(f"{i}. {tool}")
        
        try:
            choice = int(input(f"{CLIColors.OKBLUE}Select tool (1-{len(tools)}): {CLIColors.ENDC}"))
            if 1 <= choice <= len(tools):
                tool = tools[choice - 1]
                new_path = input(f"Enter new path for {tool}: ").strip()
                
                if config_manager.update_tool_path(tool, new_path):
                    self._print_success(f"Updated {tool} path to: {new_path}")
                else:
                    self._print_error(f"Failed to update {tool} path")
        except ValueError:
            self._print_error("Invalid selection")
    
    # Command handlers for non-interactive mode
    def _handle_auth_command(self, args) -> int:
        """Handle authentication commands"""
        if args.auth_command == 'login':
            return self._handle_login()
        elif args.auth_command == 'logout':
            return self._handle_logout()
        elif args.auth_command == 'whoami':
            return self._handle_whoami()
        else:
            self._print_error("Unknown auth command")
            return 1
    
    def _handle_detect_command(self, args) -> int:
        """Handle device detection command"""
        # This would need authentication and case setup
        self._print_error("Non-interactive mode requires authentication. Use 'interactive' mode.")
        return 1
    
    def _handle_analyze_command(self, args) -> int:
        """Handle device analysis command"""
        self._print_error("Non-interactive mode requires authentication. Use 'interactive' mode.")
        return 1
    
    def _handle_attack_command(self, args) -> int:
        """Handle attack execution command"""
        self._print_error("Non-interactive mode requires authentication. Use 'interactive' mode.")
        return 1
    
    def _handle_report_command(self, args) -> int:
        """Handle report generation command"""
        self._print_error("Non-interactive mode requires authentication. Use 'interactive' mode.")
        return 1
    
    def _handle_config_command(self, args) -> int:
        """Handle configuration commands"""
        if args.config_command == 'show':
            self._show_configuration()
            return 0
        elif args.config_command == 'validate':
            self._validate_tool_paths()
            return 0
        elif args.config_command == 'set':
            # Simple config setting
            if config_manager.update_setting("forensics", args.key, args.value):
                self._print_success(f"Updated {args.key} to {args.value}")
                return 0
            else:
                self._print_error(f"Failed to update {args.key}")
                return 1
        else:
            self._print_error("Unknown config command")
            return 1
    
    def _handle_login(self) -> int:
        """Handle login command"""
        if self._authenticate_user():
            self._print_success("Login successful")
            return 0
        return 1
    
    def _handle_logout(self) -> int:
        """Handle logout command"""
        if self.current_session:
            self.auth_service.logout_user(self.current_session.session_id)
            self.current_session = None
            self._print_success("Logged out successfully")
        else:
            self._print_warning("Not logged in")
        return 0
    
    def _handle_whoami(self) -> int:
        """Handle whoami command"""
        if self.current_session:
            user = self.current_session.user
            print(f"User: {user.username}")
            print(f"Role: {user.role.value}")
            print(f"Session expires: {self.current_session.expires_at}")
            return 0
        else:
            self._print_warning("Not logged in")
            return 1
    
    # Utility methods for colored output
    def _print_header(self, text: str):
        """Print header text"""
        print(f"\n{CLIColors.HEADER}=== {text} ==={CLIColors.ENDC}")
    
    def _print_success(self, text: str):
        """Print success message"""
        print(f"{CLIColors.OKGREEN}[SUCCESS] {text}{CLIColors.ENDC}")
    
    def _print_error(self, text: str):
        """Print error message"""
        print(f"{CLIColors.FAIL}[ERROR] {text}{CLIColors.ENDC}")
    
    def _print_warning(self, text: str):
        """Print warning message"""
        print(f"{CLIColors.WARNING}[WARNING] {text}{CLIColors.ENDC}")
    
    def _print_info(self, text: str):
        """Print info message"""
        print(f"{CLIColors.OKBLUE}[INFO] {text}{CLIColors.ENDC}")


def main():
    """Main entry point for CLI"""
    cli = ForensicsCLI()
    return cli.run()


if __name__ == '__main__':
    sys.exit(main())