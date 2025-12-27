"""
PyQt5 GUI Interface for Crack Droid

This module implements the main GUI application window with forensic workflow including:
- Main application window with forensic workflow
- Device selection and configuration panels
- Attack progress monitoring and visualization
- Evidence report viewing and export
"""

import sys
import os
import json
import threading
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QTabWidget, QLabel, QPushButton, QLineEdit, QTextEdit, QComboBox, QSpinBox,
    QProgressBar, QTableWidget, QTableWidgetItem, QTreeWidget, QTreeWidgetItem,
    QGroupBox, QCheckBox, QRadioButton, QButtonGroup, QSplitter, QFrame,
    QMessageBox, QFileDialog, QDialog, QDialogButtonBox, QFormLayout,
    QListWidget, QListWidgetItem, QScrollArea, QStatusBar, QMenuBar, QMenu,
    QAction, QToolBar, QHeaderView
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QRect, pyqtSlot
)
from PyQt5.QtGui import (
    QFont, QPixmap, QIcon, QPalette, QColor, QPainter, QBrush, QPen
)

from ..interfaces import (
    AndroidDevice, AttackStrategy, AttackResult, AttackType, LockType,
    UserRole, Permission, ForensicsException
)
from ..services.forensics_orchestrator import ForensicsOrchestrator, DeviceAnalysisResult
from ..services.authentication import AuthenticationService, UserManager
from ..services.legal_compliance import LegalComplianceService
from ..services.device_manager import DeviceManager, DeviceStatus, DeviceState
from ..config import config_manager


class ForensicsGUIException(ForensicsException):
    """Exception raised in GUI operations"""
    
    def __init__(self, message: str):
        super().__init__(message, "GUI_ERROR", evidence_impact=False)


class LoginDialog(QDialog):
    """Login dialog for user authentication"""
    
    def __init__(self, auth_service: AuthenticationService, parent=None):
        super().__init__(parent)
        self.auth_service = auth_service
        self.user = None
        self.session = None
        self.setup_ui()
    
    def setup_ui(self):
        """Setup login dialog UI"""
        self.setWindowTitle("Crack Droid - Login")
        self.setFixedSize(400, 300)
        self.setModal(True)
        
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Crack Droid")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 18, QFont.Bold))
        layout.addWidget(title)
        
        subtitle = QLabel("Android Forensics Toolkit")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setFont(QFont("Arial", 10))
        layout.addWidget(subtitle)
        
        layout.addSpacing(20)
        
        # Login form
        form_layout = QFormLayout()
        
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Enter username")
        form_layout.addRow("Username:", self.username_edit)
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Enter password")
        form_layout.addRow("Password:", self.password_edit)
        
        layout.addLayout(form_layout)
        
        layout.addSpacing(20)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.attempt_login)
        self.login_button.setDefault(True)
        button_layout.addWidget(self.login_button)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: red;")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
        
        # Connect enter key
        self.password_edit.returnPressed.connect(self.attempt_login)
    
    def attempt_login(self):
        """Attempt user login"""
        username = self.username_edit.text().strip()
        password = self.password_edit.text()
        
        if not username or not password:
            self.status_label.setText("Please enter username and password")
            return
        
        try:
            self.login_button.setEnabled(False)
            self.status_label.setText("Authenticating...")
            
            # Authenticate user
            user = self.auth_service.authenticate_user(username, password)
            if user:
                self.session = self.auth_service.create_session(user)
                self.user = user
                self.accept()
            else:
                self.status_label.setText("Invalid credentials")
                
        except Exception as e:
            self.status_label.setText(f"Authentication error: {e}")
        finally:
            self.login_button.setEnabled(True)


class LegalComplianceDialog(QDialog):
    """Legal compliance dialog"""
    
    def __init__(self, legal_service: LegalComplianceService, user_id: str, parent=None):
        super().__init__(parent)
        self.legal_service = legal_service
        self.user_id = user_id
        self.setup_ui()
    
    def setup_ui(self):
        """Setup legal compliance dialog UI"""
        self.setWindowTitle("Legal Compliance")
        self.setFixedSize(600, 500)
        self.setModal(True)
        
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("LEGAL DISCLAIMER")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setStyleSheet("color: red; margin: 10px;")
        layout.addWidget(title)
        
        # Disclaimer text
        try:
            disclaimer = self.legal_service.get_legal_disclaimer()
            disclaimer_text = QTextEdit()
            disclaimer_text.setPlainText(disclaimer['content'])
            disclaimer_text.setReadOnly(True)
            disclaimer_text.setFont(QFont("Arial", 10))
            layout.addWidget(disclaimer_text)
        except Exception as e:
            error_label = QLabel(f"Error loading disclaimer: {e}")
            error_label.setStyleSheet("color: red;")
            layout.addWidget(error_label)
        
        # Consent checkbox
        self.consent_checkbox = QCheckBox("I agree to the terms and conditions above")
        self.consent_checkbox.setFont(QFont("Arial", 10, QFont.Bold))
        layout.addWidget(self.consent_checkbox)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.accept_button = QPushButton("Accept")
        self.accept_button.clicked.connect(self.accept_terms)
        self.accept_button.setEnabled(False)
        button_layout.addWidget(self.accept_button)
        
        self.decline_button = QPushButton("Decline")
        self.decline_button.clicked.connect(self.reject)
        button_layout.addWidget(self.decline_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Connect checkbox
        self.consent_checkbox.toggled.connect(self.accept_button.setEnabled)
    
    def accept_terms(self):
        """Accept legal terms"""
        if self.consent_checkbox.isChecked():
            try:
                self.legal_service.record_consent(
                    user_id=self.user_id,
                    consent_type="legal_disclaimer",
                    consent_given=True
                )
                self.accept()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to record consent: {e}")


class CaseSetupDialog(QDialog):
    """Case setup dialog"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.case_id = None
        self.setup_ui()
    
    def setup_ui(self):
        """Setup case setup dialog UI"""
        self.setWindowTitle("Case Setup")
        self.setFixedSize(400, 200)
        self.setModal(True)
        
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("New Forensic Case")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title)
        
        layout.addSpacing(20)
        
        # Case ID input
        form_layout = QFormLayout()
        
        self.case_id_edit = QLineEdit()
        self.case_id_edit.setPlaceholderText("Enter case identifier (e.g., CASE_2025_001)")
        form_layout.addRow("Case ID:", self.case_id_edit)
        
        layout.addLayout(form_layout)
        
        layout.addSpacing(20)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.create_button = QPushButton("Create Case")
        self.create_button.clicked.connect(self.create_case)
        self.create_button.setDefault(True)
        button_layout.addWidget(self.create_button)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
        
        # Connect enter key
        self.case_id_edit.returnPressed.connect(self.create_case)
    
    def create_case(self):
        """Create new case"""
        case_id = self.case_id_edit.text().strip()
        
        if not case_id:
            self.status_label.setText("Please enter a case ID")
            self.status_label.setStyleSheet("color: red;")
            return
        
        # Validate case ID format
        import re
        if not re.match(r'^[A-Za-z0-9_-]+$', case_id):
            self.status_label.setText("Case ID can only contain letters, numbers, underscores, and hyphens")
            self.status_label.setStyleSheet("color: red;")
            return
        
        self.case_id = case_id
        self.status_label.setText("Case created successfully")
        self.status_label.setStyleSheet("color: green;")
        self.accept()


class DeviceWorker(QThread):
    """Worker thread for device operations"""
    
    devices_detected = pyqtSignal(list)
    device_analyzed = pyqtSignal(object)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, orchestrator: ForensicsOrchestrator, operation: str, device: AndroidDevice = None):
        super().__init__()
        self.orchestrator = orchestrator
        self.operation = operation
        self.device = device
    
    def run(self):
        """Run device operation"""
        try:
            if self.operation == "detect":
                devices = self.orchestrator.detect_devices()
                self.devices_detected.emit(devices)
            elif self.operation == "analyze" and self.device:
                analyzed_device = self.orchestrator.analyze_device(self.device)
                analysis_result = self.orchestrator.workflow_state.analysis_results[self.device.serial]
                self.device_analyzed.emit(analysis_result)
        except Exception as e:
            self.error_occurred.emit(str(e))


class AttackWorker(QThread):
    """Worker thread for attack execution"""
    
    progress_updated = pyqtSignal(dict)
    attack_completed = pyqtSignal(object)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, orchestrator: ForensicsOrchestrator, strategy: AttackStrategy):
        super().__init__()
        self.orchestrator = orchestrator
        self.strategy = strategy
        self.is_running = False
    
    def run(self):
        """Run attack execution"""
        try:
            self.is_running = True
            
            # Setup progress callback
            def progress_callback(device_serial: str, progress_data: Dict[str, Any]):
                if self.is_running:
                    self.progress_updated.emit(progress_data)
            
            self.orchestrator.set_attack_progress_callback(progress_callback)
            
            # Execute attack
            result = self.orchestrator.execute_attack(self.strategy)
            
            if self.is_running:
                self.attack_completed.emit(result)
                
        except Exception as e:
            if self.is_running:
                self.error_occurred.emit(str(e))
    
    def stop(self):
        """Stop attack execution"""
        self.is_running = False
        self.terminate()


class DeviceListWidget(QWidget):
    """Widget for displaying and managing devices"""
    
    device_selected = pyqtSignal(object)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.devices = []
        self.setup_ui()
    
    def setup_ui(self):
        """Setup device list UI"""
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("Connected Devices")
        header.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(header)
        
        # Device table
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(6)
        self.device_table.setHorizontalHeaderLabels([
            "Brand", "Model", "Serial", "Android", "USB Debug", "Lock Type"
        ])
        self.device_table.horizontalHeader().setStretchLastSection(True)
        self.device_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.device_table.itemSelectionChanged.connect(self.on_selection_changed)
        layout.addWidget(self.device_table)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_devices)
        button_layout.addWidget(self.refresh_button)
        
        self.analyze_button = QPushButton("Analyze Selected")
        self.analyze_button.clicked.connect(self.analyze_selected)
        self.analyze_button.setEnabled(False)
        button_layout.addWidget(self.analyze_button)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def update_devices(self, devices: List[AndroidDevice]):
        """Update device list"""
        self.devices = devices
        self.device_table.setRowCount(len(devices))
        
        for row, device in enumerate(devices):
            self.device_table.setItem(row, 0, QTableWidgetItem(device.brand))
            self.device_table.setItem(row, 1, QTableWidgetItem(device.model))
            self.device_table.setItem(row, 2, QTableWidgetItem(device.serial))
            self.device_table.setItem(row, 3, QTableWidgetItem(device.android_version))
            self.device_table.setItem(row, 4, QTableWidgetItem("Yes" if device.usb_debugging else "No"))
            lock_type = device.lock_type.value if device.lock_type else "Unknown"
            self.device_table.setItem(row, 5, QTableWidgetItem(lock_type))
        
        self.device_table.resizeColumnsToContents()
    
    def on_selection_changed(self):
        """Handle device selection change"""
        selected_rows = set(item.row() for item in self.device_table.selectedItems())
        self.analyze_button.setEnabled(len(selected_rows) == 1)
        
        if len(selected_rows) == 1:
            row = list(selected_rows)[0]
            if row < len(self.devices):
                self.device_selected.emit(self.devices[row])
    
    def refresh_devices(self):
        """Refresh device list"""
        # This will be connected to parent's refresh method
        pass
    
    def analyze_selected(self):
        """Analyze selected device"""
        selected_rows = set(item.row() for item in self.device_table.selectedItems())
        if len(selected_rows) == 1:
            row = list(selected_rows)[0]
            if row < len(self.devices):
                # This will be connected to parent's analyze method
                pass


class AttackConfigWidget(QWidget):
    """Widget for configuring attack parameters"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.analysis_result = None
        self.setup_ui()
    
    def setup_ui(self):
        """Setup attack configuration UI"""
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("Attack Configuration")
        header.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(header)
        
        # Device info
        self.device_info_label = QLabel("No device selected")
        self.device_info_label.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(self.device_info_label)
        
        # Attack type selection
        attack_group = QGroupBox("Attack Type")
        attack_layout = QVBoxLayout()
        
        self.attack_type_group = QButtonGroup()
        self.brute_force_radio = QRadioButton("Brute Force")
        self.dictionary_radio = QRadioButton("Dictionary Attack")
        self.pattern_radio = QRadioButton("Pattern Analysis")
        self.hash_radio = QRadioButton("Hash Cracking")
        self.hybrid_radio = QRadioButton("Hybrid Attack")
        
        self.attack_type_group.addButton(self.brute_force_radio, 0)
        self.attack_type_group.addButton(self.dictionary_radio, 1)
        self.attack_type_group.addButton(self.pattern_radio, 2)
        self.attack_type_group.addButton(self.hash_radio, 3)
        self.attack_type_group.addButton(self.hybrid_radio, 4)
        
        attack_layout.addWidget(self.brute_force_radio)
        attack_layout.addWidget(self.dictionary_radio)
        attack_layout.addWidget(self.pattern_radio)
        attack_layout.addWidget(self.hash_radio)
        attack_layout.addWidget(self.hybrid_radio)
        
        attack_group.setLayout(attack_layout)
        layout.addWidget(attack_group)
        
        # Parameters
        params_group = QGroupBox("Parameters")
        params_layout = QFormLayout()
        
        self.max_attempts_spin = QSpinBox()
        self.max_attempts_spin.setRange(1, 1000000)
        self.max_attempts_spin.setValue(10000)
        params_layout.addRow("Max Attempts:", self.max_attempts_spin)
        
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 16)
        self.threads_spin.setValue(4)
        params_layout.addRow("Threads:", self.threads_spin)
        
        self.wordlist_edit = QLineEdit()
        self.wordlist_edit.setPlaceholderText("Path to wordlist file (optional)")
        wordlist_layout = QHBoxLayout()
        wordlist_layout.addWidget(self.wordlist_edit)
        
        self.browse_wordlist_button = QPushButton("Browse")
        self.browse_wordlist_button.clicked.connect(self.browse_wordlist)
        wordlist_layout.addWidget(self.browse_wordlist_button)
        
        wordlist_widget = QWidget()
        wordlist_widget.setLayout(wordlist_layout)
        params_layout.addRow("Wordlist:", wordlist_widget)
        
        self.gpu_checkbox = QCheckBox("Enable GPU acceleration")
        self.gpu_checkbox.setChecked(config_manager.forensics_settings.gpu_acceleration)
        params_layout.addRow("", self.gpu_checkbox)
        
        params_group.setLayout(params_layout)
        layout.addWidget(params_group)
        
        # Execute button
        self.execute_button = QPushButton("Execute Attack")
        self.execute_button.clicked.connect(self.execute_attack)
        self.execute_button.setEnabled(False)
        layout.addWidget(self.execute_button)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def set_analysis_result(self, analysis_result: DeviceAnalysisResult):
        """Set device analysis result"""
        self.analysis_result = analysis_result
        device = analysis_result.device
        
        # Update device info
        info_text = f"{device.brand} {device.model} (Serial: {device.serial})"
        self.device_info_label.setText(info_text)
        self.device_info_label.setStyleSheet("color: black; font-weight: bold;")
        
        # Enable/disable attack types based on recommendations
        recommended = analysis_result.recommended_strategies
        
        self.brute_force_radio.setEnabled(AttackType.BRUTE_FORCE in recommended)
        self.dictionary_radio.setEnabled(AttackType.DICTIONARY in recommended)
        self.pattern_radio.setEnabled(AttackType.PATTERN_ANALYSIS in recommended)
        self.hash_radio.setEnabled(AttackType.HASH_CRACKING in recommended)
        self.hybrid_radio.setEnabled(AttackType.HYBRID in recommended)
        
        # Select first available attack type
        if recommended:
            if AttackType.BRUTE_FORCE in recommended:
                self.brute_force_radio.setChecked(True)
            elif AttackType.DICTIONARY in recommended:
                self.dictionary_radio.setChecked(True)
            elif AttackType.PATTERN_ANALYSIS in recommended:
                self.pattern_radio.setChecked(True)
            elif AttackType.HASH_CRACKING in recommended:
                self.hash_radio.setChecked(True)
            elif AttackType.HYBRID in recommended:
                self.hybrid_radio.setChecked(True)
        
        self.execute_button.setEnabled(len(recommended) > 0)
    
    def browse_wordlist(self):
        """Browse for wordlist file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Wordlist File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.wordlist_edit.setText(file_path)
    
    def get_attack_strategy(self) -> Optional[AttackStrategy]:
        """Get configured attack strategy"""
        if not self.analysis_result:
            return None
        
        # Get selected attack type
        attack_type_map = {
            0: AttackType.BRUTE_FORCE,
            1: AttackType.DICTIONARY,
            2: AttackType.PATTERN_ANALYSIS,
            3: AttackType.HASH_CRACKING,
            4: AttackType.HYBRID
        }
        
        selected_id = self.attack_type_group.checkedId()
        if selected_id == -1:
            return None
        
        attack_type = attack_type_map[selected_id]
        
        # Get wordlists
        wordlists = []
        wordlist_path = self.wordlist_edit.text().strip()
        if wordlist_path:
            wordlists.append(wordlist_path)
        
        # Create strategy
        from ..models.attack import AttackStrategy as StrategyModel
        strategy = StrategyModel(
            strategy_type=attack_type,
            target_device=self.analysis_result.device,
            max_attempts=self.max_attempts_spin.value(),
            thread_count=self.threads_spin.value(),
            wordlists=wordlists,
            gpu_acceleration=self.gpu_checkbox.isChecked()
        )
        
        return strategy
    
    def execute_attack(self):
        """Execute attack - to be connected to parent"""
        pass


class AttackProgressWidget(QWidget):
    """Widget for displaying attack progress"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        """Setup attack progress UI"""
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("Attack Progress")
        header.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(header)
        
        # Status
        self.status_label = QLabel("No active attack")
        self.status_label.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(self.status_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Details
        details_group = QGroupBox("Details")
        details_layout = QFormLayout()
        
        self.attempts_label = QLabel("0")
        details_layout.addRow("Attempts:", self.attempts_label)
        
        self.duration_label = QLabel("0s")
        details_layout.addRow("Duration:", self.duration_label)
        
        self.rate_label = QLabel("0/s")
        details_layout.addRow("Rate:", self.rate_label)
        
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.stop_button = QPushButton("Stop Attack")
        self.stop_button.clicked.connect(self.stop_attack)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def start_attack(self, strategy: AttackStrategy):
        """Start attack progress display"""
        device = strategy.target_device
        self.status_label.setText(f"Executing {strategy.strategy_type.value} attack on {device.brand} {device.model}")
        self.status_label.setStyleSheet("color: blue; font-weight: bold;")
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, strategy.max_attempts)
        self.progress_bar.setValue(0)
        
        self.stop_button.setEnabled(True)
        
        # Reset counters
        self.attempts_label.setText("0")
        self.duration_label.setText("0s")
        self.rate_label.setText("0/s")
    
    def update_progress(self, progress_data: Dict[str, Any]):
        """Update attack progress"""
        if 'attempts' in progress_data:
            attempts = progress_data['attempts']
            self.attempts_label.setText(str(attempts))
            self.progress_bar.setValue(attempts)
        
        if 'duration' in progress_data:
            duration = progress_data['duration']
            self.duration_label.setText(f"{duration:.1f}s")
        
        if 'rate' in progress_data:
            rate = progress_data['rate']
            self.rate_label.setText(f"{rate:.1f}/s")
        
        if 'status' in progress_data:
            status = progress_data['status']
            self.status_label.setText(f"Status: {status}")
    
    def attack_completed(self, result: AttackResult):
        """Handle attack completion"""
        if result.success:
            self.status_label.setText("Attack completed successfully!")
            self.status_label.setStyleSheet("color: green; font-weight: bold;")
        else:
            self.status_label.setText("Attack failed")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")
        
        self.progress_bar.setVisible(False)
        self.stop_button.setEnabled(False)
        
        # Update final stats
        self.attempts_label.setText(str(result.attempts))
        self.duration_label.setText(f"{result.duration:.1f}s")
        
        if result.duration > 0:
            rate = result.attempts / result.duration
            self.rate_label.setText(f"{rate:.1f}/s")
    
    def attack_error(self, error_message: str):
        """Handle attack error"""
        self.status_label.setText(f"Attack error: {error_message}")
        self.status_label.setStyleSheet("color: red; font-weight: bold;")
        
        self.progress_bar.setVisible(False)
        self.stop_button.setEnabled(False)
    
    def stop_attack(self):
        """Stop attack - to be connected to parent"""
        pass


class EvidenceReportWidget(QWidget):
    """Widget for viewing and exporting evidence reports"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_report = None
        self.setup_ui()
    
    def setup_ui(self):
        """Setup evidence report UI"""
        layout = QVBoxLayout()
        
        # Header
        header_layout = QHBoxLayout()
        
        header = QLabel("Evidence Report")
        header.setFont(QFont("Arial", 12, QFont.Bold))
        header_layout.addWidget(header)
        
        header_layout.addStretch()
        
        self.generate_button = QPushButton("Generate Report")
        self.generate_button.clicked.connect(self.generate_report)
        header_layout.addWidget(self.generate_button)
        
        self.export_button = QPushButton("Export Report")
        self.export_button.clicked.connect(self.export_report)
        self.export_button.setEnabled(False)
        header_layout.addWidget(self.export_button)
        
        layout.addLayout(header_layout)
        
        # Report display
        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        self.report_text.setFont(QFont("Courier", 9))
        layout.addWidget(self.report_text)
        
        self.setLayout(layout)
    
    def set_report(self, report: Dict[str, Any]):
        """Set evidence report"""
        self.current_report = report
        self.display_report(report)
        self.export_button.setEnabled(True)
    
    def display_report(self, report: Dict[str, Any]):
        """Display evidence report"""
        report_text = self.format_report(report)
        self.report_text.setPlainText(report_text)
    
    def format_report(self, report: Dict[str, Any]) -> str:
        """Format report for display"""
        lines = []
        
        lines.append("=" * 60)
        lines.append("FORENSIC EVIDENCE REPORT")
        lines.append("=" * 60)
        lines.append("")
        
        # Case information
        lines.append(f"Case ID: {report.get('case_id', 'N/A')}")
        lines.append(f"Generated: {report.get('report_generated_at', 'N/A')}")
        lines.append(f"Generated by: {report.get('generated_by', 'N/A')}")
        lines.append("")
        
        # Workflow summary
        workflow = report.get('workflow_summary', {})
        lines.append("WORKFLOW SUMMARY")
        lines.append("-" * 20)
        lines.append(f"Status: {workflow.get('workflow_status', 'N/A')}")
        lines.append(f"Start Time: {workflow.get('start_time', 'N/A')}")
        lines.append(f"Last Activity: {workflow.get('last_activity', 'N/A')}")
        lines.append(f"Devices Detected: {workflow.get('devices_detected', 0)}")
        lines.append(f"Devices Analyzed: {workflow.get('devices_analyzed', 0)}")
        lines.append("")
        
        # Device summary
        device_summary = report.get('device_summary', {})
        if device_summary:
            lines.append("DEVICE SUMMARY")
            lines.append("-" * 15)
            for device_serial, device_info in device_summary.items():
                lines.append(f"Device: {device_serial}")
                lines.append(f"  Brand: {device_info.get('brand', 'N/A')}")
                lines.append(f"  Model: {device_info.get('model', 'N/A')}")
                lines.append(f"  Android: {device_info.get('android_version', 'N/A')}")
                lines.append(f"  USB Debug: {device_info.get('usb_debugging', 'N/A')}")
                lines.append("")
        
        # Attack summary
        attack_summary = report.get('attack_summary', {})
        if attack_summary:
            lines.append("ATTACK SUMMARY")
            lines.append("-" * 15)
            for device_serial, attack_info in attack_summary.items():
                lines.append(f"Device: {device_serial}")
                lines.append(f"  Attack Type: {attack_info.get('attack_type', 'N/A')}")
                lines.append(f"  Success: {attack_info.get('success', 'N/A')}")
                lines.append(f"  Attempts: {attack_info.get('attempts', 'N/A')}")
                lines.append(f"  Duration: {attack_info.get('duration', 'N/A')}s")
                if attack_info.get('result_data'):
                    lines.append(f"  Result: {attack_info['result_data']}")
                lines.append("")
        
        # Evidence records
        evidence_records = report.get('evidence_records', [])
        if evidence_records:
            lines.append("EVIDENCE RECORDS")
            lines.append("-" * 16)
            for i, record in enumerate(evidence_records, 1):
                lines.append(f"Record {i}:")
                lines.append(f"  Timestamp: {record.get('timestamp', 'N/A')}")
                lines.append(f"  Operation: {record.get('operation_type', 'N/A')}")
                lines.append(f"  Device: {record.get('device_serial', 'N/A')}")
                lines.append(f"  Result: {record.get('result', 'N/A')}")
                lines.append("")
        
        # Integrity verification
        integrity = report.get('integrity_verification', False)
        lines.append("INTEGRITY VERIFICATION")
        lines.append("-" * 21)
        lines.append(f"Status: {'VERIFIED' if integrity else 'FAILED'}")
        lines.append("")
        
        lines.append("=" * 60)
        lines.append("END OF REPORT")
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def generate_report(self):
        """Generate report - to be connected to parent"""
        pass
    
    def export_report(self):
        """Export report to file"""
        if not self.current_report:
            QMessageBox.warning(self, "Warning", "No report to export")
            return
        
        case_id = self.current_report.get('case_id', 'unknown')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_filename = f"report_{case_id}_{timestamp}.json"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", default_filename, 
            "JSON Files (*.json);;Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                if file_path.endswith('.txt'):
                    # Export as formatted text
                    with open(file_path, 'w') as f:
                        f.write(self.format_report(self.current_report))
                else:
                    # Export as JSON
                    with open(file_path, 'w') as f:
                        json.dump(self.current_report, f, indent=2, default=str)
                
                QMessageBox.information(self, "Success", f"Report exported to:\n{file_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export report:\n{e}")


class ForensicsMainWindow(QMainWindow):
    """Main application window for Crack Droid GUI"""
    
    def __init__(self):
        super().__init__()
        
        # Services
        self.auth_service = AuthenticationService()
        self.legal_service = LegalComplianceService()
        self.current_session = None
        self.current_orchestrator = None
        
        # Workers
        self.device_worker = None
        self.attack_worker = None
        
        # Setup UI
        self.setup_ui()
        self.setup_menu_bar()
        self.setup_status_bar()
        
        # Authenticate user
        if not self.authenticate_user():
            sys.exit(1)
        
        # Handle legal compliance
        if not self.handle_legal_compliance():
            sys.exit(1)
        
        # Setup case
        self.setup_case()
    
    def setup_ui(self):
        """Setup main UI"""
        self.setWindowTitle("Crack Droid - Android Forensics Toolkit")
        self.setGeometry(100, 100, 1200, 800)
        
        # Central widget with tabs
        self.central_widget = QTabWidget()
        self.setCentralWidget(self.central_widget)
        
        # Device management tab
        self.device_widget = DeviceListWidget()
        self.device_widget.device_selected.connect(self.on_device_selected)
        self.central_widget.addTab(self.device_widget, "Devices")
        
        # Attack configuration tab
        self.attack_config_widget = AttackConfigWidget()
        self.attack_config_widget.execute_attack = self.execute_attack
        self.central_widget.addTab(self.attack_config_widget, "Attack Config")
        
        # Attack progress tab
        self.attack_progress_widget = AttackProgressWidget()
        self.attack_progress_widget.stop_attack = self.stop_attack
        self.central_widget.addTab(self.attack_progress_widget, "Attack Progress")
        
        # Evidence report tab
        self.evidence_widget = EvidenceReportWidget()
        self.evidence_widget.generate_report = self.generate_report
        self.central_widget.addTab(self.evidence_widget, "Evidence Report")
        
        # Connect device refresh
        self.device_widget.refresh_devices = self.detect_devices
        self.device_widget.analyze_selected = self.analyze_selected_device
    
    def setup_menu_bar(self):
        """Setup menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        new_case_action = QAction('New Case', self)
        new_case_action.triggered.connect(self.setup_case)
        file_menu.addAction(new_case_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        detect_action = QAction('Detect Devices', self)
        detect_action.triggered.connect(self.detect_devices)
        tools_menu.addAction(detect_action)
        
        config_action = QAction('Configuration', self)
        config_action.triggered.connect(self.show_configuration)
        tools_menu.addAction(config_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
    
    def authenticate_user(self) -> bool:
        """Authenticate user"""
        login_dialog = LoginDialog(self.auth_service, self)
        if login_dialog.exec_() == QDialog.Accepted:
            self.current_session = login_dialog.session
            user = login_dialog.user
            self.status_bar.showMessage(f"Logged in as: {user.username} ({user.role.value})")
            return True
        return False
    
    def handle_legal_compliance(self) -> bool:
        """Handle legal compliance"""
        compliance_dialog = LegalComplianceDialog(
            self.legal_service, 
            self.current_session.user.username, 
            self
        )
        return compliance_dialog.exec_() == QDialog.Accepted
    
    def setup_case(self):
        """Setup forensic case"""
        case_dialog = CaseSetupDialog(self)
        if case_dialog.exec_() == QDialog.Accepted:
            case_id = case_dialog.case_id
            
            try:
                self.current_orchestrator = ForensicsOrchestrator(
                    case_id=case_id,
                    user_session=self.current_session.session_id
                )
                
                self.setWindowTitle(f"Crack Droid - Case: {case_id}")
                self.status_bar.showMessage(f"Case '{case_id}' active")
                
                # Auto-detect devices
                self.detect_devices()
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to setup case:\n{e}")
    
    def detect_devices(self):
        """Detect connected devices"""
        if not self.current_orchestrator:
            QMessageBox.warning(self, "Warning", "No active case. Please setup a case first.")
            return
        
        if self.device_worker and self.device_worker.isRunning():
            return
        
        self.status_bar.showMessage("Detecting devices...")
        
        self.device_worker = DeviceWorker(self.current_orchestrator, "detect")
        self.device_worker.devices_detected.connect(self.on_devices_detected)
        self.device_worker.error_occurred.connect(self.on_device_error)
        self.device_worker.start()
    
    def on_devices_detected(self, devices: List[AndroidDevice]):
        """Handle devices detected"""
        self.device_widget.update_devices(devices)
        self.status_bar.showMessage(f"Detected {len(devices)} device(s)")
    
    def on_device_error(self, error_message: str):
        """Handle device operation error"""
        QMessageBox.critical(self, "Device Error", error_message)
        self.status_bar.showMessage("Device operation failed")
    
    def on_device_selected(self, device: AndroidDevice):
        """Handle device selection"""
        # Switch to attack config tab
        self.central_widget.setCurrentIndex(1)
    
    def analyze_selected_device(self):
        """Analyze selected device"""
        selected_rows = set(item.row() for item in self.device_widget.device_table.selectedItems())
        if len(selected_rows) != 1:
            return
        
        row = list(selected_rows)[0]
        if row >= len(self.device_widget.devices):
            return
        
        device = self.device_widget.devices[row]
        
        if self.device_worker and self.device_worker.isRunning():
            return
        
        self.status_bar.showMessage(f"Analyzing device {device.serial}...")
        
        self.device_worker = DeviceWorker(self.current_orchestrator, "analyze", device)
        self.device_worker.device_analyzed.connect(self.on_device_analyzed)
        self.device_worker.error_occurred.connect(self.on_device_error)
        self.device_worker.start()
    
    def on_device_analyzed(self, analysis_result: DeviceAnalysisResult):
        """Handle device analyzed"""
        self.attack_config_widget.set_analysis_result(analysis_result)
        self.central_widget.setCurrentIndex(1)  # Switch to attack config tab
        self.status_bar.showMessage(f"Device {analysis_result.device.serial} analyzed")
    
    def execute_attack(self):
        """Execute attack"""
        strategy = self.attack_config_widget.get_attack_strategy()
        if not strategy:
            QMessageBox.warning(self, "Warning", "Please configure attack parameters")
            return
        
        if self.attack_worker and self.attack_worker.isRunning():
            QMessageBox.warning(self, "Warning", "Attack already in progress")
            return
        
        # Switch to progress tab
        self.central_widget.setCurrentIndex(2)
        
        # Start attack
        self.attack_progress_widget.start_attack(strategy)
        self.status_bar.showMessage("Executing attack...")
        
        self.attack_worker = AttackWorker(self.current_orchestrator, strategy)
        self.attack_worker.progress_updated.connect(self.attack_progress_widget.update_progress)
        self.attack_worker.attack_completed.connect(self.on_attack_completed)
        self.attack_worker.error_occurred.connect(self.on_attack_error)
        self.attack_worker.start()
    
    def on_attack_completed(self, result: AttackResult):
        """Handle attack completion"""
        self.attack_progress_widget.attack_completed(result)
        
        if result.success:
            self.status_bar.showMessage("Attack completed successfully")
            QMessageBox.information(self, "Success", 
                f"Attack completed successfully!\n"
                f"Attempts: {result.attempts}\n"
                f"Duration: {result.duration:.1f}s\n"
                f"Result: {result.result_data}")
        else:
            self.status_bar.showMessage("Attack failed")
            QMessageBox.warning(self, "Attack Failed", 
                f"Attack failed after {result.attempts} attempts\n"
                f"Duration: {result.duration:.1f}s\n"
                f"Error: {result.error_message or 'Unknown error'}")
    
    def on_attack_error(self, error_message: str):
        """Handle attack error"""
        self.attack_progress_widget.attack_error(error_message)
        self.status_bar.showMessage("Attack error")
        QMessageBox.critical(self, "Attack Error", error_message)
    
    def stop_attack(self):
        """Stop current attack"""
        if self.attack_worker and self.attack_worker.isRunning():
            self.attack_worker.stop()
            self.status_bar.showMessage("Attack stopped")
    
    def generate_report(self):
        """Generate evidence report"""
        if not self.current_orchestrator:
            QMessageBox.warning(self, "Warning", "No active case")
            return
        
        try:
            self.status_bar.showMessage("Generating report...")
            
            report = self.current_orchestrator.generate_evidence_report(
                self.current_orchestrator.case_id
            )
            
            self.evidence_widget.set_report(report)
            self.central_widget.setCurrentIndex(3)  # Switch to evidence tab
            self.status_bar.showMessage("Report generated")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate report:\n{e}")
            self.status_bar.showMessage("Report generation failed")
    
    def show_configuration(self):
        """Show configuration dialog"""
        QMessageBox.information(self, "Configuration", "Configuration dialog not implemented yet")
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About Crack Droid", 
            "Crack Droid v1.0.0\n\n"
            "Android Forensics Toolkit\n"
            "For authorized forensic investigations only\n\n"
            "© 2025 Forensics Team")
    
    def closeEvent(self, event):
        """Handle application close"""
        # Stop any running workers
        if self.device_worker and self.device_worker.isRunning():
            self.device_worker.terminate()
        
        if self.attack_worker and self.attack_worker.isRunning():
            self.attack_worker.stop()
        
        # Logout user
        if self.current_session:
            self.auth_service.logout_user(self.current_session.session_id)
        
        event.accept()


def main():
    """Main entry point for GUI application"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Crack Droid")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Forensics Team")
    
    # Create and show main window
    try:
        window = ForensicsMainWindow()
        window.show()
        
        # Run application
        sys.exit(app.exec_())
        
    except Exception as e:
        QMessageBox.critical(None, "Fatal Error", f"Failed to start application:\n{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()