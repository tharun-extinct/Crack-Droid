"""
User Interface components for Crack Droid
"""

from .cli import ForensicsCLI

# GUI components (optional, requires PyQt5)
try:
    from .gui import (
        ForensicsMainWindow, LoginDialog, LegalComplianceDialog, 
        CaseSetupDialog, DeviceListWidget, AttackConfigWidget,
        AttackProgressWidget, EvidenceReportWidget
    )
    GUI_AVAILABLE = True
    __all__ = [
        'ForensicsCLI', 'ForensicsMainWindow', 'LoginDialog', 
        'LegalComplianceDialog', 'CaseSetupDialog', 'DeviceListWidget',
        'AttackConfigWidget', 'AttackProgressWidget', 'EvidenceReportWidget'
    ]
except ImportError:
    GUI_AVAILABLE = False
    __all__ = ['ForensicsCLI']

__version__ = "1.0.0"