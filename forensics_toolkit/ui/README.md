# Crack Droid GUI Interface

This directory contains the PyQt5-based graphical user interface for the Crack Droid Android forensics toolkit.

## Overview

The GUI provides a comprehensive interface for forensic investigators to:
- Authenticate and manage user sessions
- Handle legal compliance requirements
- Set up and manage forensic cases
- Detect and analyze Android devices
- Configure and execute forensic attacks
- Monitor attack progress in real-time
- View and export evidence reports

## Components

### Main Application (`gui.py`)

The main GUI application consists of several key components:

#### `ForensicsMainWindow`
- Main application window with tabbed interface
- Handles user authentication and legal compliance
- Manages forensic case setup and workflow
- Coordinates between different UI components

#### `LoginDialog`
- User authentication dialog
- Integrates with the authentication service
- Provides secure login functionality

#### `LegalComplianceDialog`
- Displays legal disclaimer
- Captures user consent
- Records compliance for audit trail

#### `CaseSetupDialog`
- Creates new forensic cases
- Validates case ID format
- Initializes forensic orchestrator

#### `DeviceListWidget`
- Displays connected Android devices
- Shows device information (brand, model, serial, etc.)
- Provides device selection and analysis capabilities

#### `AttackConfigWidget`
- Configures attack parameters
- Shows recommended attack strategies based on device analysis
- Allows selection of attack type, wordlists, and other parameters

#### `AttackProgressWidget`
- Real-time attack progress monitoring
- Shows attempts, duration, and success rate
- Provides attack control (stop/pause functionality)

#### `EvidenceReportWidget`
- Displays comprehensive evidence reports
- Formats reports for readability
- Provides export functionality (JSON/text formats)

### Worker Threads

#### `DeviceWorker`
- Handles device detection and analysis in background threads
- Prevents UI blocking during long operations
- Emits signals for UI updates

#### `AttackWorker`
- Executes forensic attacks asynchronously
- Provides progress updates via signals
- Handles attack completion and error reporting

## Features

### Authentication & Security
- Role-based access control
- Session management with timeout
- Legal compliance workflow
- Audit trail logging

### Device Management
- Multi-device detection and analysis
- Device capability assessment
- Real-time device status monitoring
- Automatic device reconnection

### Attack Execution
- Multiple attack strategies (brute force, dictionary, pattern analysis, hash cracking)
- GPU acceleration support
- Multi-threaded execution
- Progress monitoring and control

### Evidence Management
- Comprehensive evidence logging
- Chain of custody tracking
- Report generation and export
- Integrity verification

### User Experience
- Intuitive tabbed interface
- Real-time progress updates
- Error handling and user feedback
- Keyboard shortcuts and accessibility

## Installation

### Prerequisites

The GUI requires PyQt5 to be installed:

```bash
pip install PyQt5
```

### Dependencies

The GUI depends on the following forensics toolkit components:
- `forensics_toolkit.interfaces`
- `forensics_toolkit.services.forensics_orchestrator`
- `forensics_toolkit.services.authentication`
- `forensics_toolkit.services.legal_compliance`
- `forensics_toolkit.config`

## Usage

### Starting the GUI

#### Option 1: Using the launcher script
```bash
python forensics_toolkit/ui/launch_gui.py
```

#### Option 2: Direct execution
```bash
python -m forensics_toolkit.ui.gui
```

#### Option 3: From Python code
```python
from forensics_toolkit.ui.gui import main
main()
```

### Workflow

1. **Authentication**: Login with valid credentials
2. **Legal Compliance**: Accept legal disclaimer and terms
3. **Case Setup**: Create or select a forensic case
4. **Device Detection**: Detect connected Android devices
5. **Device Analysis**: Analyze device capabilities and security
6. **Attack Configuration**: Configure attack parameters
7. **Attack Execution**: Execute forensic attacks with monitoring
8. **Evidence Review**: Generate and export evidence reports

## Configuration

The GUI uses the global configuration manager for:
- Tool paths (ADB, Fastboot, Hashcat, etc.)
- Security settings
- Performance parameters
- Evidence storage locations

Configuration can be modified through the GUI or by editing the configuration files.

## Testing

### Unit Tests

The GUI includes comprehensive unit tests:

```bash
# Run all GUI tests
python -m pytest tests/test_gui_simple.py -v

# Run specific test class
python -m pytest tests/test_gui_simple.py::TestGUILogic -v
```

### Test Coverage

Tests cover:
- Data formatting and validation
- Attack strategy processing
- Progress monitoring logic
- Report generation
- Error handling
- User input validation

## Architecture

### Design Patterns

- **Model-View-Controller (MVC)**: Separation of data, presentation, and logic
- **Observer Pattern**: Signal/slot mechanism for UI updates
- **Worker Thread Pattern**: Background processing without UI blocking
- **Factory Pattern**: Dynamic widget creation based on device capabilities

### Threading Model

- **Main Thread**: UI operations and user interaction
- **Worker Threads**: Device operations and attack execution
- **Signal/Slot Communication**: Thread-safe UI updates

### Error Handling

- Graceful error recovery
- User-friendly error messages
- Detailed logging for debugging
- Fallback mechanisms for critical operations

## Security Considerations

### Access Control
- User authentication required
- Role-based permissions
- Session timeout enforcement
- Audit logging of all operations

### Data Protection
- Sensitive data encryption
- Secure evidence storage
- Chain of custody maintenance
- Integrity verification

### Legal Compliance
- Legal disclaimer presentation
- Consent recording
- Authorized environment verification
- Compliance audit trails

## Troubleshooting

### Common Issues

#### PyQt5 Not Found
```
ImportError: No module named 'PyQt5'
```
**Solution**: Install PyQt5 using `pip install PyQt5`

#### Authentication Failures
- Check user credentials
- Verify user database integrity
- Check session timeout settings

#### Device Detection Issues
- Verify ADB installation and PATH
- Check USB debugging settings
- Ensure proper device drivers

#### Attack Execution Errors
- Verify tool paths in configuration
- Check device compatibility
- Review attack parameters

### Debug Mode

Enable debug logging by setting the log level:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Log Files

GUI operations are logged to:
- Application logs: `logs/forensics.log`
- Evidence logs: `evidence/{case_id}/logs/`
- Audit logs: `logs/audit.log`

## Contributing

### Code Style
- Follow PEP 8 guidelines
- Use type hints where appropriate
- Document all public methods
- Include unit tests for new features

### Testing Requirements
- All new features must include tests
- Maintain test coverage above 80%
- Test both success and failure scenarios
- Include integration tests for complex workflows

### Documentation
- Update this README for new features
- Include docstrings for all classes and methods
- Provide usage examples
- Document configuration options

## License

This GUI interface is part of the Crack Droid forensics toolkit and is subject to the same licensing terms as the main project.

## Support

For issues, questions, or contributions, please refer to the main project documentation and issue tracking system.