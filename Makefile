# Crack Droid Makefile
# Installation and deployment automation

.PHONY: help install setup test clean validate deploy uninstall

# Default target
help:
	@echo "Crack Droid Installation and Deployment"
	@echo "============================================="
	@echo ""
	@echo "Available targets:"
	@echo "  install     - Run complete installation (install.sh + setup.py)"
	@echo "  setup       - Run Python setup script only"
	@echo "  test        - Run deployment tests"
	@echo "  validate    - Validate configuration"
	@echo "  clean       - Clean temporary files"
	@echo "  deploy      - Full deployment (install + test + validate)"
	@echo "  uninstall   - Remove installation"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Requirements:"
	@echo "  - Kali Linux or Ubuntu"
	@echo "  - Python 3.8+"
	@echo "  - sudo privileges"
	@echo ""

# Check if running on supported OS
check-os:
	@if [ ! -f /etc/os-release ]; then \
		echo "Error: Cannot detect operating system"; \
		exit 1; \
	fi
	@. /etc/os-release; \
	if [ "$$ID" != "kali" ] && [ "$$ID" != "ubuntu" ]; then \
		echo "Error: Unsupported OS. This installer supports Kali Linux and Ubuntu only."; \
		exit 1; \
	fi
	@echo "✓ Operating system check passed"

# Check Python version
check-python:
	@python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" || \
		(echo "Error: Python 3.8 or higher required" && exit 1)
	@echo "✓ Python version check passed"

# Check if running as non-root
check-user:
	@if [ "$$(id -u)" -eq 0 ]; then \
		echo "Error: Do not run as root. Use a regular user with sudo privileges."; \
		exit 1; \
	fi
	@echo "✓ User check passed"

# Pre-installation checks
pre-checks: check-os check-python check-user
	@echo "✓ All pre-installation checks passed"

# Run shell installation script
install-system: pre-checks
	@echo "Running system installation..."
	@chmod +x install.sh
	@./install.sh
	@echo "✓ System installation completed"

# Run Python setup script
setup: pre-checks
	@echo "Running Python setup..."
	@python3 setup.py
	@echo "✓ Python setup completed"

# Complete installation
install: install-system setup
	@echo "✓ Complete installation finished"
	@echo ""
	@echo "Installation completed successfully!"
	@echo "Configuration directory: ~/.forensics-toolkit"
	@echo ""
	@echo "Next steps:"
	@echo "1. Run 'make test' to validate installation"
	@echo "2. Run 'make validate' to check configuration"
	@echo "3. Start the toolkit with: python3 crackdroid.py"

# Run deployment tests
test:
	@echo "Running deployment tests..."
	@python3 test_deployment.py -v
	@echo "✓ Deployment tests completed"

# Validate configuration
validate:
	@echo "Validating configuration..."
	@python3 validate_config.py -v
	@echo "✓ Configuration validation completed"

# Fix common permission issues
fix-permissions:
	@echo "Fixing file permissions..."
	@python3 validate_config.py --fix-permissions
	@echo "✓ Permissions fixed"

# Clean temporary files and caches
clean:
	@echo "Cleaning temporary files..."
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.log" -delete 2>/dev/null || true
	@rm -rf build/ dist/ *.egg-info/ 2>/dev/null || true
	@if [ -d ~/.forensics-toolkit/temp ]; then \
		rm -rf ~/.forensics-toolkit/temp/*; \
	fi
	@echo "✓ Cleanup completed"

# Full deployment process
deploy: clean install test validate
	@echo ""
	@echo "=========================================="
	@echo "DEPLOYMENT COMPLETED SUCCESSFULLY!"
	@echo "=========================================="
	@echo ""
	@echo "Crack Droid is ready for use."
	@echo ""
	@echo "Usage:"
	@echo "  CLI mode:  python3 crackdroid.py"
	@echo "  GUI mode:  python3 crackdroid.py --gui"
	@echo "  Help:      python3 crackdroid.py --help"
	@echo ""

# Development setup (for contributors)
dev-setup: setup
	@echo "Setting up development environment..."
	@pip install pytest pytest-cov black flake8 mypy
	@echo "✓ Development environment ready"

# Run code quality checks
lint:
	@echo "Running code quality checks..."
	@python3 -m flake8 forensics_toolkit/ --max-line-length=100
	@python3 -m black --check forensics_toolkit/
	@echo "✓ Code quality checks passed"

# Format code
format:
	@echo "Formatting code..."
	@python3 -m black forensics_toolkit/
	@echo "✓ Code formatted"

# Run unit tests (if available)
unit-test:
	@echo "Running unit tests..."
	@if [ -d tests/ ]; then \
		python3 -m pytest tests/ -v; \
	else \
		echo "No unit tests found"; \
	fi

# Create backup of configuration
backup-config:
	@echo "Creating configuration backup..."
	@if [ -d ~/.forensics-toolkit ]; then \
		tar -czf forensics-toolkit-backup-$$(date +%Y%m%d_%H%M%S).tar.gz -C ~/ .forensics-toolkit/; \
		echo "✓ Configuration backed up"; \
	else \
		echo "No configuration found to backup"; \
	fi

# Restore configuration from backup
restore-config:
	@echo "Available backups:"
	@ls -la forensics-toolkit-backup-*.tar.gz 2>/dev/null || echo "No backups found"
	@echo "To restore, run: tar -xzf <backup-file> -C ~/"

# Uninstall the toolkit
uninstall:
	@echo "Uninstalling Crack Droid..."
	@read -p "This will remove all configuration and data. Continue? (y/N): " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		echo "Creating backup before uninstall..."; \
		make backup-config 2>/dev/null || true; \
		echo "Removing configuration directory..."; \
		rm -rf ~/.forensics-toolkit; \
		echo "Removing virtual environment..."; \
		rm -rf venv/; \
		echo "Removing tools directory..."; \
		rm -rf tools/; \
		echo "✓ Uninstallation completed"; \
	else \
		echo "Uninstallation cancelled"; \
	fi

# Show system information
info:
	@echo "System Information:"
	@echo "==================="
	@echo "OS: $$(lsb_release -d 2>/dev/null | cut -f2 || cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')"
	@echo "Kernel: $$(uname -r)"
	@echo "Python: $$(python3 --version)"
	@echo "Architecture: $$(uname -m)"
	@echo "Memory: $$(free -h | awk 'NR==2{print $$2}')"
	@echo "Disk Space: $$(df -h / | awk 'NR==2{print $$4}') available"
	@echo ""
	@echo "Tool Availability:"
	@echo "=================="
	@for tool in adb fastboot hashcat john; do \
		if command -v $$tool >/dev/null 2>&1; then \
			echo "✓ $$tool: $$(command -v $$tool)"; \
		else \
			echo "✗ $$tool: not found"; \
		fi; \
	done
	@echo ""
	@if [ -d ~/.forensics-toolkit ]; then \
		echo "Installation Status: ✓ Installed"; \
		echo "Config Directory: ~/.forensics-toolkit"; \
		echo "Config Size: $$(du -sh ~/.forensics-toolkit 2>/dev/null | cut -f1)"; \
	else \
		echo "Installation Status: ✗ Not installed"; \
	fi

# Quick health check
health-check:
	@echo "Running health check..."
	@python3 validate_config.py 2>/dev/null && echo "✓ Configuration healthy" || echo "✗ Configuration issues found"
	@python3 -c "import forensics_toolkit" 2>/dev/null && echo "✓ Toolkit importable" || echo "✗ Import issues"
	@echo "✓ Health check completed"

# Show installation logs
logs:
	@echo "Recent installation logs:"
	@echo "========================="
	@if [ -f /tmp/forensics-toolkit-install.log ]; then \
		tail -20 /tmp/forensics-toolkit-install.log; \
	else \
		echo "No installation log found"; \
	fi
	@echo ""
	@if [ -d ~/.forensics-toolkit/logs ]; then \
		echo "Application logs:"; \
		ls -la ~/.forensics-toolkit/logs/; \
	fi

# Update the toolkit (for future use)
update:
	@echo "Updating Crack Droid..."
	@git pull 2>/dev/null || echo "Not a git repository - manual update required"
	@make setup
	@echo "✓ Update completed"

# Performance benchmark
benchmark:
	@echo "Running performance benchmark..."
	@python3 -c "
import time
import sqlite3
from pathlib import Path

config_dir = Path.home() / '.forensics-toolkit'
if not config_dir.exists():
    print('Toolkit not installed')
    exit(1)

# Database query benchmark
db_path = config_dir / 'patterns.db'
if db_path.exists():
    start = time.time()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM patterns ORDER BY frequency DESC LIMIT 1000')
    results = cursor.fetchall()
    conn.close()
    db_time = time.time() - start
    print(f'Database query: {db_time:.3f}s ({len(results)} results)')

# File I/O benchmark
test_file = config_dir / 'temp' / 'benchmark.txt'
test_file.parent.mkdir(exist_ok=True)
test_data = 'x' * 100000  # 100KB

start = time.time()
with open(test_file, 'w') as f:
    f.write(test_data)
write_time = time.time() - start

start = time.time()
with open(test_file, 'r') as f:
    read_data = f.read()
read_time = time.time() - start

test_file.unlink()
print(f'File write: {write_time:.3f}s (100KB)')
print(f'File read: {read_time:.3f}s (100KB)')
print('✓ Benchmark completed')
"

# Show version information
version:
	@echo "Crack Droid Version Information"
	@echo "===================================="
	@if [ -f ~/.forensics-toolkit/config.json ]; then \
		python3 -c "import json; config=json.load(open('$(HOME)/.forensics-toolkit/config.json')); print('Version:', config['installation']['version']); print('Install Date:', config['installation']['install_date'])"; \
	else \
		echo "Not installed"; \
	fi