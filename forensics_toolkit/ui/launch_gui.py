#!/usr/bin/env python3
"""
GUI Launcher for ForenCrack Droid

This script provides a convenient way to launch the PyQt5 GUI interface
with proper error handling and dependency checking.
"""

import sys
import os
import subprocess
from pathlib import Path

# Add the project root to the path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


def check_dependencies():
    """Check if required dependencies are installed"""
    missing_deps = []
    
    # Check PyQt5
    try:
        import PyQt5
        from PyQt5.QtWidgets import QApplication
    except ImportError:
        missing_deps.append("PyQt5")
    
    # Check other required modules
    required_modules = [
        'forensics_toolkit.interfaces',
        'forensics_toolkit.services.forensics_orchestrator',
        'forensics_toolkit.services.authentication',
        'forensics_toolkit.services.legal_compliance',
        'forensics_toolkit.config'
    ]
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError as e:
            missing_deps.append(f"{module} ({e})")
    
    return missing_deps


def install_pyqt5():
    """Attempt to install PyQt5 using pip"""
    print("Attempting to install PyQt5...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "PyQt5"])
        print("PyQt5 installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to install PyQt5: {e}")
        return False


def main():
    """Main launcher function"""
    print("ForenCrack Droid GUI Launcher")
    print("=" * 40)
    
    # Check dependencies
    print("Checking dependencies...")
    missing_deps = check_dependencies()
    
    if missing_deps:
        print("Missing dependencies:")
        for dep in missing_deps:
            print(f"  - {dep}")
        
        # Try to install PyQt5 if it's missing
        if any("PyQt5" in dep for dep in missing_deps):
            install_choice = input("\nWould you like to try installing PyQt5? (y/n): ").lower()
            if install_choice in ['y', 'yes']:
                if install_pyqt5():
                    # Re-check dependencies
                    missing_deps = check_dependencies()
                    if not missing_deps:
                        print("All dependencies are now available!")
                    else:
                        print("Some dependencies are still missing:")
                        for dep in missing_deps:
                            print(f"  - {dep}")
                        return 1
                else:
                    return 1
            else:
                print("Cannot start GUI without required dependencies.")
                return 1
        else:
            print("Cannot start GUI without required dependencies.")
            return 1
    
    print("All dependencies are available!")
    print("Starting GUI...")
    
    try:
        # Import and run GUI
        from forensics_toolkit.ui.gui import main as gui_main
        gui_main()
        return 0
        
    except ImportError as e:
        print(f"Failed to import GUI module: {e}")
        print("Please ensure all forensics toolkit modules are properly installed.")
        return 1
    
    except Exception as e:
        print(f"Failed to start GUI: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())