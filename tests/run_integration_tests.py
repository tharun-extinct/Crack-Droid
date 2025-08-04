"""
Integration Test Runner for Android Forensics Toolkit

This module provides a comprehensive test runner that orchestrates all
integration tests, generates reports, and validates system requirements.
"""

import pytest
import sys
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import subprocess

# Import test modules
from tests.integration_test_framework import (
    IntegrationTestFramework, TestForensicWorkflows, TestDeviceManagerIntegration
)
from tests.test_device_simulation import TestDeviceSimulation
from tests.test_evidence_integrity_validation import TestEvidenceIntegrityValidation
from tests.test_performance_benchmarks import TestPerformanceBenchmarks


class IntegrationTestRunner:
    """Comprehensive integration test runner"""
    
    def __init__(self, output_dir: str = "test_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.test_results = {
            'start_time': None,
            'end_time': None,
            'duration_seconds': 0,
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'skipped_tests': 0,
            'test_suites': {},
            'system_info': self._get_system_info(),
            'requirements_validation': {},
            'performance_summary': {},
            'integrity_validation': {},
            'errors': []
        }
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        try:
            import platform
            import psutil
            
            return {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'cpu_count': psutil.cpu_count(),
                'memory_gb': round(psutil.virtual_memory().total / (1024**3), 2),
                'disk_space_gb': round(psutil.disk_usage('/').total / (1024**3), 2),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def run_all_tests(self, test_filter: str = None, verbose: bool = True) -> Dict[str, Any]:
        """Run all integration tests"""
        print("=" * 80)
        print("ANDROID FORENSICS TOOLKIT - INTEGRATION TEST SUITE")
        print("=" * 80)
        
        self.test_results['start_time'] = datetime.now()
        
        # Define test suites
        test_suites = [
            {
                'name': 'forensic_workflows',
                'description': 'End-to-end forensic workflow tests',
                'test_class': TestForensicWorkflows,
                'critical': True
            },
            {
                'name': 'device_simulation',
                'description': 'Device simulation and mocking tests',
                'test_class': TestDeviceSimulation,
                'critical': True
            },
            {
                'name': 'evidence_integrity',
                'description': 'Evidence integrity validation tests',
                'test_class': TestEvidenceIntegrityValidation,
                'critical': True
            },
            {
                'name': 'performance_benchmarks',
                'description': 'Performance benchmarking tests',
                'test_class': TestPerformanceBenchmarks,
                'critical': False
            },
            {
                'name': 'device_manager_integration',
                'description': 'Device manager integration tests',
                'test_class': TestDeviceManagerIntegration,
                'critical': True
            }
        ]
        
        # Filter test suites if specified
        if test_filter:
            test_suites = [ts for ts in test_suites if test_filter.lower() in ts['name'].lower()]
        
        # Run each test suite
        for suite in test_suites:
            print(f"\n{'='*60}")
            print(f"Running {suite['name']}: {suite['description']}")
            print(f"{'='*60}")
            
            suite_result = self._run_test_suite(suite, verbose)
            self.test_results['test_suites'][suite['name']] = suite_result
            
            # Update totals
            self.test_results['total_tests'] += suite_result['total']
            self.test_results['passed_tests'] += suite_result['passed']
            self.test_results['failed_tests'] += suite_result['failed']
            self.test_results['skipped_tests'] += suite_result['skipped']
            
            # Check if critical test suite failed
            if suite['critical'] and suite_result['failed'] > 0:
                print(f"CRITICAL TEST SUITE FAILED: {suite['name']}")
                self.test_results['errors'].append(
                    f"Critical test suite '{suite['name']}' had {suite_result['failed']} failures"
                )
        
        self.test_results['end_time'] = datetime.now()
        self.test_results['duration_seconds'] = (
            self.test_results['end_time'] - self.test_results['start_time']
        ).total_seconds()
        
        # Generate reports
        self._generate_test_report()
        self._validate_requirements()
        
        return self.test_results
    
    def _run_test_suite(self, suite: Dict[str, Any], verbose: bool) -> Dict[str, Any]:
        """Run a specific test suite"""
        suite_start = time.time()
        
        # Prepare pytest arguments
        pytest_args = [
            f"tests/test_{suite['name'].replace('_', '_')}.py",
            "--tb=short",
            "--durations=10",
            "-v" if verbose else "-q"
        ]
        
        # Add JSON report
        json_report_path = self.output_dir / f"{suite['name']}_results.json"
        pytest_args.extend([
            f"--json-report",
            f"--json-report-file={json_report_path}"
        ])
        
        try:
            # Run pytest
            result = pytest.main(pytest_args)
            
            # Parse results
            suite_result = self._parse_pytest_results(json_report_path, result)
            
        except Exception as e:
            print(f"Error running test suite {suite['name']}: {str(e)}")
            suite_result = {
                'total': 0,
                'passed': 0,
                'failed': 1,
                'skipped': 0,
                'duration': time.time() - suite_start,
                'error': str(e)
            }
        
        return suite_result
    
    def _parse_pytest_results(self, json_report_path: Path, exit_code: int) -> Dict[str, Any]:
        """Parse pytest JSON results"""
        try:
            if json_report_path.exists():
                with open(json_report_path, 'r') as f:
                    pytest_data = json.load(f)
                
                return {
                    'total': pytest_data.get('summary', {}).get('total', 0),
                    'passed': pytest_data.get('summary', {}).get('passed', 0),
                    'failed': pytest_data.get('summary', {}).get('failed', 0),
                    'skipped': pytest_data.get('summary', {}).get('skipped', 0),
                    'duration': pytest_data.get('duration', 0),
                    'exit_code': exit_code,
                    'tests': pytest_data.get('tests', [])
                }
            else:
                # Fallback if JSON report not available
                return {
                    'total': 1,
                    'passed': 1 if exit_code == 0 else 0,
                    'failed': 0 if exit_code == 0 else 1,
                    'skipped': 0,
                    'duration': 0,
                    'exit_code': exit_code
                }
        except Exception as e:
            return {
                'total': 1,
                'passed': 0,
                'failed': 1,
                'skipped': 0,
                'duration': 0,
                'error': str(e)
            }
    
    def _validate_requirements(self):
        """Validate that all requirements are covered by tests"""
        print(f"\n{'='*60}")
        print("REQUIREMENTS VALIDATION")
        print(f"{'='*60}")
        
        # Define requirements mapping to test coverage
        requirements_coverage = {
            '1.1': ['forensic_workflows', 'device_simulation'],  # Device detection with USB debugging
            '1.2': ['forensic_workflows', 'device_simulation'],  # Lock type identification
            '1.3': ['forensic_workflows'],  # Screen timeout detection
            '1.4': ['forensic_workflows'],  # Root access file pulling
            '1.5': ['device_simulation'],  # Device metadata collection
            '2.1': ['forensic_workflows', 'performance_benchmarks'],  # Brute force attacks
            '2.2': ['forensic_workflows'],  # GPU-accelerated cracking
            '2.3': ['forensic_workflows'],  # Lockout delay handling
            '2.4': ['forensic_workflows'],  # Dictionary attacks
            '3.1': ['device_simulation'],  # EDL mode access
            '3.2': ['device_simulation'],  # Firehose loaders
            '3.3': ['forensic_workflows'],  # Pattern analysis
            '3.5': ['device_simulation'],  # NAND dumps
            '4.1': ['evidence_integrity'],  # Evidence logging
            '4.2': ['evidence_integrity'],  # Report generation
            '4.3': ['evidence_integrity'],  # Chain of custody
            '4.4': ['evidence_integrity'],  # Case ID authorization
            '5.1': ['forensic_workflows'],  # Role-based access
            '5.2': ['forensic_workflows'],  # Legal disclaimer
            '5.3': ['evidence_integrity'],  # Data encryption
            '5.4': ['forensic_workflows'],  # Authorized environments
            '5.5': ['evidence_integrity'],  # Audit trails
            '6.1': ['performance_benchmarks'],  # Dictionary + mask attacks
            '6.2': ['performance_benchmarks'],  # Heuristic prioritization
            '6.3': ['device_manager_integration'],  # Multi-device processing
            '6.4': ['performance_benchmarks'],  # Lockout management
            '6.5': ['performance_benchmarks'],  # GPU acceleration
            '7.1': ['forensic_workflows'],  # Platform support
            '7.2': ['device_simulation'],  # Tool integration
            '7.3': ['forensic_workflows'],  # GUI interface
            '7.4': ['forensic_workflows'],  # Wordlist loading
            '7.5': ['performance_benchmarks']   # Tool integration
        }
        
        # Check coverage
        covered_requirements = []
        uncovered_requirements = []
        
        for req_id, test_suites in requirements_coverage.items():
            covered = any(
                suite in self.test_results['test_suites'] and 
                self.test_results['test_suites'][suite]['passed'] > 0
                for suite in test_suites
            )
            
            if covered:
                covered_requirements.append(req_id)
            else:
                uncovered_requirements.append(req_id)
        
        coverage_percentage = len(covered_requirements) / len(requirements_coverage) * 100
        
        self.test_results['requirements_validation'] = {
            'total_requirements': len(requirements_coverage),
            'covered_requirements': len(covered_requirements),
            'uncovered_requirements': len(uncovered_requirements),
            'coverage_percentage': coverage_percentage,
            'covered_list': covered_requirements,
            'uncovered_list': uncovered_requirements
        }
        
        print(f"Requirements Coverage: {coverage_percentage:.1f}%")
        print(f"Covered: {len(covered_requirements)}/{len(requirements_coverage)}")
        
        if uncovered_requirements:
            print(f"Uncovered requirements: {', '.join(uncovered_requirements)}")
    
    def _generate_test_report(self):
        """Generate comprehensive test report"""
        print(f"\n{'='*60}")
        print("TEST EXECUTION SUMMARY")
        print(f"{'='*60}")
        
        # Summary statistics
        total_tests = self.test_results['total_tests']
        passed_tests = self.test_results['passed_tests']
        failed_tests = self.test_results['failed_tests']
        skipped_tests = self.test_results['skipped_tests']
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Skipped: {skipped_tests}")
        print(f"Success Rate: {success_rate:.1f}%")
        print(f"Duration: {self.test_results['duration_seconds']:.2f} seconds")
        
        # Test suite breakdown
        print(f"\nTest Suite Breakdown:")
        for suite_name, suite_result in self.test_results['test_suites'].items():
            suite_success_rate = (
                suite_result['passed'] / suite_result['total'] * 100
                if suite_result['total'] > 0 else 0
            )
            print(f"  {suite_name}: {suite_result['passed']}/{suite_result['total']} "
                  f"({suite_success_rate:.1f}%) - {suite_result['duration']:.2f}s")
        
        # Performance summary
        perf_suites = [s for s in self.test_results['test_suites'].keys() 
                      if 'performance' in s]
        if perf_suites:
            print(f"\nPerformance Summary:")
            for suite in perf_suites:
                suite_data = self.test_results['test_suites'][suite]
                print(f"  {suite}: {suite_data['duration']:.2f}s average")
        
        # Save detailed report
        report_path = self.output_dir / "integration_test_report.json"
        with open(report_path, 'w') as f:
            json.dump(self.test_results, f, indent=2, default=str)
        
        print(f"\nDetailed report saved to: {report_path}")
        
        # Generate HTML report if possible
        try:
            self._generate_html_report()
        except Exception as e:
            print(f"Could not generate HTML report: {str(e)}")
    
    def _generate_html_report(self):
        """Generate HTML test report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Android Forensics Toolkit - Integration Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .test-suite {{ margin: 10px 0; padding: 10px; border: 1px solid #ddd; }}
        .passed {{ color: green; }}
        .failed {{ color: red; }}
        .skipped {{ color: orange; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Android Forensics Toolkit - Integration Test Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Duration: {self.test_results['duration_seconds']:.2f} seconds</p>
    </div>
    
    <div class="summary">
        <h2>Test Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Tests</td><td>{self.test_results['total_tests']}</td></tr>
            <tr><td class="passed">Passed</td><td>{self.test_results['passed_tests']}</td></tr>
            <tr><td class="failed">Failed</td><td>{self.test_results['failed_tests']}</td></tr>
            <tr><td class="skipped">Skipped</td><td>{self.test_results['skipped_tests']}</td></tr>
            <tr><td>Success Rate</td><td>{(self.test_results['passed_tests']/self.test_results['total_tests']*100) if self.test_results['total_tests'] > 0 else 0:.1f}%</td></tr>
        </table>
    </div>
    
    <div class="test-suites">
        <h2>Test Suite Results</h2>
        {self._generate_test_suite_html()}
    </div>
    
    <div class="requirements">
        <h2>Requirements Coverage</h2>
        <p>Coverage: {self.test_results.get('requirements_validation', {}).get('coverage_percentage', 0):.1f}%</p>
    </div>
    
    <div class="system-info">
        <h2>System Information</h2>
        <pre>{json.dumps(self.test_results['system_info'], indent=2)}</pre>
    </div>
</body>
</html>
"""
        
        html_path = self.output_dir / "integration_test_report.html"
        with open(html_path, 'w') as f:
            f.write(html_content)
        
        print(f"HTML report saved to: {html_path}")
    
    def _generate_test_suite_html(self) -> str:
        """Generate HTML for test suite results"""
        html = ""
        for suite_name, suite_result in self.test_results['test_suites'].items():
            success_rate = (
                suite_result['passed'] / suite_result['total'] * 100
                if suite_result['total'] > 0 else 0
            )
            
            status_class = "passed" if suite_result['failed'] == 0 else "failed"
            
            html += f"""
            <div class="test-suite">
                <h3 class="{status_class}">{suite_name}</h3>
                <p>Passed: {suite_result['passed']}, Failed: {suite_result['failed']}, 
                   Skipped: {suite_result['skipped']}</p>
                <p>Success Rate: {success_rate:.1f}%</p>
                <p>Duration: {suite_result['duration']:.2f} seconds</p>
            </div>
            """
        
        return html


def main():
    """Main entry point for integration test runner"""
    parser = argparse.ArgumentParser(description="Run Android Forensics Toolkit Integration Tests")
    parser.add_argument("--filter", help="Filter test suites by name")
    parser.add_argument("--output-dir", default="test_results", help="Output directory for results")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--quick", action="store_true", help="Run quick tests only (skip performance)")
    
    args = parser.parse_args()
    
    # Create test runner
    runner = IntegrationTestRunner(args.output_dir)
    
    # Apply quick filter
    test_filter = args.filter
    if args.quick and not test_filter:
        test_filter = "performance"  # This will exclude performance tests
    
    # Run tests
    try:
        results = runner.run_all_tests(test_filter, args.verbose)
        
        # Exit with appropriate code
        if results['failed_tests'] > 0:
            print(f"\n❌ INTEGRATION TESTS FAILED: {results['failed_tests']} failures")
            sys.exit(1)
        else:
            print(f"\n✅ ALL INTEGRATION TESTS PASSED: {results['passed_tests']} tests")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n⚠️  Test execution interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n💥 Test execution failed with error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()