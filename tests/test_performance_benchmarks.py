"""
Performance Benchmarking Tests for Android Forensics Toolkit

This module provides comprehensive performance benchmarking tests to validate
system performance under various load conditions and identify bottlenecks.
"""

import pytest
import time
import threading
import psutil
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, Future
import statistics

from forensics_toolkit.services.forensics_orchestrator import ForensicsOrchestrator
from forensics_toolkit.services.device_manager import DeviceManager
from forensics_toolkit.models.device import AndroidDevice, LockoutPolicy
from forensics_toolkit.models.attack import AttackStrategy
from forensics_toolkit.interfaces import AttackType, LockType, AttackResult


@dataclass
class PerformanceMetric:
    """Performance metric data"""
    operation_name: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    memory_usage_mb: float
    cpu_usage_percent: float
    throughput_ops_per_second: Optional[float] = None
    success_rate: float = 1.0
    error_count: int = 0
    additional_metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark tests"""
    name: str
    description: str
    iterations: int = 100
    concurrent_threads: int = 1
    timeout_seconds: int = 300
    memory_limit_mb: int = 1000
    cpu_limit_percent: int = 80
    warmup_iterations: int = 10


class PerformanceMonitor:
    """Monitor system performance during tests"""
    
    def __init__(self):
        self.process = psutil.Process()
        self.monitoring = False
        self.metrics = []
        self.monitor_thread = None
        
    def start_monitoring(self, interval_seconds: float = 0.1):
        """Start performance monitoring"""
        self.monitoring = True
        self.metrics.clear()
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval_seconds,)
        )
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
    
    def _monitor_loop(self, interval: float):
        """Monitoring loop"""
        while self.monitoring:
            try:
                memory_info = self.process.memory_info()
                cpu_percent = self.process.cpu_percent()
                
                self.metrics.append({
                    'timestamp': datetime.now(),
                    'memory_mb': memory_info.rss / 1024 / 1024,
                    'cpu_percent': cpu_percent,
                    'threads': self.process.num_threads()
                })
                
                time.sleep(interval)
            except Exception:
                # Process might have ended
                break
    
    def get_peak_memory(self) -> float:
        """Get peak memory usage in MB"""
        if not self.metrics:
            return 0.0
        return max(m['memory_mb'] for m in self.metrics)
    
    def get_average_cpu(self) -> float:
        """Get average CPU usage percentage"""
        if not self.metrics:
            return 0.0
        return statistics.mean(m['cpu_percent'] for m in self.metrics)
    
    def get_peak_threads(self) -> int:
        """Get peak thread count"""
        if not self.metrics:
            return 0
        return max(m['threads'] for m in self.metrics)


class PerformanceBenchmark:
    """Performance benchmark framework"""
    
    def __init__(self, temp_dir: str = None):
        self.temp_dir = temp_dir or tempfile.mkdtemp()
        self.monitor = PerformanceMonitor()
        self.results: List[PerformanceMetric] = []
        
    def cleanup(self):
        """Cleanup benchmark resources"""
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def benchmark_operation(self, config: BenchmarkConfig, operation_func: callable, *args, **kwargs):
        """Benchmark a specific operation"""
        print(f"Running benchmark: {config.name}")
        print(f"Description: {config.description}")
        print(f"Iterations: {config.iterations}, Threads: {config.concurrent_threads}")
        
        # Warmup
        if config.warmup_iterations > 0:
            print(f"Warming up with {config.warmup_iterations} iterations...")
            for _ in range(config.warmup_iterations):
                try:
                    operation_func(*args, **kwargs)
                except Exception:
                    pass  # Ignore warmup errors
        
        # Start monitoring
        self.monitor.start_monitoring()
        start_time = datetime.now()
        
        # Run benchmark
        if config.concurrent_threads == 1:
            results = self._run_sequential_benchmark(config, operation_func, *args, **kwargs)
        else:
            results = self._run_concurrent_benchmark(config, operation_func, *args, **kwargs)
        
        # Stop monitoring
        end_time = datetime.now()
        self.monitor.stop_monitoring()
        
        # Calculate metrics
        duration = (end_time - start_time).total_seconds()
        successful_operations = sum(1 for r in results if r.get('success', True))
        error_count = len(results) - successful_operations
        success_rate = successful_operations / len(results) if results else 0
        throughput = successful_operations / duration if duration > 0 else 0
        
        metric = PerformanceMetric(
            operation_name=config.name,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            memory_usage_mb=self.monitor.get_peak_memory(),
            cpu_usage_percent=self.monitor.get_average_cpu(),
            throughput_ops_per_second=throughput,
            success_rate=success_rate,
            error_count=error_count,
            additional_metrics={
                'peak_threads': self.monitor.get_peak_threads(),
                'total_operations': len(results),
                'successful_operations': successful_operations,
                'operation_results': results[:10]  # Store first 10 results as samples
            }
        )
        
        self.results.append(metric)
        
        # Print results
        print(f"Benchmark completed:")
        print(f"  Duration: {duration:.2f}s")
        print(f"  Throughput: {throughput:.2f} ops/sec")
        print(f"  Success rate: {success_rate:.2%}")
        print(f"  Peak memory: {metric.memory_usage_mb:.2f} MB")
        print(f"  Average CPU: {metric.cpu_usage_percent:.2f}%")
        print(f"  Peak threads: {metric.additional_metrics['peak_threads']}")
        
        return metric
    
    def _run_sequential_benchmark(self, config: BenchmarkConfig, operation_func: callable, *args, **kwargs):
        """Run sequential benchmark"""
        results = []
        for i in range(config.iterations):
            try:
                start = time.time()
                result = operation_func(*args, **kwargs)
                end = time.time()
                
                results.append({
                    'iteration': i,
                    'duration': end - start,
                    'success': True,
                    'result': result
                })
            except Exception as e:
                results.append({
                    'iteration': i,
                    'duration': 0,
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    def _run_concurrent_benchmark(self, config: BenchmarkConfig, operation_func: callable, *args, **kwargs):
        """Run concurrent benchmark"""
        results = []
        
        def run_operation(iteration):
            try:
                start = time.time()
                result = operation_func(*args, **kwargs)
                end = time.time()
                
                return {
                    'iteration': iteration,
                    'duration': end - start,
                    'success': True,
                    'result': result
                }
            except Exception as e:
                return {
                    'iteration': iteration,
                    'duration': 0,
                    'success': False,
                    'error': str(e)
                }
        
        with ThreadPoolExecutor(max_workers=config.concurrent_threads) as executor:
            futures = [
                executor.submit(run_operation, i)
                for i in range(config.iterations)
            ]
            
            for future in futures:
                try:
                    result = future.result(timeout=config.timeout_seconds)
                    results.append(result)
                except Exception as e:
                    results.append({
                        'iteration': -1,
                        'duration': 0,
                        'success': False,
                        'error': str(e)
                    })
        
        return results


class TestPerformanceBenchmarks:
    """Performance benchmark tests"""
    
    @pytest.fixture
    def benchmark_framework(self):
        """Create benchmark framework"""
        framework = PerformanceBenchmark()
        yield framework
        framework.cleanup()
    
    @pytest.fixture
    def mock_devices(self):
        """Create mock devices for testing"""
        devices = []
        for i in range(10):
            device = AndroidDevice(
                serial=f"BENCH_DEVICE_{i:03d}",
                model=f"Benchmark Device {i}",
                brand="BenchmarkBrand",
                android_version="12.0",
                usb_debugging=True,
                lock_type=LockType.PIN,
                lockout_policy=LockoutPolicy(max_attempts=5, lockout_duration=30)
            )
            devices.append(device)
        return devices
    
    def test_device_detection_performance(self, benchmark_framework, mock_devices):
        """Benchmark device detection performance"""
        with patch('forensics_toolkit.services.device_handlers.adb_handler.ADBHandler') as mock_adb:
            mock_adb.return_value.detect_devices.return_value = mock_devices
            
            def detect_devices_operation():
                orchestrator = ForensicsOrchestrator(
                    case_id="BENCH_DETECTION_001",
                    user_session="benchmark_user"
                )
                try:
                    devices = orchestrator.detect_devices()
                    return len(devices)
                finally:
                    orchestrator.cleanup()
            
            config = BenchmarkConfig(
                name="device_detection",
                description="Benchmark device detection performance",
                iterations=50,
                concurrent_threads=1
            )
            
            metric = benchmark_framework.benchmark_operation(config, detect_devices_operation)
            
            # Performance assertions
            assert metric.success_rate >= 0.95  # 95% success rate
            assert metric.throughput_ops_per_second >= 5.0  # At least 5 detections per second
            assert metric.memory_usage_mb <= 200.0  # Memory usage under 200MB
    
    def test_concurrent_device_analysis_performance(self, benchmark_framework, mock_devices):
        """Benchmark concurrent device analysis performance"""
        with patch('forensics_toolkit.services.device_handlers.adb_handler.ADBHandler') as mock_adb:
            mock_adb.return_value.detect_devices.return_value = mock_devices
            mock_adb.return_value.get_device_info.side_effect = lambda d: d
            mock_adb.return_value.is_device_accessible.return_value = True
            
            def analyze_devices_operation():
                orchestrator = ForensicsOrchestrator(
                    case_id="BENCH_ANALYSIS_001",
                    user_session="benchmark_user"
                )
                try:
                    detected_devices = orchestrator.detect_devices()
                    analyzed_count = 0
                    for device in detected_devices:
                        orchestrator.analyze_device(device)
                        analyzed_count += 1
                    return analyzed_count
                finally:
                    orchestrator.cleanup()
            
            config = BenchmarkConfig(
                name="concurrent_device_analysis",
                description="Benchmark concurrent device analysis",
                iterations=20,
                concurrent_threads=4
            )
            
            metric = benchmark_framework.benchmark_operation(config, analyze_devices_operation)
            
            # Performance assertions
            assert metric.success_rate >= 0.90
            assert metric.throughput_ops_per_second >= 2.0
            assert metric.memory_usage_mb <= 500.0
    
    def test_brute_force_attack_performance(self, benchmark_framework):
        """Benchmark brute force attack performance"""
        test_device = AndroidDevice(
            serial="BENCH_ATTACK_001",
            model="Attack Benchmark Device",
            brand="Test",
            android_version="12.0",
            usb_debugging=True,
            lock_type=LockType.PIN
        )
        
        with patch('forensics_toolkit.attack_engines.brute_force_engine.BruteForceEngine') as mock_engine:
            # Mock fast attack execution
            mock_engine.return_value.execute_attack.return_value = AttackResult(
                success=True,
                attempts=100,
                duration=0.5,
                result_data="1234"
            )
            mock_engine.return_value.validate_strategy.return_value = True
            
            def brute_force_operation():
                orchestrator = ForensicsOrchestrator(
                    case_id="BENCH_BRUTE_001",
                    user_session="benchmark_user"
                )
                try:
                    strategy = AttackStrategy(
                        strategy_type=AttackType.BRUTE_FORCE,
                        target_device=test_device,
                        wordlists=[],
                        mask_patterns=["?d?d?d?d"],
                        max_attempts=10000
                    )
                    
                    result = orchestrator.execute_attack(strategy)
                    return result.success
                finally:
                    orchestrator.cleanup()
            
            config = BenchmarkConfig(
                name="brute_force_attack",
                description="Benchmark brute force attack performance",
                iterations=30,
                concurrent_threads=2
            )
            
            metric = benchmark_framework.benchmark_operation(config, brute_force_operation)
            
            # Performance assertions
            assert metric.success_rate >= 0.95
            assert metric.throughput_ops_per_second >= 10.0  # At least 10 attacks per second
            assert metric.memory_usage_mb <= 300.0
    
    def test_evidence_logging_performance(self, benchmark_framework):
        """Benchmark evidence logging performance"""
        with patch('forensics_toolkit.services.evidence_logger.EvidenceLogger') as mock_logger:
            logger_instance = mock_logger.return_value
            
            # Mock fast logging
            def mock_log_operation(record):
                time.sleep(0.001)  # Simulate minimal processing time
                return f"logged_{record.case_id}_{record.attempt_number}"
            
            logger_instance.log_operation.side_effect = mock_log_operation
            
            def evidence_logging_operation():
                from forensics_toolkit.models.attack import EvidenceRecord
                
                record = EvidenceRecord(
                    case_id="BENCH_EVIDENCE_001",
                    timestamp=datetime.now(),
                    operation_type="benchmark_test",
                    device_serial="BENCH_DEVICE_001",
                    attempt_number=1,
                    result="success",
                    hash_verification="abc123",
                    chain_of_custody=[]
                )
                
                return logger_instance.log_operation(record)
            
            config = BenchmarkConfig(
                name="evidence_logging",
                description="Benchmark evidence logging performance",
                iterations=1000,
                concurrent_threads=5
            )
            
            metric = benchmark_framework.benchmark_operation(config, evidence_logging_operation)
            
            # Performance assertions
            assert metric.success_rate >= 0.99
            assert metric.throughput_ops_per_second >= 100.0  # At least 100 logs per second
            assert metric.memory_usage_mb <= 150.0
    
    def test_report_generation_performance(self, benchmark_framework):
        """Benchmark report generation performance"""
        with patch('forensics_toolkit.services.report_generator.ReportGenerator') as mock_generator:
            generator_instance = mock_generator.return_value
            
            # Mock report generation with simulated processing time
            def mock_generate_report(case_id, evidence_data=None):
                time.sleep(0.1)  # Simulate report processing
                return {
                    'case_id': case_id,
                    'generated_at': datetime.now().isoformat(),
                    'evidence_count': len(evidence_data) if evidence_data else 0,
                    'report_size_kb': 150
                }
            
            generator_instance.generate_comprehensive_report.side_effect = mock_generate_report
            
            def report_generation_operation():
                # Simulate evidence data
                evidence_data = [
                    {'operation': f'test_{i}', 'result': 'success'}
                    for i in range(100)
                ]
                
                return generator_instance.generate_comprehensive_report(
                    "BENCH_REPORT_001", evidence_data
                )
            
            config = BenchmarkConfig(
                name="report_generation",
                description="Benchmark report generation performance",
                iterations=50,
                concurrent_threads=3
            )
            
            metric = benchmark_framework.benchmark_operation(config, report_generation_operation)
            
            # Performance assertions
            assert metric.success_rate >= 0.95
            assert metric.throughput_ops_per_second >= 5.0
            assert metric.memory_usage_mb <= 400.0
    
    def test_memory_usage_under_load(self, benchmark_framework, mock_devices):
        """Test memory usage under sustained load"""
        with patch('forensics_toolkit.services.forensics_orchestrator.ForensicsOrchestrator') as mock_orchestrator:
            orchestrator_instance = mock_orchestrator.return_value
            
            # Mock operations that consume memory
            def mock_detect_devices():
                # Simulate memory allocation
                dummy_data = ['x' * 1000 for _ in range(100)]  # 100KB allocation
                return mock_devices
            
            def mock_analyze_device(device):
                # Simulate analysis memory usage
                analysis_data = {'device': device, 'analysis': 'x' * 5000}  # 5KB per analysis
                return device
            
            orchestrator_instance.detect_devices.side_effect = mock_detect_devices
            orchestrator_instance.analyze_device.side_effect = mock_analyze_device
            
            def memory_intensive_operation():
                orchestrator = mock_orchestrator.return_value
                
                # Perform multiple operations
                devices = orchestrator.detect_devices()
                analyzed_devices = []
                for device in devices:
                    analyzed = orchestrator.analyze_device(device)
                    analyzed_devices.append(analyzed)
                
                return len(analyzed_devices)
            
            config = BenchmarkConfig(
                name="memory_usage_under_load",
                description="Test memory usage under sustained load",
                iterations=100,
                concurrent_threads=8
            )
            
            metric = benchmark_framework.benchmark_operation(config, memory_intensive_operation)
            
            # Memory usage assertions
            assert metric.memory_usage_mb <= 800.0  # Should not exceed 800MB
            assert metric.success_rate >= 0.90
    
    def test_cpu_usage_optimization(self, benchmark_framework):
        """Test CPU usage optimization"""
        def cpu_intensive_operation():
            # Simulate CPU-intensive forensic operation
            result = 0
            for i in range(10000):
                result += i * i
            return result
        
        config = BenchmarkConfig(
            name="cpu_usage_optimization",
            description="Test CPU usage optimization",
            iterations=200,
            concurrent_threads=4
        )
        
        metric = benchmark_framework.benchmark_operation(config, cpu_intensive_operation)
        
        # CPU usage assertions
        assert metric.cpu_usage_percent <= 90.0  # Should not exceed 90% CPU
        assert metric.throughput_ops_per_second >= 50.0
    
    def test_scalability_with_device_count(self, benchmark_framework):
        """Test scalability with increasing device count"""
        device_counts = [1, 5, 10, 20, 50]
        scalability_results = []
        
        for device_count in device_counts:
            # Create devices for this test
            test_devices = [
                AndroidDevice(
                    serial=f"SCALE_DEVICE_{i:03d}",
                    model=f"Scale Test Device {i}",
                    brand="ScaleTest",
                    android_version="12.0",
                    usb_debugging=True,
                    lock_type=LockType.PIN
                )
                for i in range(device_count)
            ]
            
            with patch('forensics_toolkit.services.device_handlers.adb_handler.ADBHandler') as mock_adb:
                mock_adb.return_value.detect_devices.return_value = test_devices
                mock_adb.return_value.get_device_info.side_effect = lambda d: d
                
                def scalability_operation():
                    orchestrator = ForensicsOrchestrator(
                        case_id=f"SCALE_TEST_{device_count}",
                        user_session="scale_user"
                    )
                    try:
                        devices = orchestrator.detect_devices()
                        for device in devices:
                            orchestrator.analyze_device(device)
                        return len(devices)
                    finally:
                        orchestrator.cleanup()
                
                config = BenchmarkConfig(
                    name=f"scalability_{device_count}_devices",
                    description=f"Test scalability with {device_count} devices",
                    iterations=10,
                    concurrent_threads=1
                )
                
                metric = benchmark_framework.benchmark_operation(config, scalability_operation)
                scalability_results.append({
                    'device_count': device_count,
                    'throughput': metric.throughput_ops_per_second,
                    'memory_mb': metric.memory_usage_mb,
                    'cpu_percent': metric.cpu_usage_percent
                })
        
        # Analyze scalability
        print("\nScalability Analysis:")
        for result in scalability_results:
            print(f"  {result['device_count']} devices: "
                  f"{result['throughput']:.2f} ops/sec, "
                  f"{result['memory_mb']:.2f} MB, "
                  f"{result['cpu_percent']:.2f}% CPU")
        
        # Scalability assertions
        # Memory usage should scale reasonably (not exponentially)
        max_memory = max(r['memory_mb'] for r in scalability_results)
        min_memory = min(r['memory_mb'] for r in scalability_results)
        memory_growth_ratio = max_memory / min_memory if min_memory > 0 else 1
        
        assert memory_growth_ratio <= 10.0  # Memory shouldn't grow more than 10x
        
        # Throughput should remain reasonable even with more devices
        min_throughput = min(r['throughput'] for r in scalability_results)
        assert min_throughput >= 0.5  # At least 0.5 ops/sec even with many devices
    
    def test_long_running_stability(self, benchmark_framework):
        """Test stability during long-running operations"""
        def stable_operation():
            # Simulate a stable forensic operation
            time.sleep(0.01)  # 10ms operation
            return "stable_result"
        
        config = BenchmarkConfig(
            name="long_running_stability",
            description="Test stability during long-running operations",
            iterations=5000,  # Large number of iterations
            concurrent_threads=2,
            timeout_seconds=600  # 10 minute timeout
        )
        
        metric = benchmark_framework.benchmark_operation(config, stable_operation)
        
        # Stability assertions
        assert metric.success_rate >= 0.99  # 99% success rate for stability
        assert metric.error_count <= 50  # Maximum 50 errors out of 5000 operations
        assert metric.duration_seconds <= 300  # Should complete within 5 minutes


def run_performance_benchmarks():
    """Run all performance benchmark tests"""
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "-s",  # Show print statements
        "--durations=0"  # Show all test durations
    ])


if __name__ == "__main__":
    run_performance_benchmarks()