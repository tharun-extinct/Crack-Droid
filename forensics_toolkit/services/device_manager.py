"""
Device Manager for multi-device handling and state tracking

This module implements the DeviceManager class for managing multiple Android devices
simultaneously, including device state tracking, concurrent processing capabilities,
and device health monitoring with error recovery.
"""

import logging
import threading
import time
from typing import List, Dict, Any, Optional, Callable, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, Future, as_completed

from ..interfaces import IDeviceHandler, AndroidDevice, ForensicsException
from ..models.device import AndroidDevice as DeviceModel
from ..config import config_manager


class DeviceState(Enum):
    """Device connection states"""
    UNKNOWN = "unknown"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    BUSY = "busy"
    ERROR = "error"
    LOCKED_OUT = "locked_out"
    ANALYZING = "analyzing"
    UNDER_ATTACK = "under_attack"


class DeviceHealthStatus(Enum):
    """Device health status"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    OFFLINE = "offline"


@dataclass
class DeviceStatus:
    """Comprehensive device status information"""
    device: AndroidDevice
    state: DeviceState = DeviceState.UNKNOWN
    health: DeviceHealthStatus = DeviceHealthStatus.OFFLINE
    last_seen: datetime = field(default_factory=datetime.now)
    last_health_check: datetime = field(default_factory=datetime.now)
    connection_attempts: int = 0
    error_count: int = 0
    last_error: Optional[str] = None
    handler_name: Optional[str] = None
    current_operation: Optional[str] = None
    lockout_until: Optional[datetime] = None
    
    @property
    def is_available(self) -> bool:
        """Check if device is available for operations"""
        if self.state in [DeviceState.DISCONNECTED, DeviceState.ERROR]:
            return False
        
        if self.lockout_until and datetime.now() < self.lockout_until:
            return False
        
        return self.state in [DeviceState.CONNECTED, DeviceState.UNKNOWN]
    
    @property
    def time_since_last_seen(self) -> timedelta:
        """Time since device was last seen"""
        return datetime.now() - self.last_seen
    
    def update_state(self, new_state: DeviceState, operation: str = None, error: str = None):
        """Update device state with optional operation and error info"""
        self.state = new_state
        self.last_seen = datetime.now()
        
        if operation:
            self.current_operation = operation
        
        if error:
            self.last_error = error
            self.error_count += 1
        elif new_state == DeviceState.CONNECTED:
            # Reset error count on successful connection
            self.error_count = max(0, self.error_count - 1)


class DeviceManagerException(ForensicsException):
    """Exception raised during device management operations"""
    
    def __init__(self, message: str, device_serial: str = None):
        super().__init__(message, "DEVICE_MANAGER_ERROR", evidence_impact=False)
        self.device_serial = device_serial


class DeviceManager:
    """
    Multi-device manager with state tracking and health monitoring
    
    This class provides comprehensive device management capabilities including:
    - Multi-device state tracking and management
    - Concurrent device processing capabilities
    - Device health monitoring and error recovery
    - Automatic device discovery and reconnection
    """
    
    def __init__(self, 
                 device_handlers: Dict[str, IDeviceHandler],
                 max_concurrent_devices: int = None,
                 health_check_interval: int = 30,
                 logger: Optional[logging.Logger] = None):
        """
        Initialize device manager
        
        Args:
            device_handlers: Dictionary of device handlers by name
            max_concurrent_devices: Maximum concurrent device operations
            health_check_interval: Health check interval in seconds
            logger: Optional logger instance
        """
        self.device_handlers = device_handlers
        self.max_concurrent_devices = max_concurrent_devices or config_manager.forensics_settings.max_concurrent_attacks
        self.health_check_interval = health_check_interval
        self.logger = logger or logging.getLogger(__name__)
        
        # Device tracking
        self.device_status: Dict[str, DeviceStatus] = {}
        self._lock = threading.RLock()
        
        # Thread pool for concurrent operations
        self._executor = ThreadPoolExecutor(max_workers=self.max_concurrent_devices)
        
        # Health monitoring
        self._health_monitor_thread: Optional[threading.Thread] = None
        self._health_monitor_stop = threading.Event()
        self._start_health_monitoring()
        
        # Callbacks
        self._device_state_changed_callback: Optional[Callable[[str, DeviceState], None]] = None
        self._device_health_changed_callback: Optional[Callable[[str, DeviceHealthStatus], None]] = None
        self._device_error_callback: Optional[Callable[[str, str], None]] = None
        
        self.logger.info(f"DeviceManager initialized with {len(device_handlers)} handlers")
    
    def set_device_state_changed_callback(self, callback: Callable[[str, DeviceState], None]):
        """Set callback for device state changes"""
        self._device_state_changed_callback = callback
    
    def set_device_health_changed_callback(self, callback: Callable[[str, DeviceHealthStatus], None]):
        """Set callback for device health changes"""
        self._device_health_changed_callback = callback
    
    def set_device_error_callback(self, callback: Callable[[str, str], None]):
        """Set callback for device errors"""
        self._device_error_callback = callback
    
    def discover_devices(self) -> List[AndroidDevice]:
        """
        Discover all available devices using all handlers
        
        Returns:
            List[AndroidDevice]: List of discovered devices
        """
        self.logger.info("Starting device discovery")
        
        discovered_devices = []
        discovery_futures = []
        
        # Submit discovery tasks for each handler
        for handler_name, handler in self.device_handlers.items():
            future = self._executor.submit(self._discover_with_handler, handler_name, handler)
            discovery_futures.append((handler_name, future))
        
        # Collect results
        for handler_name, future in discovery_futures:
            try:
                devices = future.result(timeout=30)  # 30 second timeout per handler
                
                for device in devices:
                    if device.serial not in [d.serial for d in discovered_devices]:
                        discovered_devices.append(device)
                        self._register_device(device, handler_name)
                
                self.logger.info(f"Handler {handler_name} discovered {len(devices)} devices")
                
            except Exception as e:
                self.logger.warning(f"Discovery failed for handler {handler_name}: {e}")
        
        self.logger.info(f"Device discovery completed: {len(discovered_devices)} devices found")
        return discovered_devices
    
    def _discover_with_handler(self, handler_name: str, handler: IDeviceHandler) -> List[AndroidDevice]:
        """Discover devices with a specific handler"""
        try:
            return handler.detect_devices()
        except Exception as e:
            self.logger.error(f"Device discovery failed for {handler_name}: {e}")
            return []
    
    def _register_device(self, device: AndroidDevice, handler_name: str):
        """Register a discovered device"""
        with self._lock:
            if device.serial not in self.device_status:
                status = DeviceStatus(
                    device=device,
                    state=DeviceState.CONNECTED,
                    health=DeviceHealthStatus.HEALTHY,
                    handler_name=handler_name
                )
                self.device_status[device.serial] = status
                
                self.logger.info(f"Registered device: {device.serial} with handler {handler_name}")
                
                # Trigger callback
                if self._device_state_changed_callback:
                    self._device_state_changed_callback(device.serial, DeviceState.CONNECTED)
    
    def get_device_status(self, device_serial: str) -> Optional[DeviceStatus]:
        """
        Get status for a specific device
        
        Args:
            device_serial: Device serial number
            
        Returns:
            DeviceStatus: Device status or None if not found
        """
        with self._lock:
            return self.device_status.get(device_serial)
    
    def get_all_device_status(self) -> Dict[str, DeviceStatus]:
        """Get status for all managed devices"""
        with self._lock:
            return self.device_status.copy()
    
    def get_available_devices(self) -> List[str]:
        """
        Get list of available device serials
        
        Returns:
            List[str]: List of available device serials
        """
        with self._lock:
            return [serial for serial, status in self.device_status.items() if status.is_available]
    
    def get_devices_by_state(self, state: DeviceState) -> List[str]:
        """
        Get devices in a specific state
        
        Args:
            state: Device state to filter by
            
        Returns:
            List[str]: List of device serials in the specified state
        """
        with self._lock:
            return [serial for serial, status in self.device_status.items() if status.state == state]
    
    def set_device_state(self, device_serial: str, state: DeviceState, operation: str = None, error: str = None):
        """
        Set device state
        
        Args:
            device_serial: Device serial number
            state: New device state
            operation: Current operation (optional)
            error: Error message (optional)
        """
        with self._lock:
            if device_serial in self.device_status:
                old_state = self.device_status[device_serial].state
                self.device_status[device_serial].update_state(state, operation, error)
                
                self.logger.debug(f"Device {device_serial} state changed: {old_state.value} -> {state.value}")
                
                # Trigger callback
                if self._device_state_changed_callback and old_state != state:
                    self._device_state_changed_callback(device_serial, state)
                
                # Trigger error callback if error occurred
                if error and self._device_error_callback:
                    self._device_error_callback(device_serial, error)
    
    def set_device_lockout(self, device_serial: str, lockout_duration: int):
        """
        Set device lockout
        
        Args:
            device_serial: Device serial number
            lockout_duration: Lockout duration in seconds
        """
        with self._lock:
            if device_serial in self.device_status:
                lockout_until = datetime.now() + timedelta(seconds=lockout_duration)
                self.device_status[device_serial].lockout_until = lockout_until
                self.set_device_state(device_serial, DeviceState.LOCKED_OUT)
                
                self.logger.info(f"Device {device_serial} locked out until {lockout_until}")
    
    def check_device_connection(self, device_serial: str) -> bool:
        """
        Check if device is still connected
        
        Args:
            device_serial: Device serial number
            
        Returns:
            bool: True if device is connected
        """
        status = self.get_device_status(device_serial)
        if not status:
            return False
        
        try:
            # Get appropriate handler
            handler = self.device_handlers.get(status.handler_name)
            if not handler:
                return False
            
            # Check device accessibility
            is_accessible = handler.is_device_accessible(status.device)
            
            if is_accessible:
                self.set_device_state(device_serial, DeviceState.CONNECTED)
                return True
            else:
                self.set_device_state(device_serial, DeviceState.DISCONNECTED, 
                                    error="Device not accessible")
                return False
                
        except Exception as e:
            self.set_device_state(device_serial, DeviceState.ERROR, 
                                error=f"Connection check failed: {e}")
            return False
    
    def reconnect_device(self, device_serial: str) -> bool:
        """
        Attempt to reconnect a device
        
        Args:
            device_serial: Device serial number
            
        Returns:
            bool: True if reconnection successful
        """
        status = self.get_device_status(device_serial)
        if not status:
            return False
        
        self.logger.info(f"Attempting to reconnect device: {device_serial}")
        
        try:
            # Get appropriate handler
            handler = self.device_handlers.get(status.handler_name)
            if not handler:
                self.logger.error(f"No handler available for device {device_serial}")
                return False
            
            # Increment connection attempts
            status.connection_attempts += 1
            
            # Attempt connection
            if handler.connect_device(status.device):
                self.set_device_state(device_serial, DeviceState.CONNECTED)
                self.logger.info(f"Successfully reconnected device: {device_serial}")
                return True
            else:
                self.set_device_state(device_serial, DeviceState.DISCONNECTED,
                                    error="Reconnection failed")
                return False
                
        except Exception as e:
            error_msg = f"Reconnection error: {e}"
            self.set_device_state(device_serial, DeviceState.ERROR, error=error_msg)
            self.logger.error(f"Failed to reconnect device {device_serial}: {e}")
            return False
    
    def perform_concurrent_operation(self, 
                                   device_serials: List[str], 
                                   operation_func: Callable[[str], Any],
                                   operation_name: str = "operation") -> Dict[str, Any]:
        """
        Perform operation on multiple devices concurrently
        
        Args:
            device_serials: List of device serials to operate on
            operation_func: Function to execute on each device
            operation_name: Name of the operation for logging
            
        Returns:
            Dict[str, Any]: Results keyed by device serial
        """
        self.logger.info(f"Starting concurrent {operation_name} on {len(device_serials)} devices")
        
        # Filter to available devices
        available_devices = [serial for serial in device_serials if self._is_device_available(serial)]
        
        if not available_devices:
            self.logger.warning("No available devices for concurrent operation")
            return {}
        
        # Set devices to busy state
        for device_serial in available_devices:
            self.set_device_state(device_serial, DeviceState.BUSY, operation=operation_name)
        
        # Submit operations
        futures = {}
        for device_serial in available_devices:
            future = self._executor.submit(self._safe_device_operation, 
                                         device_serial, operation_func, operation_name)
            futures[device_serial] = future
        
        # Collect results
        results = {}
        for device_serial, future in futures.items():
            try:
                result = future.result(timeout=300)  # 5 minute timeout per device
                results[device_serial] = result
                self.set_device_state(device_serial, DeviceState.CONNECTED)
                
            except Exception as e:
                error_msg = f"{operation_name} failed: {e}"
                results[device_serial] = {'error': error_msg}
                self.set_device_state(device_serial, DeviceState.ERROR, error=error_msg)
        
        self.logger.info(f"Concurrent {operation_name} completed: {len(results)} results")
        return results
    
    def _safe_device_operation(self, device_serial: str, operation_func: Callable[[str], Any], operation_name: str) -> Any:
        """Safely execute operation on device with error handling"""
        try:
            return operation_func(device_serial)
        except Exception as e:
            self.logger.error(f"{operation_name} failed for device {device_serial}: {e}")
            raise
    
    def _is_device_available(self, device_serial: str) -> bool:
        """Check if device is available for operations"""
        status = self.get_device_status(device_serial)
        return status is not None and status.is_available
    
    def _start_health_monitoring(self):
        """Start health monitoring thread"""
        if self._health_monitor_thread is None or not self._health_monitor_thread.is_alive():
            self._health_monitor_thread = threading.Thread(
                target=self._health_monitor_loop,
                name="DeviceHealthMonitor",
                daemon=True
            )
            self._health_monitor_thread.start()
            self.logger.info("Device health monitoring started")
    
    def _health_monitor_loop(self):
        """Health monitoring loop"""
        while not self._health_monitor_stop.is_set():
            try:
                self._perform_health_checks()
                time.sleep(self.health_check_interval)
            except Exception as e:
                self.logger.error(f"Health monitoring error: {e}")
                time.sleep(5)  # Short delay before retry
    
    def _perform_health_checks(self):
        """Perform health checks on all devices"""
        with self._lock:
            device_serials = list(self.device_status.keys())
        
        for device_serial in device_serials:
            try:
                self._check_device_health(device_serial)
            except Exception as e:
                self.logger.error(f"Health check failed for device {device_serial}: {e}")
    
    def _check_device_health(self, device_serial: str):
        """Check health of a specific device"""
        status = self.get_device_status(device_serial)
        if not status:
            return
        
        old_health = status.health
        new_health = self._assess_device_health(status)
        
        if new_health != old_health:
            status.health = new_health
            status.last_health_check = datetime.now()
            
            self.logger.info(f"Device {device_serial} health changed: {old_health.value} -> {new_health.value}")
            
            # Trigger callback
            if self._device_health_changed_callback:
                self._device_health_changed_callback(device_serial, new_health)
            
            # Take action based on health status
            self._handle_health_status_change(device_serial, new_health)
    
    def _assess_device_health(self, status: DeviceStatus) -> DeviceHealthStatus:
        """Assess device health based on status"""
        # Check if device is offline
        if status.time_since_last_seen > timedelta(minutes=5):
            return DeviceHealthStatus.OFFLINE
        
        # Check error count
        if status.error_count > 10:
            return DeviceHealthStatus.CRITICAL
        elif status.error_count > 5:
            return DeviceHealthStatus.WARNING
        
        # Check connection state
        if status.state == DeviceState.ERROR:
            return DeviceHealthStatus.CRITICAL
        elif status.state == DeviceState.DISCONNECTED:
            return DeviceHealthStatus.WARNING
        
        return DeviceHealthStatus.HEALTHY
    
    def _handle_health_status_change(self, device_serial: str, health_status: DeviceHealthStatus):
        """Handle device health status changes"""
        if health_status == DeviceHealthStatus.CRITICAL:
            # Attempt recovery for critical devices
            self.logger.warning(f"Device {device_serial} is critical, attempting recovery")
            self._attempt_device_recovery(device_serial)
        
        elif health_status == DeviceHealthStatus.OFFLINE:
            # Mark offline devices as disconnected
            self.set_device_state(device_serial, DeviceState.DISCONNECTED, 
                                error="Device appears offline")
    
    def _attempt_device_recovery(self, device_serial: str):
        """Attempt to recover a problematic device"""
        self.logger.info(f"Attempting recovery for device: {device_serial}")
        
        # Try reconnection
        if self.reconnect_device(device_serial):
            self.logger.info(f"Device {device_serial} recovered successfully")
        else:
            self.logger.warning(f"Failed to recover device {device_serial}")
    
    def get_health_summary(self) -> Dict[str, Any]:
        """
        Get health summary for all devices
        
        Returns:
            Dict[str, Any]: Health summary statistics
        """
        with self._lock:
            summary = {
                'total_devices': len(self.device_status),
                'healthy_devices': 0,
                'warning_devices': 0,
                'critical_devices': 0,
                'offline_devices': 0,
                'available_devices': 0,
                'busy_devices': 0,
                'error_devices': 0,
                'device_details': {}
            }
            
            for serial, status in self.device_status.items():
                # Health statistics
                if status.health == DeviceHealthStatus.HEALTHY:
                    summary['healthy_devices'] += 1
                elif status.health == DeviceHealthStatus.WARNING:
                    summary['warning_devices'] += 1
                elif status.health == DeviceHealthStatus.CRITICAL:
                    summary['critical_devices'] += 1
                elif status.health == DeviceHealthStatus.OFFLINE:
                    summary['offline_devices'] += 1
                
                # State statistics
                if status.is_available:
                    summary['available_devices'] += 1
                elif status.state == DeviceState.BUSY:
                    summary['busy_devices'] += 1
                elif status.state == DeviceState.ERROR:
                    summary['error_devices'] += 1
                
                # Device details
                summary['device_details'][serial] = {
                    'brand': status.device.brand,
                    'model': status.device.model,
                    'state': status.state.value,
                    'health': status.health.value,
                    'last_seen': status.last_seen.isoformat(),
                    'error_count': status.error_count,
                    'current_operation': status.current_operation
                }
            
            return summary
    
    def shutdown(self):
        """Shutdown device manager"""
        self.logger.info("Shutting down DeviceManager")
        
        # Stop health monitoring
        self._health_monitor_stop.set()
        if self._health_monitor_thread and self._health_monitor_thread.is_alive():
            self._health_monitor_thread.join(timeout=5)
        
        # Shutdown executor
        if self._executor:
            self._executor.shutdown(wait=True)
        
        self.logger.info("DeviceManager shutdown completed")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.shutdown()