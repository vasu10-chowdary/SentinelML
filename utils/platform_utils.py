"""
SentinelML V2 — Platform Abstraction Layer
===========================================
Handles cross-platform compatibility for Windows, Linux, and macOS.
"""

import sys
import platform
import os
from pathlib import Path
from typing import List, Dict, Optional

class PlatformInfo:
    """Detect and provide platform-specific information."""
    
    def __init__(self):
        self.system = platform.system()  # 'Windows', 'Linux', 'Darwin' (macOS)
        self.release = platform.release()
        self.version = platform.version()
        self.machine = platform.machine()
        self.python_version = platform.python_version()
        
    def is_windows(self) -> bool:
        """Check if running on Windows."""
        return self.system == 'Windows'
    
    def is_linux(self) -> bool:
        """Check if running on Linux."""
        return self.system == 'Linux'
    
    def is_macos(self) -> bool:
        """Check if running on macOS."""
        return self.system == 'Darwin'
    
    def get_os_name(self) -> str:
        """Get human-readable OS name."""
        if self.is_windows():
            return f"Windows {self.release}"
        elif self.is_linux():
            # Try to get distribution info
            try:
                with open('/etc/os-release', 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith('PRETTY_NAME='):
                            return line.split('=')[1].strip().strip('"')
            except Exception:
                pass
            return f"Linux {self.release}"
        elif self.is_macos():
            return f"macOS {self.release}"
        else:
            return f"{self.system} {self.release}"
    
    def get_home_directory(self) -> Path:
        """Get user's home directory (cross-platform)."""
        return Path.home()
    
    def get_monitored_directories(self) -> List[Path]:
        """Get default directories to monitor (platform-specific)."""
        import os
        import logging
        log = logging.getLogger(__name__)

        home = self.get_home_directory()

        if self.is_windows():
            # Windows default paths
            paths = [
                home / "Documents",
                home / "Desktop",
                home / "Downloads",
            ]
            # Add OneDrive if it exists
            onedrive = home / "OneDrive"
            if onedrive.exists():
                paths.append(onedrive)

            # Return only paths that exist (preserve Windows behavior exactly)
            return [p for p in paths if p.exists()]

        elif self.is_linux() or self.is_macos():
            # Linux/macOS default paths
            paths = [
                home / "Documents",
                home / "Desktop",
                home / "Downloads",
                home / "Pictures",
                home / "Videos",
                home / "Music",
                home / "Public",
                home / "Templates"
            ]

            # Include only if exists, is a directory, and is readable
            valid_paths = [p for p in paths if p.exists() and p.is_dir() and os.access(p, os.R_OK)]

            # Fallback to home if XDG folders are missing
            if not valid_paths:
                if home.exists() and home.is_dir() and os.access(home, os.R_OK):
                    valid_paths = [home]

            log.debug("Linux/macOS monitored directories: %s", [str(p) for p in valid_paths])
            return valid_paths

        else:
            # Fallback: just home directory
            paths = [home]
            return [p for p in paths if p.exists()]
    
    def get_temp_directory(self) -> Path:
        """Get system temp directory (cross-platform)."""
        import tempfile
        return Path(tempfile.gettempdir())
    
    def get_process_count(self) -> int:
        """Get total process count (cross-platform via psutil)."""
        try:
            import psutil
            return len(psutil.pids())
        except Exception:
            return 0
    
    def supports_gui(self) -> bool:
        """Check if GUI is supported."""
        if self.is_windows():
            return True  # Windows always has GUI
        elif self.is_linux() or self.is_macos():
            # Check if DISPLAY is set (X11/Wayland)
            return 'DISPLAY' in os.environ or 'WAYLAND_DISPLAY' in os.environ
        return False
    
    def to_dict(self) -> Dict[str, str]:
        """Convert platform info to dictionary."""
        return {
            'system': self.system,
            'os_name': self.get_os_name(),
            'release': self.release,
            'version': self.version,
            'machine': self.machine,
            'python_version': self.python_version,
            'home_directory': str(self.get_home_directory()),
            'temp_directory': str(self.get_temp_directory()),
            'supports_gui': str(self.supports_gui()),
        }
    
    def __str__(self) -> str:
        """String representation."""
        return f"{self.get_os_name()} ({self.machine}), Python {self.python_version}"


class PlatformPaths:
    """Platform-specific path handling."""
    
    def __init__(self, platform_info: PlatformInfo):
        self.platform = platform_info
    
    def normalize_path(self, path: str) -> Path:
        """Normalize path for current platform."""
        # Convert Windows paths to Unix paths on Linux and vice versa
        path = path.replace('\\', os.sep).replace('/', os.sep)
        return Path(path)
    
    def get_application_data_dir(self) -> Path:
        """Get application data directory (platform-specific)."""
        if self.platform.is_windows():
            # Windows: C:\Users\<user>\AppData\Local\SentinelML
            appdata = os.getenv('LOCALAPPDATA')
            if appdata:
                return Path(appdata) / "SentinelML"
            else:
                return self.platform.get_home_directory() / "AppData" / "Local" / "SentinelML"
        
        elif self.platform.is_linux():
            # Linux: ~/.config/SentinelML
            config_home = os.getenv('XDG_CONFIG_HOME')
            if config_home:
                return Path(config_home) / "SentinelML"
            else:
                return self.platform.get_home_directory() / ".config" / "SentinelML"
        
        elif self.platform.is_macos():
            # macOS: ~/Library/Application Support/SentinelML
            return self.platform.get_home_directory() / "Library" / "Application Support" / "SentinelML"
        
        else:
            # Fallback
            return self.platform.get_home_directory() / ".SentinelML"


class PlatformFeatures:
    """Platform-specific feature availability."""
    
    def __init__(self, platform_info: PlatformInfo):
        self.platform = platform_info
    
    def has_filesystem_watcher(self) -> bool:
        """Check if filesystem watching is available."""
        # watchdog library works on all platforms
        try:
            import watchdog
            return True
        except ImportError:
            return False
    
    def has_system_tray(self) -> bool:
        """Check if system tray is available."""
        if self.platform.is_windows():
            return True  # Windows has system tray
        elif self.platform.is_linux():
            # Linux may or may not have system tray (depends on DE)
            return 'DISPLAY' in os.environ
        elif self.platform.is_macos():
            return True  # macOS has menu bar
        return False
    
    def has_process_monitoring(self) -> bool:
        """Check if process monitoring is available (via psutil)."""
        try:
            import psutil
            return True
        except ImportError:
            return False
    
    def supports_ml_inference(self) -> bool:
        """Check if ML inference is available."""
        try:
            import sklearn
            import numpy
            import joblib
            return True
        except ImportError:
            return False


# Global platform info instance
_platform_info: Optional[PlatformInfo] = None

def get_platform_info() -> PlatformInfo:
    """Get singleton platform info instance."""
    global _platform_info
    if _platform_info is None:
        _platform_info = PlatformInfo()
    return _platform_info


def get_platform_paths() -> PlatformPaths:
    """Get platform paths helper."""
    return PlatformPaths(get_platform_info())


def get_platform_features() -> PlatformFeatures:
    """Get platform features helper."""
    return PlatformFeatures(get_platform_info())


# Convenience functions
def is_windows() -> bool:
    """Check if running on Windows."""
    return get_platform_info().is_windows()


def is_linux() -> bool:
    """Check if running on Linux."""
    return get_platform_info().is_linux()


def is_macos() -> bool:
    """Check if running on macOS."""
    return get_platform_info().is_macos()


def get_monitored_directories() -> List[Path]:
    """Get directories to monitor (platform-specific)."""
    return get_platform_info().get_monitored_directories()


if __name__ == '__main__':
    # Test platform detection
    info = get_platform_info()
    print("=" * 60)
    print("SENTINELML V2 — PLATFORM DETECTION")
    print("=" * 60)
    print(f"OS: {info}")
    print(f"System: {info.system}")
    print(f"Release: {info.release}")
    print(f"Machine: {info.machine}")
    print(f"Python: {info.python_version}")
    print(f"Home: {info.get_home_directory()}")
    print(f"Temp: {info.get_temp_directory()}")
    print(f"GUI Support: {info.supports_gui()}")
    print()
    print("Monitored Directories:")
    for path in info.get_monitored_directories():
        print(f"  - {path}")
    print()
    print("Features:")
    features = get_platform_features()
    print(f"  Filesystem Watcher: {features.has_filesystem_watcher()}")
    print(f"  System Tray: {features.has_system_tray()}")
    print(f"  Process Monitoring: {features.has_process_monitoring()}")
    print(f"  ML Inference: {features.supports_ml_inference()}")
    print("=" * 60)
