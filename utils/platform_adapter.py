"""
SentinelML V2 — Platform Adapter Layer
======================================
Provides clean, decoupled platform abstraction for Windows, Linux, and macOS.
Encapsulates OS-specific APIs (Win32, X11/XDG, Launchd, psutil variances)
behind a unified, strictly typed adapter interface.

Contract Guarantees:
- Safe, non-throwing operations across all platforms.
- Graceful degradation when APIs or permissions are unavailable.
- Preserves the 19-feature ML schema and exact classification contracts.
- Strictly separates user-space behavioral monitoring from kernel-level defense.
"""

from __future__ import annotations

import abc
import logging
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger("sentinel.platform")


class ProcessInfoProxy:
    """Lightweight process proxy object for cross-platform process representation."""
    __slots__ = ("pid", "ppid", "name", "exe", "num_threads", "num_handles", "info", "_ps")

    def __init__(self, data: Dict[str, Any]):
        self.pid = int(data.get("pid") or 0)
        self.ppid = int(data.get("ppid") or 0)
        self.name = str(data.get("name") or "")
        self.exe = str(data.get("exe") or "")
        self.num_threads = int(data.get("num_threads") or 0)
        self.num_handles = int(data.get("num_handles") or 0)
        self.info = data
        self._ps = None

    def memory_maps(self) -> list:
        if self._ps is None:
            try:
                import psutil
                self._ps = psutil.Process(self.pid)
            except Exception:
                return []
        try:
            return self._ps.memory_maps()
        except Exception:
            return []


class PlatformAdapter(abc.ABC):
    """Abstract Base Class for OS-specific system integration."""

    @abc.abstractmethod
    def get_platform_name(self) -> str:
        """Return canonical platform name: 'windows', 'linux', or 'macos'."""
        pass

    @abc.abstractmethod
    def acquire_single_instance_lock(self) -> Optional[Any]:
        """
        Acquire application-wide single instance lock.
        Returns lock handle/token if acquired, or None if another instance is running.
        """
        pass

    @abc.abstractmethod
    def release_single_instance_lock(self, lock_token: Any) -> None:
        """Release the acquired single instance lock."""
        pass

    @abc.abstractmethod
    def show_native_fatal_error(self, title: str, message: str, crash_file: Path) -> None:
        """Display a native OS message box / alert without depending on a running Tk event loop."""
        pass

    @abc.abstractmethod
    def bring_existing_instance_to_front(self, window_title: str) -> bool:
        """Attempt to activate and restore a running application window."""
        pass

    @abc.abstractmethod
    def get_process_snapshot(self) -> List[ProcessInfoProxy]:
        """
        Collect active process list safely and quickly.
        Filters kernel workers / idle pseudo-processes on all platforms.
        """
        pass

    @abc.abstractmethod
    def is_suspicious_process_name(self, name: str) -> bool:
        """Determine if process name represents a known administrative or destruction tool."""
        pass

    @abc.abstractmethod
    def is_crypto_module(self, module_name_or_path: str) -> bool:
        """Check if library path corresponds to a platform cryptographic library."""
        pass

    @abc.abstractmethod
    def check_security_service_tampering(self) -> float:
        """
        Check for tampering with platform security services.
        Returns count of tampered/disabled services.
        """
        pass

    @abc.abstractmethod
    def set_autostart(self, enable: bool, exe_or_script_path: str) -> bool:
        """Configure or remove application autostart on system logon."""
        pass

    @abc.abstractmethod
    def set_window_icon(self, window: Any, icon_path: Path) -> None:
        """Set window icon appropriately for the platform."""
        pass

    @abc.abstractmethod
    def get_font_preference(self) -> List[str]:
        """Return platform-appropriate font family preferences in priority order."""
        pass

    def is_user_path(self, file_path: Path) -> bool:
        """Check if file resides within user home directory or user document roots."""
        try:
            home = Path.home().resolve()
            resolved = file_path.resolve()
            return home in resolved.parents or home == resolved
        except Exception:
            path_str = str(file_path).lower()
            return any(k in path_str for k in ("users", "home", "documents", "desktop", "downloads"))


class WindowsPlatformAdapter(PlatformAdapter):
    """Windows-specific platform adapter using Win32 APIs and ctypes."""

    SUSPICIOUS_PROCS: Set[str] = {
        "vssadmin.exe", "wmic.exe", "bcdedit.exe", "wbadmin.exe", "cipher.exe",
        "sdelete.exe", "icacls.exe", "attrib.exe", "net.exe", "net1.exe",
        "taskkill.exe", "wevtutil.exe", "reg.exe", "regsvr32.exe", "mshta.exe",
        "wscript.exe", "cscript.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe",
        "powershell_ise.exe", "msiexec.exe", "expand.exe",
    }

    CRYPTO_MODULES: Set[str] = {
        "bcrypt.dll", "cryptsp.dll", "crypt32.dll", "advapi32.dll",
        "ncrypt.dll", "rsaenh.dll", "dpapi.dll",
    }

    DEFENDER_SERVICES: Set[str] = {"WinDefend", "SecurityHealthService", "wscsvc"}

    def get_platform_name(self) -> str:
        return "windows"

    def acquire_single_instance_lock(self) -> Optional[Any]:
        try:
            import ctypes
            from ctypes import wintypes
            mutex_name = "Local\\SentinelML_V2_SingleInstanceMutex"
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.CreateMutexW(None, wintypes.BOOL(True), mutex_name)
            last_error = kernel32.GetLastError()
            ERROR_ALREADY_EXISTS = 183
            if last_error == ERROR_ALREADY_EXISTS:
                if handle:
                    kernel32.CloseHandle(handle)
                return None
            return handle
        except Exception as e:
            log.warning("Windows mutex creation failed: %s; allowing launch", e)
            return True

    def release_single_instance_lock(self, lock_token: Any) -> None:
        try:
            if lock_token and lock_token is not True:
                import ctypes
                ctypes.windll.kernel32.CloseHandle(lock_token)
        except Exception as e:
            log.debug("Error closing mutex handle: %s", e)

    def show_native_fatal_error(self, title: str, message: str, crash_file: Path) -> None:
        try:
            import ctypes
            body = (
                f"SentinelML V2 encountered an unexpected error and cannot continue:\n\n"
                f"{message}\n\n"
                f"Detailed crash logs have been written to:\n{crash_file}"
            )
            ctypes.windll.user32.MessageBoxW(0, body, title, 0x10)
        except Exception:
            sys.stderr.write(f"FATAL: {title}\n{message}\nLog: {crash_file}\n")

    def bring_existing_instance_to_front(self, window_title: str) -> bool:
        try:
            import ctypes
            hwnd = ctypes.windll.user32.FindWindowW(None, window_title)
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                ctypes.windll.user32.SetForegroundWindow(hwnd)
                return True
        except Exception as e:
            log.debug("Failed to bring existing window to front: %s", e)
        return False

    def get_process_snapshot(self) -> List[ProcessInfoProxy]:
        # High-speed native Win32 Toolhelp32 snapshot
        try:
            import ctypes
            import ctypes.wintypes
            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ('dwSize', ctypes.wintypes.DWORD),
                    ('cntUsage', ctypes.wintypes.DWORD),
                    ('th32ProcessID', ctypes.wintypes.DWORD),
                    ('th32DefaultHeapID', ctypes.c_size_t),
                    ('th32ModuleID', ctypes.wintypes.DWORD),
                    ('cntThreads', ctypes.wintypes.DWORD),
                    ('th32ParentProcessID', ctypes.wintypes.DWORD),
                    ('pcPriClassBase', ctypes.c_long),
                    ('dwFlags', ctypes.wintypes.DWORD),
                    ('szExeFile', ctypes.c_char * 260)
                ]
            snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
            success = ctypes.windll.kernel32.Process32First(snap, ctypes.byref(entry))
            procs_dict = {}
            while success:
                procs_dict[entry.th32ProcessID] = {
                    'pid': entry.th32ProcessID,
                    'ppid': entry.th32ParentProcessID,
                    'num_threads': entry.cntThreads,
                    'name': entry.szExeFile.decode('ansi', errors='ignore'),
                    'exe': '',
                    'num_handles': 0
                }
                success = ctypes.windll.kernel32.Process32Next(snap, ctypes.byref(entry))
            ctypes.windll.kernel32.CloseHandle(snap)

            kernel32 = ctypes.windll.kernel32
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            buf = ctypes.create_unicode_buffer(1024)
            size = ctypes.wintypes.DWORD(1024)
            handle_cnt = ctypes.wintypes.DWORD(0)

            try:
                import psutil._pswindows as psw
                proc_exe_fn = psw.cext.proc_exe
            except Exception:
                proc_exe_fn = None

            for pid, info in procs_dict.items():
                if pid > 4 and proc_exe_fn:
                    try:
                        info['exe'] = proc_exe_fn(pid)
                    except Exception:
                        pass
                h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if h:
                    if not info.get('exe'):
                        size.value = 1024
                        if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                            info['exe'] = buf.value
                    if kernel32.GetProcessHandleCount(h, ctypes.byref(handle_cnt)):
                        info['num_handles'] = handle_cnt.value
                    kernel32.CloseHandle(h)

            return [ProcessInfoProxy(d) for d in procs_dict.values()]
        except Exception as e:
            log.debug("Native Win32 process snapshot failed, falling back to psutil: %s", e)

        import psutil
        results = []
        for p in psutil.process_iter(["pid", "name", "exe", "ppid", "num_threads", "num_handles"]):
            try:
                results.append(ProcessInfoProxy(p.info))
            except Exception:
                pass
        return results

    def is_suspicious_process_name(self, name: str) -> bool:
        return name.lower() in self.SUSPICIOUS_PROCS

    def is_crypto_module(self, module_name_or_path: str) -> bool:
        norm = module_name_or_path.replace('\\', '/')
        fname = Path(norm).name.lower()
        return fname in self.CRYPTO_MODULES

    def check_security_service_tampering(self) -> float:
        import psutil
        count = 0.0
        for service_name in self.DEFENDER_SERVICES:
            try:
                svc = psutil.win_service_get(service_name)
                status = svc.status()
                if status not in ("running", "start_pending"):
                    log.warning("Security service '%s' NOT running: %s", service_name, status)
                    count += 1.0
            except psutil.NoSuchProcess:
                log.warning("Security service '%s' not found", service_name)
                count += 1.0
            except Exception:
                pass
        return count

    def set_autostart(self, enable: bool, exe_or_script_path: str) -> bool:
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as k:
                if enable:
                    winreg.SetValueEx(k, "SentinelML", 0, winreg.REG_SZ, f'"{exe_or_script_path}"')
                else:
                    try:
                        winreg.DeleteValue(k, "SentinelML")
                    except FileNotFoundError:
                        pass
            return True
        except Exception as e:
            log.warning("Windows autostart configure failed: %s", e)
            return False

    def set_window_icon(self, window: Any, icon_path: Path) -> None:
        try:
            if icon_path.exists():
                window.iconbitmap(str(icon_path))
        except Exception as e:
            log.debug("Failed setting Windows window icon: %s", e)

    def get_font_preference(self) -> List[str]:
        return ["Segoe UI", "Inter", "Arial"]


class LinuxPlatformAdapter(PlatformAdapter):
    """Linux-specific platform adapter using POSIX semantics and XDG standards."""

    SUSPICIOUS_PROCS: Set[str] = {
        "vssadmin.exe", "shred", "srm", "wipe", "dd", "cryptsetup",
        "pwsh", "powershell",
    }

    CRYPTO_MODULES: Set[str] = {
        "libcrypto.so", "libssl.so", "libgnutls.so", "libgcrypt.so",
        "libnettle.so", "libmbedcrypto.so",
    }

    def __init__(self):
        self._lock_fd: Optional[int] = None
        self._lock_file: Optional[Path] = None

    def get_platform_name(self) -> str:
        return "linux"

    def acquire_single_instance_lock(self) -> Optional[Any]:
        try:
            import fcntl
            from utils.paths import get_user_data_root
            lock_dir = get_user_data_root()
            lock_dir.mkdir(parents=True, exist_ok=True)
            self._lock_file = lock_dir / ".sentinelml_instance.lock"
            self._lock_fd = os.open(str(self._lock_file), os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self._lock_fd
            except (BlockingIOError, OSError):
                os.close(self._lock_fd)
                self._lock_fd = None
                return None
        except Exception as e:
            log.warning("Linux single instance lock failed: %s; allowing launch", e)
            return True

    def release_single_instance_lock(self, lock_token: Any) -> None:
        try:
            if self._lock_fd is not None:
                import fcntl
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                os.close(self._lock_fd)
                self._lock_fd = None
        except Exception as e:
            log.debug("Error releasing Linux lock file: %s", e)

    def show_native_fatal_error(self, title: str, message: str, crash_file: Path) -> None:
        body = f"{message}\n\nCrash log: {crash_file}"
        sys.stderr.write(f"FATAL: {title}\n{body}\n")
        # Try native dialogs if GUI available
        if "DISPLAY" in os.environ or "WAYLAND_DISPLAY" in os.environ:
            for cmd in (["zenity", "--error", f"--title={title}", f"--text={body}"],
                        ["kdialog", "--title", title, "--error", body]):
                try:
                    subprocess.run(cmd, timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return
                except Exception:
                    pass

    def bring_existing_instance_to_front(self, window_title: str) -> bool:
        if "DISPLAY" in os.environ:
            for cmd in (["wmctrl", "-a", window_title], ["xdotool", "search", "--name", window_title, "windowactivate"]):
                try:
                    res = subprocess.run(cmd, timeout=2, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if res.returncode == 0:
                        return True
                except Exception:
                    pass
        return False

    def get_process_snapshot(self) -> List[ProcessInfoProxy]:
        import psutil
        results = []
        for p in psutil.process_iter(["pid", "name", "exe", "ppid", "num_threads"]):
            try:
                info = p.info
                pid = info.get("pid", 0)
                ppid = info.get("ppid", 0)
                name = info.get("name") or ""
                # Filter Linux kernel threads (PID <= 2, PPID == 2, or bracketed name like [kworker/...])
                if pid <= 2 or ppid == 2 or (name.startswith("[") and name.endswith("]")):
                    continue
                results.append(ProcessInfoProxy(info))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception:
                pass
        return results

    def is_suspicious_process_name(self, name: str) -> bool:
        n = name.lower()
        return n in self.SUSPICIOUS_PROCS or any(n.endswith(f"/{tool}") for tool in self.SUSPICIOUS_PROCS)

    def is_crypto_module(self, module_name_or_path: str) -> bool:
        lower = module_name_or_path.lower()
        return any(c in lower for c in self.CRYPTO_MODULES)

    def check_security_service_tampering(self) -> float:
        # Linux security (AppArmor/SELinux) is kernel-enforced; return baseline 0.0
        return 0.0

    def set_autostart(self, enable: bool, exe_or_script_path: str) -> bool:
        try:
            autostart_dir = Path.home() / ".config" / "autostart"
            desktop_file = autostart_dir / "sentinelml.desktop"
            if enable:
                autostart_dir.mkdir(parents=True, exist_ok=True)
                content = (
                    "[Desktop Entry]\n"
                    "Type=Application\n"
                    "Name=SentinelML\n"
                    f"Exec={exe_or_script_path}\n"
                    "Terminal=false\n"
                    "StartupNotify=false\n"
                )
                desktop_file.write_text(content, encoding="utf-8")
            else:
                if desktop_file.exists():
                    desktop_file.unlink()
            return True
        except Exception as e:
            log.warning("Linux autostart configure failed: %s", e)
            return False

    def set_window_icon(self, window: Any, icon_path: Path) -> None:
        try:
            # On Linux Tkinter, PhotoImage with a PNG file is preferred over .ico
            png_path = icon_path.with_suffix(".png")
            target = png_path if png_path.exists() else icon_path
            if target.exists():
                import tkinter as tk
                img = tk.PhotoImage(file=str(target))
                window.iconphoto(True, img)
        except Exception as e:
            log.debug("Failed setting Linux window icon: %s", e)

    def get_font_preference(self) -> List[str]:
        return ["Ubuntu", "DejaVu Sans", "Liberation Sans", "Noto Sans", "Arial"]


class MacOSPlatformAdapter(PlatformAdapter):
    """macOS-specific platform adapter using Darwin conventions and LaunchAgents."""

    SUSPICIOUS_PROCS: Set[str] = {
        "vssadmin.exe", "tmutil", "diskutil", "csrutil", "srm",
        "pwsh", "powershell",
    }

    CRYPTO_MODULES: Set[str] = {
        "libcrypto.dylib", "libssl.dylib", "commoncrypto", "corecrypto",
    }

    def __init__(self):
        self._lock_fd: Optional[int] = None
        self._lock_file: Optional[Path] = None

    def get_platform_name(self) -> str:
        return "macos"

    def acquire_single_instance_lock(self) -> Optional[Any]:
        try:
            import fcntl
            from utils.paths import get_user_data_root
            lock_dir = get_user_data_root()
            lock_dir.mkdir(parents=True, exist_ok=True)
            self._lock_file = lock_dir / ".sentinelml_instance.lock"
            self._lock_fd = os.open(str(self._lock_file), os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self._lock_fd
            except (BlockingIOError, OSError):
                os.close(self._lock_fd)
                self._lock_fd = None
                return None
        except Exception as e:
            log.warning("macOS single instance lock failed: %s; allowing launch", e)
            return True

    def release_single_instance_lock(self, lock_token: Any) -> None:
        try:
            if self._lock_fd is not None:
                import fcntl
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                os.close(self._lock_fd)
                self._lock_fd = None
        except Exception as e:
            log.debug("Error releasing macOS lock file: %s", e)

    def show_native_fatal_error(self, title: str, message: str, crash_file: Path) -> None:
        body = f"{message}\\n\\nCrash log: {crash_file}"
        sys.stderr.write(f"FATAL: {title}\n{message}\nLog: {crash_file}\n")
        try:
            applescript = f'display alert "{title}" message "{body}" as critical'
            subprocess.run(["osascript", "-e", applescript], timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    def bring_existing_instance_to_front(self, window_title: str) -> bool:
        try:
            applescript = 'tell application "SentinelML" to activate'
            res = subprocess.run(["osascript", "-e", applescript], timeout=2, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return res.returncode == 0
        except Exception:
            return False

    def get_process_snapshot(self) -> List[ProcessInfoProxy]:
        import psutil
        results = []
        for p in psutil.process_iter(["pid", "name", "exe", "ppid", "num_threads"]):
            try:
                info = p.info
                # On macOS, PID 0 is kernel_task
                if info.get("pid", 0) == 0:
                    continue
                results.append(ProcessInfoProxy(info))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception:
                pass
        return results

    def is_suspicious_process_name(self, name: str) -> bool:
        return name.lower() in self.SUSPICIOUS_PROCS

    def is_crypto_module(self, module_name_or_path: str) -> bool:
        lower = module_name_or_path.lower()
        return any(c in lower for c in self.CRYPTO_MODULES)

    def check_security_service_tampering(self) -> float:
        # macOS XProtect and Gatekeeper are SIP / kernel enforced; return baseline 0.0
        return 0.0

    def set_autostart(self, enable: bool, exe_or_script_path: str) -> bool:
        try:
            launch_agents = Path.home() / "Library" / "LaunchAgents"
            plist_file = launch_agents / "com.sentinelml.v2.plist"
            if enable:
                launch_agents.mkdir(parents=True, exist_ok=True)
                plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sentinelml.v2</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe_or_script_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
                plist_file.write_text(plist_content, encoding="utf-8")
            else:
                if plist_file.exists():
                    plist_file.unlink()
            return True
        except Exception as e:
            log.warning("macOS autostart configure failed: %s", e)
            return False

    def set_window_icon(self, window: Any, icon_path: Path) -> None:
        # On macOS, window icon is typically handled by the application bundle (.app)
        try:
            png_path = icon_path.with_suffix(".png")
            target = png_path if png_path.exists() else icon_path
            if target.exists():
                import tkinter as tk
                img = tk.PhotoImage(file=str(target))
                window.iconphoto(True, img)
        except Exception as e:
            log.debug("Failed setting macOS window icon: %s", e)

    def get_font_preference(self) -> List[str]:
        return [".AppleSystemUIFont", "SF Pro Display", "Helvetica Neue", "Arial"]


# ── Global Adapter Factory ───────────────────────────────────────────────────
_adapter_instance: Optional[PlatformAdapter] = None

def get_platform_adapter() -> PlatformAdapter:
    """Return the singleton platform adapter for the running operating system."""
    global _adapter_instance
    if _adapter_instance is None:
        sys_name = platform.system()
        if sys_name == "Windows":
            _adapter_instance = WindowsPlatformAdapter()
        elif sys_name == "Darwin":
            _adapter_instance = MacOSPlatformAdapter()
        elif sys_name == "Linux":
            _adapter_instance = LinuxPlatformAdapter()
        else:
            # Fallback to Linux adapter for POSIX-like platforms (BSD, etc.)
            _adapter_instance = LinuxPlatformAdapter()
        log.info("Initialized platform adapter: %s (%s)", _adapter_instance.get_platform_name(), sys_name)
    return _adapter_instance
