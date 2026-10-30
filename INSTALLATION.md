# SentinelML — Installation & Launch Guide (v3.1.0)

This document details installation, system prerequisites, environment setup, and launch
commands for SentinelML v3.1.0 across supported platforms. Verified configurations and raw
evidence are recorded in [docs/releases/v3.1.0/](docs/releases/v3.1.0/README.md).

---

## 1. Windows Installation (10 & 11, 64-bit)

### Option A: Existing v3.0.0 Package (not equivalent to v3.1.0)
The existing [v3.0.0 release](https://github.com/vasu10-chowdary/SentinelML/releases/tag/v3.0.0)
ships a Windows executable. It **predates the v3.1.0 process-only fix and INCONCLUSIVE UI
changes**, so it is not a v3.1.0 build. No new binaries are attached to v3.1.0.
1. Download the v3.0.0 asset from that release if you need a prebuilt Windows binary.
2. Alternatively, build from a reviewed v3.1.0 commit (Option B) or compile with
   `python -m PyInstaller SentinelML_Production.spec --clean --noconfirm`.

### Option B: Running from Source
1. **Prerequisites**:
   - Python 3.10 – 3.14 (64-bit)
   - Git
2. **Setup**:
   ```powershell
   # Clone repository and navigate to root
   cd C:\Users\<Username>\Desktop\SentinalMl

   # Create and activate virtual environment
   python -m venv .venv
   .venv\Scripts\activate

   # Install dependencies
   pip install --upgrade pip
   pip install -r requirements.txt
   ```
3. **Launch**:
   ```powershell
   python app.py
   ```

---

## 2. Linux Installation (Ubuntu, Debian, Kali, Mint)

### Option A: AppImage (build it yourself)
The AppImage build bundles the application runtime, dependencies, and CustomTkinter theme
assets. **No v3.1.0 AppImage is published**; the script in `packaging/linux/build_appimage.sh`
produces one on the target distribution.

1. **Prerequisites**:
   - Modern Linux distribution with glibc 2.31+
   - X11 or Wayland display server with `Xwayland`
   - `fuse` or `libfuse2`:
     ```bash
     sudo apt update && sudo apt install -y libfuse2
     ```
2. **Launch**:
   ```bash
   chmod +x SentinelML-x86_64.AppImage
   ./SentinelML-x86_64.AppImage
   ```

### Option B: Running from Source
1. **Prerequisites**:
   - Python 3.10 – 3.14
   - Tkinter runtime for Python:
     ```bash
     sudo apt update
     sudo apt install -y python3-tk python3-venv python3-dev
     ```
2. **Setup**:
   ```bash
   cd ~/SentinelMl
   python3 -m venv sentinel_venv
   source sentinel_venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements-linux.txt
   ```
   Verified configuration (Kali 2026.1): Python 3.13.12, customtkinter 6.0.0,
   scikit-learn 1.8.0, numpy 2.3.5, joblib 1.5.2, psutil 7.1.0, Tk 8.6.
3. **Launch**:
   ```bash
   python3 app.py
   ```

### Linux Privilege & Telemetry Notes
- Standard user execution monitors all user processes, monitored home directory files, and system sockets.
- Running with `sudo` gives access to inspect other users' processes, but system-wide Windows-specific handle enumeration remains unavailable on Linux. Clean scans will report `INCONCLUSIVE — LIMITED COVERAGE` to prevent false confidence.
- **Process-only scans need no filesystem path.** Use **Live Host Scan → Start Live Scan**
  (or `ScanType.PROCESS`) to enumerate processes and evaluate them in about 1–2 s. Filesystem
  `QUICK`/`FULL` scans still require the Windows-only sensors and usually end `INCONCLUSIVE`.
- Headless hosts need a display server, for example:
  ```bash
  Xvfb :99 -screen 0 1600x1000x24 &
  DISPLAY=:99 python3 app.py
  ```

---

## 3. macOS Installation (macOS 12 Monterey or Newer)

> [!WARNING]
> SentinelML for macOS is currently **CODE-READY, UNVERIFIED**. Build and adapter logic are implemented, but binary execution on physical Mac hardware has not been formally verified.

### Running from Source
1. **Prerequisites**:
   - Python 3.10 – 3.14 with `python-tk`:
     ```bash
     brew install python-tk
     ```
2. **Setup**:
   ```bash
   cd SentinelML
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. **Launch**:
   ```bash
   python3 app.py
   ```

---

## 4. Troubleshooting & Common Issues

| Issue | Cause | Resolution |
|---|---|---|
| `_tkinter.TclError: no display name` | Running headless without an X11 server | Ensure `DISPLAY` variable is set (e.g. `export DISPLAY=:0` or run under WSLg/desktop session). |
| `Permission denied` on AppImage | Executable flag missing | Run `chmod +x SentinelML-x86_64.AppImage`. |
| `Cannot load libfuse.so.2` | Missing FUSE 2 library on Ubuntu 22.04+ | Install via `sudo apt install libfuse2` or run with `--appimage-extract-and-run`. |
| `Scan result shows INCONCLUSIVE` | Expected behavior on Linux/macOS | The host is clean under active checks, but 4–5 Windows-specific sensors are unavailable on POSIX. |
| `Process-only scan runs without paths` | Expected behavior in v3.1.0+ | No filesystem path is required for `ScanType.PROCESS`. |
| Single instance lock error | Previous session still running | Terminate any lingering background instance or remove `.sentinelml_instance.lock`. |
