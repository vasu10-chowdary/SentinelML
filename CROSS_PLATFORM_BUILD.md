# SentinelML — Cross-Platform Native Build & Packaging Guide (v3.1.0)

This guide describes how to produce standalone native release artifacts for **Windows**,
**Linux**, and **macOS** from the SentinelML v3.1.0 codebase.

---

## 1. Release artifact matrix

| Target OS | Primary artifact | Status in v3.1.0 |
|---|---|---|
| **Windows 10/11** | `SentinelML.exe` / Inno Setup installer | Build configuration present; **no v3.1.0 binary published** (the existing v3.0.0 executable predates the process-only fix) |
| **Linux (x86_64)** | `SentinelML-x86_64.AppImage` | Build script `packaging/linux/build_appimage.sh` provided; **no v3.1.0 AppImage published**. Source installation is the verified path |
| **macOS (Darwin)** | `SentinelML.app` / `.dmg` | **Code-ready, unverified** — no physical Mac testing |

---

## 2. Windows Build Instructions

### Prerequisites
- Python 3.11, 3.12, 3.13, or 3.14 (64-bit)
- Inno Setup 6 (optional, for installer `.exe`)
- Dependencies: `pip install -r requirements.txt`

### Build Single Executable (.exe)
```powershell
# 1. Activate your virtual environment
.\venv\Scripts\Activate.ps1

# 2. Verify all models and assets exist
python -c "import joblib; joblib.load('models/saved_model.pkl'); print('Model OK')"

# 3. Build with PyInstaller using the production spec
pyinstaller SentinelML_Production.spec

# Output artifact: dist\SentinelML.exe
```

### Build Inno Setup Installer
If Inno Setup 6 is installed at `C:\Program Files (x86)\Inno Setup 6\ISCC.exe`:
```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" SentinelML_Setup.iss
# Output artifact: Installer\Output\SentinelML_Setup_v2.exe
```

---

## 3. Linux Build Instructions

### Prerequisites (Debian/Ubuntu/Kali)
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-tk libxcb-cursor0 libgl1 libfuse2 binutils
```

### Option A: Build Standalone AppImage
`packaging/linux/build_appimage.sh` compiles the application with PyInstaller, bundles
CustomTkinter assets and the model files, and packages an AppImage:

```bash
chmod +x packaging/linux/build_appimage.sh
./packaging/linux/build_appimage.sh

# Output artifact: SentinelML-x86_64.AppImage
```

The script was used to produce Linux artifacts during earlier development, but no v3.1.0
AppImage was verified in the final audit. Verify the build on your target distribution
before distributing it.

#### Running the AppImage
```bash
chmod +x SentinelML-x86_64.AppImage

# Directly execute:
./SentinelML-x86_64.AppImage

# Or on systems without FUSE:
./SentinelML-x86_64.AppImage --appimage-extract-and-run
```

### Option B: Build Debian Package (.deb)
To create a standard `.deb` package for Debian/Ubuntu distributions:

```bash
# 1. Prepare directory structure
mkdir -p package_deb/DEBIAN
mkdir -p package_deb/opt/sentinelml
mkdir -p package_deb/usr/share/applications
mkdir -p package_deb/usr/share/icons/hicolor/256x256/apps

# 2. Copy compiled binary and models from PyInstaller dist/
cp -r dist/SentinelML/* package_deb/opt/sentinelml/

# 3. Create desktop launcher (package_deb/usr/share/applications/sentinelml.desktop)
cat << 'EOF' > package_deb/usr/share/applications/sentinelml.desktop
[Desktop Entry]
Name=SentinelML
Comment=Behavioral Ransomware Detection & Threat Analysis
Exec=/opt/sentinelml/SentinelML
Icon=sentinelml
Terminal=false
Type=Application
Categories=Security;System;
EOF

# 4. Create control file (package_deb/DEBIAN/control)
cat << 'EOF' > package_deb/DEBIAN/control
Package: sentinelml
Version: 3.1.0
Section: utils
Priority: optional
Architecture: amd64
Maintainer: SentinelML Security Team
Depends: python3-tk, libfuse2 | libfuse3-3
Description: SentinelML AI-Powered Ransomware Defense
 Behavioral endpoint telemetry analysis and Random Forest threat detection.
EOF

# 5. Build package
dpkg-deb --build package_deb sentinelml_3.1.0_amd64.deb
```

---

## 4. macOS Build Instructions

> **Platform Caveat:** SentinelML incorporates a macOS platform adapter (`MacOSPlatformAdapter` in `utils/platform_adapter.py`) supporting LaunchAgents autostart, POSIX single-instance file locking, AppleScript native dialogs, and dylib crypto enumeration. However, physical testing has not been performed on Apple Silicon or macOS hardware.

### Prerequisites (macOS 12+)
```bash
brew install python@3.12 tcl-tk
pip install -r requirements.txt
```

### Build Application Bundle (.app)
```bash
pyinstaller --onedir --windowed \
    --name "SentinelML" \
    --icon "Installer/app.ico" \
    --add-data "models/saved_model.pkl:models" \
    --add-data "models/scaler.pkl:models" \
    --add-data "models/metrics.json:models" \
    --add-data "config.json:." \
    app.py
```

### Build Disk Image (.dmg)
```bash
hdiutil create -volname "SentinelML" -srcfolder dist/SentinelML.app -ov -format UDZO SentinelML.dmg
```

---

## 5. Artifact Verification Checklist

Before releasing any platform artifact, verify the following contracts:
- [ ] Model loaded cleanly: `models/saved_model.pkl` and `models/scaler.pkl` are bundled in their relative paths.
- [ ] 19-position feature vector: verified finite, zero-padded for OS-specific unavailable sensors.
- [ ] Single-instance lock: prevents concurrent instances (`.sentinelml_instance.lock`).
- [ ] Stale-token protection: verified active across scan state transitions.
- [ ] Incomplete scans: CANCELLED or ERROR scans never evaluate or display as SAFE.
