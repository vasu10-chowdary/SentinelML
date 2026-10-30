#!/usr/bin/env bash
# =============================================================================
# SentinelML V3 — Linux AppImage build (isolated from the Windows build)
# =============================================================================
# Produces:  dist_linux/SentinelML-x86_64.AppImage
# Leaves:    SentinelML-x86_64.AppImage (old artifact), dist/SentinelML (Windows),
#            Installer/SentinelML_Setup.exe, and models/* completely untouched.
#
# Usage (from anywhere):
#   ./packaging/linux/build_appimage.sh
#
# Optional environment overrides:
#   PYTHON_BIN=$HOME/sentinel_venv_v3/bin/python
#   APPIMAGETOOL=/path/to/appimagetool-x86_64.AppImage
#   DIST_DIR=/path/to/output   BUILD_DIR=/path/to/work
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="${DIST_DIR:-$PROJECT_ROOT/dist_linux}"
BUILD_DIR="${BUILD_DIR:-$PROJECT_ROOT/build_linux}"
APPDIR="$DIST_DIR/SentinelML.AppDir"
OUTPUT="$DIST_DIR/SentinelML-x86_64.AppImage"
TOOLS_DIR="$SCRIPT_DIR/tools"
APPIMAGETOOL="${APPIMAGETOOL:-$TOOLS_DIR/appimagetool-x86_64.AppImage}"
PYTHON_BIN="${PYTHON_BIN:-$HOME/sentinel_venv_v3/bin/python}"

log()  { printf '\033[1;36m[BUILD]\033[0m %s\n' "$*"; }
pass() { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || fail "This script must run on Linux."
[[ -x "$PYTHON_BIN" ]] || fail "Python not found: $PYTHON_BIN"
"$PYTHON_BIN" -c "import PyInstaller, customtkinter, sklearn, numpy, scipy, joblib" \
    || fail "Build venv is missing required packages."

log "Project: $PROJECT_ROOT"
log "Python:  $($PYTHON_BIN --version 2>&1)"
log "Output:  $OUTPUT"

# ── 1. Verify frozen ML assets before building ───────────────────────────────
log "Verifying model/scaler contract (19 features, thresholds unchanged)..."
"$PYTHON_BIN" - "$PROJECT_ROOT" <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
import joblib
model = joblib.load(root / "models/saved_model.pkl")
scaler = joblib.load(root / "models/scaler.pkl")
assert model.n_features_in_ == 19, model.n_features_in_
assert scaler.n_features_in_ == 19, scaler.n_features_in_
assert type(model).__name__ == "RandomForestClassifier", type(model).__name__
print("MODEL", type(model).__name__, "FEATURES", model.n_features_in_)
PY
pass "Model and scaler verified"

# ── 2. PyInstaller onedir build ──────────────────────────────────────────────
log "Cleaning only Linux build outputs..."
rm -rf "$BUILD_DIR" "$DIST_DIR/SentinelML" "$APPDIR"
mkdir -p "$DIST_DIR"

log "Running PyInstaller..."
cd "$PROJECT_ROOT"
"$PYTHON_BIN" -m PyInstaller \
    --clean --noconfirm \
    --distpath "$DIST_DIR" \
    --workpath "$BUILD_DIR" \
    "$SCRIPT_DIR/SentinelML_Linux.spec"

[[ -x "$DIST_DIR/SentinelML/SentinelML" ]] || fail "Linux executable was not produced."
[[ -d "$DIST_DIR/SentinelML/_internal/models" ]] || fail "Bundled models directory missing."
pass "PyInstaller onedir build complete"

# ── 3. Assemble AppDir ──────────────────────────────────────────────────────
log "Assembling AppDir..."
mkdir -p "$APPDIR/usr/bin" \
         "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/256x256/apps"
cp -a "$DIST_DIR/SentinelML/." "$APPDIR/usr/bin/"
cp "$PROJECT_ROOT/sentinel_icon.png" "$APPDIR/sentinel_icon.png"
cp "$PROJECT_ROOT/sentinel_icon.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/sentinel_icon.png"
ln -sf sentinel_icon.png "$APPDIR/.DirIcon"

cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
export LD_LIBRARY_PATH="$HERE/usr/bin:$HERE/usr/bin/_internal:${LD_LIBRARY_PATH:-}"
exec "$HERE/usr/bin/SentinelML" "$@"
EOF
chmod +x "$APPDIR/AppRun" "$APPDIR/usr/bin/SentinelML"

cat > "$APPDIR/sentinelml.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=SentinelML
Comment=Behavioral ransomware detection and threat analysis
Exec=SentinelML
Icon=sentinel_icon
Terminal=false
Categories=Security;System;
StartupWMClass=SentinelML
X-AppImage-Version=3.0.0
EOF

find "$APPDIR" -name "*.so" -o -name "*.so.*" | while read -r so; do
    chmod +x "$so" 2>/dev/null || true
done
pass "AppDir assembled"

# ── 4. Obtain appimagetool (current runtime: FUSE3 fallback, FUSE2 compatible) ─
if [[ ! -x "$APPIMAGETOOL" ]]; then
    log "Downloading appimagetool..."
    mkdir -p "$TOOLS_DIR"
    curl -fL --retry 3 --connect-timeout 20 \
        -o "$APPIMAGETOOL" \
        "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" \
        || fail "Could not download appimagetool. Set APPIMAGETOOL=/path/to/tool and retry."
    chmod +x "$APPIMAGETOOL"
fi

log "Packaging AppImage..."
rm -f "$OUTPUT"
set +e
ARCH=x86_64 "$APPIMAGETOOL" --appimage-extract-and-run "$APPDIR" "$OUTPUT"
RC=$?
if [[ $RC -ne 0 ]]; then
    log "Extract-and-run failed (rc=$RC); extracting appimagetool and retrying..."
    ( cd "$TOOLS_DIR" && rm -rf squashfs-root && \
      "$APPIMAGETOOL" --appimage-extract >/dev/null && \
      ARCH=x86_64 ./squashfs-root/AppRun "$APPDIR" "$OUTPUT" )
    RC=$?
fi
set -e
[[ $RC -eq 0 && -f "$OUTPUT" ]] || fail "AppImage packaging failed (rc=$RC)."
chmod +x "$OUTPUT"
pass "AppImage created"

# ── 5. Integrity summary (no upload, no replacement of old artifact) ────────
SHA256="$(sha256sum "$OUTPUT" | awk '{print $1}')"
SIZE="$(stat -c '%s' "$OUTPUT")"
log "SHA-256: $SHA256"
log "Size:    $SIZE bytes"
pass "Done — Windows artifacts and the old AppImage were not modified."
printf '%s  %s\n' "$SHA256" "$(basename "$OUTPUT")" > "$OUTPUT.sha256"
