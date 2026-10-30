"""
SentinelML V2 — Shared colour palette and UI constants.
All widgets import from here so changing one constant updates the whole app.
"""

# ── Dark theme palette ────────────────────────────────────────────────────
COLOURS = {
    "bg":       "#0d1117",   # window background
    "panel":    "#161b22",   # sidebar / card background
    "card":     "#1f2937",   # inner card / hover
    "border":   "#30363d",   # subtle borders
    "accent":   "#00d4aa",   # teal accent (brand colour)
    "accent2":  "#0ea5e9",   # sky-blue secondary accent
    "white":    "#f0f6fc",   # primary text
    "muted":    "#8b949e",   # secondary / muted text
    "green":    "#3fb950",   # safe / ok
    "yellow":   "#d29922",   # warning
    "red":      "#f85149",   # danger / threat
    "orange":   "#e3b341",   # medium risk
}

# ── Font stacks ──────────────────────────────────────────────────────────
# Resolved at runtime in main_window.py after Tk is initialised.
# These are the preferred fallback order — first available font wins.
FONT_PREFERENCE = [
    "Segoe UI",         # Windows 10/11
    "SF Pro Display",   # macOS (modern)
    "Ubuntu",           # Ubuntu Linux
    "DejaVu Sans",      # Linux / POSIX standard
    "Liberation Sans",  # Red Hat / Fedora Linux
    "Noto Sans",        # Modern Linux / Android
    "Helvetica Neue",   # macOS (classic)
    "Inter",            # if manually installed
    "Arial",            # Universal fallback
]

# ── Window defaults ──────────────────────────────────────────────────────
WINDOW_TITLE    = "SentinelML V2"
WINDOW_MIN_W    = 1000
WINDOW_MIN_H    = 640
SIDEBAR_W       = 230

# ── App version ──────────────────────────────────────────────────────────
APP_VERSION = "3.1.0"
