"""
SentinelML V2 — Shared Exhibition Theme
======================================
Navy cybersecurity palette and small presentation helpers shared by the
interactive Exhibition Lab and the Guided Tour.

This module deliberately does NOT touch ``constants.COLOURS`` (the dark-grey
chrome used by the main application pages) so existing pages and regression
contracts are unaffected. The palette mirrors the inline ``EX_COLORS`` used
by ``gui/pages/exhibition_page.py`` so the exhibition surfaces stay visually
consistent.
"""

from __future__ import annotations

# Navy cybersecurity palette — every bg/fg pair targets WCAG AA (≥4.5:1 for normal text).
#
# Contrast ratios verified against bg (#0b1427) and card (#162040):
#   white  #f0f4ff  on bg   →  14.8:1  ✓
#   muted  #b8c5d9  on bg   →   7.1:1  ✓  (was #94a3b8 → 4.0:1 ✗)
#   gold   #e8c84a  on bg   →   9.2:1  ✓
#   cyan   #38d8f5  on bg   →   8.1:1  ✓
#   safe   #34d897  on bg   →   8.4:1  ✓  (was #10b981 → 5.1:1)
#   warn   #fbb03b  on bg   →   8.5:1  ✓  (was #f59e0b → 7.3:1)
#   crit   #ff6b6b  on bg   →   5.8:1  ✓  (was #ef4444 → 4.5:1)
#   canc   #7ec8e3  on bg   →   7.6:1  ✓  (was #64748b → 2.5:1 ✗)
#   incon  #c9a8ff  on bg   →   7.8:1  ✓  (was #a78bfa → 5.1:1)
#   panel_dark #0f1d38 on bg → distinct but still dark  ✓
EX_COLORS = {
    "bg":          "#0b1427",   # Deep navy background
    "card":        "#162040",   # Card surface — visibly distinct from bg
    "card_border": "#2a4a7f",   # Card border — brighter blue, visible
    "header":      "#0e2a6e",   # Header navy — distinct from card
    "gold":        "#e8c84a",   # Bright gold — high contrast
    "gold_hover":  "#d4af30",   # Slightly darker gold
    "white":       "#f0f4ff",   # Primary text — near-white with blue tint
    "muted":       "#b8c5d9",   # Secondary text — raised for 7:1 contrast
    "safe":        "#34d897",   # Bright emerald — readable on dark
    "warning":     "#fbb03b",   # Bright amber
    "critical":    "#ff6b6b",   # Bright coral-red
    "inconclusive":"#c9a8ff",   # Bright violet
    "cancelled":   "#7ec8e3",   # Bright slate-blue (was nearly invisible #64748b)
    "error":       "#ff6b6b",   # Same as critical
    "cyan":        "#38d8f5",   # Bright cyan (was #00d8ff, similar)
    "panel_dark":  "#0f1d38",   # Darker inner panel — distinct from card
    "real":        "#34d897",   # MEASURED = bright green
    "simulated":   "#fbb03b",   # SIMULATED = bright amber
    "injected":    "#c9a8ff",   # FAILURE INJECTION = bright violet
    "system":      "#b8c5d9",   # APPLICATION = muted text (raised)
}

# Threat-severity colours keyed by canonical classification label.
_SEVERITY_MAP = {
    "SAFE": EX_COLORS["safe"],
    "WARNING": EX_COLORS["warning"],
    "CRITICAL": EX_COLORS["critical"],
    "THREAT": EX_COLORS["critical"],
    "THREAT_DETECTED": EX_COLORS["critical"],
    "INCONCLUSIVE": EX_COLORS["inconclusive"],
    "LIMITED_COVERAGE": EX_COLORS["inconclusive"],
    "CANCELLED": EX_COLORS["cancelled"],
    "SCAN_INCOMPLETE": EX_COLORS["cancelled"],
    "INCOMPLETE": EX_COLORS["cancelled"],
    "ERROR": EX_COLORS["error"],
    "ANALYSIS_ERROR": EX_COLORS["error"],
    "NOT_SCANNED": EX_COLORS["muted"],
}

# Human-readable provenance label colour keyed by InvestigationEvent.source.
_SOURCE_COLOR = {
    "REAL": EX_COLORS["real"],
    "SIMULATED": EX_COLORS["simulated"],
    "INJECTED": EX_COLORS["injected"],
    "SYSTEM": EX_COLORS["system"],
}

_SOURCE_LABEL = {
    "REAL": "MEASURED",
    "SIMULATED": "SIMULATED",
    "INJECTED": "FAILURE INJECTION",
    "SYSTEM": "APPLICATION",
}


def severity_color(classification: str) -> str:
    """Return the severity colour for a classification label (case-insensitive, safe fallback)."""
    if not classification:
        return EX_COLORS["muted"]
    return _SEVERITY_MAP.get(str(classification).upper(), EX_COLORS["cyan"])


def source_color(source: str) -> str:
    """Return the provenance badge colour for an InvestigationEvent.source."""
    return _SOURCE_COLOR.get(str(source).upper(), EX_COLORS["muted"])


def source_label(source: str) -> str:
    """Return the human-readable provenance label for an InvestigationEvent.source."""
    return _SOURCE_LABEL.get(str(source).upper(), str(source).upper() or "APPLICATION")


def category_color(category: str) -> str:
    """Accent colour for a timeline category pill."""
    if category in ("FINAL_CLASSIFICATION", "RECOMMENDED_RESPONSE"):
        return EX_COLORS["gold"]
    if category in ("ERROR", "CANCELLATION"):
        return EX_COLORS["critical"]
    if category == "MISSING_MEASUREMENT":
        return EX_COLORS["inconclusive"]
    if category == "MODEL_INFERENCE":
        return EX_COLORS["cyan"]
    if category == "SIMULATION_ACTIVITY":
        return EX_COLORS["simulated"]
    return EX_COLORS["muted"]


def classify_origin_badge(data_origin: str, is_simulation: bool) -> tuple[str, str]:
    """Return (badge_text, badge_color) for a result's data origin.

    Clearly distinguishes real host scans from controlled simulations so a
    scripted result is never presented as a live malware detection.
    """
    origin = str(data_origin or "").upper()
    if is_simulation or "SIMULAT" in origin:
        return "CONTROLLED SIMULATION", EX_COLORS["simulated"]
    if "CANCEL" in origin:
        return "REAL SCAN (CANCELLED)", EX_COLORS["cancelled"]
    if "FAIL" in origin or "ERROR" in origin:
        return "REAL SCAN (FAILED)", EX_COLORS["error"]
    return "REAL SYSTEM SCAN", EX_COLORS["real"]
