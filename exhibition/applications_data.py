"""
SentinelML V2 — Real-World Applications Data (pure logic, no Tkinter)
======================================================================
Defines the five use-case specifications for the Applications Center.

Honesty rules (tested in test_applications_center.py):
  1. No use-case may claim guaranteed prevention, auto-recovery, or
     production readiness without qualification.
  2. Healthcare is explicitly marked illustrative.
  3. Every limitation list must be non-empty.
  4. Demonstrations reference existing page keys only.
  5. Features listed must be a subset of the real 19-feature schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ml.predictor import FEATURE_NAMES as _ALL_FEATURES

ALL_FEATURES: List[str] = list(_ALL_FEATURES)


@dataclass(frozen=True)
class UseCase:
    key: str
    title: str
    sector: str
    problem: str
    capabilities: List[str]
    telemetry_features: List[str]
    model_outputs: List[str]
    demo_page: str
    demo_description: str
    investigation_steps: List[str]
    next_steps: List[str]
    limitations: List[str]
    production_requirements: List[str]
    simulated_data: List[str] = field(default_factory=list)
    is_illustrative: bool = False


# ---------------------------------------------------------------------------
# 1. Enterprise Workstation Behavioral Investigation
# ---------------------------------------------------------------------------
_ENTERPRISE_FEATURES = [
    "total_processes", "suspicious_process_count", "malfind_injection_count",
    "cmd_vssadmin_count", "powershell_process_count", "unsigned_module_count",
    "suspicious_thread_count", "defender_tampering_count", "network_connection_count",
    "unique_external_ips", "registry_handle_count",
]

ENTERPRISE_WORKSTATION = UseCase(
    key="enterprise",
    title="Enterprise Workstation Investigation",
    sector="Enterprise / Corporate IT",
    problem=(
        "A security analyst suspects a workstation has been compromised after "
        "an employee clicked a phishing link. Standard antivirus found nothing. "
        "The analyst needs behavioral evidence — anomalous processes, memory "
        "injection indicators, shadow-copy deletion, unusual network activity — "
        "to decide whether to isolate the machine or escalate to IR."
    ),
    capabilities=[
        "Live behavioral telemetry scan (process table, entropy, network sockets)",
        "Random Forest threat classification (SAFE / WARNING / CRITICAL)",
        "Investigation timeline with timestamped, source-tagged events",
        "Incident-report generation with sanitized paths",
        "AI Observatory for transparent feature vector inspection",
        "Scenario B (Suspicious Process Behavior) for controlled comparison",
    ],
    telemetry_features=_ENTERPRISE_FEATURES,
    model_outputs=[
        "Threat probability (0.0–1.0) and classification (SAFE/WARNING/CRITICAL)",
        "Feature vector with availability status (MEASURED / HEURISTIC_PROXY / UNAVAILABLE)",
        "Suspicious-file list from heuristic filesystem scanner",
        "Investigation timeline (ordered, source-tagged events)",
    ],
    demo_page="ai_observatory",
    demo_description=(
        "Run the AI Observatory with 'Measure now' to show the real 19-feature "
        "behavioral vector measured on this host, then switch to 'Simulated "
        "suspicious' to contrast a scripted malicious vector. Compare probabilities "
        "and observe which features drive the elevated score."
    ),
    investigation_steps=[
        "1. Open the AI Observatory — select 'Measure now' and press Run.",
        "2. Review the 19-feature table: identify any features at WARNING status.",
        "3. Switch to 'Simulated suspicious' vector — observe probability jump.",
        "4. Open the Exhibition Lab → Scenario B (Suspicious Process Behavior).",
        "5. Inspect the Investigation Timeline for MEASURED vs SIMULATED events.",
        "6. Review Detection Result: probability, indicators, missing telemetry.",
        "7. Generate an Incident Report from the Detection Result tab.",
        "8. Compare features flagged here against known ransomware IOCs.",
    ],
    next_steps=[
        "Isolate the workstation from the network if CRITICAL is returned.",
        "Preserve volatile memory (RAM dump) for deeper forensic analysis.",
        "Review flagged process names against known-good application baselines.",
        "Escalate to full IR if shadow-copy deletion or code injection is observed.",
        "Re-run a Full Scan once the host is isolated for deeper coverage.",
    ],
    limitations=[
        "SentinelML performs user-space behavioral observation only — no kernel-level "
        "interception, memory forensics depth, or real-time blocking.",
        "The Random Forest is trained on synthetic data (EXPERIMENTAL_SYNTHETIC_BASELINE_V1); "
        "it is a risk indicator, not a forensic certainty.",
        "Several features (malfind_injection_count, registry_handle_count, "
        "suspicious_mutex_count) are heuristic proxies, not direct kernel measurements.",
        "Quick scan covers depth=1 from monitored roots; lateral movement on "
        "unmapped drives is not detected.",
        "A SAFE result means no threat detected under tests performed — "
        "not that the host is definitely clean.",
    ],
    production_requirements=[
        "Kernel-mode driver or ETW for accurate memory forensics.",
        "Fleet-wide deployment with centralized alert aggregation.",
        "Integration with SIEM/SOAR for automated escalation workflows.",
        "A retrained model on real enterprise malware datasets.",
        "Active Directory integration for privilege-baseline comparison.",
    ],
    simulated_data=[
        "Scenario B (Suspicious Process Behavior) injects a scripted malicious "
        "vector — every injected value is tagged SIMULATED or INJECTED.",
        "The 'Simulated suspicious' preset in the AI Observatory is hand-authored, "
        "not measured; it exists only to contrast against the real host vector.",
        "Everything tagged MEASURED (process table, entropy, sockets) is read from "
        "the live host at scan time.",
    ],
)

# ---------------------------------------------------------------------------
# 2. College and Computer-Lab Security Education
# ---------------------------------------------------------------------------
_EDU_FEATURES = [
    "total_processes", "suspicious_process_count", "avg_entropy", "max_entropy",
    "high_entropy_region_count", "network_connection_count", "unique_external_ips",
    "powershell_process_count", "file_handle_count",
]

COLLEGE_EDUCATION = UseCase(
    key="education",
    title="College & Computer-Lab Security Education",
    sector="Education / Academia",
    problem=(
        "A computer-science lecturer wants to teach students how behavioral "
        "ransomware detection works in practice — what telemetry is collected, "
        "how a machine-learning model evaluates a behavioral vector, and how "
        "incident investigation proceeds — without exposing real malware or "
        "damaging lab machines."
    ),
    capabilities=[
        "Attack Replay Simulator — scripted kill-chain with Play/Pause/Speed controls",
        "AI Observatory — transparent 19-feature model inspection",
        "Exhibition Lab Scenarios A–E — guided investigation walkthrough",
        "Guided Exhibition Tour — 8-stage narrated presentation",
        "File Integrity Watchtower — before/after baseline comparison",
        "Incident-report generation for post-lab review",
    ],
    telemetry_features=_EDU_FEATURES,
    model_outputs=[
        "Step-by-step attack narrative (all events labelled SIMULATED)",
        "Live probability readout as simulated features are injected",
        "19-feature table with status badges (MEASURED / UNAVAILABLE / SIMULATED)",
        "Global model feature importance (Gini, model-level aggregate)",
    ],
    demo_page="attack_replay",
    demo_description=(
        "Run the Attack Replay Simulator at 0.5× speed so students can follow "
        "each kill-chain step. Pause at the entropy-spike event, then switch to "
        "the AI Observatory with 'Simulated suspicious' to show the probability "
        "exceeding the WARNING threshold. All events are clearly labelled SIMULATED."
    ),
    investigation_steps=[
        "1. Open the Attack Replay Simulator — play at 0.5× speed.",
        "2. Pause at Step 8 (high-entropy rewrites) — discuss Shannon entropy.",
        "3. Open the AI Observatory → 'Simulated suspicious' → inspect features.",
        "4. Run Scenario C (Simulated Ransomware) in the Exhibition Lab.",
        "5. Walk the Investigation Timeline — discuss SIMULATED vs MEASURED tags.",
        "6. Show the Feature Importance chart — discuss global Gini attribution.",
        "7. Complete the 8-stage Guided Tour for a structured narrative.",
        "8. Export an Incident Report as the lab submission artefact.",
    ],
    next_steps=[
        "Export the incident report as a student lab submission.",
        "Compare SAFE vs CRITICAL vector feature values as a class exercise.",
        "Discuss the difference between heuristic proxies and direct measurements.",
        "Explore the File Integrity Watchtower as a 'before/after' integrity demo.",
        "Assign students to identify which limitations prevent production deployment.",
    ],
    limitations=[
        "All Attack Replay events are scripted simulations — not real malware executions.",
        "Feature importance shows model-level Gini aggregate, not per-prediction attribution.",
        "The model is trained on synthetic data; real-world accuracy is unvalidated.",
        "Network simulation is not included; only the local process and file subsystem is observed.",
    ],
    production_requirements=[
        "Curriculum materials and assessment rubrics aligned to security standards.",
        "Isolated lab network to safely run benign detection exercises.",
        "A real-malware sample set (sandboxed) for advanced courses.",
        "A graded Challenge Mode exercise bank with instructor answer keys.",
    ],
    simulated_data=[
        "Every Attack Replay step is scripted narrative — no ransomware runs on the machine.",
        "Exhibition Lab Scenarios A–E replay recorded feature vectors; they never "
        "touch files or launch processes.",
        "Challenge Mode cases are hand-authored scenarios with fixed evidence; they "
        "are teaching aids, not observed incidents.",
    ],
)

# ---------------------------------------------------------------------------
# 3. Digital Forensics and Incident Investigation
# ---------------------------------------------------------------------------
_FORENSICS_FEATURES = [
    "suspicious_process_count", "malfind_injection_count", "cmd_vssadmin_count",
    "avg_entropy", "max_entropy", "high_entropy_region_count",
    "defender_tampering_count", "unsigned_module_count", "suspicious_thread_count",
    "abnormal_privilege_count", "suspicious_mutex_count", "orphan_process_count",
]

DIGITAL_FORENSICS = UseCase(
    key="forensics",
    title="Digital Forensics & Incident Investigation",
    sector="Digital Forensics / IR",
    problem=(
        "A digital forensics analyst is triaging a suspected ransomware incident. "
        "They need to quickly characterize the behavioral fingerprint of the attack — "
        "entropy elevation, shadow-copy deletion, injection indicators, privilege "
        "escalation — produce a timestamped evidence timeline, and generate a "
        "sanitized incident report without exposing sensitive file paths."
    ),
    capabilities=[
        "Chronological investigation timeline (ordered, source-tagged, selectable events)",
        "Incident report with sanitized paths and full feature vector",
        "6-stage detection verification pipeline evidence",
        "File Integrity Watchtower for before/after hash comparison",
        "Scenario B evidence output (MEASURED baseline vs SIMULATED indicators)",
        "Scan-origin tagging (LIVE_HOST_SCAN vs CONTROLLED_SIMULATION)",
    ],
    telemetry_features=_FORENSICS_FEATURES,
    model_outputs=[
        "Timestamped investigation timeline with MEASURED/SIMULATED/INJECTED provenance",
        "Probability and classification with honest 'not available' disclosure",
        "Sanitized incident report (paths hashed/redacted)",
        "Missing-feature disclosure (UNAVAILABLE_PLATFORM / RESTRICTED_PERMISSION)",
    ],
    demo_page="exhibition_lab",
    demo_description=(
        "Run Scenario B (Suspicious Process Behavior) in the Exhibition Lab. "
        "Switch to the Investigation Timeline tab — select events to inspect "
        "timestamps, evidence, and source tags. Then open the Detection Result "
        "tab, review indicators vs baselines, and export the sanitized Incident Report."
    ),
    investigation_steps=[
        "1. Exhibition Lab → Scenario B → Run Scenario.",
        "2. Investigation Timeline → select each event → inspect evidence detail.",
        "3. Note MEASURED events (real host) vs SIMULATED (scripted vector).",
        "4. Detection Result tab → review indicators flagged above baseline.",
        "5. Check Telemetry section — note which sensors are UNAVAILABLE.",
        "6. Export Incident Report → review sanitized feature vector.",
        "7. File Integrity Watchtower → establish baseline → simulate change → compare.",
        "8. Document the chain of events for the investigation record.",
    ],
    next_steps=[
        "Preserve the exported incident report as evidence.",
        "Cross-reference the flagged process names with threat-intelligence databases.",
        "Run File Integrity Watchtower on identified staging directories.",
        "Escalate missing-telemetry findings to request elevated scan permissions.",
        "Document limitations (heuristic proxies, user-space only) in the investigation report.",
    ],
    limitations=[
        "SentinelML produces behavioral risk scores — not legally admissible forensic evidence.",
        "Path sanitization removes details that may be needed for full chain-of-custody.",
        "Timestamps are local host time — not synchronized to a forensic time server.",
        "No memory image acquisition or volatile-data preservation capability.",
        "Incomplete scans must never be interpreted as SAFE — the tool enforces this.",
    ],
    production_requirements=[
        "Integration with forensic acquisition tools (FTK, Autopsy, Volatility).",
        "Cryptographically verified evidence chain with hash manifests.",
        "Legal review of admissibility requirements in the relevant jurisdiction.",
        "Synchronized timestamps from a trusted time authority.",
    ],
    simulated_data=[
        "Scenario B combines a MEASURED host baseline with a SIMULATED attack "
        "vector; each timeline event carries its provenance tag.",
        "Timestamps reflect when the demonstration ran, not the original incident.",
        "File Integrity Watchtower diffs are computed from real files you choose — "
        "but the changes are the ones you make, not attacker activity.",
    ],
)

# ---------------------------------------------------------------------------
# 4. Small-Business and Personal-Computer Monitoring
# ---------------------------------------------------------------------------
_SMB_FEATURES = [
    "total_processes", "suspicious_process_count", "avg_entropy",
    "high_entropy_region_count", "network_connection_count", "unique_external_ips",
    "cmd_vssadmin_count", "powershell_process_count", "file_handle_count",
    "defender_tampering_count",
]

SMALL_BUSINESS = UseCase(
    key="small_business",
    title="Small-Business & Personal-Computer Monitoring",
    sector="SMB / Personal",
    problem=(
        "A small-business owner or home user has no dedicated security team. "
        "They want a straightforward way to check whether their PC shows signs of "
        "ransomware-like activity — unusual process behavior, suspicious file "
        "operations, elevated entropy — and to monitor a folder of critical "
        "documents for unauthorized changes."
    ),
    capabilities=[
        "One-click Quick Scan with SAFE / WARNING / CRITICAL result",
        "File Integrity Watchtower for critical-document folders",
        "Dashboard status indicator connected to actual scan results",
        "Plain-language incident report for non-technical users",
        "Scenario A (Benign System Activity) for routine baseline scanning",
    ],
    telemetry_features=_SMB_FEATURES,
    model_outputs=[
        "Simple SAFE / WARNING / CRITICAL classification",
        "Threat probability percentage for the current host state",
        "List of flagged suspicious files (heuristic scanner)",
        "File integrity diff (added / modified / deleted since baseline)",
    ],
    demo_page="integrity_watchtower",
    demo_description=(
        "Open the File Integrity Watchtower, choose a test folder (e.g. a "
        "temp directory), establish a baseline, add/modify a file, then click "
        "'Compare Now' to see the diff with SHA-256 hashes, timestamps, and "
        "change status. Note: this shows file-state changes, NOT confirmed ransomware."
    ),
    investigation_steps=[
        "1. Run a Quick Scan from the Dashboard — review SAFE/WARNING/CRITICAL.",
        "2. Open File Integrity Watchtower → select the Documents folder.",
        "3. Establish a baseline (SHA-256 hashes of all files).",
        "4. After a suspicious incident, click 'Compare Now'.",
        "5. Review added/modified/deleted files with hashes and timestamps.",
        "6. If WARNING or CRITICAL: run Scenario A in the Exhibition Lab for context.",
        "7. Export the Incident Report for records or IT support handoff.",
    ],
    next_steps=[
        "If CRITICAL: disconnect from the network and contact IT support.",
        "Preserve the incident report before attempting any recovery.",
        "Do NOT pay a ransom without consulting a security professional.",
        "Restore from the most recent known-good offline backup.",
        "Re-enable automatic OS updates and patch all software.",
    ],
    limitations=[
        "User-space monitoring only — kernel-level or BIOS-level attacks are not detected.",
        "The SAFE result means no behavioral anomaly was found under the tests run, "
        "not that the computer is definitely malware-free.",
        "File Integrity Watchtower monitors file state, not process behavior — changes "
        "detected are not by themselves proof of ransomware.",
        "This tool is not a replacement for a commercial antivirus or EDR product.",
        "No real-time blocking or automatic quarantine capability.",
    ],
    production_requirements=[
        "Scheduled scan automation (Windows Task Scheduler / cron).",
        "Cloud backup integration for automatic recovery point creation.",
        "Email or push notification on CRITICAL findings.",
        "User-friendly onboarding and one-click remediation guidance.",
    ],
    simulated_data=[
        "Quick Scan readings are MEASURED from this computer at scan time.",
        "File Integrity Watchtower compares real SHA-256 hashes of the folder you "
        "select — added/modified/deleted entries show file-state change only.",
        "Scenario A (Benign System Activity) is a scripted baseline you can run "
        "for comparison; it is labelled SIMULATED.",
    ],
)

# ---------------------------------------------------------------------------
# 5. Healthcare Cybersecurity (Illustrative Use Case)
# ---------------------------------------------------------------------------
_HEALTH_FEATURES = [
    "total_processes", "suspicious_process_count", "avg_entropy",
    "high_entropy_region_count", "cmd_vssadmin_count", "file_handle_count",
    "registry_handle_count", "unsigned_module_count", "defender_tampering_count",
    "network_connection_count",
]

HEALTHCARE = UseCase(
    key="healthcare",
    title="Healthcare Cybersecurity (Illustrative)",
    sector="Healthcare (Illustrative Only)",
    problem=(
        "Hospitals and clinics are high-value ransomware targets. A ransomware "
        "attack on a medical workstation can delay patient care, corrupt EHR data, "
        "and trigger regulatory reporting obligations. An illustrative scenario: "
        "could a behavioral detection tool like SentinelML provide early warning "
        "on a clinical workstation before encryption begins?"
    ),
    capabilities=[
        "Behavioral scan detecting pre-encryption indicators (shadow-copy deletion, "
        "entropy elevation, process injection) — observed on this host as illustration",
        "Investigation timeline for auditable evidence documentation",
        "File Integrity Watchtower for monitoring critical configuration directories",
        "Incident report generation for regulatory documentation support",
        "Scenario D (Limited Telemetry) demonstrates INCONCLUSIVE behavior when "
        "sensors are restricted — relevant in locked-down clinical environments",
    ],
    telemetry_features=_HEALTH_FEATURES,
    model_outputs=[
        "SAFE / WARNING / CRITICAL / INCONCLUSIVE classification",
        "INCONCLUSIVE result when telemetry is insufficient (Scenario D)",
        "Incident report for audit/documentation purposes",
        "Investigation timeline for compliance evidence",
    ],
    demo_page="exhibition_lab",
    demo_description=(
        "Run Scenario D (Limited Telemetry) in the Exhibition Lab to show how "
        "SentinelML returns INCONCLUSIVE — never a false SAFE — when required "
        "sensors are unavailable. This illustrates the tool's safe-failure behavior "
        "in locked-down environments. All results are clearly labelled SIMULATION."
    ),
    investigation_steps=[
        "1. Exhibition Lab → Scenario D → Run Scenario.",
        "2. Observe INCONCLUSIVE result — note that the tool refuses to claim SAFE.",
        "3. Review missing sensors — explain clinical environment restrictions.",
        "4. Run Scenario C (Simulated Ransomware) for pre-encryption indicators.",
        "5. Investigation Timeline → note evidence timestamps for documentation.",
        "6. Export Incident Report — review regulatory-relevant fields.",
        "7. Discuss what additional capabilities a real clinical deployment needs.",
    ],
    next_steps=[
        "Consult a certified healthcare cybersecurity specialist before any deployment.",
        "Conduct a HIPAA/GDPR risk assessment before processing any patient data.",
        "Isolate affected systems immediately if ransomware indicators are observed.",
        "Engage the healthcare organization's incident response plan.",
        "Report ransomware incidents to relevant regulatory bodies as required.",
    ],
    limitations=[
        "ILLUSTRATIVE USE CASE ONLY. SentinelML has NOT been validated "
        "for clinical deployment, is NOT HIPAA-certified, and MUST NOT be used as the "
        "sole security control in any healthcare environment.",
        "Patient data is never processed by SentinelML in this demonstration.",
        "Clinical environments often restrict the OS sensors needed for full coverage; "
        "Scenario D demonstrates the resulting INCONCLUSIVE safe-failure behavior.",
        "Regulatory compliance (HIPAA, HITECH, GDPR, NIS2) requires certified, "
        "audited tools — this project does not qualify without additional validation.",
        "Real hospital environments require network segmentation, MDM, and dedicated "
        "medical-device security controls not provided here.",
    ],
    production_requirements=[
        "Full HIPAA Security Rule compliance assessment and third-party audit.",
        "Integration with hospital SIEM, EHR audit logging, and SOC workflows.",
        "Certified incident response procedures with defined RTO/RPO.",
        "Validated model performance on real clinical endpoint telemetry datasets.",
        "Approval from the healthcare organization's CISO and legal team.",
    ],
    simulated_data=[
        "All clinical scenarios here are illustrative: Scenarios C and D replay "
        "scripted vectors — no patient data and no EHR system is involved.",
        "Results are labelled SIMULATION and cannot be cited as clinical validation.",
    ],
    is_illustrative=True,
)

# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------
ALL_USE_CASES = [
    ENTERPRISE_WORKSTATION,
    COLLEGE_EDUCATION,
    DIGITAL_FORENSICS,
    SMALL_BUSINESS,
    HEALTHCARE,
]

USE_CASE_BY_KEY = {uc.key: uc for uc in ALL_USE_CASES}
REQUIRED_DEMO_PAGES = list({uc.demo_page for uc in ALL_USE_CASES})


def validate_use_cases() -> List[str]:
    """Return validation errors. Empty = all pass."""
    errors: List[str] = []
    forbidden = [
        "guaranteed", "guarantee", "prevent all", "prevents all",
        "automatically recover", "production ready", "production-ready",
    ]
    for uc in ALL_USE_CASES:
        text = " ".join([
            uc.problem, uc.demo_description,
            " ".join(uc.capabilities),
            " ".join(uc.next_steps),
            " ".join(uc.limitations),
            " ".join(uc.simulated_data),
        ]).lower()
        for phrase in forbidden:
            if phrase in text:
                errors.append(f"{uc.key}: forbidden phrase '{phrase}'")
        if not uc.simulated_data:
            errors.append(f"{uc.key}: simulated_data empty — must state what is "
                          "scripted vs measured")
        if uc.key == "healthcare" and not uc.is_illustrative:
            errors.append("healthcare must be marked is_illustrative=True")
        if uc.key == "healthcare":
            if "ILLUSTRATIVE" not in " ".join(uc.limitations).upper():
                errors.append("healthcare limitations must say ILLUSTRATIVE")
        if not uc.limitations:
            errors.append(f"{uc.key}: limitations empty")
        unknown = [f for f in uc.telemetry_features if f not in ALL_FEATURES]
        if unknown:
            errors.append(f"{uc.key}: unknown features {unknown}")
        if not uc.demo_page:
            errors.append(f"{uc.key}: demo_page empty")
    return errors
