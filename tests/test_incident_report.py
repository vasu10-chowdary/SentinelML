"""Incident report generator tests (Phase 5).

Covers honest classification/probability, exact feature order, provenance,
correlation findings, integrity embedding, sanitisation, deterministic
filenames, and the never-SAFE invariant for invalid scans.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from exhibition.evidence_correlation import EvidenceCorrelator
from exhibition.incident_report import (
    NEXT_STEPS,
    REPORT_NOTICE,
    build_integrity_report,
    build_incident_report,
    render_incident_markdown,
    write_report,
)
from exhibition.report_exporter import ExhibitionReportExporter
from ml.predictor import FEATURE_NAMES
from scanner.scan_engine import ScanResult, ScanState, ScanType


def _scan(**overrides):
    features = overrides.pop("_features", np.array([[float(i) for i in range(19)]]))
    values = dict(
        scan_type=ScanType.QUICK,
        state=ScanState.SAFE,
        files_inspected=100,
        directories_inspected=5,
        processes_analyzed=40,
        ml_executed=True,
        ml_probability=0.21,
        threat_level="SAFE",
        elapsed_seconds=2.5,
        scan_id="SCN-INC-1",
        scan_origin="LIVE_HOST_SCAN",
    )
    values.update(overrides)
    result = ScanResult(**values)
    result._features = features
    return result


def _correlator(scan):
    c = EvidenceCorrelator()
    c.add_scan_result(scan)
    return c


class TestIncidentScanBlock(unittest.TestCase):

    def test_valid_scan_reports_probability_and_classification(self):
        report = build_incident_report(_scan())
        scan = report["scan"]
        self.assertEqual(report["report_type"], "INCIDENT")
        self.assertEqual(scan["scan_id"], "SCN-INC-1")
        self.assertEqual(scan["classification"], "SAFE")
        self.assertAlmostEqual(scan["probability"], 0.21)
        self.assertEqual(scan["probability_status"], "MEASURED")
        self.assertFalse(scan["is_simulation"])
        self.assertEqual(scan["features"][0]["name"], FEATURE_NAMES[0])
        self.assertEqual(scan["feature_coverage"]["measured"], 19)

    def test_cancelled_scan_never_safe_and_no_probability(self):
        report = build_incident_report(_scan(cancelled=True, threat_level="CRITICAL"))
        scan = report["scan"]
        self.assertNotEqual(scan["classification"], "SAFE")
        self.assertIsNone(scan["probability"])
        self.assertEqual(scan["probability_status"], "UNAVAILABLE")

    def test_error_scan_marks_inputs_error(self):
        report = build_incident_report(_scan(state=ScanState.ERROR))
        self.assertTrue(all(f["status"] == "ERROR" for f in report["scan"]["features"]))
        self.assertTrue(all(f["value"] is None for f in report["scan"]["features"]))
        self.assertNotEqual(report["scan"]["classification"], "SAFE")

    def test_inconclusive_scan_never_safe(self):
        report = build_incident_report(_scan(
            state=ScanState.INCONCLUSIVE, ml_probability=0.95, threat_level="SAFE"))
        self.assertNotEqual(report["scan"]["classification"], "SAFE")
        self.assertIsNone(report["scan"]["probability"])

    def test_no_scan_is_explicitly_unavailable(self):
        report = build_incident_report(None)
        scan = report["scan"]
        self.assertFalse(scan["available"])
        self.assertEqual(scan["classification"], "UNAVAILABLE")
        self.assertIsNone(scan["probability"])
        self.assertEqual(scan["features"], [])
        self.assertEqual(scan["feature_coverage"]["total"], 0)

    def test_missing_features_are_not_measured(self):
        result = ScanResult(scan_type=ScanType.QUICK, state=ScanState.COMPLETE,
                            scan_id="SCN-NOFEAT", ml_executed=False)
        report = build_incident_report(result)
        statuses = {f["status"] for f in report["scan"]["features"]}
        self.assertEqual(statuses, {"UNAVAILABLE"})
        self.assertTrue(all(f["value"] is None for f in report["scan"]["features"]))

    def test_unavailable_sensors_recorded(self):
        result = _scan(telemetry_availability={"avg_entropy": "UNAVAILABLE_PLATFORM"},
                       missing_features=["avg_entropy"], available_feature_count=18)
        report = build_incident_report(result)
        cov = report["scan"]["feature_coverage"]
        self.assertEqual(cov["unavailable"], 1)
        self.assertIn("avg_entropy", cov["not_measured"])
        md = render_incident_markdown(report)
        self.assertIn("avg_entropy", md)
        self.assertIn("18/19", md)


class TestCorrelationAndIntegrity(unittest.TestCase):

    def test_correlator_evidence_and_findings_are_included(self):
        scan = _scan(ml_probability=0.93, threat_level="CRITICAL")
        report = build_incident_report(scan, correlator=_correlator(scan))
        corr = report["correlation"]
        self.assertTrue(corr["available"])
        self.assertGreaterEqual(corr["summary"]["total"], 2)
        kinds = [f["kind"] for f in corr["findings"]]
        self.assertIn("MODEL_ONLY", kinds)
        self.assertTrue(any("not confirmed malware" in f["caveat"].lower()
                            for f in corr["findings"]))

    def test_simulated_scan_marks_evidence_simulated(self):
        scan = _scan(is_simulation=True, scan_origin="CONTROLLED_SIMULATION",
                     ml_probability=0.8, threat_level="WARNING", scan_id="SCN-SIM")
        report = build_incident_report(scan, correlator=_correlator(scan))
        self.assertTrue(report["scan"]["is_simulation"])
        self.assertTrue(report["measured_vs_simulated"]["scan_is_simulation"])
        self.assertGreaterEqual(report["measured_vs_simulated"]["evidence_simulated"], 1)
        self.assertTrue(any("controlled simulation" in lim.lower()
                            for lim in report["limitations"]))

    def test_integrity_report_is_embedded(self):
        from tests.test_integrity_upgrade import _sample_diff
        integrity = build_integrity_report(_sample_diff(), "/tmp/folder",
                                           baseline_at="t0", compared_at="t1")
        report = build_incident_report(_scan(), integrity_report=integrity)
        self.assertEqual(report["integrity"]["summary"]["modified"], 1)
        md = render_incident_markdown(report)
        self.assertIn("File Integrity Results", md)
        self.assertIn("docs/changed.txt", md)

    def test_ai_summary_paths_are_sanitized(self):
        report = build_incident_report(_scan(), ai_summary=r"see C:\Users\vasur\notes.txt")
        self.assertNotIn("vasur", report["ai_summary"])
        self.assertIn("[USER_PROFILE]", report["ai_summary"])


class TestIncidentMarkdown(unittest.TestCase):

    def test_report_contains_disclaimer_steps_and_limitations(self):
        report = build_incident_report(_scan(), correlator=_correlator(_scan()))
        md = render_incident_markdown(report)
        self.assertIn("INCIDENT INVESTIGATION REPORT", md)
        self.assertIn(REPORT_NOTICE, md)
        self.assertIn("not a forensic certification", md.lower())
        self.assertIn("Next Steps", md)
        self.assertIn(NEXT_STEPS[0][:20], md)
        self.assertIn("Limitations", md)
        self.assertIn("Model Inputs (19, exact trained order)", md)
        for name in FEATURE_NAMES[:3]:
            self.assertIn(name, md)

    def test_no_evidence_report_is_honest(self):
        report = build_incident_report(None)
        md = render_incident_markdown(report)
        self.assertIn("UNAVAILABLE", md)
        self.assertIn("No scan result was supplied", md)
        self.assertNotIn("`SAFE`", md)

    def test_expected_next_steps_present_in_json(self):
        report = build_incident_report(_scan())
        self.assertEqual(report["next_steps"], NEXT_STEPS)
        self.assertIn("isolate the host", " ".join(NEXT_STEPS).lower())
        self.assertIn("backup", " ".join(NEXT_STEPS).lower())


class TestIncidentExport(unittest.TestCase):

    def test_write_report_renders_incident_markdown(self):
        report = build_incident_report(_scan())
        with tempfile.TemporaryDirectory() as td:
            paths = write_report(report, output_dir=Path(td), stem="incident_x")
            self.assertEqual(paths["json"].name, "incident_x.json")
            md = paths["md"].read_text(encoding="utf-8")
            self.assertIn("INCIDENT INVESTIGATION REPORT", md)
            data = json.loads(paths["json"].read_text(encoding="utf-8"))
            self.assertEqual(data["scan"]["scan_id"], "SCN-INC-1")

    def test_second_incident_export_does_not_overwrite(self):
        exporter = ExhibitionReportExporter()
        with tempfile.TemporaryDirectory() as td:
            first = exporter.export_incident_report(_scan(), output_dir=Path(td), stem="inc")
            second = exporter.export_incident_report(_scan(), output_dir=Path(td), stem="inc")
            self.assertNotEqual(first["json"], second["json"])
            self.assertEqual(second["json"].name, "inc_2.json")
            self.assertTrue(first["md"].exists() and second["md"].exists())

    def test_exporter_never_fabricates_probability_for_failed_scan(self):
        exporter = ExhibitionReportExporter()
        with tempfile.TemporaryDirectory() as td:
            paths = exporter.export_incident_report(
                _scan(state=ScanState.ERROR), output_dir=Path(td), stem="failed")
            data = json.loads(paths["json"].read_text(encoding="utf-8"))
            self.assertIsNone(data["scan"]["probability"])
            self.assertNotEqual(data["scan"]["classification"], "SAFE")


class TestDashboardTextReport(unittest.TestCase):
    """The dashboard's plain-text export must carry limitations, provenance,
    next steps and the benchmark caveat — not just the structured copy."""

    def test_exported_text_report_states_limitations(self):
        import customtkinter as ctk
        import gui.pages.dashboard as dash_mod
        from gui.pages.dashboard import DashboardPage

        try:
            root = ctk.CTk()
        except Exception as exc:
            self.skipTest(f"Tk unavailable: {exc}")

        tmp = Path(tempfile.mkdtemp(prefix="sentinel_report_test_"))
        target = tmp / "report.txt"
        old_save = dash_mod.filedialog.asksaveasfilename
        old_yes = dash_mod.messagebox.askyesno
        old_info = dash_mod.messagebox.showinfo
        dash_mod.filedialog.asksaveasfilename = lambda *a, **k: str(target)
        dash_mod.messagebox.askyesno = lambda *a, **k: False
        dash_mod.messagebox.showinfo = lambda *a, **k: None
        try:
            page = DashboardPage(root, config={})
            page._do_generate_report(None, target_result=_scan())
        finally:
            dash_mod.filedialog.asksaveasfilename = old_save
            dash_mod.messagebox.askyesno = old_yes
            dash_mod.messagebox.showinfo = old_info
            root.destroy()

        self.assertTrue(target.exists(), "text report was not written")
        text = target.read_text(encoding="utf-8")
        self.assertIn("LIMITATIONS & UNCERTAINTY", text)
        self.assertIn("not a forensic certification", text)
        self.assertIn("95.67%", text)
        self.assertIn("not a measured real-world ransomware detection rate", text)
        self.assertIn("RECOMMENDED NEXT STEPS", text)
        self.assertIn("MEASURED", text)
        self.assertIn("Sensor Coverage", text)
        self.assertIn("Correlation in time does not establish causation", text)
        self.assertIn("A changed file hash alone does not prove ransomware", text)

    def test_simulated_scan_is_labelled_in_text_report(self):
        import customtkinter as ctk
        import gui.pages.dashboard as dash_mod
        from gui.pages.dashboard import DashboardPage

        try:
            root = ctk.CTk()
        except Exception as exc:
            self.skipTest(f"Tk unavailable: {exc}")

        tmp = Path(tempfile.mkdtemp(prefix="sentinel_report_sim_"))
        target = tmp / "sim.txt"
        old_save = dash_mod.filedialog.asksaveasfilename
        old_yes = dash_mod.messagebox.askyesno
        old_info = dash_mod.messagebox.showinfo
        dash_mod.filedialog.asksaveasfilename = lambda *a, **k: str(target)
        dash_mod.messagebox.askyesno = lambda *a, **k: False
        dash_mod.messagebox.showinfo = lambda *a, **k: None
        try:
            page = DashboardPage(root, config={})
            page._do_generate_report(
                None, target_result=_scan(scan_origin="CONTROLLED_SIMULATION"))
        finally:
            dash_mod.filedialog.asksaveasfilename = old_save
            dash_mod.messagebox.askyesno = old_yes
            dash_mod.messagebox.showinfo = old_info
            root.destroy()

        text = target.read_text(encoding="utf-8")
        self.assertIn("SIMULATED", text)
        self.assertNotIn("MEASURED (live host observations)", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
