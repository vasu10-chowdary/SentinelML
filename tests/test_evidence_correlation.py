"""Tests for the evidence-correlation engine (Phase 2)."""

import time
import unittest

from exhibition.evidence_correlation import (
    EvidenceCorrelator,
    EvidenceItem,
    PROV_APPLICATION,
    PROV_ERROR,
    PROV_HEURISTIC,
    PROV_MEASURED,
    PROV_SIMULATED,
    PROV_UNAVAILABLE,
    demo_correlator,
    format_timestamp,
)
from exhibition.integrity_watchtower import IntegrityChange, IntegrityDiff
from exhibition.investigation_timeline import (
    CATEGORY_CLASSIFICATION,
    InvestigationTimeline,
    SOURCE_INJECTED,
    SOURCE_REAL,
    SOURCE_SIMULATED,
    SOURCE_SYSTEM,
)
from scanner.scan_engine import ScanResult, ScanState, ScanType


def _scan(**overrides):
    values = dict(
        scan_type=ScanType.QUICK,
        state=ScanState.COMPLETE,
        files_inspected=120,
        directories_inspected=8,
        processes_analyzed=64,
        ml_executed=True,
        ml_probability=0.72,
        threat_level="WARNING",
        elapsed_seconds=3.5,
        scan_id="SCN-TEST000001",
        scan_origin="LIVE_HOST_SCAN",
        model_source="EXPERIMENTAL_SYNTHETIC_BASELINE_V1",
    )
    values.update(overrides)
    return ScanResult(**values)


class TestEvidenceItem(unittest.TestCase):
    def test_unknown_provenance_downgrades_to_unavailable(self):
        item = EvidenceItem(category="X", title="Y", provenance="MADE_UP")
        self.assertEqual(item.provenance, PROV_UNAVAILABLE)
        self.assertTrue(any("provenance" in lim.lower() for lim in item.limitations))

    def test_unparseable_timestamp_is_dropped(self):
        item = EvidenceItem(category="X", title="Y", timestamp="not-a-number")
        self.assertIsNone(item.timestamp)
        self.assertEqual(format_timestamp(item.timestamp), "TIME UNAVAILABLE")

    def test_negative_timestamp_is_dropped(self):
        item = EvidenceItem(category="X", title="Y", timestamp=-5)
        self.assertIsNone(item.timestamp)


class TestScanCorrelation(unittest.TestCase):
    def test_measured_scan_items_keep_provenance(self):
        c = EvidenceCorrelator()
        c.add_scan_result(_scan(), when=1000.0)
        summary = c.summary()
        self.assertEqual(summary["measured"], 2)
        self.assertEqual(summary["simulated"], 0)
        titles = [e.title for e in c.items]
        self.assertTrue(any("SCN-TEST000001" in t for t in titles))
        pred = [e for e in c.items if e.category == "MODEL_INFERENCE"][0]
        self.assertIn("WARNING", pred.title)
        self.assertIn("0.720", pred.detail)
        self.assertEqual(pred.timestamp, 1000.0)

    def test_simulated_scan_marks_prediction_simulated(self):
        c = EvidenceCorrelator()
        c.add_scan_result(_scan(is_simulation=True,
                                scan_origin="CONTROLLED_SIMULATION"),
                          when=2000.0)
        pred = [e for e in c.items if e.category == "MODEL_INFERENCE"][0]
        self.assertEqual(pred.provenance, PROV_SIMULATED)
        self.assertEqual(c.summary()["measured"], 0)
        self.assertTrue(c.summary()["has_simulated"])

    def test_missing_ml_prediction_is_unavailable_or_error(self):
        c = EvidenceCorrelator()
        c.add_scan_result(_scan(ml_executed=False, threat_level="ANALYSIS_ERROR",
                                state=ScanState.ANALYSIS_ERROR,
                                error_message="pipeline failed"), when=1.0)
        pred = [e for e in c.items if e.category == "MODEL_INFERENCE"][0]
        self.assertEqual(pred.provenance, PROV_ERROR)

        c2 = EvidenceCorrelator()
        c2.add_scan_result(_scan(ml_executed=False, state=ScanState.SCAN_INCOMPLETE,
                                 cancelled=True), when=1.0)
        pred2 = [e for e in c2.items if e.category == "MODEL_INFERENCE"][0]
        self.assertEqual(pred2.provenance, PROV_UNAVAILABLE)

    def test_suspicious_files_are_heuristic(self):
        c = EvidenceCorrelator()
        c.add_scan_result(_scan(suspicious_files=["C:/tmp/a.bin", "C:/tmp/b.bin"]),
                          when=5.0)
        heur = c.by_provenance(PROV_HEURISTIC)
        self.assertEqual(len(heur), 1)
        self.assertIn("not proof", " ".join(heur[0].limitations).lower())
        self.assertEqual(c.summary()["heuristic"], 1)

    def test_missing_sensors_and_denied_paths_are_unavailable(self):
        c = EvidenceCorrelator()
        c.add_scan_result(_scan(missing_features=["registry_handle_count"],
                                access_denied=4), when=9.0)
        provs = [e.provenance for e in c.items if e.category == "TELEMETRY_GAP"]
        self.assertEqual(provs, [PROV_UNAVAILABLE, PROV_UNAVAILABLE])

    def test_duplicate_scan_result_is_deduplicated(self):
        c = EvidenceCorrelator()
        c.add_scan_result(_scan(), when=42.0)
        before = len(c)
        c.add_scan_result(_scan(), when=42.0)
        self.assertEqual(len(c), before)

    def test_none_scan_result_is_ignored(self):
        c = EvidenceCorrelator()
        self.assertEqual(c.add_scan_result(None), [])
        self.assertEqual(len(c), 0)


class TestIntegrityCorrelation(unittest.TestCase):
    def _diff(self):
        return IntegrityDiff(
            added=[IntegrityChange("a.txt", "added", "", "h1", "", "t", 0, 4)],
            modified=[IntegrityChange("b.txt", "modified", "h2", "h3", "t1", "t2", 4, 5)],
            deleted=[IntegrityChange("c.txt", "deleted", "h4", "", "t1", "", 9, 0)],
            unchanged_count=12,
            skipped=[],
            total=15,
        )

    def test_changes_are_measured_with_caution(self):
        c = EvidenceCorrelator()
        c.add_integrity_diff(self._diff(), baseline_at=100.0, compared_at=200.0)
        rows = [e for e in c.items if e.category == "FILE_INTEGRITY"]
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(e.provenance == PROV_MEASURED for e in rows))
        modified = [e for e in rows if "modified" in e.title][0]
        self.assertEqual(modified.timestamp, 200.0)
        joined = " ".join(modified.limitations).lower()
        self.assertIn("changed hash", joined)
        self.assertIn("not why", joined)

    def test_empty_integrity_diff_is_unavailable(self):
        c = EvidenceCorrelator()
        c.add_integrity_diff(IntegrityDiff(total=0), compared_at=5.0)
        row = [e for e in c.items if e.category == "FILE_INTEGRITY"][0]
        self.assertEqual(row.provenance, PROV_UNAVAILABLE)
        self.assertIn("does not show", " ".join(row.limitations).lower())

    def test_skipped_paths_are_unavailable(self):
        diff = IntegrityDiff(total=3, skipped=["locked.db"])
        c = EvidenceCorrelator()
        c.add_integrity_diff(diff)
        rows = [e for e in c.items if e.category == "FILE_INTEGRITY"]
        self.assertEqual(rows[0].provenance, PROV_UNAVAILABLE)

    def test_no_diff_is_ignored(self):
        c = EvidenceCorrelator()
        self.assertEqual(c.add_integrity_diff(None), [])


class TestTimelineCorrelation(unittest.TestCase):
    def test_source_mapping_is_preserved(self):
        timeline = InvestigationTimeline()
        timeline.add(CATEGORY_CLASSIFICATION, "Model verdict", "detail", source=SOURCE_REAL)
        timeline.add(CATEGORY_CLASSIFICATION, "Scenario step", "detail", source=SOURCE_SIMULATED)
        timeline.add(CATEGORY_CLASSIFICATION, "Injected failure", "detail", source=SOURCE_INJECTED)
        timeline.add(CATEGORY_CLASSIFICATION, "App event", "detail", source=SOURCE_SYSTEM)

        c = EvidenceCorrelator()
        c.add_timeline(timeline)
        provs = [e.provenance for e in c.items]
        self.assertEqual(provs, [PROV_MEASURED, PROV_SIMULATED,
                                 PROV_SIMULATED, PROV_APPLICATION])

    def test_timeline_without_timestamps_lands_after_timed_events(self):
        c = EvidenceCorrelator()
        c.add_manual("X", "Untimed first", timestamp=None)
        c.add_manual("X", "Timed second", timestamp=500.0)
        c.add_manual("X", "Untimed third", timestamp=None)
        ordered = c.ordered_events()
        self.assertEqual(ordered[0].title, "Timed second")
        self.assertEqual([e.title for e in ordered[1:]], ["Untimed first", "Untimed third"])
        self.assertEqual(c.summary()["missing_timestamps"], 2)


class TestAlerts(unittest.TestCase):
    def test_alert_metadata_simulation_is_respected(self):
        c = EvidenceCorrelator()
        c.add_alert({
            "title": "Simulation alert", "message": "demo",
            "severity": "HIGH", "category": "simulation", "source": "x",
            "timestamp": "2026-10-29T10:00:00", "metadata": {"is_simulation": True},
        })
        self.assertEqual(c.items[0].provenance, PROV_SIMULATED)
        self.assertIsNotNone(c.items[0].timestamp)

    def test_non_dict_alert_ignored_but_untimed_dict_is_kept(self):
        c = EvidenceCorrelator()
        self.assertIsNone(c.add_alert("not a dict"))
        item = c.add_alert({"title": "no timestamp", "severity": "LOW"})
        self.assertIsNotNone(item)
        self.assertIsNone(item.timestamp)
        self.assertEqual(len(c), 1)  # evidence kept, reported as TIME UNAVAILABLE


class TestFindings(unittest.TestCase):
    def test_empty_correlator_says_no_conclusion(self):
        findings = EvidenceCorrelator().findings()
        self.assertEqual(findings[0]["kind"], "NO_EVIDENCE")
        self.assertIn("no conclusions", findings[0]["statement"].lower())

    def test_elevated_prediction_with_corroboration_is_not_causal(self):
        c = EvidenceCorrelator()
        c.add_scan_result(_scan(suspicious_files=["C:/x/a.bin"]), when=10.0)
        findings = c.findings()
        kinds = [f["kind"] for f in findings]
        self.assertIn("CO_OCCURRENCE", kinds)
        text = " ".join(f["statement"] + " " + f["caveat"] for f in findings)
        self.assertIn("not causation", text.lower())

    def test_model_only_prediction_is_not_confirmed_malware(self):
        c = EvidenceCorrelator()
        c.add_scan_result(_scan(), when=10.0)
        findings = c.findings()
        model_only = [f for f in findings if f["kind"] == "MODEL_ONLY"]
        self.assertTrue(model_only)
        self.assertIn("not confirmed malware", model_only[0]["caveat"].lower())

    def test_simulation_only_finding(self):
        c = demo_correlator()
        kinds = [f["kind"] for f in c.findings()]
        self.assertIn("SIMULATION_ONLY", kinds)

    def test_coverage_gap_finding(self):
        c = EvidenceCorrelator()
        c.add_scan_result(_scan(missing_features=["avg_entropy"]), when=1.0)
        kinds = [f["kind"] for f in c.findings()]
        self.assertIn("COVERAGE_GAP", kinds)

    def test_file_change_caveat_present(self):
        c = EvidenceCorrelator()
        c.add_integrity_diff(IntegrityDiff(
            modified=[IntegrityChange("b", "modified", "1", "2", "", "", 1, 2)],
            total=1), compared_at=3.0)
        file_f = [f for f in c.findings() if f["kind"] == "FILE_CHANGE"][0]
        self.assertIn("does not prove ransomware", file_f["caveat"].lower())

    def test_missing_time_finding(self):
        c = EvidenceCorrelator()
        c.add_manual("X", "Untimed", timestamp=None)
        kinds = [f["kind"] for f in c.findings()]
        self.assertIn("MISSING_TIME", kinds)


class TestDemoCorrelator(unittest.TestCase):
    def test_demo_is_deterministic_and_simulated(self):
        a = demo_correlator()
        b = demo_correlator()
        self.assertEqual(a.to_dicts(), b.to_dicts())
        self.assertEqual(a.summary()["measured"], 0)
        self.assertGreaterEqual(a.summary()["simulated"], 3)

    def test_demo_custom_clock(self):
        c = demo_correlator(now=1234.0)
        self.assertEqual(c.ordered_events()[0].timestamp, 1234.0)


if __name__ == "__main__":
    unittest.main()
