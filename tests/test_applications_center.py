"""
SentinelML V2 — Real-World Applications Center tests (Part A)
=============================================================
Covers exhibition/applications_data.py (pure logic, no Tkinter) and the
honesty rules declared in that module's docstring, plus basic Tk construction
of ApplicationsCenterPage using a single shared CTk root.
"""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from exhibition.applications_data import (
    ALL_USE_CASES,
    REQUIRED_DEMO_PAGES,
    USE_CASE_BY_KEY,
    UseCase,
    validate_use_cases,
)
from ml.predictor import FEATURE_NAMES


# ---------------------------------------------------------------------------
# Pure-logic tests — no Tkinter
# ---------------------------------------------------------------------------

class TestUseCaseCatalogue(unittest.TestCase):

    def test_exactly_five_use_cases(self):
        self.assertEqual(len(ALL_USE_CASES), 5)

    def test_all_keys_unique(self):
        keys = [uc.key for uc in ALL_USE_CASES]
        self.assertEqual(len(keys), len(set(keys)))

    def test_use_case_by_key_lookups(self):
        for uc in ALL_USE_CASES:
            self.assertIs(USE_CASE_BY_KEY[uc.key], uc)

    def test_all_titles_nonempty(self):
        for uc in ALL_USE_CASES:
            self.assertTrue(uc.title.strip(), f"{uc.key}: title is empty")

    def test_all_problems_nonempty(self):
        for uc in ALL_USE_CASES:
            self.assertTrue(uc.problem.strip(), f"{uc.key}: problem is empty")

    def test_all_demo_pages_nonempty(self):
        for uc in ALL_USE_CASES:
            self.assertTrue(uc.demo_page.strip(), f"{uc.key}: demo_page is empty")

    def test_required_demo_pages_list(self):
        # All required demo pages must be non-empty strings
        self.assertTrue(all(p.strip() for p in REQUIRED_DEMO_PAGES))

    def test_investigation_steps_present(self):
        for uc in ALL_USE_CASES:
            self.assertGreater(len(uc.investigation_steps), 0,
                               f"{uc.key}: no investigation steps")

    def test_next_steps_present(self):
        for uc in ALL_USE_CASES:
            self.assertGreater(len(uc.next_steps), 0, f"{uc.key}: no next steps")

    def test_capabilities_present(self):
        for uc in ALL_USE_CASES:
            self.assertGreater(len(uc.capabilities), 0, f"{uc.key}: no capabilities")

    def test_production_requirements_present(self):
        for uc in ALL_USE_CASES:
            self.assertGreater(len(uc.production_requirements), 0,
                               f"{uc.key}: no production requirements")


class TestHonestyRules(unittest.TestCase):
    """Enforce the honesty rules declared in applications_data.py."""

    def test_validate_passes_no_errors(self):
        errs = validate_use_cases()
        self.assertEqual(errs, [],
                         f"validate_use_cases() returned errors: {errs}")

    def test_no_forbidden_phrases(self):
        forbidden = ["guaranteed", "guarantee", "prevent all", "prevents all",
                     "automatically recover", "production ready", "production-ready"]
        for uc in ALL_USE_CASES:
            text = " ".join([uc.problem, uc.demo_description,
                             " ".join(uc.capabilities),
                             " ".join(uc.next_steps),
                             " ".join(uc.limitations)]).lower()
            for phrase in forbidden:
                self.assertNotIn(phrase, text,
                                 f"{uc.key}: contains forbidden phrase '{phrase}'")

    def test_healthcare_is_illustrative(self):
        hc = USE_CASE_BY_KEY["healthcare"]
        self.assertTrue(hc.is_illustrative,
                        "healthcare use-case must be marked is_illustrative=True")

    def test_healthcare_limitations_say_illustrative(self):
        hc = USE_CASE_BY_KEY["healthcare"]
        all_lim = " ".join(hc.limitations).upper()
        self.assertIn("ILLUSTRATIVE", all_lim,
                      "Healthcare limitations must explicitly say ILLUSTRATIVE")

    def test_all_limitations_nonempty(self):
        for uc in ALL_USE_CASES:
            self.assertTrue(uc.limitations, f"{uc.key}: limitations list is empty")

    def test_telemetry_features_are_real_schema(self):
        for uc in ALL_USE_CASES:
            for feat in uc.telemetry_features:
                self.assertIn(feat, FEATURE_NAMES,
                              f"{uc.key}: '{feat}' not in the real 19-feature schema")

    def test_non_healthcare_not_illustrative(self):
        for uc in ALL_USE_CASES:
            if uc.key != "healthcare":
                self.assertFalse(uc.is_illustrative,
                                 f"{uc.key}: should not be marked illustrative")

    def test_healthcare_not_clinical_deployment_claim(self):
        hc = USE_CASE_BY_KEY["healthcare"]
        # The limitations must assert the tool is NOT validated for clinical deployment,
        # i.e., the phrase "not been validated" or "has not been validated" must appear.
        text = " ".join(hc.limitations + hc.production_requirements).lower()
        # Verify the negation exists — the tool explicitly disclaims clinical validation
        has_disclaimer = ("not been validated" in text or
                          "not validated" in text or
                          "has not" in text)
        self.assertTrue(has_disclaimer,
                        "Healthcare must explicitly disclaim clinical validation "
                        "(e.g. 'has NOT been validated for clinical deployment')")

    def test_demo_description_nonempty_all(self):
        for uc in ALL_USE_CASES:
            self.assertTrue(uc.demo_description.strip(),
                            f"{uc.key}: demo_description is empty")


class TestUseCaseContent(unittest.TestCase):
    """Spot-check key content assertions for each use case."""

    def test_enterprise_has_ai_observatory_or_lab(self):
        uc = USE_CASE_BY_KEY["enterprise"]
        self.assertIn(uc.demo_page, ["ai_observatory", "exhibition_lab"])

    def test_education_has_attack_replay_or_lab(self):
        uc = USE_CASE_BY_KEY["education"]
        self.assertIn(uc.demo_page, ["attack_replay", "exhibition_lab"])

    def test_forensics_demo_page_is_lab(self):
        uc = USE_CASE_BY_KEY["forensics"]
        self.assertEqual(uc.demo_page, "exhibition_lab")

    def test_small_business_demo_page_is_watchtower(self):
        uc = USE_CASE_BY_KEY["small_business"]
        self.assertEqual(uc.demo_page, "integrity_watchtower")

    def test_healthcare_demo_page_is_lab(self):
        uc = USE_CASE_BY_KEY["healthcare"]
        self.assertEqual(uc.demo_page, "exhibition_lab")

    def test_enterprise_mentions_safe_result_caveat(self):
        uc = USE_CASE_BY_KEY["enterprise"]
        text = " ".join(uc.limitations).lower()
        # Must acknowledge that SAFE doesn't guarantee absence of malware
        self.assertTrue(
            "safe" in text and ("not" in text or "does not" in text),
            "Enterprise limitations must caveat the SAFE result meaning"
        )

    def test_small_business_disclaimer_no_replacement(self):
        uc = USE_CASE_BY_KEY["small_business"]
        text = " ".join(uc.limitations).lower()
        self.assertIn("not a replacement", text,
                      "Small-business limitations must say 'not a replacement'")

    def test_forensics_not_legally_admissible_claim(self):
        uc = USE_CASE_BY_KEY["forensics"]
        text = " ".join(uc.limitations).lower()
        self.assertIn("not", text)
        self.assertIn("forensic", text)

    def test_every_use_case_states_simulated_vs_measured(self):
        for uc in ALL_USE_CASES:
            self.assertTrue(uc.simulated_data,
                            f"{uc.key}: simulated_data is empty")
            text = " ".join(uc.simulated_data).upper()
            self.assertTrue(
                "SIMULAT" in text or "SCRIPTED" in text or "MEASURED" in text,
                f"{uc.key}: simulated_data must name what is simulated or measured")

    def test_every_use_case_produces_evidence(self):
        for uc in ALL_USE_CASES:
            self.assertTrue(uc.model_outputs,
                            f"{uc.key}: model_outputs (evidence) is empty")


# ---------------------------------------------------------------------------
# Tk UI tests — single shared root
# ---------------------------------------------------------------------------

class TestApplicationsCenterPageUI(unittest.TestCase):
    _root = None

    @classmethod
    def setUpClass(cls):
        try:
            import customtkinter as ctk
            cls._root = ctk.CTk()
            cls._root.withdraw()
        except Exception as exc:
            cls._root = None
            cls._skip_reason = str(exc)

    @classmethod
    def tearDownClass(cls):
        if cls._root is not None:
            try:
                cls._root.destroy()
            except Exception:
                pass

    def _skip(self):
        if self._root is None:
            self.skipTest(getattr(self, "_skip_reason", "Tk unavailable"))

    def test_page_constructs(self):
        self._skip()
        from gui.pages.applications_center import ApplicationsCenterPage
        page = ApplicationsCenterPage(self._root, config={})
        try:
            # Should auto-select first use case
            self.assertIsNotNone(page._selected_key)
            self.assertIn(page._selected_key, USE_CASE_BY_KEY)
            # Should have 5 selector cards
            self.assertEqual(len(page._selector_btns), 5)
            # Demo button should be enabled after auto-select
            self.assertEqual(page._demo_btn.cget("state"), "normal")
        finally:
            page.destroy()

    def test_select_each_use_case(self):
        self._skip()
        from gui.pages.applications_center import ApplicationsCenterPage
        page = ApplicationsCenterPage(self._root, config={})
        try:
            for key in USE_CASE_BY_KEY:
                page._select(key)
                self.assertEqual(page._selected_key, key)
                # Demo button should show the page name
                btn_text = page._demo_btn.cget("text")
                self.assertIn("Demo", btn_text)
        finally:
            page.destroy()

    def test_healthcare_shows_in_selector(self):
        self._skip()
        from gui.pages.applications_center import ApplicationsCenterPage
        page = ApplicationsCenterPage(self._root, config={})
        try:
            self.assertIn("healthcare", page._selector_btns)
        finally:
            page.destroy()

    def test_destroy_sets_flag(self):
        self._skip()
        from gui.pages.applications_center import ApplicationsCenterPage
        page = ApplicationsCenterPage(self._root, config={})
        page.destroy()
        self.assertTrue(page._is_destroyed)

    def test_back_to_lab_safe_without_show_page(self):
        self._skip()
        from gui.pages.applications_center import ApplicationsCenterPage
        page = ApplicationsCenterPage(self._root, config={})
        try:
            # master (shared CTk root) has no _show_page — must not raise
            page._back_to_lab()
        finally:
            page.destroy()

    def test_challenge_entry_navigates_to_challenge_mode(self):
        self._skip()
        from gui.pages.applications_center import ApplicationsCenterPage

        calls = []

        class _FakeMaster:
            def _show_page(self, uid):
                calls.append(uid)

        page = ApplicationsCenterPage(self._root, config={})
        page.master = _FakeMaster()
        try:
            page._open_challenge()
        finally:
            page.destroy()
        self.assertEqual(calls, ["challenge_mode"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
