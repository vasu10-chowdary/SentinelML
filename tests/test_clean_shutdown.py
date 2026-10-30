"""SentinelML V2 — clean shutdown guarantees (no Tk required)."""

import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import gui.main_window as main_window


class _FakeWindow:
    """Minimal stand-in for MainWindow; only the shutdown path is exercised."""

    def __init__(self, destroy_error=None):
        self._pages = {}
        self._config = {}
        self._destroy_error = destroy_error
        self.destroy_called = False
        self.quit_called = False

    def destroy(self):
        self.destroy_called = True
        if self._destroy_error is not None:
            raise self._destroy_error

    def quit(self):
        self.quit_called = True


class TestCleanShutdown(unittest.TestCase):
    def _close(self, window):
        with mock.patch.object(main_window.cfg, "save"), mock.patch(
            "guard.sentinel_guard.get_guard_instance"
        ) as guard:
            guard.return_value.stop.return_value = None
            return main_window.MainWindow._on_close(window)

    def test_close_destroys_window_and_stops_mainloop(self):
        window = _FakeWindow()
        self._close(window)
        self.assertTrue(window.destroy_called)
        self.assertTrue(window.quit_called)

    def test_close_still_stops_mainloop_when_destroy_fails(self):
        """A teardown error must not leave an invisible process running."""
        window = _FakeWindow(destroy_error=RuntimeError("teardown failed"))
        with self.assertRaises(RuntimeError):
            self._close(window)
        self.assertTrue(window.destroy_called)
        self.assertTrue(window.quit_called)


if __name__ == "__main__":
    unittest.main()
