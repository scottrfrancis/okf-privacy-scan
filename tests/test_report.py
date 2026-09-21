"""The human-readable report."""
import unittest
from pathlib import Path

from kbscan import report
from kbscan.harnesses import ConfigGap
from kbscan.scan import Exposure, Result


def exposure(path, agents=(), egress=(), detectors=("gov-id",)):
    return Exposure(path=path, detectors=detectors, fingerprints=("abc123",),
                    agents=tuple(agents), egress=tuple(egress))


class TestHeadline(unittest.TestCase):
    def test_leads_with_the_number_of_reachable_files(self):
        r = Result(exposures=[exposure("/a", agents=["claude-code"]), exposure("/b")])
        first = report.render_text(r, gaps=[]).splitlines()[0]
        self.assertIn("1", first)
        self.assertIn("reachable", first.lower())

    def test_reachable_files_are_listed_before_unreachable_ones(self):
        r = Result(exposures=[exposure("/unreached"), exposure("/reached", agents=["x"])])
        text = report.render_text(r, gaps=[])
        self.assertLess(text.index("/reached"), text.index("/unreached"))

    def test_egress_is_shown_for_a_local_model_grant(self):
        r = Result(exposures=[exposure("/a", agents=["openclaw"], egress=["chat-relay"])])
        self.assertIn("chat-relay", report.render_text(r, gaps=[]))


class TestNeverReportsCleanWithUnknowns(unittest.TestCase):
    """Unknown must not read as clean."""

    def test_zero_exposures_and_no_gaps_is_reported_as_clean(self):
        text = report.render_text(Result(), gaps=[])
        self.assertIn("no sensitive content reachable", text.lower())

    def test_zero_exposures_with_gaps_is_not_reported_as_clean(self):
        gap = ConfigGap(Path("/home/u/.claude/settings.json"), "invalid JSON")
        text = report.render_text(Result(), gaps=[gap]).lower()
        self.assertNotIn("no sensitive content reachable", text)
        self.assertIn("incomplete", text)
        self.assertIn("settings.json", text)


class TestCopies(unittest.TestCase):
    def test_reports_the_worst_identifier_copy_count(self):
        r = Result(copies_per_identifier={"f1": 4, "f2": 1})
        self.assertIn("4", report.render_text(r, gaps=[]))


if __name__ == "__main__":
    unittest.main()
