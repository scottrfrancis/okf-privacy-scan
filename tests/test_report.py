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


class TestSummaryIsSafeForAnAgentToRead(unittest.TestCase):
    """An agent running the scan is itself a crossing. Paths are disclosure too."""

    def setUp(self):
        self.r = Result(
            exposures=[
                exposure("/kb/health/dr-aurelia-vance.md", agents=["claude-code"], egress=["cloud-model"]),
                exposure("/kb/family/grandmother-ssn.md", detectors=("gov-id", "roster-name")),
            ],
            copies_per_identifier={"f1": 3},
            scanned_files=40,
        )

    def test_summary_contains_no_paths_or_path_fragments(self):
        text = report.render_summary(self.r, gaps=[])
        for leak in ("/kb", "health", "aurelia", "vance", "grandmother", "family"):
            self.assertNotIn(leak, text.lower(), leak)

    def test_summary_still_carries_the_numbers_that_matter(self):
        text = report.render_summary(self.r, gaps=[])
        self.assertIn("reachable: 1", text)
        self.assertIn("sensitive_files: 2", text)
        self.assertIn("max_copies_of_one_identifier: 3", text)

    def test_summary_counts_by_detector_and_agent(self):
        text = report.render_summary(self.r, gaps=[])
        self.assertIn("gov-id: 2", text)
        self.assertIn("claude-code: 1", text)

    def test_summary_names_gaps_by_count_not_path(self):
        from pathlib import Path
        gap = ConfigGap(Path("/home/u/.secret-agent/cfg.json"), "invalid JSON")
        text = report.render_summary(self.r, gaps=[gap])
        self.assertIn("config_gaps: 1", text)
        self.assertNotIn("secret-agent", text)


class TestLaunchRootCaveat(unittest.TestCase):
    """Roots passed on the command line appear in no file. Say so every time."""

    def test_summary_always_states_the_launch_root_limit(self):
        self.assertIn("launch_roots_visible: partial", report.render_summary(Result(), gaps=[]))

    def test_text_report_names_the_limit_and_the_remedy(self):
        text = report.render_text(Result(), gaps=[]).lower()
        self.assertIn("--assume-root", text)
