"""The command line, which is what cron runs."""
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from kbscan import cli


class CliCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.home = self.base / "home"
        self.corpus = self.base / "corpus"
        self.config = self.base / "cfg"
        for d in (self.home, self.corpus, self.config):
            d.mkdir()
        self.addCleanup(self._tmp.cleanup)

    def run_cli(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main([*args, "--home", str(self.home), "--config-dir", str(self.config)])
        return code, buf.getvalue()


class TestSalt(CliCase):
    def test_salt_is_created_once_and_reused(self):
        self.run_cli("assess", str(self.corpus))
        salt = self.config / "salt"
        first = salt.read_bytes()
        self.run_cli("assess", str(self.corpus))
        self.assertEqual(first, salt.read_bytes(), "a new salt breaks every baseline")

    def test_salt_file_is_private(self):
        self.run_cli("assess", str(self.corpus))
        mode = stat.S_IMODE(os.stat(self.config / "salt").st_mode)
        self.assertEqual(mode, 0o600)


class TestExitCodes(CliCase):
    def test_assess_exits_zero_when_nothing_is_reachable(self):
        self.assertEqual(self.run_cli("assess", str(self.corpus))[0], 0)

    def test_check_exits_nonzero_on_a_new_exposure(self):
        baseline = self.base / "baseline.json"
        self.run_cli("baseline", str(self.corpus), "--out", str(baseline))
        (self.corpus / "a.md").write_text("SSN: 123-45-6789\n")
        code, out = self.run_cli("check", str(self.corpus), "--baseline", str(baseline))
        self.assertEqual(code, 1)
        self.assertNotIn("6789", out)

    def test_check_exits_zero_when_nothing_changed(self):
        (self.corpus / "a.md").write_text("SSN: 123-45-6789\n")
        baseline = self.base / "baseline.json"
        self.run_cli("baseline", str(self.corpus), "--out", str(baseline))
        self.assertEqual(self.run_cli("check", str(self.corpus), "--baseline", str(baseline))[0], 0)


class TestJsonOutput(CliCase):
    def test_json_flag_emits_parseable_json_without_values(self):
        (self.corpus / "a.md").write_text("SSN: 123-45-6789\n")
        code, out = self.run_cli("assess", str(self.corpus), "--json")
        data = json.loads(out)
        self.assertEqual(len(data["exposures"]), 1)
        self.assertNotIn("6789", out)


if __name__ == "__main__":
    unittest.main()


class TestSummaryFlag(CliCase):
    def test_summary_flag_prints_no_paths(self):
        (self.corpus / "clinic-notes.md").write_text("SSN: 123-45-6789\n")
        code, out = self.run_cli("assess", str(self.corpus), "--summary")
        self.assertIn("sensitive_files: 1", out)
        self.assertNotIn("clinic-notes", out)
        self.assertNotIn(str(self.corpus), out)
