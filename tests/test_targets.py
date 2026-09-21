"""The places ordinary tooling skips."""
import tempfile
import unittest
from pathlib import Path

from kbscan import targets


class TestDefaultTargets(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def touch(self, rel):
        p = self.home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
        return p

    def test_shell_history_is_included_when_present(self):
        p = self.touch(".zsh_history")
        self.assertIn(p, targets.derived_copy_targets(self.home))

    def test_agent_session_directories_are_included_when_present(self):
        self.touch(".claude/projects/p/session.jsonl")
        self.assertIn(self.home / ".claude/projects", targets.derived_copy_targets(self.home))

    def test_absent_locations_are_not_invented(self):
        self.assertEqual(targets.derived_copy_targets(self.home), [])


class TestSyncRoots(unittest.TestCase):
    def test_recognises_common_sync_roots(self):
        cases = {
            "/Users/u/Library/CloudStorage/OneDrive-Personal/notes/a.md": "onedrive",
            "/Users/u/Dropbox/a.md": "dropbox",
            "/Users/u/Library/CloudStorage/GoogleDrive-u@x/My Drive/a.md": "google-drive",
            "/Users/u/Library/Mobile Documents/com~apple~CloudDocs/a.md": "icloud",
        }
        for path, expected in cases.items():
            self.assertEqual(targets.sync_root(Path(path)), expected, path)

    def test_ordinary_path_is_not_synced(self):
        self.assertIsNone(targets.sync_root(Path("/srv/kb/a.md")))


if __name__ == "__main__":
    unittest.main()
