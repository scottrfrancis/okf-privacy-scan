"""Sensitivity that comes from where a file is, not what it contains."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from kbscan import scan

HAS_GIT = shutil.which("git") is not None


@unittest.skipUnless(HAS_GIT, "git not installed")
class TestEncryptedLocations(unittest.TestCase):
    """A path you chose to encrypt is a path you consider sensitive."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name) / "kb"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        self.addCleanup(self._tmp.cleanup)

    def write(self, rel, text):
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def test_plaintext_file_in_an_encrypted_path_is_reported(self):
        self.write(".gitattributes", "health/** filter=git-crypt diff=git-crypt\n")
        self.write("health/visit-notes.md", "Discussed the plan. Follow up in six weeks.\n")
        [exp] = scan.assess([self.repo], [], salt=b"s").exposures
        self.assertEqual(exp.detectors, ("encrypted-location",))

    def test_nested_gitattributes_are_honoured(self):
        """The one that is easy to miss when auditing from the root file alone."""
        self.write(".gitattributes", "health/** filter=git-crypt\n")
        self.write("family/.gitattributes", "* filter=git-crypt\n")
        self.write("family/notes.md", "nothing structured here\n")
        paths = [e.path for e in scan.assess([self.repo], [], salt=b"s").exposures]
        self.assertIn(str(self.repo / "family/notes.md"), paths)

    def test_file_outside_every_encrypted_path_is_not_reported(self):
        self.write(".gitattributes", "health/** filter=git-crypt\n")
        self.write("infra/hosts.md", "nothing sensitive\n")
        self.assertEqual(scan.assess([self.repo], [], salt=b"s").exposures, [])

    def test_the_gitattributes_file_itself_is_not_a_finding(self):
        self.write("family/.gitattributes", "* filter=git-crypt\n")
        paths = [e.path for e in scan.assess([self.repo], [], salt=b"s").exposures]
        self.assertNotIn(str(self.repo / "family/.gitattributes"), paths)

    def test_location_findings_do_not_inflate_copy_counts(self):
        self.write(".gitattributes", "health/** filter=git-crypt\n")
        for n in ("a.md", "b.md", "c.md"):
            self.write(f"health/{n}", "prose only\n")
        self.assertEqual(scan.assess([self.repo], [], salt=b"s").copies_per_identifier, {})


class TestDeclaredLocations(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_user_declared_glob_marks_files_sensitive(self):
        p = self.root / "clients" / "acme" / "notes.md"
        p.parent.mkdir(parents=True)
        p.write_text("prose only\n")
        result = scan.assess([self.root], [], salt=b"s", sensitive_globs=["clients/**"])
        self.assertEqual([e.detectors for e in result.exposures], [("declared-location",)])

    def test_outside_a_git_repo_there_is_no_crash_and_no_location_finding(self):
        p = self.root / "a.md"
        p.write_text("prose only\n")
        self.assertEqual(scan.assess([self.root], [], salt=b"s").exposures, [])


if __name__ == "__main__":
    unittest.main()
