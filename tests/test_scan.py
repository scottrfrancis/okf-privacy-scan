"""The join: sensitive content crossed with the directories agents were handed."""
import tempfile
import unittest
from pathlib import Path

from kbscan import scan
from kbscan.harnesses import Grant


class ScanCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def grant(self, rel, agent="claude-code", models="cloud", egress=()):
        return Grant(agent=agent, root=self.root / rel, source=self.root / "cfg",
                     models=models, egress=tuple(egress))


class TestTheJoin(ScanCase):
    def test_sensitive_file_inside_a_grant_is_exposed(self):
        self.write("work/notes/med.md", "SSN: 123-45-6789\n")
        result = scan.assess([self.root], [self.grant("work")], salt=b"s")
        [exp] = result.exposures
        self.assertEqual([g.agent for g in exp.grants], ["claude-code"])

    def test_sensitive_file_outside_every_grant_is_found_but_not_exposed(self):
        self.write("private/med.md", "SSN: 123-45-6789\n")
        result = scan.assess([self.root], [self.grant("work")], salt=b"s")
        [exp] = result.exposures
        self.assertEqual(exp.grants, [])
        self.assertEqual(result.exposed_count, 0)
        self.assertEqual(result.finding_count, 1)

    def test_the_headline_number_counts_files_not_findings(self):
        self.write("work/a.md", "SSN: 123-45-6789\ncard 4111 1111 1111 1111\n")
        result = scan.assess([self.root], [self.grant("work")], salt=b"s")
        self.assertEqual(result.exposed_count, 1)
        self.assertEqual(result.finding_count, 2)

    def test_two_grants_covering_one_file_are_both_reported(self):
        self.write("work/a.md", "SSN: 123-45-6789\n")
        grants = [self.grant("work"), self.grant("work", agent="openclaw", models="local")]
        [exp] = scan.assess([self.root], grants, salt=b"s").exposures
        self.assertEqual(sorted(g.agent for g in exp.grants), ["claude-code", "openclaw"])

    def test_a_local_model_grant_still_counts_as_exposure(self):
        """Local models were the reassurance that turned out not to be one."""
        self.write("work/a.md", "SSN: 123-45-6789\n")
        g = self.grant("work", agent="openclaw", models="local", egress=["chat-relay"])
        result = scan.assess([self.root], [g], salt=b"s")
        self.assertEqual(result.exposed_count, 1)
        self.assertEqual(result.exposures[0].egress, ("chat-relay",))


class TestCopiesPerIdentifier(ScanCase):
    def test_the_same_identifier_in_three_files_counts_as_three_copies(self):
        for name in ("a.md", "b.md", "c.md"):
            self.write(f"work/{name}", "SSN: 123-45-6789\n")
        result = scan.assess([self.root], [], salt=b"s")
        self.assertEqual(max(result.copies_per_identifier.values()), 3)


class TestWalkDiscipline(ScanCase):
    def test_binary_files_are_skipped(self):
        (self.root / "blob.bin").write_bytes(b"\x00\x01SSN: 123-45-6789")
        self.assertEqual(scan.assess([self.root], [], salt=b"s").finding_count, 0)

    def test_git_internals_are_skipped(self):
        self.write(".git/x.md", "SSN: 123-45-6789\n")
        self.assertEqual(scan.assess([self.root], [], salt=b"s").finding_count, 0)

    def test_oversized_files_are_skipped_and_counted(self):
        self.write("big.md", "x" * 40)
        result = scan.assess([self.root], [], salt=b"s", max_bytes=10)
        self.assertEqual(result.skipped_large, 1)


class TestReportsNeverCarryContent(ScanCase):
    def test_serialised_result_has_no_matched_value(self):
        self.write("work/a.md", "SSN: 123-45-6789\n")
        blob = scan.assess([self.root], [self.grant("work")], salt=b"s").to_json()
        self.assertNotIn("123-45-6789", blob)
        self.assertNotIn("6789", blob)


class TestDetectiveMode(ScanCase):
    def test_unchanged_corpus_reports_nothing_new(self):
        self.write("work/a.md", "SSN: 123-45-6789\n")
        base = scan.assess([self.root], [self.grant("work")], salt=b"s")
        later = scan.assess([self.root], [self.grant("work")], salt=b"s")
        d = scan.diff(base, later)
        self.assertEqual((d.new, d.resolved), ([], []))

    def test_a_new_exposure_is_reported(self):
        base = scan.assess([self.root], [self.grant("work")], salt=b"s")
        self.write("work/a.md", "SSN: 123-45-6789\n")
        later = scan.assess([self.root], [self.grant("work")], salt=b"s")
        self.assertEqual(len(scan.diff(base, later).new), 1)

    def test_a_removed_exposure_is_reported_as_resolved(self):
        p = self.write("work/a.md", "SSN: 123-45-6789\n")
        base = scan.assess([self.root], [self.grant("work")], salt=b"s")
        p.unlink()
        later = scan.assess([self.root], [self.grant("work")], salt=b"s")
        self.assertEqual(len(scan.diff(base, later).resolved), 1)

    def test_diff_survives_a_round_trip_through_json(self):
        self.write("work/a.md", "SSN: 123-45-6789\n")
        base = scan.assess([self.root], [self.grant("work")], salt=b"s")
        restored = scan.Result.from_json(base.to_json())
        self.assertEqual(scan.diff(restored, base).new, [])


if __name__ == "__main__":
    unittest.main()


class TestLargeFilesAreStreamedNotSkipped(ScanCase):
    """Agent transcripts are routinely over a megabyte. Skipping them skips the point."""

    def test_identifier_near_the_end_of_a_large_file_is_found(self):
        body = "filler line\n" * 5000 + "SSN: 123-45-6789\n"
        self.write("work/session.jsonl", body)
        result = scan.assess([self.root], [], salt=b"s", chunk_bytes=4096)
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.skipped_large, 0)

    def test_a_match_is_counted_once_across_chunk_boundaries(self):
        body = ("SSN: 123-45-6789\n" + "x" * 90 + "\n") * 200
        self.write("work/s.jsonl", body)
        result = scan.assess([self.root], [], salt=b"s", chunk_bytes=512)
        self.assertEqual(result.finding_count, 200)

    def test_front_matter_is_only_honoured_at_the_top_of_the_file(self):
        later = "---\nvisibility: sensitive\n---\n"
        self.write("work/notes.md", "# heading\n" + "line\n" * 2000 + later)
        result = scan.assess([self.root], [], salt=b"s", chunk_bytes=256)
        self.assertEqual(result.finding_count, 0)

    def test_front_matter_at_the_top_still_counts_when_chunked(self):
        self.write("work/notes.md", "---\nvisibility: sensitive\n---\n" + "line\n" * 2000)
        result = scan.assess([self.root], [], salt=b"s", chunk_bytes=256)
        self.assertEqual([e.detectors for e in result.exposures], [("declared-sensitive",)])
