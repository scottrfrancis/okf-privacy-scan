"""Discovering which directories were handed to which agent, and what each can reach."""
import json
import tempfile
import unittest
from pathlib import Path

from kbscan import harnesses


class HarnessCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, rel, payload):
        p = self.home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload) if isinstance(payload, (dict, list)) else payload)
        return p


class TestClaudeCode(HarnessCase):
    def test_additional_directories_become_grants(self):
        self.write(".claude/settings.json",
                   {"permissions": {"additionalDirectories": ["/data/work", "/data/notes"]}})
        grants = harnesses.discover(self.home)
        self.assertEqual({str(g.root) for g in grants}, {"/data/work", "/data/notes"})
        self.assertTrue(all(g.agent == "claude-code" for g in grants))

    def test_a_cloud_harness_is_recorded_as_cloud(self):
        self.write(".claude/settings.json", {"permissions": {"additionalDirectories": ["/d"]}})
        self.assertEqual(harnesses.discover(self.home)[0].models, "cloud")

    def test_top_level_additional_directories_are_also_read(self):
        self.write(".claude/settings.json", {"additionalDirectories": ["/d"]})
        self.assertEqual([str(g.root) for g in harnesses.discover(self.home)], ["/d"])


class TestOpenClaw(HarnessCase):
    def test_no_cloud_profiles_means_local_models(self):
        self.write(".openclaw/openclaw.json",
                   {"auth": {"profiles": {}}, "workspace": "/srv/kb",
                    "tools": {"web": {"search": False, "fetch": False}}})
        g = harnesses.discover(self.home)[0]
        self.assertEqual(g.models, "local")

    def test_local_models_still_report_chat_egress(self):
        """The model being local says nothing about where the answer lands."""
        self.write(".openclaw/openclaw.json",
                   {"auth": {"profiles": {}}, "workspace": "/srv/kb",
                    "channels": {"default": "#ops"}})
        self.assertIn("chat-relay", harnesses.discover(self.home)[0].egress)

    def test_web_fetch_enabled_is_egress(self):
        self.write(".openclaw/openclaw.json",
                   {"auth": {"profiles": {}}, "workspace": "/srv/kb",
                    "tools": {"web": {"fetch": True}}})
        self.assertIn("web", harnesses.discover(self.home)[0].egress)

    def test_cloud_profiles_make_it_a_cloud_harness(self):
        self.write(".openclaw/openclaw.json",
                   {"auth": {"profiles": {"anthropic": {}}}, "workspace": "/srv/kb"})
        self.assertEqual(harnesses.discover(self.home)[0].models, "cloud")


class TestUnparsedConfigsAreGrayNotAbsent(unittest.TestCase):
    """An agent config we cannot read is an unknown, not a clean result."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_malformed_config_is_reported_not_swallowed(self):
        p = self.home / ".claude" / "settings.json"
        p.parent.mkdir(parents=True)
        p.write_text("{not json")
        grants, unparsed = harnesses.discover_with_gaps(self.home)
        self.assertEqual(grants, [])
        self.assertEqual([str(u.path) for u in unparsed], [str(p)])

    def test_clean_home_has_no_grants_and_no_gaps(self):
        self.assertEqual(harnesses.discover_with_gaps(self.home), ([], []))


if __name__ == "__main__":
    unittest.main()


class TestProjectLevelAndImplicitRoots(HarnessCase):
    """The grant that matters most is the one no config file records."""

    def test_a_project_with_a_claude_dir_is_an_implicit_working_root(self):
        proj = self.home / "work" / "blog"
        (proj / ".claude").mkdir(parents=True)
        grants, _ = harnesses.discover_with_gaps(self.home, search_roots=[self.home / "work"])
        implicit = [g for g in grants if g.kind == "implicit"]
        self.assertEqual([g.root for g in implicit], [proj])
        self.assertEqual(implicit[0].agent, "claude-code")

    def test_project_level_additional_directories_are_read(self):
        proj = self.home / "work" / "blog"
        self.write("work/blog/.claude/settings.local.json",
                   {"permissions": {"additionalDirectories": ["/data/shared"]}})
        grants, _ = harnesses.discover_with_gaps(self.home, search_roots=[self.home / "work"])
        self.assertIn(Path("/data/shared"), [g.root for g in grants])

    def test_malformed_project_settings_are_a_gap(self):
        self.write("work/blog/.claude/settings.local.json", "{nope")
        _, gaps = harnesses.discover_with_gaps(self.home, search_roots=[self.home / "work"])
        self.assertEqual(len(gaps), 1)

    def test_git_and_vendor_trees_are_not_searched(self):
        (self.home / "work" / "node_modules" / "pkg" / ".claude").mkdir(parents=True)
        grants, _ = harnesses.discover_with_gaps(self.home, search_roots=[self.home / "work"])
        self.assertEqual([g for g in grants if g.kind == "implicit"], [])

    def test_declared_grants_default_to_kind_declared(self):
        self.write(".claude/settings.json", {"additionalDirectories": ["/d"]})
        self.assertEqual(harnesses.discover(self.home)[0].kind, "declared")

    def test_user_asserted_roots_are_included(self):
        grants, _ = harnesses.discover_with_gaps(self.home, assumed_roots=[Path("/launch/here")])
        [g] = grants
        self.assertEqual((g.root, g.kind), (Path("/launch/here"), "assumed"))


class TestGlobalConfigIsNotALaunchRoot(HarnessCase):
    def test_home_dot_claude_does_not_make_home_an_implicit_root(self):
        (self.home / ".claude").mkdir()
        grants, _ = harnesses.discover_with_gaps(self.home, search_roots=[self.home])
        self.assertNotIn(self.home, [g.root for g in grants if g.kind == "implicit"])
