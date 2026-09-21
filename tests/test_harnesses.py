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
