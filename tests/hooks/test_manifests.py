"""Coerenza dei manifest del plugin kynfra (Claude Code e Codex)."""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLAUDE_MARKET = ROOT / ".claude-plugin" / "marketplace.json"
CODEX_MARKET = ROOT / ".agents" / "plugins" / "marketplace.json"
CLAUDE_PLUGIN = ROOT / "plugins" / "kynfra" / ".claude-plugin" / "plugin.json"
CODEX_PLUGIN = ROOT / "plugins" / "kynfra" / ".codex-plugin" / "plugin.json"


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


class ManifestsTest(unittest.TestCase):
    def test_manifests_consistent(self):
        claude_market, codex_market = load(CLAUDE_MARKET), load(CODEX_MARKET)
        claude_plugin, codex_plugin = load(CLAUDE_PLUGIN), load(CODEX_PLUGIN)

        self.assertEqual(claude_market["name"], "kynfra")
        self.assertEqual(codex_market["name"], "kynfra")
        self.assertEqual(claude_plugin["name"], "kynfra")
        self.assertEqual(codex_plugin["name"], "kynfra")
        self.assertEqual(claude_market["plugins"][0]["name"], "kynfra")
        self.assertEqual(codex_market["plugins"][0]["name"], "kynfra")

        self.assertEqual(claude_plugin["version"], codex_plugin["version"])

        claude_source = claude_market["plugins"][0]["source"]
        codex_source = codex_market["plugins"][0]["source"]["path"]
        self.assertEqual(claude_source, "./plugins/kynfra")
        self.assertEqual(codex_source, "./plugins/kynfra")
        self.assertTrue((ROOT / claude_source).is_dir())
        self.assertTrue((ROOT / codex_source).is_dir())

        self.assertEqual(codex_plugin["skills"], "./skills/")
        self.assertEqual(codex_plugin["hooks"], "./hooks/hooks.json")


if __name__ == "__main__":
    unittest.main()
