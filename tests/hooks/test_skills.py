"""Test delle skill e degli agenti di base di kynfra."""
import json
import re
import sys
import unittest
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[2] / "plugins" / "kynfra"
sys.path.insert(0, str(PLUGIN / "scripts"))
import rules  # noqa: E402

SKILLS = PLUGIN / "skills"
CORE = ("kynfra-architecture", "kynfra-init", "kynfra-plan", "kynfra-review", "kynfra-tools")


def frontmatter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert m, f"{path}: frontmatter mancante"
    out, key = {}, None
    for line in m.group(1).splitlines():
        if re.match(r"^\s+- ", line) and key:
            out[key].append(line.split("- ", 1)[1].strip())
        elif ":" in line:
            key, _, val = line.partition(":")
            key, val = key.strip(), val.strip()
            out[key] = [] if val == "" else val
    return out


class SkillsTest(unittest.TestCase):
    def test_skill_frontmatter(self):
        for name in CORE:
            with self.subTest(skill=name):
                fm = frontmatter(SKILLS / name / "SKILL.md")
                self.assertEqual(fm["name"], name)
                self.assertRegex(fm["name"], r"^[a-z0-9-]+$")
                self.assertTrue(fm["description"])

    def test_agents_frontmatter(self):
        expected = {"architect": "Read, Glob, Grep", "implementer": None, "reviewer": "Read, Glob, Grep, Bash"}
        for name, tools in expected.items():
            with self.subTest(agent=name):
                fm = frontmatter(PLUGIN / "agents" / f"{name}.md")
                self.assertEqual(fm["name"], name)
                self.assertTrue(fm["description"])
                self.assertEqual(fm.get("tools"), tools)
                self.assertEqual(fm["skills"], ["kynfra-architecture"])

    def test_codex_yaml_present(self):
        for name in CORE:
            with self.subTest(skill=name):
                y = (SKILLS / name / "agents" / "openai.yaml").read_text(encoding="utf-8")
                self.assertIn("interface:", y)
                self.assertIn(f"${name}", y)
                self.assertIn("display_name", y)

    def test_architecture_mentions_every_rule(self):
        text = (SKILLS / "kynfra-architecture" / "SKILL.md").read_text(encoding="utf-8")
        for rule in rules.DEFAULT_RULES:
            with self.subTest(rule=rule):
                self.assertIn(f"`{rule}`", text)

    def test_architecture_reference_covers_patterns(self):
        ref = (SKILLS / "kynfra-architecture" / "references" / "aws.md").read_text(encoding="utf-8")
        for token in ("redirect-to-https", "TLSv1.2_2021", "ELBSecurityPolicy-TLS13-1-2-2021-06",
                      "drop_invalid_header_fields = true", "IMMUTABLE", "http_tokens = \"required\"",
                      "enable_key_rotation = true", "use_lockfile = true", "encrypt = true", "Context7"):
            with self.subTest(token=token):
                self.assertIn(token, ref)
        for pattern in ("network", "spa", "backend", "elb", "eks", "ecr", "secrets"):
            self.assertRegex(ref, rf"(?m)^## .*\b{pattern}\b")

    def test_brand_color_matches_plugin(self):
        brand = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        color = next(v for k, v in _walk(brand) if k == "brandColor")
        for name in CORE:
            with self.subTest(skill=name):
                y = (SKILLS / name / "agents" / "openai.yaml").read_text(encoding="utf-8")
                self.assertIn(f'brand_color: "{color}"', y)

    def test_tools_skill_one_at_a_time(self):
        text = (SKILLS / "kynfra-tools" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("uno strumento alla volta", text)
        for needle in ("tools.py status", "tools.py plan", "--approved-by", "tools.lock.json", "richiesto", "opzionale"):
            self.assertIn(needle, text)
        found = False
        for line in text.splitlines():
            m = re.search(r"tools\.py install\s+(.*)", line)
            if m:
                found = True
                before = m.group(1).split("--approved-by")[0]
                args = [w for w in before.split() if not w.startswith("-")]
                self.assertEqual(len(args), 1, line)
        self.assertTrue(found)


def _walk(d):
    if isinstance(d, dict):
        for k, v in d.items():
            yield k, v
            yield from _walk(v)
    elif isinstance(d, list):
        for v in d:
            yield from _walk(v)


if __name__ == "__main__":
    unittest.main()
