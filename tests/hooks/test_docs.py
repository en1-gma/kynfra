"""Coerenza tra documentazione, workflow CI e prodotto: ogni regola, pattern e skill è documentato, la matrice della CI
elenca esattamente i pattern del kit, i link relativi dei documenti risolvono."""
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins" / "kynfra"
DOCS = ROOT / "docs"
sys.path.insert(0, str(PLUGIN / "scripts"))
import rules  # noqa: E402

WORKFLOW = ROOT / ".github" / "workflows" / "kit-tests.yml"
PAGES = ("README", "architettura", "configurazione", "controlli", "strumenti", "segreti", "account", "codex",
         "sviluppo", "roadmap")


def pattern_keys() -> list:
    data = json.loads((PLUGIN / "templates" / "aws" / "patterns.json").read_text(encoding="utf-8"))
    return sorted(k for k in data if not k.startswith("_"))


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class DocsTest(unittest.TestCase):
    def test_docs_cover_rules(self):
        text = read(DOCS / "controlli.md")
        for rule in rules.DEFAULT_RULES:
            self.assertIn(f"`{rule}`", text, f"regola '{rule}' non documentata in docs/controlli.md")

    def test_docs_cover_patterns(self):
        readme = read(ROOT / "README.md")
        for p in pattern_keys():
            if p == "bootstrap":
                self.assertIn("bootstrap", readme)
                continue  # il bootstrap non ha una pagina di pattern: sta in architettura.md
            page = DOCS / "pattern" / f"{p}.md"
            self.assertTrue(page.is_file(), f"manca docs/pattern/{p}.md")
            self.assertIn("```mermaid", read(page), f"{page.name}: manca il diagramma Mermaid")
            self.assertIn(f"/kynfra:create-{p}-infra-aws", readme, f"pattern '{p}' assente dal README")
            self.assertIn(f"pattern/{p}.md", read(DOCS / "README.md"), f"pattern '{p}' assente dall'indice docs")

    def test_every_skill_in_readme(self):
        readme = read(ROOT / "README.md")
        for d in sorted((PLUGIN / "skills").iterdir()):
            if d.is_dir():
                self.assertIn(d.name, readme, f"skill '{d.name}' assente dal README")

    def test_docs_pages_exist_and_are_indexed(self):
        index = read(DOCS / "README.md")
        for page in PAGES:
            self.assertTrue((DOCS / f"{page}.md").is_file(), f"manca docs/{page}.md")
            if page != "README":
                self.assertIn(f"]({page}.md", index, f"docs/{page}.md non è nell'indice")
        self.assertTrue((DOCS / "assets" / "kynfra-banner.svg").is_file())

    def test_relative_links_resolve(self):
        files = [ROOT / "README.md", *sorted(DOCS.glob("*.md")), *sorted((DOCS / "pattern").glob("*.md"))]
        for f in files:
            for target in re.findall(r"\]\((?!https?://|#|mailto:)([^)\s]+)\)", read(f)):
                path = target.split("#", 1)[0]
                if path:
                    self.assertTrue((f.parent / path).exists(), f"{f.relative_to(ROOT)}: link rotto '{target}'")

    def test_every_config_key_documented(self):
        text = read(DOCS / "configurazione.md")
        for key in rules.normalize_config({}):
            self.assertIn(f"`{key}", text, f"chiave di config '{key}' non documentata")

    def test_workflow_matrix_matches_patterns(self):
        text = read(WORKFLOW)
        m = re.search(r"^\s*pattern:\s*\[([^\]]*)\]", text, re.M)
        self.assertIsNotNone(m, "matrice 'pattern: [...]' non trovata in kit-tests.yml")
        listed = sorted(x.strip().strip("\"'") for x in m.group(1).split(",") if x.strip())
        self.assertEqual(listed, pattern_keys())

    def test_workflow_is_least_privilege_and_complete(self):
        text = read(WORKFLOW)
        self.assertRegex(text, r"(?m)^permissions:\n  contents: read\n")
        self.assertNotIn("id-token", text, "la CI del kit non usa OIDC né credenziali cloud")
        self.assertNotRegex(text, r"(?i)aws-actions|AWS_ACCESS_KEY|AWS_SECRET|secrets\.")
        self.assertRegex(text, r"(?m)^  hooks:")
        self.assertRegex(text, r"(?m)^  patterns:")
        self.assertIn("bash tests/run.sh --patterns ${{ matrix.pattern }}", text)
        self.assertIn("KYNFRA_REQUIRE_TOOLS=1", text)
        self.assertIn("KYNFRA_TOOLS_PROJECT=$GITHUB_WORKSPACE", text)
        for tool in ("terraform", "tflint", "tflint-ruleset-aws", "checkov"):
            self.assertIn(f"tools.py install {tool} --approved-by ci", text, f"manca l'installazione di {tool}")
        self.assertRegex(text, r'python:\s*\[[^\]]*"3\.10"', "manca la gamba Python 3.10 (versione minima)")

    def test_workflow_pins_actions_to_versions(self):
        for use in re.findall(r"uses:\s*(\S+)", read(WORKFLOW)):
            self.assertRegex(use, r"@v\d+$", f"azione non fissata a una versione: {use}")

    def test_gitignore_has_local_tools_dir(self):
        self.assertIn(".kynfra/", read(ROOT / ".gitignore").splitlines())


if __name__ == "__main__":
    unittest.main()
