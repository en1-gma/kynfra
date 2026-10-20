"""Test della base di rules.py: configurazione, progetto, struttura e file protetti."""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "plugins" / "kynfra" / "scripts"))

import rules  # noqa: E402


def cfg_for(infra_root="."):
    return rules.normalize_config({"infra_root": infra_root})


class RulesCoreTest(unittest.TestCase):
    def test_no_config_is_noop(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(rules.load_config(Path(d)))

    def test_normalize_defaults(self):
        cfg = rules.normalize_config({})
        self.assertEqual(cfg["iac"], "terraform")
        self.assertEqual(cfg["region"], "eu-south-1")
        self.assertEqual(cfg["infra_root"], ".")
        self.assertEqual(set(cfg["environments"]), {"dev", "staging", "prod"})
        self.assertEqual(cfg["environments"]["dev"], {"account": "main"})
        self.assertEqual(cfg["rules"]["remote-state"], "block")
        self.assertEqual(cfg["rules"]["variables-typed"], "warn")
        self.assertEqual(cfg["scanner"], "checkov")
        self.assertIsNone(cfg["kybes"])
        self.assertEqual(cfg["stop_gate"]["commands"], [])
        self.assertIn("**/.terraform/**", cfg["exclude"])
        self.assertEqual(cfg["literal_reuse"], {"max_duplicate_ratio": 0.10, "min_values": 20})

    def test_default_rules_keys(self):
        warn = {k for k, v in rules.DEFAULT_RULES.items() if v == "warn"}
        self.assertEqual(warn, {"variables-typed", "region-pinning", "literal-reuse", "config"})
        self.assertEqual(len(rules.DEFAULT_RULES), 28)

    def test_load_config_and_discovery(self):
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d).resolve() / "app"
            (proj / ".kynfra").mkdir(parents=True)
            (proj / ".kynfra" / "config.json").write_text('{"project": "acme"}')
            self.assertEqual(rules.load_config(proj)["project"], "acme")
            self.assertEqual(rules.project_for_file(str(proj / "infra" / "new" / "main.tf"), d), proj)
            self.assertEqual(rules.discover_projects(Path(d)), [proj])

    def test_files_outside_infra_root_ignored(self):
        cfg = cfg_for("infra")
        self.assertIsNone(rules.infra_rel("services/x/handler.py", cfg))
        self.assertIsNone(rules.infra_rel(".github/workflows/x.yml", cfg))
        self.assertEqual(rules.infra_rel("infra/envs/dev/spa/main.tf", cfg), "envs/dev/spa/main.tf")
        self.assertEqual(rules.infra_rel("envs/dev/spa/main.tf", cfg_for(".")), "envs/dev/spa/main.tf")

    def test_infra_root_normalization(self):
        for v in ("./infra", "infra/", "infra//", "infra\\"):
            self.assertEqual(cfg_for(v)["infra_root"], "infra", v)
        for v in ("..", "../x", "/abs", "", "."):
            self.assertEqual(cfg_for(v)["infra_root"], ".", v)
        self.assertEqual(rules.infra_rel("infra/envs/dev/spa/main.tf", cfg_for("./infra")), "envs/dev/spa/main.tf")

    def test_is_iac_file(self):
        for ok in ("a.tf", "a.tf.json", "a.tfvars", "a.tfvars.json", "native/spa/t.yaml", "native/spa/t.bicep"):
            self.assertTrue(rules.is_iac_file(ok), ok)
        for no in ("README.md", "modules/spa/x.yaml", "a.py"):
            self.assertFalse(rules.is_iac_file(no), no)

    def test_layout_allowed(self):
        cfg = cfg_for()
        for rel in ("envs/dev/spa/main.tf", "envs/shared/dns/main.tf", "modules/spa/main.tf",
                    "bootstrap/main.tf", "native/spa/template.yaml"):
            self.assertEqual(rules.check_layout(rel, cfg), [], rel)

    def test_layout_rejected(self):
        cfg = cfg_for()
        for rel in ("main.tf", "envs/qa/spa/main.tf", "envs/dev/main.tf", "modules/Spa/main.tf"):
            f = rules.check_layout(rel, cfg)
            self.assertEqual([x.rule for x in f], ["folder-layout"], rel)

    def test_layout_ignores_outside_infra_root(self):
        self.assertEqual(rules.check_layout("main.tf", cfg_for("infra")), [])

    def test_protected(self):
        cfg = cfg_for("infra")
        for rel in (".kynfra/config.json", ".kynfra/tools.lock.json", "tools/kynfra/x", ".claude/settings.json",
                    ".codex/hooks.json", ".claude/rules/kynfra/x.md", ".agents/skills/kynfra-x/SKILL.md",
                    ".github/workflows/kynfra-check.yml", "infra/envs/dev/spa/.terraform.lock.hcl",
                    ".Kynfra/Config.json"):
            f = rules.check_protected(rel, cfg)
            self.assertEqual([x.rule for x in f], ["protected-files"], rel)
        self.assertEqual(rules.check_protected("infra/envs/dev/spa/main.tf", cfg), [])
        self.assertEqual(rules.check_protected("other/.terraform.lock.hcl", cfg), [])

    def test_git_hooks_and_config_protected(self):
        cfg = cfg_for("infra")
        for rel in (".git/hooks/pre-commit", ".git/hooks/post-checkout", ".git/config", ".GIT/Hooks/pre-push"):
            self.assertEqual([x.rule for x in rules.check_protected(rel, cfg)], ["protected-files"], rel)
        for rel in (".github/workflows/ci.yml", ".gitignore", "docs/.git-notes.md"):
            self.assertEqual(rules.check_protected(rel, cfg), [], rel)

    def test_git_worktree_and_module_config_protected(self):
        cfg = cfg_for("infra")
        for rel in (".git/config.worktree", ".git/modules/sub/hooks/pre-commit", ".git/modules/a/b/hooks/x",
                    ".git/modules/sub/config", ".GIT/Modules/Sub/Config"):
            self.assertEqual([x.rule for x in rules.check_protected(rel, cfg)], ["protected-files"], rel)
        for rel in (".git/modules/sub/HEAD", ".git/modules/sub/objects/ab/cd"):
            self.assertEqual(rules.check_protected(rel, cfg), [], rel)

    def test_stack_of(self):
        self.assertEqual(rules.stack_of("envs/prod/spa/main.tf"), ("prod", "spa"))
        self.assertIsNone(rules.stack_of("modules/spa/main.tf"))

    def test_finding_format(self):
        f = rules.Finding("r", "block", "a.tf", 3, "msg", "aws_x.y")
        self.assertEqual(f.format(), "- [r] a.tf:3 (aws_x.y) — msg")
        self.assertEqual(rules.Finding("r", "block", "a.tf", 0, "msg").format(), "- [r] a.tf — msg")

    def test_iter_project_files(self):
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            for rel in ("infra/envs/dev/spa/main.tf", "infra/envs/dev/spa/.terraform/p/x.tf",
                        "infra/README.md", "services/a.tf"):
                (proj / rel).parent.mkdir(parents=True, exist_ok=True)
                (proj / rel).write_text("")
            got = [r for r, _ in rules.iter_project_files(proj, cfg_for("infra"))]
            self.assertEqual(got, ["infra/envs/dev/spa/main.tf"])


if __name__ == "__main__":
    unittest.main()
