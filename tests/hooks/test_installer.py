"""Test dell'installer: esegue install.sh in cartelle temporanee con --no-plugin (nessuna chiamata a `claude`).

Esecuzione: python3 -B -m unittest discover -s tests/hooks -v
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins" / "kynfra"
sys.path.insert(0, str(PLUGIN / "scripts"))

import rules  # noqa: E402


class InstallerCase(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        self.d = tmp / "my_Proj "
        self.d.mkdir()

    def run_install(self, *extra, check=True):
        cmd = ["bash", str(PLUGIN / "install.sh"), "--target", str(self.d), "--no-plugin", *extra]
        return subprocess.run(cmd, check=check, capture_output=True, text=True)

    def cfg(self):
        return json.loads((self.d / ".kynfra/config.json").read_text())


class InstallerTest(InstallerCase):
    def test_install_plain_repo(self):
        res = self.run_install("--account-id", "123456789012")
        cfg = self.cfg()
        self.assertEqual(cfg["infra_root"], ".")
        self.assertEqual(cfg["iac"], "terraform")
        self.assertEqual(cfg["project"], "my-proj")  # kebab-case dal nome cartella
        self.assertEqual(cfg["region"], "eu-south-1")
        self.assertEqual(cfg["accounts"], {"main": {"id": "123456789012"}})
        self.assertEqual(cfg["environments"], {e: {"account": "main"} for e in ("dev", "staging", "prod")})
        self.assertNotIn("kybes", cfg)
        self.assertIn("tags", cfg)
        self.assertNotIn("000000000000", res.stdout)
        self.assertIn("Owner", res.stdout)  # avviso sui tag da compilare
        # la config è accettata dal motore delle regole
        self.assertEqual(rules.normalize_config(cfg)["infra_root"], ".")
        tflint = (self.d / ".tflint.hcl").read_text()
        versions = json.loads((PLUGIN / "templates/versions.json").read_text())
        self.assertIn(versions["tflint_ruleset_aws"]["version"], tflint)
        self.assertIn('call_module_type = "local"', tflint)
        self.assertIn("github.com/terraform-linters/tflint-ruleset-aws", tflint)
        self.assertTrue((self.d / "tools/kynfra/plugins/kynfra/scripts/arch_check.py").is_file())
        rule = (self.d / ".claude/rules/kynfra/shared.md").read_text()
        self.assertIn('"**/*.tf"', rule)
        self.assertNotIn("__", rule)

    def test_placeholder_account_warns(self):
        res = self.run_install()
        self.assertEqual(self.cfg()["accounts"]["main"]["id"], "000000000000")
        self.assertIn("000000000000", res.stdout)

    def test_no_iac_files_written(self):
        self.run_install()
        found = [p for p in self.d.rglob("*") if p.is_file() and "tools/kynfra" not in p.as_posix()
                 and p.name.endswith((".tf", ".tfvars", ".tf.json"))]
        self.assertEqual(found, [])

    def test_install_detects_kybes(self):
        (self.d / ".kybes").mkdir()
        self.run_install("--envs", "dev,prod")
        cfg = self.cfg()
        self.assertEqual(cfg["infra_root"], "infra")
        self.assertTrue((self.d / "infra").is_dir())
        self.assertEqual(cfg["kybes"], {"root": ".", "openapi": "schemas/openapi.yaml"})
        self.assertEqual(set(cfg["environments"]), {"dev", "prod"})
        self.assertTrue((self.d / "infra/.tflint.hcl").is_file())
        self.assertFalse((self.d / ".tflint.hcl").exists())
        self.assertIn('"infra/**/*.tf"', (self.d / ".claude/rules/kynfra/aws.md").read_text())

    def test_infra_root_detection_and_override(self):
        (self.d / "infra").mkdir()
        self.run_install()
        self.assertEqual(self.cfg()["infra_root"], "infra")
        other = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, other, True)
        subprocess.run(["bash", str(PLUGIN / "install.sh"), "--target", str(other), "--no-plugin",
                        "--infra-root", "cloud", "--iac", "opentofu"], check=True, capture_output=True)
        cfg = json.loads((other / ".kynfra/config.json").read_text())
        self.assertEqual((cfg["infra_root"], cfg["iac"]), ("cloud", "opentofu"))
        self.assertTrue((other / "cloud/.tflint.hcl").is_file())
        bad = subprocess.run(["bash", str(PLUGIN / "install.sh"), "--target", str(other), "--no-plugin",
                              "--infra-root", "../x"], capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)

    def test_install_idempotent(self):
        (self.d / "AGENTS.md").write_text("# Note del team\n")
        self.run_install()
        cfg_path = self.d / ".kynfra/config.json"
        cfg = json.loads(cfg_path.read_text())
        cfg["tags"] = {"Owner": "team-x", "CostCenter": "cc1"}
        cfg_path.write_text(json.dumps(cfg))
        (self.d / ".tflint.hcl").write_text("# mio\n")
        before = cfg_path.read_text()
        self.run_install("--project", "altro", "--region", "us-east-1")
        self.assertEqual(cfg_path.read_text(), before)
        self.assertEqual((self.d / ".tflint.hcl").read_text(), "# mio\n")
        for f in ("CLAUDE.md", "AGENTS.md"):
            self.assertEqual((self.d / f).read_text().count("kynfra:start"), 1)
        self.assertTrue((self.d / "AGENTS.md").read_text().startswith("# Note del team"))
        gi = (self.d / ".gitignore").read_text().splitlines()
        for line in (".kynfra/bin/", ".kynfra/venv/", ".kynfra/tflint.d/", "**/.terraform/"):
            self.assertEqual(gi.count(line), 1)
        deny = json.loads((self.d / ".claude/settings.json").read_text())["permissions"]["deny"]
        self.assertEqual(len(deny), len(set(deny)))
        hooks = json.loads((self.d / ".codex/hooks.json").read_text())["hooks"]
        self.assertEqual(len(hooks["PreToolUse"]), 2)

    def test_force_overwrites_config(self):
        self.run_install()
        (self.d / ".kynfra/config.json").write_text("{}")
        self.run_install("--force")
        self.assertEqual(self.cfg()["project"], "my-proj")

    def test_install_codex_files(self):
        self.run_install()
        for r in ("architect", "implementer", "reviewer"):
            self.assertTrue((self.d / f".codex/agents/kynfra_{r}.toml").is_file())
        hooks = json.loads((self.d / ".codex/hooks.json").read_text())["hooks"]
        self.assertEqual(set(hooks), {"SessionStart", "PreToolUse", "PostToolUse", "Stop"})
        self.assertIn("tools/kynfra/plugins/kynfra/scripts/stop_gate.py", json.dumps(hooks["Stop"]))
        self.assertIn("kynfra:start", (self.d / "AGENTS.md").read_text())
        self.assertTrue((self.d / ".agents/skills").is_dir())

    def test_codex_hooks_merge_keeps_foreign(self):
        (self.d / ".codex").mkdir()
        (self.d / ".codex/hooks.json").write_text(json.dumps(
            {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo altro"}]}]}}))
        self.run_install()
        self.assertEqual(len(json.loads((self.d / ".codex/hooks.json").read_text())["hooks"]["Stop"]), 2)
        self.run_install("--uninstall")
        left = json.loads((self.d / ".codex/hooks.json").read_text())["hooks"]
        self.assertEqual(json.dumps(left), json.dumps({"Stop": [{"hooks": [{"type": "command", "command": "echo altro"}]}]}))

    def test_install_claude_deny_rules(self):
        self.run_install("--agents", "claude")
        deny = json.loads((self.d / ".claude/settings.json").read_text())["permissions"]["deny"]
        for r in ("Edit(.kynfra/**)", "Edit(tools/kynfra/**)", "Edit(.claude/settings.json)",
                  "Edit(.claude/settings.local.json)"):
            self.assertIn(r, deny)
        self.assertFalse((self.d / ".codex").exists())
        text = (self.d / "CLAUDE.md").read_text()
        self.assertIn("/kynfra:create-<pattern>-infra-aws", text)
        self.assertIn("kynfra:architect", text)
        for name in ("shared", "aws", "security"):
            body = (self.d / f".claude/rules/kynfra/{name}.md").read_text()
            self.assertTrue(body.startswith("---\npaths:"))
            self.assertIn("**/*.tfvars", body)
            self.assertIn("**/*.tf.json", body)

    def test_uninstall_keeps_config(self):
        (self.d / "CLAUDE.md").write_text("# Mio\n")
        self.run_install()
        self.run_install("--uninstall")
        self.assertTrue((self.d / ".kynfra/config.json").is_file())
        self.assertTrue((self.d / ".tflint.hcl").is_file())
        self.assertFalse((self.d / "tools/kynfra").exists())
        self.assertFalse((self.d / ".claude/settings.json").exists())
        self.assertFalse((self.d / ".codex/hooks.json").exists())
        self.assertFalse((self.d / ".github/workflows/kynfra-check.yml").exists())
        self.assertEqual((self.d / "CLAUDE.md").read_text().strip(), "# Mio")
        self.run_install("--uninstall", "--force")
        self.assertFalse((self.d / ".kynfra").exists())

    def test_ci_workflow_no_cloud_credentials(self):
        self.run_install()
        wf = (self.d / ".github/workflows/kynfra-check.yml").read_text()
        self.assertNotIn("aws-actions/configure-aws-credentials", wf)
        self.assertNotIn("id-token", wf)
        self.assertIn("contents: read", wf)
        self.assertIn("python-version: \"3.12\"", wf)
        for tool in ("terraform", "tflint", "tflint-ruleset-aws", "checkov"):
            self.assertIn(f"tools.py install {tool} --approved-by ci", wf)
        self.assertIn("arch_check.py . --strict --external", wf)
        self.assertNotIn("__", wf)

    def test_ci_opentofu_and_none(self):
        self.run_install("--iac", "opentofu")
        wf = (self.d / ".github/workflows/kynfra-check.yml").read_text()
        self.assertIn("tools.py install opentofu --approved-by ci", wf)
        self.assertNotIn("install terraform", wf)
        other = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, other, True)
        subprocess.run(["bash", str(PLUGIN / "install.sh"), "--target", str(other), "--no-plugin", "--ci", "none"],
                       check=True, capture_output=True)
        self.assertFalse((other / ".github").exists())

    def test_tflint_hcl_is_not_iac(self):
        self.run_install()
        self.assertFalse(rules.is_iac_file(".tflint.hcl"))
        cfg = rules.normalize_config(self.cfg())
        self.assertEqual(rules.check_layout(".tflint.hcl", cfg), [])

    def test_bash_syntax_and_templates_valid(self):
        subprocess.run(["bash", "-n", str(PLUGIN / "install.sh")], check=True)
        subprocess.run(["bash", "-n", str(PLUGIN / "templates/setup.sh")], check=True)
        json.loads((PLUGIN / "templates/codex-hooks.json").read_text())

    def test_invalid_json_settings_abort_before_any_write(self):
        for rel in (".claude/settings.json", ".codex/hooks.json"):
            with self.subTest(rel=rel):
                d = Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, d, True)
                (d / rel).parent.mkdir(parents=True)
                (d / rel).write_text('{ // commento\n "permissions": {} }\n')
                res = subprocess.run(["bash", str(PLUGIN / "install.sh"), "--target", str(d), "--no-plugin"],
                                     capture_output=True, text=True)
                self.assertNotEqual(res.returncode, 0)
                self.assertIn(rel, res.stderr)
                self.assertEqual(sorted(p.relative_to(d).as_posix() for p in d.rglob("*") if p.is_file()), [rel])

    def test_help_lists_every_flag(self):
        res = subprocess.run(["bash", str(PLUGIN / "install.sh"), "--help"], check=True, capture_output=True, text=True)
        for flag in ("--target", "--iac", "--providers", "--infra-root", "--project", "--envs", "--region",
                     "--account-id", "--agents", "--ci", "--scope", "--no-plugin", "--force", "--uninstall"):
            self.assertIn(flag, res.stdout)

    def test_invalid_values_rejected(self):
        bad = [("--project", "My_Proj"), ("--project", "-x"), ("--account-id", "123"), ("--account-id", "12345678901a"),
               ("--region", "Europe"), ("--region", "eu-south-x"), ("--scope", "global"),
               ("--envs", "dev,Prod"), ("--envs", "dev,a_b"), ("--infra-root", "a|b"),
               ("--infra-root", "a&b"), ("--infra-root", "a\\b")]
        for flag, val in bad:
            with self.subTest(flag=flag, val=val):
                d = Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, d, True)
                res = subprocess.run(["bash", str(PLUGIN / "install.sh"), "--target", str(d), "--no-plugin", flag, val],
                                     capture_output=True, text=True)
                self.assertNotEqual(res.returncode, 0)
                self.assertFalse((d / ".kynfra").exists())
                self.assertFalse((d / "tools").exists())
        self.run_install("--project", "ok-1", "--account-id", "123456789012", "--region", "us-east-1",
                         "--scope", "user", "--envs", "dev,prod-eu")


if __name__ == "__main__":
    unittest.main()
