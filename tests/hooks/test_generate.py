"""Test del generatore di pattern (generate.py)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "plugins" / "kynfra" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import arch_check  # noqa: E402
import generate  # noqa: E402
import rules  # noqa: E402

REFERENCE_CONFIG = {
    "iac": "terraform",
    "providers": ["aws"],
    "infra_root": "infra",
    "project": "acme",
    "region": "eu-south-1",
    "accounts": {"main": {"id": "123456789012"}},
    "environments": {"dev": {"account": "main"}, "staging": {"account": "main"}, "prod": {"account": "main"}},
    "tags": {"Owner": "platform", "CostCenter": "cc-001"},
    "scanner": "checkov",
    "rules": {},
    "exceptions": [],
}


def make_project(base: Path, raw: dict = None) -> dict:
    raw = dict(REFERENCE_CONFIG if raw is None else raw)
    (base / ".kynfra").mkdir(parents=True, exist_ok=True)
    (base / ".kynfra/config.json").write_text(json.dumps(raw), encoding="utf-8")
    return rules.load_config(base)


def tree(base: Path) -> dict:
    return {p.relative_to(base).as_posix(): p.read_bytes() for p in sorted(base.rglob("*"))
            if p.is_file() and ".kynfra" not in p.parts}


class RenderTest(unittest.TestCase):
    def test_render_replaces_placeholders(self):
        self.assertEqual(generate.render('a = "{{ name }}" {{x}}', {"name": "acme", "x": "1"}), 'a = "acme" 1')

    def test_render_unknown_placeholder_fails(self):
        with self.assertRaises(generate.GenerateError) as cm:
            generate.render("a = {{ missing }}", {"name": "acme"})
        self.assertIn("missing", str(cm.exception))

    def test_render_rejects_leftover_braces(self):
        with self.assertRaises(generate.GenerateError):
            generate.render("a = {{ not valid }}", {})

    def test_version_constraints_are_pessimistic(self):
        ctx = generate.version_context("terraform")
        for name in generate.VERSION_PLACEHOLDERS:
            self.assertIn(name, ctx)
        self.assertRegex(ctx["tf_version_constraint"], r"^~> \d+\.\d+$")
        self.assertRegex(ctx["aws_provider_constraint"], r"^~> \d+\.\d+$")
        tofu = generate.version_context("opentofu")
        versions = json.loads((ROOT / "plugins/kynfra/templates/versions.json").read_text())
        major, minor = versions["opentofu"]["version"].split(".")[:2]
        self.assertEqual(tofu["tf_version_constraint"], f"~> {major}.{minor}")


class VersionsFileTest(unittest.TestCase):
    def test_versions_file_complete(self):
        v = json.loads((ROOT / "plugins/kynfra/templates/versions.json").read_text())
        for key in ("terraform", "opentofu", "tflint", "tflint_ruleset_aws", "checkov", "trivy", "aws_provider",
                    "helm_provider", "random_provider", "aws_load_balancer_controller_chart", "karpenter_chart",
                    "keda_chart"):
            self.assertRegex(v[key]["version"], r"^\d+\.\d+\.\d+$", key)
        self.assertNotIn("_comment", v)
        self.assertEqual(v["_verified"]["date"], "2026-10-20")


class GenerateTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)
        self.cfg = make_project(self.d)

    def tearDown(self):
        self._tmp.cleanup()

    def test_load_pattern(self):
        p = generate.load_pattern("aws", "bootstrap")
        self.assertEqual(p["requires"], [])
        with self.assertRaises(generate.GenerateError):
            generate.load_pattern("aws", "nope")

    def test_generate_creates_module_and_stacks(self):
        res = generate.generate(self.d, self.cfg, "aws", "bootstrap", ["dev", "prod"], {})
        main = self.d / "infra/bootstrap/main.tf"
        self.assertTrue(main.is_file())
        self.assertIn("infra/bootstrap/main.tf", res["created"])
        text = main.read_text()
        self.assertTrue(text.startswith(f"# Generato da kynfra {generate.kit_version()} — pattern bootstrap\n"))
        tfvars = (self.d / "infra/bootstrap/terraform.tfvars").read_text()
        self.assertIn('"123456789012"', tfvars)
        self.assertIn('"acme"', tfvars)
        for f in res["created"]:
            self.assertNotIn("{{", (self.d / f).read_text(), f)
        self.assertEqual(res["skipped"], [])
        self.assertEqual(res["missing_requires"], [])
        self.assertTrue(res["next_steps"])

    def test_generate_is_deterministic(self):
        with tempfile.TemporaryDirectory() as other:
            o = Path(other)
            cfg2 = make_project(o)
            generate.generate(self.d, self.cfg, "aws", "bootstrap", ["dev", "prod"], {})
            generate.generate(o, cfg2, "aws", "bootstrap", ["dev", "prod"], {})
            self.assertEqual(tree(self.d), tree(o))
            for content in tree(o).values():
                self.assertTrue(content.endswith(b"\n") and not content.endswith(b"\n\n"))

    def test_generate_never_overwrites(self):
        generate.generate(self.d, self.cfg, "aws", "bootstrap", ["dev"], {})
        main = self.d / "infra/bootstrap/main.tf"
        main.write_text("# personalizzato\n")
        res = generate.generate(self.d, self.cfg, "aws", "bootstrap", ["dev"], {})
        self.assertIn("infra/bootstrap/main.tf", res["skipped"])
        self.assertEqual(res["created"], [])
        self.assertEqual(main.read_text(), "# personalizzato\n")
        res = generate.generate(self.d, self.cfg, "aws", "bootstrap", ["dev"], {}, force=True)
        self.assertIn("infra/bootstrap/main.tf", res["created"])
        self.assertNotEqual(main.read_text(), "# personalizzato\n")

    def test_upgrade_reports_diff_only(self):
        generate.generate(self.d, self.cfg, "aws", "bootstrap", ["dev"], {})
        main = self.d / "infra/bootstrap/main.tf"
        main.write_text(main.read_text() + "# aggiunta locale\n")
        before = tree(self.d)
        res = generate.generate(self.d, self.cfg, "aws", "bootstrap", ["dev"], {}, upgrade=True)
        self.assertEqual(tree(self.d), before)
        self.assertEqual(res["created"], [])
        self.assertEqual(list(res["diffs"]), ["infra/bootstrap/main.tf"])
        self.assertIn("-# aggiunta locale", res["diffs"]["infra/bootstrap/main.tf"])

    def test_upgrade_on_empty_project_writes_nothing(self):
        res = generate.generate(self.d, self.cfg, "aws", "bootstrap", ["dev"], {}, upgrade=True)
        self.assertFalse((self.d / "infra").exists())
        self.assertIn("infra/bootstrap/main.tf", res["diffs"])

    def test_unknown_env_fails(self):
        with self.assertRaises(generate.GenerateError):
            generate.generate(self.d, self.cfg, "aws", "bootstrap", ["qa"], {})

    def test_unsafe_value_rejected(self):
        raw = dict(REFERENCE_CONFIG, tags={"Owner": 'x" }', "CostCenter": "cc"})
        cfg = make_project(self.d, raw)
        with self.assertRaises(generate.GenerateError):
            generate.generate(self.d, cfg, "aws", "bootstrap", ["dev"], {})

    def test_empty_owner_rejected(self):
        cfg = make_project(self.d, dict(REFERENCE_CONFIG, tags={"Owner": "", "CostCenter": "cc"}))
        with self.assertRaises(generate.GenerateError) as cm:
            generate.generate(self.d, cfg, "aws", "bootstrap", ["dev"], {})
        self.assertIn("Owner", str(cm.exception))

    def test_pattern_bootstrap_passes_arch_check(self):
        generate.generate(self.d, self.cfg, "aws", "bootstrap", ["dev", "prod"], {})
        findings = arch_check.run(self.d, self.cfg)
        self.assertEqual([f.format() for f in findings], [])


FAKE_PATTERNS = {
    "network": {"description": "rete", "requires": [], "inputs": {}, "stacks": ["network"], "shared": False},
    "elb": {"description": "lb", "requires": ["network"],
            "inputs": {"domain": {"type": "string", "required": True, "help": "dominio"},
                       "deletion_protection": {"type": "bool", "required": False, "default": "false",
                                               "help": "protezione"}},
            "env_defaults": {"prod": {"deletion_protection": "true"}},
            "stacks": ["elb"], "shared": False, "next_steps": ["init in envs/{{ envs }}"]},
}


class FakeTemplatesTest(unittest.TestCase):
    """Pattern con modulo e stack, su template finti (i pattern veri arrivano con i task successivi)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.tpl = base / "templates"
        aws = self.tpl / "aws"
        (aws / "modules/elb").mkdir(parents=True)
        (aws / "modules/elb/main.tf").write_text("# modulo {{ project }}\n")
        (aws / "stacks/elb").mkdir(parents=True)
        (aws / "stacks/elb/terraform.tfvars").write_text(
            'environment = "{{ environment }}"\ndomain = "{{ domain }}"\nprotection = {{ deletion_protection }}\n'
            'key = "{{ state_key }}"\n')
        (aws / "stacks/network").mkdir(parents=True)
        (aws / "stacks/network/main.tf").write_text("# rete\n")
        (aws / "patterns.json").write_text(json.dumps(FAKE_PATTERNS))
        (self.tpl / "versions.json").write_text(
            (ROOT / "plugins/kynfra/templates/versions.json").read_text())
        self.d = base / "proj"
        self.cfg = make_project(self.d)
        self.patch = mock.patch.object(generate, "TEMPLATES", self.tpl)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self._tmp.cleanup()

    def test_missing_requires_reported(self):
        res = generate.generate(self.d, self.cfg, "aws", "elb", ["dev", "prod"], {"domain": "example.com"})
        self.assertEqual(res["missing_requires"], ["network"])
        generate.generate(self.d, self.cfg, "aws", "network", ["dev", "prod"], {})
        res = generate.generate(self.d, self.cfg, "aws", "elb", ["dev", "prod"], {"domain": "example.com"},
                                force=True)
        self.assertEqual(res["missing_requires"], [])

    def test_module_and_stack_per_env(self):
        res = generate.generate(self.d, self.cfg, "aws", "elb", ["dev", "prod"], {"domain": "example.com"})
        self.assertEqual(res["created"], ["infra/envs/dev/elb/terraform.tfvars", "infra/envs/prod/elb/terraform.tfvars",
                                          "infra/modules/elb/main.tf"])
        dev = (self.d / "infra/envs/dev/elb/terraform.tfvars").read_text()
        prod = (self.d / "infra/envs/prod/elb/terraform.tfvars").read_text()
        self.assertIn("protection = false", dev)
        self.assertIn("protection = true", prod)  # valore prod-restrittivo da patterns.json
        self.assertIn('key = "acme/prod/elb.tfstate"', prod)
        self.assertIn('environment = "dev"', dev)
        res = generate.generate(self.d, self.cfg, "aws", "elb", ["prod"],
                                {"domain": "example.com", "deletion_protection": "false"}, force=True)
        self.assertIn("protection = false", (self.d / "infra/envs/prod/elb/terraform.tfvars").read_text())

    def test_required_input_missing(self):
        with self.assertRaises(generate.GenerateError) as cm:
            generate.generate(self.d, self.cfg, "aws", "elb", ["dev"], {})
        self.assertIn("domain", str(cm.exception))

    def test_unknown_var_and_bad_bool(self):
        with self.assertRaises(generate.GenerateError):
            generate.generate(self.d, self.cfg, "aws", "elb", ["dev"], {"domain": "a.com", "nope": "1"})
        with self.assertRaises(generate.GenerateError):
            generate.generate(self.d, self.cfg, "aws", "elb", ["dev"],
                              {"domain": "a.com", "deletion_protection": "yes"})


def clean_env() -> dict:
    return {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PROJECT_DIR", "KYNFRA_PROJECT_DIR")}


class CliTest(unittest.TestCase):
    def test_cli_json(self):
        with tempfile.TemporaryDirectory() as d:
            make_project(Path(d))
            r = subprocess.run([sys.executable, "-B", str(SCRIPTS / "generate.py"), "--pattern", "bootstrap",
                                "--provider", "aws", "--env", "dev,prod", "--json"],
                               cwd=d, capture_output=True, text=True, env=clean_env())
            self.assertEqual(r.returncode, 0, r.stderr)
            out = json.loads(r.stdout)
            self.assertIn("infra/bootstrap/main.tf", out["created"])

    def test_cli_error_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            make_project(Path(d))
            r = subprocess.run([sys.executable, "-B", str(SCRIPTS / "generate.py"), "--pattern", "nope",
                                "--provider", "aws", "--env", "dev"],
                               cwd=d, capture_output=True, text=True, env=clean_env())
            self.assertEqual(r.returncode, 2)
            self.assertIn("nope", r.stderr)


if __name__ == "__main__":
    unittest.main()
