"""Test di rules.check_project, load_stacks e literal_reuse."""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "plugins" / "kynfra" / "scripts"))
sys.path.insert(0, str(ROOT / "tests" / "hooks"))

import hcl  # noqa: E402
import rules  # noqa: E402
from test_rules_common import GOOD_BACKEND, GOOD_PROVIDER  # noqa: E402

VERSIONS = 'terraform {\n  required_version = "~> 1.10"\n}\n'


def cfg_for(**raw):
    return rules.normalize_config({"infra_root": ".", "project": "acme", **raw})


def write(base: Path, files: dict):
    for rel, text in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def complete_stack(prefix="envs/dev/spa/"):
    return {prefix + "backend.tf": GOOD_BACKEND, prefix + "versions.tf": VERSIONS,
            prefix + "providers.tf": GOOD_PROVIDER, prefix + "main.tf": "# vuoto\n"}


class StackTest(unittest.TestCase):
    def check(self, files, **kw):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), files)
            return rules.check_project(Path(d), cfg_for(**kw))

    def test_stack_without_backend(self):
        out = self.check({"envs/dev/spa/main.tf": "# x\n"})
        by = {f.rule: f for f in out}
        self.assertEqual(by["remote-state"].severity, "block")
        self.assertEqual(by["remote-state"].path, "envs/dev/spa/")
        self.assertEqual(by["remote-state"].line, 0)
        for rule in ("version-pinning", "required-tags", "account-guard"):
            self.assertEqual(by[rule].path, "envs/dev/spa/")

    def test_stack_complete_ok(self):
        out = self.check(complete_stack())
        self.assertEqual([f for f in out if f.severity == "block"], [])

    def test_no_duplicate_with_per_file_finding(self):
        files = complete_stack()
        files["envs/dev/spa/backend.tf"] = 'terraform {\n  backend "local" {}\n}\n'
        out = [f for f in self.check(files) if f.rule == "remote-state"]
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].path, "envs/dev/spa/backend.tf")

    def test_two_backends(self):
        files = complete_stack()
        files["envs/dev/spa/other.tf"] = GOOD_BACKEND
        out = [f for f in self.check(files) if f.rule == "remote-state"]
        self.assertEqual(len(out), 1)
        self.assertIn("2 backend", out[0].message)

    def test_bootstrap_local_backend_ok(self):
        out = self.check({"bootstrap/main.tf": 'terraform {\n  required_version = "~> 1.10"\n  backend "local" {}\n}\n'
                          + GOOD_PROVIDER})
        self.assertEqual([f for f in out if f.severity == "block"], [])

    def test_bootstrap_missing_version(self):
        out = self.check({"bootstrap/main.tf": GOOD_PROVIDER})
        self.assertEqual([(f.rule, f.path) for f in out if f.severity == "block"],
                         [("version-pinning", "bootstrap/")])

    def test_infra_root_prefix(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), {"infra/envs/dev/spa/main.tf": "# x\n"})
            out = rules.check_project(Path(d), cfg_for(infra_root="infra"))
        self.assertIn("infra/envs/dev/spa/", {f.path for f in out})

    def test_load_stacks(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), complete_stack())
            stacks = rules.load_stacks(Path(d), cfg_for())
        self.assertEqual(list(stacks), [("dev", "spa")])
        self.assertIn("envs/dev/spa/backend.tf", [i for i, _ in stacks[("dev", "spa")]])


def parsed(path, text):
    return path, hcl.parse(text, path.rsplit("/", 1)[-1])


class ReuseTest(unittest.TestCase):
    CIDR = 'resource "aws_security_group_rule" "a" {\n  cidr_blocks = ["10.0.0.0/16"]\n}\n'

    def test_literal_reuse_warn(self):
        files = [parsed("modules/net/a.tf", self.CIDR), parsed("envs/dev/spa/b.tf", self.CIDR)]
        out = rules.literal_reuse(files, cfg_for())
        self.assertEqual(len(out), 1)
        self.assertEqual((out[0].severity, out[0].path), ("warn", "envs/dev/spa/b.tf"))

    def test_same_file_not_flagged(self):
        files = [parsed("modules/net/a.tf", self.CIDR + self.CIDR)]
        self.assertEqual(rules.literal_reuse(files, cfg_for()), [])

    def test_tfvars_are_definitions(self):
        files = [parsed("envs/dev/spa/terraform.tfvars", 'vpc_cidr = "10.0.0.0/16"\n'),
                 parsed("modules/net/a.tf", self.CIDR)]
        self.assertEqual(rules.literal_reuse(files, cfg_for(), stop_gate=True), [])

    def test_ports_fqdn_prefix(self):
        a = 'resource "x" "a" {\n  from_port = 8080\n  host = "api.example.com"\n  name = "acme-dev-api"\n}\n'
        out = rules.literal_reuse([parsed("modules/a/a.tf", a), parsed("modules/b/b.tf", a)], cfg_for())
        self.assertEqual(len(out), 3)

    def test_ignored_values(self):
        a = ('resource "x" "a" {\n  port = 443\n  cidr_blocks = ["0.0.0.0/0"]\n  p = "lambda.amazonaws.com"\n'
             '  other = "foo-bar"\n}\n')
        self.assertEqual(rules.literal_reuse([parsed("modules/a/a.tf", a), parsed("modules/b/b.tf", a)],
                                             cfg_for()), [])

    def test_ratio_blocks_only_at_stop_gate(self):
        files = [parsed(f"modules/m/{n}.tf", self.CIDR) for n in "abcd"]
        cfg = cfg_for(literal_reuse={"min_values": 4})
        self.assertTrue(all(f.severity == "warn" for f in rules.literal_reuse(files, cfg)))
        out = rules.literal_reuse(files, cfg, stop_gate=True)
        blocks = [f for f in out if f.severity == "block"]
        self.assertEqual(len(blocks), 1)
        self.assertIn("10.0.0.0/16", blocks[0].message)

    def test_ratio_below_min_values(self):
        files = [parsed(f"modules/m/{n}.tf", self.CIDR) for n in "ab"]
        out = rules.literal_reuse(files, cfg_for(), stop_gate=True)
        self.assertEqual([f for f in out if f.severity == "block"], [])

    def test_check_project_ratio_survives_post_process(self):
        with tempfile.TemporaryDirectory() as d:
            write(Path(d), {f"modules/m/{n}.tf": self.CIDR for n in "abcd"})
            cfg = cfg_for(literal_reuse={"min_values": 4})
            soft = rules.check_project(Path(d), cfg)
            hard = rules.check_project(Path(d), cfg, stop_gate=True)
        self.assertEqual([f for f in soft if f.rule == "literal-reuse" and f.severity == "block"], [])
        self.assertEqual(len([f for f in hard if f.rule == "literal-reuse" and f.severity == "block"]), 1)


if __name__ == "__main__":
    unittest.main()
