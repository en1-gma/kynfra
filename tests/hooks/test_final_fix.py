"""Test della final review fix wave (C1, I1–I6, F1, F3, F9 e correzioni minori).

I comandi di prova sono stringhe passate a bash_guard (analisi statica) o eventi JSON passati agli hook: non vengono
mai eseguiti da una shell.

Esecuzione: python3 -B -m unittest discover -s tests/hooks -v
"""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins" / "kynfra"
SCRIPTS = PLUGIN / "scripts"
sys.path.insert(0, str(SCRIPTS))

import bash_guard  # noqa: E402
import generate  # noqa: E402
import pre_write  # noqa: E402
import rules  # noqa: E402
import rules_aws  # noqa: E402

KIT = "tools/kynfra/plugins/kynfra/scripts"
STACK = "envs/dev/spa/"


def make_project(raw: dict) -> Path:
    d = Path(tempfile.mkdtemp(prefix="kynfra-ff-")).resolve()
    (d / ".kynfra").mkdir()
    (d / ".kynfra" / "config.json").write_text(json.dumps(raw), encoding="utf-8")
    return d


def put(proj: Path, rel: str, text: str) -> Path:
    p = proj / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def run_script(script: str, event: dict) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PROJECT_DIR", "KYNFRA_PROJECT_DIR")}
    return subprocess.run([sys.executable, "-B", str(SCRIPTS / script)], input=json.dumps(event),
                          capture_output=True, text=True, timeout=60, env=env)


def decision(r: subprocess.CompletedProcess) -> str:
    out = json.loads(r.stdout) if r.stdout.strip() else {}
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision", "")


def bash_event(proj: Path, command: str, tool: str = "Bash") -> dict:
    return {"cwd": str(proj), "hook_event_name": "PreToolUse", "tool_name": tool, "session_id": "ff-" + proj.name,
            "tool_input": {"command": command}}


def write_event(proj: Path, path: str, content: str) -> dict:
    return {"cwd": str(proj), "hook_event_name": "PreToolUse", "tool_name": "Write", "session_id": "ff",
            "tool_input": {"file_path": path, "content": content}}


def content(rel: str, text: str, cfg: dict = None, rule: str = None):
    out = rules.check_content(rel, text, cfg or rules.normalize_config({"infra_root": "."}))
    return [f for f in out if rule is None or f.rule == rule]


class TempProject(unittest.TestCase):
    raw: dict = {"project": "acme"}

    def setUp(self):
        self.proj = make_project(self.raw)
        self.addCleanup(shutil.rmtree, self.proj, True)
        self.old_env = {k: os.environ.pop(k) for k in ("CLAUDE_PROJECT_DIR", "KYNFRA_PROJECT_DIR") if k in os.environ}
        self.addCleanup(os.environ.update, self.old_env)

    def guard(self, cmd: str):
        return bash_guard.check(cmd, self.proj, self.proj, rules.load_config(self.proj))

    def assert_denied(self, cmds):
        for c in cmds:
            with self.subTest(cmd=c):
                self.assertTrue(self.guard(c), f"doveva essere rifiutato: {c!r}")

    def assert_allowed(self, cmds):
        for c in cmds:
            with self.subTest(cmd=c):
                self.assertEqual(self.guard(c), [], f"doveva essere consentito: {c!r}")


# ---------------------------------------------------------------- C1: moduli e provider di terze parti

class C1ThirdPartyTest(unittest.TestCase):
    def test_registry_module_blocked_even_pinned(self):
        text = ('module "b" {\n  source  = "terraform-aws-modules/s3-bucket/aws"\n  version = "4.1.2"\n'
                '  acl     = "public-read"\n}\n')
        f = content(STACK + "main.tf", text, rule="module-source")
        self.assertEqual(len(f), 1, [x.format() for x in f])
        self.assertEqual(f[0].severity, "block")
        self.assertEqual(f[0].line, 2)

    def test_git_module_blocked_even_with_tag(self):
        text = 'module "x" {\n  source = "git::https://github.com/a/b.git?ref=v1.2.3"\n}\n'
        self.assertEqual(len(content(STACK + "main.tf", text, rule="module-source")), 1)

    def test_local_module_ok_and_escape_blocked(self):
        ok = 'module "spa" {\n  source = "../../../modules/spa"\n}\n'
        self.assertEqual(content(STACK + "main.tf", ok, rule="module-source"), [])
        self.assertEqual(content("modules/eks/main.tf", 'module "a" {\n  source = "./addons"\n}\n',
                                 rule="module-source"), [])
        out = 'module "x" {\n  source = "../../../../../tmp/evil"\n}\n'
        self.assertEqual(len(content(STACK + "main.tf", out, rule="module-source")), 1)

    def test_provider_source_allowlist(self):
        bad = ('terraform {\n  required_providers {\n    evil = {\n      source  = "evil.example.com/x/evil"\n'
               '      version = "~> 1.0"\n    }\n  }\n}\n')
        f = content(STACK + "versions.tf", bad, rule="provider-source")
        self.assertEqual(len(f), 1, [x.format() for x in f])
        self.assertEqual(f[0].severity, "block")
        good = ('terraform {\n  required_providers {\n    aws = {\n      source  = "hashicorp/aws"\n'
                '      version = "~> 6.0"\n    }\n    helm = {\n      source  = "registry.terraform.io/hashicorp/helm"\n'
                '      version = "~> 3.0"\n    }\n    random = "~> 3.6"\n  }\n}\n')
        self.assertEqual(content(STACK + "versions.tf", good, rule="provider-source"), [])
        # alias di un nome ammesso verso una sorgente diversa
        aliased = good.replace('"hashicorp/aws"', '"evilcorp/aws"')
        self.assertEqual(len(content(STACK + "versions.tf", aliased, rule="provider-source")), 1)

    def test_implicit_providers_from_resources_and_blocks(self):
        for text in ('resource "local_file" "x" {\n  filename = "x"\n}\n', 'provider "evil" {}\n',
                     'data "http" "x" {\n  url = "https://x"\n}\n',
                     'terraform {\n  required_providers {\n    null = "~> 3.0"\n  }\n}\n'):
            with self.subTest(text=text):
                self.assertEqual(len(content(STACK + "main.tf", text, rule="provider-source")), 1)
        for text in ('resource "terraform_data" "x" {}\n', 'data "terraform_remote_state" "n" {\n  backend = "s3"\n}\n',
                     'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n', 'resource "tls_private_key" "k" {}\n'):
            with self.subTest(text=text):
                self.assertEqual(content(STACK + "main.tf", text, rule="provider-source"), [])

    def test_exception_still_works(self):
        cfg = rules.normalize_config({"infra_root": ".", "exceptions": [
            {"rule": "module-source", "path": "envs/dev/**", "reason": "approvato", "expires": "2999-01-01"}]})
        text = 'module "vpc" {\n  source  = "terraform-aws-modules/vpc/aws"\n  version = "5.0.0"\n}\n'
        self.assertEqual(content(STACK + "main.tf", text, cfg, rule="module-source"), [])

    def test_pre_write_denies_registry_module(self):
        proj = make_project({"project": "acme"})
        self.addCleanup(shutil.rmtree, proj, True)
        text = 'module "b" {\n  source  = "terraform-aws-modules/s3-bucket/aws"\n  version = "4.1.2"\n}\n'
        r = run_script("pre_write.py", write_event(proj, str(proj / STACK / "main.tf"), text))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(decision(r), "deny")
        self.assertIn("module-source", r.stdout)


# ---------------------------------------------------------------- I1: config malformata

class I1MalformedConfigTest(unittest.TestCase):
    def test_normalize_coerces_types(self):
        cfg = rules.normalize_config({"accounts": ["x"], "rules": ["x"], "stop_gate": True, "providers": "aws",
                                      "environments": ["dev"], "tags": "x", "exceptions": {"rule": "x"},
                                      "exclude": "x/**", "literal_reuse": 3, "infra_root": ["x"],
                                      "public_routes": "GET /x", "region": 5, "project": ["a"]})
        self.assertEqual(cfg["providers"], ["aws"])
        self.assertEqual(cfg["accounts"], {})
        self.assertEqual(cfg["rules"], rules.DEFAULT_RULES)
        self.assertTrue(cfg["stop_gate"]["enabled"])
        self.assertIsInstance(cfg["environments"], dict)
        self.assertEqual(cfg["tags"], {})
        self.assertEqual(len(cfg["exceptions"]), 1)
        self.assertIsNone(rules._parse_exception(cfg["exceptions"][0]))
        self.assertIn("x/**", cfg["exclude"])
        self.assertEqual(cfg["infra_root"], ".")
        self.assertEqual(cfg["public_routes"], ["GET /x"])
        self.assertEqual(cfg["region"], "eu-south-1")
        self.assertEqual(cfg["project"], "")
        self.assertTrue(cfg["config_problems"])

    def test_invalid_severity_falls_back_to_default(self):
        cfg = rules.normalize_config({"rules": {"s3-private": "nope", "secrets": "warn"}})
        self.assertEqual(cfg["rules"]["s3-private"], "block")
        self.assertEqual(cfg["rules"]["secrets"], "warn")

    def test_unknown_provider_and_problems_reported(self):
        proj = make_project({"project": "acme", "providers": ["aws", "azurerm"], "accounts": ["x"]})
        self.addCleanup(shutil.rmtree, proj, True)
        cfg = rules.load_config(proj)
        msgs = [f.message for f in rules.check_project(proj, cfg) if f.rule == "config"]
        self.assertTrue(any("azurerm" in m for m in msgs), msgs)
        self.assertTrue(any("accounts" in m for m in msgs), msgs)

    def test_bash_guard_denies_apply_with_malformed_config(self):
        for raw in ({"accounts": ["x"]}, {"rules": ["x"]}, {"stop_gate": True}, {"providers": "aws"},
                    {"environments": "dev"}, {"exceptions": "x"}, {"exclude": 3}):
            with self.subTest(raw=raw):
                proj = make_project({"project": "acme", **raw})
                self.addCleanup(shutil.rmtree, proj, True)
                r = run_script("bash_guard.py", bash_event(proj, "terraform apply -auto-approve"))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(decision(r), "deny")

    def test_pre_write_denies_with_malformed_config(self):
        bucket = 'resource "aws_s3_bucket_acl" "a" {\n  bucket = "x"\n  acl    = "public-read"\n}\n'
        for raw in ({"accounts": ["x"]}, {"rules": ["x"]}, {"providers": "aws"}, {"stop_gate": True}):
            with self.subTest(raw=raw):
                proj = make_project({"project": "acme", **raw})
                self.addCleanup(shutil.rmtree, proj, True)
                r = run_script("pre_write.py", write_event(proj, str(proj / "modules/spa/s3.tf"), bucket))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(decision(r), "deny")

    def test_hooks_fail_closed_on_internal_error(self):
        proj = make_project({"project": "acme"})
        self.addCleanup(shutil.rmtree, proj, True)
        event = write_event(proj, str(proj / "modules/spa/main.tf"), "")
        buf = io.StringIO()
        with mock.patch.object(pre_write.hc, "read_event", return_value=event), \
                mock.patch.object(pre_write.rules, "load_config", side_effect=RuntimeError("x")), redirect_stdout(buf):
            self.assertEqual(pre_write.main(), 0)
        self.assertIn('"deny"', buf.getvalue())
        buf = io.StringIO()
        with mock.patch.object(bash_guard.hc, "read_event", return_value=bash_event(proj, "ls")), \
                mock.patch.object(bash_guard.rules, "load_config", side_effect=RuntimeError("x")), \
                redirect_stdout(buf):
            self.assertEqual(bash_guard.main(), 0)
        self.assertIn('"deny"', buf.getvalue())

    def test_hooks_outside_projects_stay_silent(self):
        d = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, d, True)
        r = run_script("bash_guard.py", bash_event(d, "ls"))
        self.assertEqual((r.returncode, r.stdout.strip()), (0, ""))


# ---------------------------------------------------------------- I2: .kynfra annidate

class I2NestedConfigTest(unittest.TestCase):
    def test_any_kynfra_component_protected(self):
        for rel in ("infra/.kynfra/config.json", "a/b/.KYNFRA/config.json", "sub/.kynfra"):
            with self.subTest(rel=rel):
                self.assertTrue(rules.protected_reason(rel))
        self.assertIsNone(rules.protected_reason("infra/kynfra/notes.md"))

    def test_pre_write_denies_nested_config(self):
        proj = make_project({"project": "acme"})
        self.addCleanup(shutil.rmtree, proj, True)
        (proj / "sub").mkdir()
        r = run_script("pre_write.py", write_event(proj, str(proj / "sub/.kynfra/config.json"),
                                                   json.dumps({"rules": {"s3-private": "off"}})))
        self.assertEqual(decision(r), "deny")

    def test_installer_denies_nested_kynfra_edits(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        subprocess.run(["bash", str(PLUGIN / "install.sh"), "--target", str(d), "--no-plugin"], check=True,
                       capture_output=True, text=True)
        deny = json.loads((d / ".claude/settings.json").read_text())["permissions"]["deny"]
        self.assertIn("Edit(**/.kynfra/**)", deny)


# ---------------------------------------------------------------- I3: perl/ruby/lua senza parentesi

class I3InterpreterSpawnTest(TempProject):
    def test_spawn_without_parentheses(self):
        self.assert_denied([
            "perl -e 'system \"terraform apply -auto-approve\"'",
            "perl -e 'exec \"terraform\",\"apply\"'",
            "ruby -e 'system \"terraform apply\"'",
            "lua -e 'os.execute(\"terraform apply\")'",
            "luajit -e 'os.execute(\"aws s3 rb s3://x\")'",
            "php -r 'shell_exec(\"terraform apply\");'",
            "perl -e 'open(my $f, \"|-\", \"terraform apply\")'",
        ])

    def test_harmless_inline_code_allowed(self):
        self.assert_allowed(["perl -e 'print \"hello\\n\"'", "ruby -e 'puts 1'", "lua -e 'print(1)'"])


# ---------------------------------------------------------------- I4: link simbolici

class I4SymlinkTest(TempProject):
    raw = {"project": "acme", "infra_root": "infra"}

    def setUp(self):
        super().setUp()
        (self.proj / "infra/envs/dev/net").mkdir(parents=True)
        self.outside = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.outside, True)
        (self.outside / "x.tf").write_text("")

    def test_guard_denies_links_under_infra_root(self):
        o = self.outside
        self.assert_denied([
            f"ln -s {o}/x.tf infra/envs/dev/net/main.tf", f"ln {o}/x.tf infra/envs/dev/net/main.tf",
            f"ln -s {o} infra/envs/dev/net2", f"ln -sf {o} infra/modules", f"cp -s {o}/x.tf infra/envs/dev/net/a.tf",
            f"cp -l {o}/x.tf infra/envs/dev/net/a.tf", f"cp --symbolic-link {o}/x.tf infra/envs/dev/net/b",
            f"link {o}/x.tf infra/envs/dev/net/notes", f"ln -s {o}/x.tf -t infra/envs/dev/net",
            f"cd infra/envs/dev/net && ln -s {o}/x.tf",
        ])

    def test_guard_allows_links_outside_infra_root(self):
        self.assert_allowed([f"ln -s {self.outside}/x.tf docs-link", "ln -s ../README.md docs/readme"])

    def test_pre_write_denies_path_through_symlink(self):
        os.symlink(self.outside, self.proj / "infra/envs/dev/net/linked")
        r = run_script("pre_write.py", write_event(self.proj, str(self.proj / "infra/envs/dev/net/linked/main.tf"),
                                                   'resource "aws_s3_bucket" "b" {}\n'))
        self.assertEqual(decision(r), "deny")
        self.assertIn("link", r.stdout)

    def test_pre_write_denies_symlinked_file(self):
        os.symlink(self.proj / "notes.txt", self.proj / "infra/envs/dev/net/main.tf")
        (self.proj / "notes.txt").write_text("")
        r = run_script("pre_write.py", write_event(self.proj, str(self.proj / "infra/envs/dev/net/main.tf"),
                                                   'resource "aws_s3_bucket_acl" "a" {\n  acl = "public-read"\n}\n'))
        self.assertEqual(decision(r), "deny")

    def test_check_project_flags_symlinks(self):
        os.symlink(self.outside / "x.tf", self.proj / "infra/envs/dev/net/main.tf")
        os.symlink(self.outside, self.proj / "infra/modules")
        cfg = rules.load_config(self.proj)
        found = [f for f in rules.check_project(self.proj, cfg) if "link simbolico" in f.message]
        self.assertEqual(sorted(f.path for f in found), ["infra/envs/dev/net/main.tf", "infra/modules"])
        self.assertTrue(all(f.severity == "block" for f in found))


# ---------------------------------------------------------------- I5: tools.py install chiede all'utente

class I5ToolsInstallAskTest(TempProject):
    def test_claude_code_asks(self):
        r = run_script("bash_guard.py", bash_event(self.proj, f"python3 -B {KIT}/tools.py install tflint"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(decision(r), "ask")
        self.assertIn("tflint", r.stdout)

    def test_codex_denies_with_instructions(self):
        r = run_script("bash_guard.py", bash_event(self.proj, f"python3 -B {KIT}/tools.py install tflint", "shell"))
        self.assertEqual(decision(r), "deny")
        self.assertIn("tools.py install tflint", json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"])

    def test_status_and_plan_not_asked(self):
        for cmd in (f"python3 -B {KIT}/tools.py status", f"python3 -B {KIT}/tools.py plan tflint"):
            r = run_script("bash_guard.py", bash_event(self.proj, cmd))
            self.assertEqual(r.stdout.strip(), "", cmd)


# ---------------------------------------------------------------- I6: ambienti di prod per flag

class I6ProdEnvsTest(unittest.TestCase):
    ENVS = {"dev": {"account": "main"}, "production": {"account": "main", "prod": True},
            "prod": {"account": "main", "prod": False}, "live": {"account": "main", "prod": True}}

    def cfg(self, envs=None):
        return rules.normalize_config({"infra_root": ".", "environments": envs or self.ENVS})

    def test_prod_envs(self):
        self.assertEqual(rules.prod_envs(self.cfg()), {"production", "live"})
        self.assertEqual(rules.prod_envs(rules.normalize_config({})), {"prod"})

    def test_is_prod_follows_flag(self):
        cfg = self.cfg()
        self.assertTrue(rules_aws.is_prod("envs/production/spa/main.tf", cfg))
        self.assertTrue(rules_aws.is_prod("envs/live/spa/main.tf", cfg))
        self.assertFalse(rules_aws.is_prod("envs/prod/spa/main.tf", cfg))
        self.assertFalse(rules_aws.is_prod("envs/dev/spa/main.tf", cfg))

    def test_prod_toggles_on_flagged_env(self):
        var = 'variable "deletion_protection" {\n  type        = bool\n  description = "x"\n  default     = false\n}\n'
        alb = ('resource "aws_lb" "this" {\n  name                       = "x"\n  load_balancer_type         = "application"\n'
               '  drop_invalid_header_fields = true\n  enable_deletion_protection = var.deletion_protection\n'
               '  access_logs {\n    bucket  = "b"\n    enabled = true\n  }\n}\n')
        with tempfile.TemporaryDirectory() as d:
            files = {"modules/elb/lb.tf": alb, "modules/elb/variables.tf": var,
                     "envs/production/elb/main.tf": 'module "elb" {\n  source = "../../../modules/elb"\n}\n'}
            for rel, text in files.items():
                put(Path(d), rel, text)
            out = [f for f in rules.check_project(Path(d), self.cfg())
                   if f.path.startswith("envs/production/") and "deletion" in f.message.lower()]
        self.assertTrue(out)

    def test_generator_applies_prod_defaults_to_flagged_env(self):
        entry = {"inputs": {"flag": {"type": "bool", "default": False}},
                 "env_defaults": {"prod": {"flag": True}}}
        self.assertEqual(generate._inputs(entry, {}, "production", {}, "p", prod=True), {"flag": "true"})
        self.assertEqual(generate._inputs(entry, {}, "prod", {}, "p", prod=False), {"flag": "false"})
        self.assertEqual(generate._inputs(entry, {}, "prod", {}, "p"), {"flag": "true"})

    def test_generate_flagged_env_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            raw = {"iac": "terraform", "providers": ["aws"], "infra_root": "infra", "project": "acme",
                   "region": "eu-south-1", "accounts": {"main": {"id": "123456789012"}},
                   "environments": {"dev": {"account": "main"}, "production": {"account": "main", "prod": True}},
                   "tags": {"Owner": "platform", "CostCenter": "cc-001"}}
            put(Path(d), ".kynfra/config.json", json.dumps(raw))
            cfg = rules.load_config(Path(d))
            generate.generate(Path(d), cfg, "aws", "network", ["dev", "production"], {})
            prod = (Path(d) / "infra/envs/production/network/terraform.tfvars").read_text()
            dev = (Path(d) / "infra/envs/dev/network/terraform.tfvars").read_text()
        self.assertRegex(prod, r"az_count\s*=\s*3")
        self.assertNotRegex(dev, r"az_count\s*=\s*3")


# ---------------------------------------------------------------- installer: F1, F3, I6, infra_root

class InstallerFixTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)

    def install(self, *extra, check=True):
        return subprocess.run(["bash", str(PLUGIN / "install.sh"), "--target", str(self.d), "--no-plugin", *extra],
                              check=check, capture_output=True, text=True)

    def cfg(self):
        return json.loads((self.d / ".kynfra/config.json").read_text())

    def test_f1_owner_and_cost_center(self):
        res = self.install("--owner", "platform-team", "--cost-center", "cc-042")
        self.assertEqual(self.cfg()["tags"], {"Owner": "platform-team", "CostCenter": "cc-042"})
        self.assertNotIn("Owner e CostCenter vuoti", res.stdout)

    def test_f1_still_warns_when_empty(self):
        res = self.install("--owner", "platform-team")
        self.assertIn("CostCenter", res.stdout)

    def test_f3_no_plugin_warns_about_hooks(self):
        res = self.install("--agents", "claude")
        self.assertIn("hook", res.stdout.lower())
        self.assertIn("--no-plugin", res.stdout)

    def test_i6_prod_envs_flag(self):
        self.install("--envs", "dev,production", "--prod-envs", "production")
        envs = self.cfg()["environments"]
        self.assertTrue(envs["production"].get("prod"))
        self.assertFalse(envs["dev"].get("prod", False))

    def test_i6_default_prod_and_warning(self):
        self.install()
        self.assertTrue(self.cfg()["environments"]["prod"].get("prod"))
        shutil.rmtree(self.d / ".kynfra")
        res = self.install("--envs", "dev,test")
        self.assertIn("prod", res.stdout)
        self.assertFalse(any(e.get("prod") for e in self.cfg()["environments"].values()))

    def test_i6_prod_envs_must_exist(self):
        res = self.install("--envs", "dev,live", "--prod-envs", "prod", check=False)
        self.assertNotEqual(res.returncode, 0)

    def test_infra_root_from_existing_config_validated(self):
        (self.d / ".kynfra").mkdir()
        (self.d / ".kynfra/config.json").write_text(json.dumps({"infra_root": "infra|x"}))
        res = self.install(check=False)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("infra_root", res.stderr)


# ---------------------------------------------------------------- minori

class IamWildcardArnTest(unittest.TestCase):
    def test_action_star_with_arn_wildcards(self):
        for res in ("arn:*", "arn:aws:*", "arn:*:*", "arn:aws:*:*:*:*"):
            text = ('resource "aws_iam_policy" "p" {\n  name = "p"\n  policy = jsonencode({\n'
                    '    Version = "2012-10-17"\n    Statement = [{\n      Effect   = "Allow"\n'
                    f'      Action   = "*"\n      Resource = "{res}"\n    }}]\n  }})\n}}\n')
            with self.subTest(res=res):
                cfg = rules.normalize_config({"infra_root": ".", "providers": ["aws"]})
                self.assertEqual(len(content("modules/spa/iam.tf", text, cfg, "iam-least-privilege")), 1)


class SecretReadsTest(TempProject):
    def test_more_secret_ops(self):
        self.assert_denied([
            "aws redshift get-cluster-credentials --cluster-identifier x --db-user y",
            "aws redshift get-cluster-credentials-with-iam --cluster-identifier x",
            "aws redshift-serverless get-credentials --workgroup-name x",
            "aws lightsail get-instance-access-details --instance-name x",
            "aws ssm get-parameter --name x --with-d", "aws ssm get-parameter --name x --with-decrypt",
        ])
        self.assert_allowed(["aws ssm get-parameter --name x", "aws redshift describe-clusters"])

    def test_credential_files(self):
        put(self.proj, ".env", "X=1")
        self.assert_denied(["cat ~/.aws/credentials", "head $HOME/.aws/credentials",
                            "cat ~/.aws/sso/cache/abc.json", "cat ~/.aws/cli/cache/x.json", "cat .env",
                            "grep KEY .env.local", "tail -n 5 ./.env", "while read l; do echo $l; done < .env",
                            "jq . < ~/.aws/sso/cache/x.json"])
        self.assert_allowed(["cat .env.example", "ls -la .env", "cat ~/.aws/config.d-notes", "cat README.md",
                             "docker compose --env-file .env up -d"])


class DocsAndSkillsTest(unittest.TestCase):
    def test_f9_ecr_skill_uses_context_names(self):
        text = (PLUGIN / "skills/create-ecr-infra-aws/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("<contesto>-<nome>", text)
        self.assertNotIn("(nome della cartella)", text)

    def test_f5_backend_skill_separator(self):
        text = (PLUGIN / "skills/create-backend-infra-aws/SKILL.md").read_text(encoding="utf-8")
        self.assertNotIn("`db_proxy_security_group_id` verificare", text)

    def test_f3_readme_option_cells(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("`--force`, `--uninstall` | |", text)
        for opt in ("--owner", "--cost-center", "--prod-envs"):
            self.assertIn(opt, text)

    def test_f6_f7_tools_texts(self):
        self.assertNotIn("checksum atteso", (ROOT / "docs/strumenti.md").read_text(encoding="utf-8"))
        import tools
        text = tools.plan_install(Path("/tmp/p"), "checkov", "linux", "amd64")["approval_text"]
        self.assertNotIn("Firme GPG", text)
        self.assertIn("pip download", text)
        self.assertIn("Firme GPG", tools.plan_install(Path("/tmp/p"), "tflint", "linux", "amd64")["approval_text"])

    def test_r4_plugin_cache_documented(self):
        for doc in ("docs/strumenti.md", "docs/controlli.md"):
            self.assertIn("TF_PLUGIN_CACHE_DIR", (ROOT / doc).read_text(encoding="utf-8"), doc)

    def test_r2_lock_files_in_skill_summaries(self):
        for skill in ("create-network-infra-aws", "create-spa-infra-aws", "create-backend-infra-aws",
                      "create-ecr-infra-aws", "create-eks-infra-aws", "create-elb-infra-aws",
                      "create-secrets-infra-aws"):
            text = (PLUGIN / f"skills/{skill}/SKILL.md").read_text(encoding="utf-8")
            self.assertIn(".terraform.lock.hcl", text, skill)


class EksTemplateTest(unittest.TestCase):
    EKS = PLUGIN / "templates/aws/modules/eks"

    def test_lb_controller_policy_in_own_file_and_baseline_scoped(self):
        self.assertIn('resource "aws_iam_role_policy" "lb_controller"', (self.EKS / "iam_lb_controller.tf").read_text())
        self.assertNotIn('"lb_controller"', (self.EKS / "main.tf").read_text())
        base = json.loads((PLUGIN / "templates/scanner-baseline.json").read_text())
        for e in base["checkov"]:
            if e["id"] in ("CKV_AWS_290", "CKV_AWS_355") and any("eks" in p for p in e["paths"]):
                self.assertEqual(e["paths"], ["modules/eks/iam_lb_controller.tf"])

    def test_upgrade_policy_standard(self):
        main = (self.EKS / "main.tf").read_text()
        self.assertIn("upgrade_policy", main)
        self.assertIn("var.support_type", main)
        var = (self.EKS / "variables.tf").read_text()
        self.assertIn('variable "support_type"', var)
        self.assertIn('"STANDARD"', var)


if __name__ == "__main__":
    unittest.main()
