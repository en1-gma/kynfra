"""Test di arch_check, stop gate e strumenti esterni (con eseguibili finti: nessun terraform reale)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "plugins" / "kynfra" / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT / "tests" / "hooks"))

import external  # noqa: E402
import hook_common  # noqa: E402
import stop_gate  # noqa: E402
import rules  # noqa: E402
from test_rules_common import GOOD_BACKEND, GOOD_PROVIDER  # noqa: E402

VERSIONS = 'terraform {\n  required_version = "~> 1.10"\n}\n'
PUBLIC_BUCKET = 'resource "aws_s3_bucket" "site" {\n  bucket = "acme-dev-site"\n  acl    = "public-read"\n}\n'

FAKE = """#!{py}
import json, os, sys
name = os.path.basename(sys.argv[0])
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps({{"tool": name, "args": sys.argv[1:], "cwd": os.getcwd(),
                         "data_dir": os.environ.get("TF_DATA_DIR"), "auto": os.environ.get("TF_IN_AUTOMATION"),
                         "input": os.environ.get("TF_INPUT")}}) + "\\n")
if name in os.environ.get("FAKE_FAIL", "").split(","):
    print("boom da " + name)
    sys.exit(3)
"""


def make_bin(d: Path, tools=("terraform", "tofu", "tflint", "checkov", "trivy")) -> None:
    d.mkdir(parents=True, exist_ok=True)
    for t in tools:
        p = d / t
        p.write_text(FAKE.format(py=sys.executable))
        p.chmod(0o755)


def write(base: Path, files: dict) -> None:
    for rel, text in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def stack(prefix="envs/dev/spa/", extra=""):
    return {prefix + "backend.tf": GOOD_BACKEND, prefix + "versions.tf": VERSIONS,
            prefix + "providers.tf": GOOD_PROVIDER, prefix + "main.tf": "# vuoto\n" + extra}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="kynfra-sg-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.proj = self.tmp / "proj"
        self.bin = self.tmp / "bin"
        self.log = self.tmp / "calls.log"
        self.proj.mkdir()

    def config(self, **extra):
        cfg = {"project": "acme", "infra_root": ".", "stop_gate": {"commands": []}, **extra}
        write(self.proj, {".kynfra/config.json": json.dumps(cfg), ".tflint.hcl": "# config\n"})

    def env(self, path=None, **extra):
        e = dict(os.environ, FAKE_LOG=str(self.log), PATH=str(self.bin) if path is None else path, **extra)
        return e

    def calls(self):
        if not self.log.is_file():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def stop(self, active=False, sid="s", cwd=None, **env):
        ev = {"cwd": str(cwd or self.proj), "hook_event_name": "Stop", "session_id": f"{sid}-{self.tmp.name}",
              "stop_hook_active": active}
        for p in (Path(ev["cwd"]).resolve(), *rules.discover_projects(Path(ev["cwd"]).resolve())):
            self.addCleanup(stop_gate.counter_path(ev, p).unlink, True)
        r = subprocess.run([sys.executable, "-B", str(SCRIPTS / "stop_gate.py")], input=json.dumps(ev),
                           capture_output=True, text=True, timeout=60, env=self.env(**env))
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout) if r.stdout.strip() else {}

    def arch(self, *args, **env):
        return subprocess.run([sys.executable, "-B", str(SCRIPTS / "arch_check.py"), str(self.proj), *args],
                              capture_output=True, text=True, timeout=60, env=self.env(**env))


class StopGateTest(Base):
    def test_gate_blocks_on_violation(self):
        self.config()
        make_bin(self.bin)
        write(self.proj, stack(extra=PUBLIC_BUCKET))
        out = self.stop()
        self.assertEqual(out.get("decision"), "block")
        self.assertIn("arch_check", out["reason"])
        self.assertIn("[", out["reason"])

    def test_gate_passes_clean_project(self):
        self.config()
        make_bin(self.bin)
        write(self.proj, stack())
        self.assertEqual(self.stop(), {})
        self.assertTrue(self.calls())  # gli strumenti sono stati eseguiti

    def test_gate_blocks_on_external_failure(self):
        self.config()
        make_bin(self.bin)
        write(self.proj, stack())
        out = self.stop(FAKE_FAIL="terraform")
        self.assertEqual(out.get("decision"), "block")
        self.assertIn("boom da terraform", out["reason"])

    def test_gate_missing_tool_warns_not_blocks(self):
        self.config()
        self.bin.mkdir()  # PATH vuoto
        write(self.proj, stack())
        out = self.stop()
        self.assertNotIn("decision", out)
        self.assertIn("tools.py install terraform", out["systemMessage"])

    def test_gate_commands_failure_blocks(self):
        self.config(stop_gate={"commands": ["echo ko >&2; exit 2"]})
        self.bin.mkdir()
        write(self.proj, stack())
        out = self.stop()
        self.assertEqual(out.get("decision"), "block")
        self.assertIn("ko", out["reason"])

    def test_gate_max_blocks(self):
        self.config()
        make_bin(self.bin)
        write(self.proj, stack(extra=PUBLIC_BUCKET))
        self.assertEqual(self.stop().get("decision"), "block")
        self.assertEqual(self.stop(True).get("decision"), "block")
        self.assertEqual(self.stop(True).get("decision"), "block")
        last = self.stop(True)
        self.assertNotIn("decision", last)
        self.assertIn("NON è conforme", last["systemMessage"])
        self.assertEqual(self.stop(False).get("decision"), "block")  # catena nuova

    def git(self, *a):
        subprocess.run(["git", *a], cwd=self.proj, check=True, capture_output=True,
                       env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
                                GIT_COMMITTER_EMAIL="t@t"))

    def test_gate_after_commit_still_checks(self):
        self.config()
        make_bin(self.bin)
        self.git("init", "-q")
        write(self.proj, stack())
        self.git("add", "-A")
        self.git("commit", "-qm", "base")
        git_dir = os.path.dirname(shutil.which("git"))
        path = f"{self.bin}{os.pathsep}{git_dir}"
        ev = {"cwd": str(self.proj), "session_id": f"c-{self.tmp.name}"}
        hook_common.record_baseline(ev, self.proj.resolve())
        self.addCleanup(hook_common.baseline_path(ev, self.proj.resolve()).unlink, True)
        self.assertEqual(self.stop(sid="c", path=path), {})  # nessuna modifica: gate spento
        self.assertEqual(self.calls(), [])
        write(self.proj, {"envs/dev/spa/bad.tf": PUBLIC_BUCKET})
        self.git("add", "-A")
        self.git("commit", "-qm", "viola")
        self.assertEqual(self.stop(sid="c", path=path).get("decision"), "block")

    def test_monorepo_root_checks_subprojects(self):
        app = self.tmp / "mono" / "apps" / "infra"
        write(app, {".kynfra/config.json": json.dumps({"project": "acme", "infra_root": ".",
                                                      "stop_gate": {"commands": []}}),
                    **stack(extra=PUBLIC_BUCKET)})
        make_bin(self.bin)
        out = self.stop(cwd=self.tmp / "mono")
        self.assertEqual(out.get("decision"), "block")


class ArchCheckTest(Base):
    def test_exit_codes_and_ratio_line(self):
        self.config()
        write(self.proj, stack())
        r = self.arch()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("riuso letterali", r.stdout)
        write(self.proj, {"envs/dev/spa/main.tf": PUBLIC_BUCKET})
        r = self.arch()
        self.assertEqual(r.returncode, 1)
        self.assertIn("Violazioni bloccanti", r.stdout)

    def test_strict_missing_tool_fails(self):
        self.config()
        self.bin.mkdir()
        write(self.proj, stack())
        r = self.arch("--external")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("tools.py install terraform", r.stdout)
        r = self.arch("--external", "--strict")
        self.assertEqual(r.returncode, 1)
        self.assertIn("tools.py install terraform", r.stdout)

    def test_external_failure_fails_only_with_flag(self):
        self.config()
        make_bin(self.bin)
        write(self.proj, stack())
        self.assertEqual(self.arch(FAKE_FAIL="checkov").returncode, 0)
        r = self.arch("--external", FAKE_FAIL="checkov")
        self.assertEqual(r.returncode, 1)
        self.assertIn("boom da checkov", r.stdout)


class ExternalStepsTest(Base):
    def test_external_steps_per_stack(self):
        self.config()
        write(self.proj, {**stack("envs/dev/spa/"), **stack("envs/dev/api/"), **stack("envs/shared/dns/"),
                          "bootstrap/main.tf": "# x\n", ".tflint.hcl": "# c\n"})
        base = self.tmp / "baseline.json"
        base.write_text(json.dumps({"checkov": [{"id": "CKV_AWS_1", "envs": "*"}, {"id": "CKV_AWS_2", "envs": "*"}]}))
        orig = rules.baseline_path
        rules.baseline_path = lambda: base
        self.addCleanup(setattr, rules, "baseline_path", orig)
        cfg = rules.load_config(self.proj)
        steps = external.external_steps(self.proj, cfg)
        names = [s.name for s in steps]
        self.assertEqual(names[0], "fmt")
        for label in ("envs/dev/spa", "envs/dev/api", "envs/shared/dns", "bootstrap"):
            self.assertIn(f"init {label}", names)
            self.assertIn(f"validate {label}", names)
        by = {s.name: s for s in steps}
        self.assertEqual(by["init envs/dev/spa"].cwd, self.proj / "envs/dev/spa")
        self.assertEqual(by["init envs/dev/spa"].argv, ["terraform", "init", "-backend=false", "-input=false", "-no-color"])
        self.assertEqual(by["validate envs/dev/api"].cwd, self.proj / "envs/dev/api")
        self.assertEqual(by["tflint"].argv[:2], ["tflint", "--recursive"])
        self.assertIn(str((self.proj / ".tflint.hcl").resolve()), by["tflint"].argv)
        self.assertEqual(by["checkov"].argv[0], "checkov")
        argv = by["checkov"].argv
        self.assertEqual(argv[argv.index("--skip-check") + 1], "CKV_AWS_1,CKV_AWS_2")

    def test_opentofu_and_trivy(self):
        self.config(iac="opentofu", scanner="trivy")
        write(self.proj, stack())
        steps = external.external_steps(self.proj, rules.load_config(self.proj))
        self.assertTrue(all(s.argv[0] in ("tofu", "tflint", "trivy") for s in steps))
        self.assertEqual(steps[-1].argv[:3], ["trivy", "config", "--exit-code"])

    def test_no_tf_no_steps(self):
        self.config()
        self.assertEqual(external.external_steps(self.proj, rules.load_config(self.proj)), [])

    def test_run_env_and_data_dir_outside_repo(self):
        self.config()
        make_bin(self.bin)
        write(self.proj, {**stack("envs/dev/spa/"), **stack("envs/dev/api/"), ".tflint.hcl": "# c\n"})
        cfg = rules.load_config(self.proj)
        old = dict(os.environ)
        os.environ.update(self.env())
        try:
            errors, warnings = external.run_external(external.external_steps(self.proj, cfg), True, self.proj, cfg)
        finally:
            os.environ.clear()
            os.environ.update(old)
        self.assertEqual((errors, warnings), ([], []))
        calls = self.calls()
        inits = [c for c in calls if c["args"][:1] == ["init"]]
        vals = [c for c in calls if c["args"][:1] == ["validate"]]
        self.assertEqual(len(inits), 2)
        self.assertEqual(len(vals), 2)
        for c in inits + vals:
            self.assertEqual((c["auto"], c["input"]), ("1", "0"))
            self.assertFalse(c["data_dir"].startswith(str(self.proj)))
        self.assertEqual({c["cwd"] for c in inits}, {c["cwd"] for c in vals})
        self.assertEqual(len({c["data_dir"] for c in inits}), 2)
        self.assertFalse((self.proj / "envs/dev/spa/.terraform").exists())

    def test_resolve_prefers_project_bin(self):
        self.config()
        make_bin(self.proj / ".kynfra" / "bin", ("terraform",))
        (self.proj / ".kynfra/tools.lock.json").write_text(json.dumps(
            {"tools": {"terraform": {"binary_sha256": external.tools.sha256_file(self.proj / ".kynfra/bin/terraform")}}}))
        self.bin.mkdir()
        self.assertEqual(external._resolve(self.proj, "terraform"), str(self.proj / ".kynfra/bin/terraform"))
        self.assertIsNone(external._resolve(self.proj, "nonesiste-xyz"))

    def test_failed_init_skips_validate(self):
        self.config()
        make_bin(self.bin)
        write(self.proj, stack())
        cfg = rules.load_config(self.proj)
        steps = [s for s in external.external_steps(self.proj, cfg) if s.name.startswith(("init", "validate"))]
        old = dict(os.environ)
        os.environ.update(self.env(FAKE_FAIL="terraform"))
        try:
            errors, _ = external.run_external(steps, False, self.proj, cfg)
        finally:
            os.environ.clear()
            os.environ.update(old)
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("init"))

    def test_tflint_config_missing(self):
        self.config()
        (self.proj / ".tflint.hcl").unlink()
        make_bin(self.bin)
        write(self.proj, stack())
        cfg = rules.load_config(self.proj)
        steps = external.external_steps(self.proj, cfg)
        self.assertNotIn("tflint", [s.name for s in steps])
        with unittest.mock.patch.dict(os.environ, self.env()):
            errors, warnings = external.run_external(steps, False, self.proj, cfg)
            self.assertEqual(errors, [])
            self.assertTrue(any(".tflint.hcl" in w for w in warnings))
            errors, _ = external.run_external(steps, True, self.proj, cfg)
        self.assertTrue(any(".tflint.hcl" in e for e in errors))

    def test_tflint_has_no_chdir(self):
        self.config()
        write(self.proj, stack())
        steps = external.external_steps(self.proj, rules.load_config(self.proj))
        argv = [s for s in steps if s.name == "tflint"][0].argv
        self.assertNotIn("--chdir", argv)

    def test_checkov_without_skips(self):
        self.config()
        write(self.proj, stack())
        steps = external.external_steps(self.proj, rules.load_config(self.proj))
        self.assertNotIn("--skip-check", steps[-1].argv)

    def test_trivy_runs(self):
        self.config(scanner="trivy")
        make_bin(self.bin)
        write(self.proj, stack())
        cfg = rules.load_config(self.proj)
        with unittest.mock.patch.dict(os.environ, self.env(FAKE_FAIL="trivy")):
            errors, _ = external.run_external(external.external_steps(self.proj, cfg), False, self.proj, cfg)
        self.assertEqual(len(errors), 1)
        self.assertIn("boom da trivy", errors[0])
        self.assertEqual([c["tool"] for c in self.calls()][-1], "trivy")

    def test_timeout_and_oserror(self):
        self.config()
        make_bin(self.bin)
        step = external.Step("lento", ["terraform", "x"], self.proj, True)
        with unittest.mock.patch.dict(os.environ, self.env()):
            with unittest.mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("t", 1)):
                errors, _ = external.run_external([step], False, self.proj)
            self.assertIn("oltre", errors[0])
            with unittest.mock.patch("subprocess.run", side_effect=OSError("nope")):
                errors, _ = external.run_external([step], False, self.proj)
            self.assertIn("impossibile eseguire", errors[0])


class LiteralReuseStatsTest(Base):
    def test_stats_line(self):
        self.config()
        write(self.proj, stack())
        r = self.arch()
        self.assertIn("0 duplicati su", r.stdout)
        self.assertIn("nessuna soglia applicata", r.stdout)
        self.config(rules={"literal-reuse": "off"})
        self.assertIn("disattivata", self.arch().stdout)


if __name__ == "__main__":
    unittest.main()
