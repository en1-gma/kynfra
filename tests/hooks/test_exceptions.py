"""Test delle eccezioni dell'utente e della baseline dello scanner."""
import sys
import unittest
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "plugins" / "kynfra" / "scripts"))

import rules  # noqa: E402

TODAY = date(2026, 10, 20)


def cfg_with(exceptions, infra_root=".", **extra):
    return rules.normalize_config({"infra_root": infra_root, "exceptions": exceptions, **extra})


def fnd(rule="required-tags", path="modules/s3/main.tf", resource="aws_s3_bucket.logs"):
    return rules.Finding(rule, "block", path, 3, "msg", resource)


def exc(**kw):
    base = {"rule": "required-tags", "path": "modules/**", "reason": "legacy", "expires": "2026-12-31"}
    base.update(kw)
    return base


class ExceptionsTest(unittest.TestCase):
    def test_exception_suppresses(self):
        out = rules.apply_exceptions([fnd()], cfg_with([exc()]), TODAY)
        self.assertEqual(out, [])

    def test_exception_expired_keeps_finding(self):
        yesterday = (TODAY - timedelta(days=1)).isoformat()
        out = rules.apply_exceptions([fnd()], cfg_with([exc(expires=yesterday)]), TODAY)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "block")
        self.assertIn(f"(eccezione scaduta il {yesterday}: legacy)", out[0].message)

    def test_exception_without_reason_ignored(self):
        bad = exc()
        del bad["reason"]
        out = rules.apply_exceptions([fnd()], cfg_with([bad]), TODAY)
        self.assertEqual([f.rule for f in out], ["required-tags", "config"])
        self.assertEqual(out[1].severity, "warn")
        self.assertEqual(out[1].path, ".kynfra/config.json")
        self.assertIn("0", out[1].message)

    def test_exception_bad_date_ignored(self):
        out = rules.apply_exceptions([fnd()], cfg_with([exc(), exc(expires="domani")]), TODAY)
        self.assertEqual([f.rule for f in out], ["config"])
        self.assertIn("1", out[0].message)

    def test_exception_resource_scoped(self):
        e = cfg_with([exc(resource="aws_s3_bucket.logs")])
        out = rules.apply_exceptions([fnd(), fnd(resource="aws_s3_bucket.data")], e, TODAY)
        self.assertEqual([f.resource for f in out], ["aws_s3_bucket.data"])

    def test_exception_path_relative_to_infra_root(self):
        cfg = cfg_with([exc(path="modules/**")], infra_root="infra")
        out = rules.apply_exceptions([fnd(path="infra/modules/s3/main.tf"), fnd(path="other/modules/x.tf")],
                                     cfg, TODAY)
        self.assertEqual([f.path for f in out], ["other/modules/x.tf"])

    def test_other_rule_or_path_not_suppressed(self):
        cfg = cfg_with([exc(path="envs/**")])
        self.assertEqual(len(rules.apply_exceptions([fnd()], cfg, TODAY)), 1)
        self.assertEqual(len(rules.apply_exceptions([fnd("secrets")], cfg_with([exc()]), TODAY)), 1)

    def test_fail_closed_rules_never_excepted(self):
        for rule in ("hcl-syntax", "protected-files"):
            cfg = cfg_with([exc(rule=rule, path="**")])
            out = rules.apply_exceptions([fnd(rule)], cfg, TODAY)
            self.assertEqual([f.rule for f in out], [rule])
            self.assertNotIn("scaduta", out[0].message)

    def test_check_content_honours_exception(self):
        text = 'resource "aws_s3_bucket" "logs" {\n  # checkov:skip=CKV_AWS_18: no\n  bucket = "x"\n}\n'
        rel = "modules/s3/main.tf"
        base = rules.check_content(rel, text, cfg_with([]))
        self.assertTrue(any(f.rule == "scanner-suppression" for f in base))
        out = rules.check_content(rel, text, cfg_with([exc(rule="scanner-suppression", resource="")]))
        self.assertFalse(any(f.rule == "scanner-suppression" for f in out))


    def test_check_project_reports_bad_exception_once(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "modules").mkdir()
            (Path(d) / "modules" / "a.tf").write_text('variable "x" {}\n')
            (Path(d) / "modules" / "b.tf").write_text('variable "y" {}\n')
            out = rules.check_project(Path(d), cfg_with([{"rule": "secrets"}]))
        self.assertEqual(len([f for f in out if f.rule == "config"]), 1)


class BaselineTest(unittest.TestCase):
    def setUp(self):
        self._orig = rules.baseline_path
        import json, tempfile
        self._tmp = tempfile.TemporaryDirectory()
        p = Path(self._tmp.name) / "b.json"
        p.write_text(json.dumps({
            "_comment": "x",
            "checkov": [{"id": "CKV_A", "envs": ["dev", "staging"], "reason": "r"},
                        {"id": "CKV_B", "envs": "*", "reason": "r"},
                        {"id": "CKV_C", "envs": "*", "paths": ["bootstrap/**"], "reason": "r"}],
            "trivy": [{"id": "AVD-1", "envs": "*", "reason": "r"}]}))
        rules.baseline_path = lambda: p

    def tearDown(self):
        rules.baseline_path = self._orig
        self._tmp.cleanup()

    def test_baseline_env_filter(self):
        b = rules.scanner_baseline(rules.normalize_config({}))
        self.assertEqual([e["id"] for e in b], ["CKV_A", "CKV_B", "CKV_C"])
        self.assertEqual(b[0]["paths"], ["**"])  # default
        self.assertTrue(rules.baseline_allows(b, "CKV_A", "envs/dev/spa/main.tf"))
        self.assertFalse(rules.baseline_allows(b, "CKV_A", "envs/prod/spa/main.tf"))
        self.assertFalse(rules.baseline_allows(b, "CKV_A", "modules/spa/main.tf"))  # ambiente non noto
        self.assertTrue(rules.baseline_allows(b, "CKV_B", "modules/spa/main.tf"))
        self.assertFalse(rules.baseline_allows(b, "CKV_Z", "modules/spa/main.tf"))

    def test_baseline_paths_scope(self):
        b = rules.scanner_baseline(rules.normalize_config({}))
        self.assertTrue(rules.baseline_allows(b, "CKV_C", "bootstrap/main.tf"))
        self.assertFalse(rules.baseline_allows(b, "CKV_C", "modules/spa/main.tf"))
        self.assertFalse(rules.baseline_allows(b, "CKV_C", "envs/dev/spa/main.tf"))

    def test_baseline_scanner_choice(self):
        b = rules.scanner_baseline(rules.normalize_config({"scanner": "trivy"}))
        self.assertEqual([e["id"] for e in b], ["AVD-1"])

    def test_kit_baseline_file_valid(self):
        rules.baseline_path = self._orig
        import json
        data = json.loads(rules.baseline_path().read_text())
        for scanner in ("checkov", "trivy"):
            for e in data[scanner]:
                self.assertTrue(e["id"] and e["reason"].strip(), e)
                self.assertTrue(e["envs"] == "*" or isinstance(e["envs"], list), e)
                self.assertTrue(e["paths"] and all(isinstance(p, str) for p in e["paths"]), e)

if __name__ == "__main__":
    unittest.main()
