"""Test degli hook di scrittura di kynfra (pre_write, post_edit), in Claude Code e Codex.

Esecuzione: python3 -B -m unittest discover -s tests/hooks -v
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "plugins" / "kynfra" / "scripts"

BACKEND_OK = 'terraform {\n  backend "s3" {\n    bucket       = "acme-tfstate"\n    key          = "dev/web.tfstate"\n' \
             '    encrypt      = true\n    use_lockfile = true\n  }\n}\n'
PUBLIC_BUCKET = 'resource "aws_s3_bucket" "site" {\n  bucket = "acme-dev-site"\n  acl    = "public-read"\n}\n'
TAGGED_BUCKET = 'resource "aws_s3_bucket" "site" {\n  bucket = "acme-dev-site"\n  acl    = "public-read"\n' \
                '  tags = {\n    Name = "site"\n  }\n}\n'
CDN = 'resource "aws_cloudfront_distribution" "cdn" {\n  default_cache_behavior {\n' \
      '    viewer_protocol_policy = "redirect-to-https"\n  }\n}\n'


def project(**extra) -> Path:
    d = Path(tempfile.mkdtemp(prefix="kynfra-hooks-"))
    (d / ".kynfra").mkdir()
    cfg = {"project": "acme", "stop_gate": {"commands": []}, **extra}
    (d / ".kynfra" / "config.json").write_text(json.dumps(cfg))
    return d


def put(proj: Path, rel: str, text: str) -> Path:
    p = proj / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def run_hook(script: str, event: dict) -> dict:
    r = subprocess.run([sys.executable, "-B", str(SCRIPTS / script)], input=json.dumps(event),
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout) if r.stdout.strip() else {}


def pre(proj: Path, tool: str, tool_input: dict) -> dict:
    return run_hook("pre_write.py", {"cwd": str(proj), "hook_event_name": "PreToolUse", "tool_name": tool,
                                     "tool_input": tool_input})


def claude_write(proj: Path, rel: str, content: str) -> dict:
    return pre(proj, "Write", {"file_path": str(proj / rel), "content": content})


def codex_patch(proj: Path, patch: str) -> dict:
    return pre(proj, "apply_patch", {"command": "*** Begin Patch\n" + patch + "*** End Patch\n"})


def denied(out: dict) -> bool:
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision") == "deny"


def reason(out: dict) -> str:
    return (out.get("hookSpecificOutput") or {}).get("permissionDecisionReason", "")


class PreWriteTests(unittest.TestCase):
    def test_write_public_bucket_denied(self):
        out = claude_write(project(), "envs/dev/web/main.tf", PUBLIC_BUCKET)
        self.assertTrue(denied(out), out)
        self.assertIn("s3-private", reason(out))
        self.assertTrue(reason(out).endswith(
            "Correggi l'approccio secondo la skill kynfra-architecture invece di aggirare il controllo."))

    def test_write_clean_allowed(self):
        self.assertEqual(claude_write(project(), "envs/dev/web/backend.tf", BACKEND_OK), {})

    def test_bad_layout_denied(self):
        out = claude_write(project(), "stuff/main.tf", CDN)
        self.assertTrue(denied(out), out)
        self.assertIn("folder-layout", reason(out))

    def test_edit_removing_encryption_denied(self):
        proj = project()
        p = put(proj, "envs/dev/web/backend.tf", BACKEND_OK)
        out = pre(proj, "Edit", {"file_path": str(p), "old_string": "    encrypt      = true\n", "new_string": ""})
        self.assertTrue(denied(out), out)
        self.assertIn("remote-state", reason(out))

    def test_multiedit_removing_encryption_denied(self):
        proj = project()
        p = put(proj, "envs/dev/web/backend.tf", BACKEND_OK)
        out = pre(proj, "MultiEdit", {"file_path": str(p), "edits": [
            {"old_string": "dev/web.tfstate", "new_string": "dev/app.tfstate"},
            {"old_string": "    encrypt      = true\n", "new_string": ""}]})
        self.assertTrue(denied(out), out)

    def test_preexisting_violation_not_blocking(self):
        proj = project()
        p = put(proj, "envs/dev/web/main.tf", PUBLIC_BUCKET.replace("}\n", '  tags = {\n    Name = "a"\n  }\n}\n'))
        out = pre(proj, "Edit", {"file_path": str(p), "old_string": '"a"', "new_string": '"b"'})
        self.assertEqual(out, {})

    def test_edit_adding_new_violation_denied(self):
        proj = project()
        p = put(proj, "envs/dev/web/main.tf", CDN + PUBLIC_BUCKET)
        out = pre(proj, "Edit", {"file_path": str(p), "old_string": "redirect-to-https",
                                 "new_string": "allow-all"})
        self.assertTrue(denied(out), out)
        self.assertIn("allow-all", reason(out))
        self.assertNotIn("s3-private", reason(out))

    def test_hcl_syntax_blocks(self):
        out = claude_write(project(), "envs/dev/web/main.tf", 'resource "aws_s3_bucket" "b" {\n  bucket = \n')
        self.assertTrue(denied(out), out)
        self.assertIn("hcl-syntax", reason(out))

    def test_protected_file_denied(self):
        out = claude_write(project(), ".kynfra/config.json", "{}")
        self.assertTrue(denied(out), out)
        self.assertIn("protected-files", reason(out))

    def test_apply_patch_codex_denied(self):
        proj = project()
        body = "\n".join("+" + ln for ln in PUBLIC_BUCKET.splitlines())
        out = codex_patch(proj, f"*** Add File: envs/dev/web/main.tf\n{body}\n")
        self.assertTrue(denied(out), out)
        self.assertIn("s3-private", reason(out))

    def test_apply_patch_update_codex_allowed_and_denied(self):
        proj = project()
        put(proj, "envs/dev/web/backend.tf", BACKEND_OK)
        ok = codex_patch(proj, "*** Update File: envs/dev/web/backend.tf\n@@\n-    key          = \"dev/web.tfstate\"\n"
                               "+    key          = \"dev/app.tfstate\"\n")
        self.assertEqual(ok, {})
        out = codex_patch(proj, "*** Update File: envs/dev/web/backend.tf\n@@\n-    encrypt      = true\n")
        self.assertTrue(denied(out), out)

    def test_apply_patch_delete_protected_denied(self):
        proj = project()
        put(proj, ".terraform.lock.hcl", "# lock\n")
        out = codex_patch(proj, "*** Delete File: .terraform.lock.hcl\n")
        self.assertTrue(denied(out), out)
        self.assertIn("protected-files", reason(out))

    def test_apply_patch_move_from_protected_denied(self):
        proj = project()
        put(proj, ".kynfra/config.json", "{}")
        out = codex_patch(proj, "*** Update File: .kynfra/config.json\n*** Move to: envs/dev/web/x.json\n@@\n-{}\n+{}\n")
        self.assertTrue(denied(out), out)

    def test_outside_infra_root_allowed(self):
        proj = project(infra_root="infra")
        out = claude_write(proj, "services/x/app.py", 'password = "x"\n')
        self.assertEqual(out, {})

    def test_inside_infra_root_scoped(self):
        proj = project(infra_root="infra")
        out = claude_write(proj, "infra/envs/dev/web/main.tf", PUBLIC_BUCKET)
        self.assertTrue(denied(out), out)
        self.assertIn("infra/envs/dev/web/main.tf", reason(out))

    def test_no_config_noop(self):
        d = Path(tempfile.mkdtemp(prefix="kynfra-noconf-"))
        self.assertEqual(claude_write(d, "envs/dev/web/main.tf", PUBLIC_BUCKET), {})


class PostEditTests(unittest.TestCase):
    def post(self, proj: Path, rel: str) -> dict:
        return run_hook("post_edit.py", {"cwd": str(proj), "hook_event_name": "PostToolUse", "tool_name": "Write",
                                         "tool_input": {"file_path": str(proj / rel), "content": "x"}})

    def test_post_edit_warns(self):
        proj = project()
        put(proj, "envs/dev/web/variables.tf", 'variable "name" {\n}\n')
        out = self.post(proj, "envs/dev/web/variables.tf")
        ctx = out["hookSpecificOutput"]["additionalContext"]
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PostToolUse")
        self.assertIn("variables-typed", ctx)
        self.assertNotIn("hcl-syntax", ctx)

    def test_post_edit_literal_reuse(self):
        proj = project()
        one = 'resource "aws_route53_record" "a" {\n  name = "app.acme.example.it"\n}\n'
        put(proj, "envs/dev/web/a.tf", one)
        put(proj, "envs/dev/web/b.tf", one.replace('"a"', '"b"'))
        out = self.post(proj, "envs/dev/web/b.tf")
        self.assertIn("literal-reuse", out["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(self.post(proj, "envs/dev/web/a.tf"), {})

    def test_post_edit_clean_silent(self):
        proj = project()
        put(proj, "envs/dev/web/backend.tf", BACKEND_OK)
        self.assertEqual(self.post(proj, "envs/dev/web/backend.tf"), {})

    def test_post_edit_caps_lines(self):
        proj = project()
        put(proj, "envs/dev/web/variables.tf", 'variable "n" {\n}\n' * 20)
        ctx = self.post(proj, "envs/dev/web/variables.tf")["hookSpecificOutput"]["additionalContext"]
        self.assertLessEqual(len(ctx.splitlines()), 17)
        self.assertIn("e altri", ctx.splitlines()[-1])

    def test_post_edit_no_config_noop(self):
        d = Path(tempfile.mkdtemp(prefix="kynfra-noconf-"))
        put(d, "envs/dev/web/variables.tf", 'variable "name" {\n}\n')
        self.assertEqual(self.post(d, "envs/dev/web/variables.tf"), {})


class SessionStartTests(unittest.TestCase):
    def test_records_head(self):
        proj = project().resolve()
        subprocess.run(["git", "init", "-q"], cwd=proj, check=True)
        subprocess.run(["git", "-c", "user.email=a@b.c", "-c", "user.name=t", "commit", "-q", "--allow-empty",
                        "-m", "x"], cwd=proj, check=True)
        sys.path.insert(0, str(SCRIPTS))
        import hook_common as hc
        event = {"cwd": str(proj), "session_id": "s-test-1"}
        bp = hc.baseline_path(event, proj)
        bp.unlink(missing_ok=True)
        self.assertEqual(run_hook("session_start.py", event), {})
        self.assertTrue(bp.is_file())
        bp.unlink()

    def test_hooks_json_status_messages(self):
        h = json.loads((ROOT / "plugins" / "kynfra" / "hooks" / "hooks.json").read_text())
        pre_msg = h["hooks"]["PreToolUse"][0]["hooks"][0]["statusMessage"]
        stop_msg = h["hooks"]["Stop"][0]["hooks"][0]["statusMessage"]
        self.assertEqual(pre_msg, "kynfra: checking infrastructure rules")
        self.assertEqual(stop_msg, "kynfra: fmt, validate, lint, scanner, architecture")


if __name__ == "__main__":
    unittest.main()
