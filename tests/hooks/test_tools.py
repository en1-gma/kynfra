"""Test del gestore strumenti (tools.py): nessuna rete, fetch finto e archivi costruiti in memoria."""
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import unittest
import unittest.mock
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "plugins" / "kynfra" / "scripts"))

import tools  # noqa: E402

SCRIPT = "#!/bin/sh\necho 'fake {v}'\n"


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, d in entries.items():
            z.writestr(n, d)
    return buf.getvalue()


def make_targz(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for n, d in entries.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            t.addfile(ti, io.BytesIO(d))
    return buf.getvalue()


class Env:
    """Fetch finto: serve archivio e SHA256SUMS per uno strumento."""

    def __init__(self, tool, os_="linux", arch="amd64", archive=None, bad_sum=False, name_in_sums=True):
        self.tool, self.os_, self.arch = tool, os_, arch
        self.e = tools.catalog()[tool]
        v = self.e["version"]
        self.binary_bytes = SCRIPT.format(v=v).encode()
        if archive is None:
            mk = make_targz if self.e["archive"] == "tar.gz" else make_zip
            archive = mk({self.e["binary"]: self.binary_bytes, "LICENSE": b"x"})
        self.archive = archive
        self.plan = tools.plan_install(Path("/p"), tool, os_, arch)
        digest = hashlib.sha256(archive).hexdigest()
        if bad_sum:
            digest = "0" * 64
        fname = self.plan["url"].rsplit("/", 1)[1] if name_in_sums else "altro.zip"
        self.sums = f"{digest}  {fname}\n{'1' * 64}  altro.zip\n".encode()
        self.calls = []

    def fetch(self, url):
        self.calls.append(url)
        if url == self.plan["url"]:
            return self.archive
        if url == self.plan["sha256_url"]:
            return self.sums
        raise AssertionError(f"URL inatteso {url}")


class ToolsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def do_install(self, tool="tflint", env=None, approved="Mario Rossi", **kw):
        env = env or Env(tool)
        return env, tools.install(self.proj, tool, approved, fetch=env.fetch, os_="linux", arch="amd64", **kw)

    def lock(self):
        return json.loads((self.proj / ".kynfra/tools.lock.json").read_text())

    def test_catalog_has_all_tools(self):
        cat = tools.catalog()
        for t in ("terraform", "opentofu", "tflint", "tflint_ruleset_aws", "checkov", "trivy"):
            self.assertIn(t, cat)
            self.assertTrue(cat[t]["version"])
        self.assertEqual(cat["checkov"]["kind"], "pypi")

    def test_install_records_lock(self):
        env, rec = self.do_install("tflint")
        b = self.proj / ".kynfra/bin/tflint"
        self.assertTrue(b.is_file())
        self.assertEqual(stat.S_IMODE(b.stat().st_mode), 0o755)
        e = self.lock()["tools"]["tflint"]
        for k in ("version", "source", "sha256", "binary_sha256", "installed_at", "approved_by"):
            self.assertTrue(e.get(k), k)
        self.assertEqual(e["approved_by"], "Mario Rossi")
        self.assertEqual(e["sha256"], hashlib.sha256(env.archive).hexdigest())
        self.assertEqual(e["binary_sha256"], hashlib.sha256(env.binary_bytes).hexdigest())
        self.assertEqual(e["source"], env.plan["url"])
        text = (self.proj / ".kynfra/tools.lock.json").read_text()
        self.assertEqual(text, json.dumps(json.loads(text), sort_keys=True, indent=2) + "\n")

    def test_install_trivy_targz(self):
        self.do_install("trivy")
        self.assertTrue((self.proj / ".kynfra/bin/trivy").is_file())

    def test_install_verifies_checksum(self):
        env = Env("tflint", bad_sum=True)
        with self.assertRaises(tools.ToolError):
            self.do_install("tflint", env)
        self.assertFalse((self.proj / ".kynfra/bin/tflint").exists())
        self.assertEqual(list((self.proj / ".kynfra").glob("**/.tmp-*")), [])
        self.assertFalse((self.proj / ".kynfra/tools.lock.json").exists())

    def test_install_checksum_missing_entry(self):
        with self.assertRaises(tools.ToolError):
            self.do_install("tflint", Env("tflint", name_in_sums=False))
        self.assertFalse((self.proj / ".kynfra/bin/tflint").exists())

    def test_unknown_tool_rejected(self):
        with self.assertRaises(tools.ToolError):
            tools.install(self.proj, "curl", "x", fetch=lambda u: b"")
        with self.assertRaises(tools.ToolError):
            tools.plan_install(self.proj, "nope", "linux", "amd64")

    def test_approved_by_required(self):
        for v in ("", "   "):
            with self.assertRaises(tools.ToolError):
                self.do_install("tflint", approved=v)

    def test_refuses_root(self):
        with unittest.mock.patch("os.geteuid", return_value=0):
            with self.assertRaises(tools.ToolError):
                self.do_install("tflint")
        self.assertFalse((self.proj / ".kynfra/bin/tflint").exists())

    def test_rejects_unsafe_archive_entries(self):
        for bad in ("../tflint", "/etc/tflint"):
            arc = make_zip({"tflint": b"ok", bad: b"evil"})
            with self.assertRaises(tools.ToolError):
                self.do_install("tflint", Env("tflint", archive=arc))
        arc = make_targz({"x/../../tflint": b"evil"})
        with self.assertRaises(tools.ToolError):
            self.do_install("trivy", Env("trivy", archive=arc))
        self.assertFalse((self.proj / ".kynfra/bin").exists() and any((self.proj / ".kynfra/bin").iterdir()))

    def test_binary_missing_in_archive(self):
        with self.assertRaises(tools.ToolError):
            self.do_install("tflint", Env("tflint", archive=make_zip({"altro": b"x"})))

    def test_url_allowlist(self):
        for u in ("http://github.com/x", "https://evil.example/x", "ftp://github.com/x"):
            with self.assertRaises(tools.ToolError):
                tools.check_url(u)
        tools.check_url("https://releases.hashicorp.com/terraform/1/x.zip")
        for u in (tools.catalog()[t]["url_template"] for t in tools.catalog()):
            self.assertTrue(u.startswith("https://"))
            self.assertIn(u.split("/")[2], tools.ALLOWED_HOSTS)

    def test_redirect_to_foreign_host_refused(self):
        h = tools._AllowlistRedirect()
        with self.assertRaises(tools.ToolError):
            h.redirect_request(unittest.mock.Mock(), None, 302, "x", {}, "https://evil.example/a")

    def test_platform_mapping(self):
        with unittest.mock.patch("platform.system", return_value="Darwin"), \
                unittest.mock.patch("platform.machine", return_value="arm64"):
            self.assertEqual(tools.detect_platform(), ("darwin", "arm64"))
        with unittest.mock.patch("platform.system", return_value="Linux"), \
                unittest.mock.patch("platform.machine", return_value="x86_64"):
            self.assertEqual(tools.detect_platform(), ("linux", "amd64"))
        with unittest.mock.patch("platform.system", return_value="Linux"), \
                unittest.mock.patch("platform.machine", return_value="aarch64"):
            self.assertEqual(tools.detect_platform(), ("linux", "arm64"))
        with unittest.mock.patch("platform.system", return_value="Windows"), \
                unittest.mock.patch("platform.machine", return_value="AMD64"):
            with self.assertRaises(tools.ToolError):
                tools.detect_platform()

    def test_plan_shows_source_and_dest(self):
        p = tools.plan_install(self.proj, "terraform", "darwin", "arm64")
        v = tools.catalog()["terraform"]["version"]
        self.assertEqual(p["url"], f"https://releases.hashicorp.com/terraform/{v}/terraform_{v}_darwin_arm64.zip")
        self.assertTrue(p["sha256_url"].endswith("SHA256SUMS"))
        self.assertEqual(p["dest"], str(self.proj / ".kynfra/bin/terraform"))
        t = p["approval_text"]
        for needle in ("terraform", v, p["url"], p["sha256_url"], p["dest"], "GPG"):
            self.assertIn(needle, t)
        with self.assertRaises(tools.ToolError):
            tools.plan_install(self.proj, "terraform", "windows", "amd64")

    def test_plan_trivy_platform_names(self):
        p = tools.plan_install(self.proj, "trivy", "darwin", "arm64")
        self.assertIn("_macOS-ARM64.tar.gz", p["url"])

    def test_resolve_prefers_local_bin(self):
        bindir = self.proj / ".kynfra/bin"
        bindir.mkdir(parents=True)
        f = bindir / "tflint"
        f.write_text("#!/bin/sh\n")
        f.chmod(0o755)
        self.assertEqual(tools.resolve_binary(self.proj, "tflint"), str(f))
        self.assertIsNone(tools.resolve_binary(self.proj, "nonesiste-xyz"))

    def test_resolve_skips_tampered_binary(self):
        self.do_install("tflint")
        f = self.proj / ".kynfra/bin/tflint"
        self.assertEqual(tools.resolve_binary(self.proj, "tflint"), str(f))
        f.write_text("#!/bin/sh\necho evil\n")
        f.chmod(0o755)
        self.assertNotEqual(tools.resolve_binary(self.proj, "tflint"), str(f))

    def test_verify_lock_ok_then_detects_mismatch(self):
        self.do_install("tflint")
        self.assertEqual(tools.verify_lock(self.proj), [])
        f = self.proj / ".kynfra/bin/tflint"
        f.write_text("#!/bin/sh\necho 'fake 0.0.1'\n")
        f.chmod(0o755)
        probs = tools.verify_lock(self.proj)
        self.assertTrue(any("SHA256" in p for p in probs), probs)
        self.assertTrue(any("versione" in p for p in probs), probs)

    def test_verify_lock_missing_binary(self):
        self.do_install("tflint")
        (self.proj / ".kynfra/bin/tflint").unlink()
        self.assertTrue(any("manca" in p for p in tools.verify_lock(self.proj)))

    def test_status(self):
        self.do_install("tflint")
        rows = {r["tool"]: r for r in tools.status(self.proj, {"iac": "opentofu", "scanner": "trivy"})}
        self.assertTrue(rows["tflint"]["ok"] and rows["tflint"]["in_lock"] and rows["tflint"]["required"])
        self.assertTrue(rows["opentofu"]["required"])
        self.assertFalse(rows["terraform"]["required"])
        self.assertTrue(rows["trivy"]["required"])
        self.assertFalse(rows["checkov"]["required"])
        self.assertFalse(rows["trivy"]["ok"])
        self.assertIsNone(rows["trivy"]["path"] if not tools.shutil.which("trivy") else None)

    def test_checkov_pypi(self):
        calls = []

        def run(cmd, **kw):
            calls.append(cmd)
            if "venv" in cmd:
                py = Path(cmd[-1]) / "bin" / "python"
                py.parent.mkdir(parents=True)
                py.write_text("")
            else:
                b = Path(cmd[0]).parent / "checkov"
                b.write_text("#!/bin/sh\necho 3\n")
                b.chmod(0o755)
            return unittest.mock.Mock(returncode=0, stdout="", stderr="")

        rec = tools.install(self.proj, "checkov", "Mario", fetch=lambda u: b"", run=run)
        v = tools.catalog()["checkov"]["version"]
        self.assertTrue(any(f"checkov=={v}" in c for c in calls))
        e = self.lock()["tools"]["checkov"]
        self.assertEqual(e["source"], "pypi")
        self.assertIsNone(e["sha256"])
        self.assertEqual(e["approved_by"], "Mario")
        self.assertEqual(rec["path"], str(self.proj / ".kynfra/venv/bin/checkov"))

    def test_cli_install_requires_single_tool(self):
        with unittest.mock.patch.dict(os.environ, {"CLAUDE_PROJECT_DIR": str(self.proj)}), \
                unittest.mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(tools.main(["install", "tflint", "trivy", "--approved-by", "x"]), 2)
            self.assertEqual(tools.main(["install", "--approved-by", "x"]), 2)
            self.assertEqual(tools.main(["install", "curl", "--approved-by", "x"]), 1)
            self.assertEqual(tools.main(["install", "tflint"]), 1)  # senza --approved-by

    def test_external_resolve_delegates(self):
        import external
        with unittest.mock.patch("tools.resolve_binary", return_value="/x/y") as m:
            self.assertEqual(external._resolve(self.proj, "tflint"), "/x/y")
        m.assert_called_once_with(self.proj, "tflint")


if __name__ == "__main__":
    unittest.main()
