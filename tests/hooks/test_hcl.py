"""Test del parser HCL minimale (plugins/kynfra/scripts/hcl.py)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "plugins" / "kynfra" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import hcl  # noqa: E402


class HclTest(unittest.TestCase):
    def test_resource_block(self):
        blocks = hcl.parse('resource "aws_s3_bucket" "site" { bucket = "x" }\n')
        self.assertEqual(len(blocks), 1)
        b = blocks[0]
        self.assertEqual(b.type, "resource")
        self.assertEqual(b.labels, ["aws_s3_bucket", "site"])
        self.assertEqual(b.get("bucket").literal(), "x")
        self.assertEqual(b.address(), "aws_s3_bucket.site")
        self.assertEqual((b.line, b.end_line), (1, 1))

    def test_addresses(self):
        text = (
            'module "x" {}\nprovider "aws" {}\ndata "aws_iam_policy_document" "p" {}\n'
            'variable "v" {}\noutput "o" {}\nterraform {}\nlocals {}\n'
        )
        self.assertEqual(
            [b.address() for b in hcl.parse(text)],
            ["module.x", "provider.aws", "data.aws_iam_policy_document.p", "var.v", "output.o", "terraform", "locals"],
        )

    def test_nested_blocks_and_lines(self):
        text = (
            'provider "aws" {\n'
            '  region = "eu-south-1"\n'
            '  default_tags {\n'
            '    tags = {\n'
            '      Project = "p"\n'
            '    }\n'
            '  }\n'
            '}\n'
        )
        (p,) = hcl.parse(text)
        self.assertEqual((p.line, p.end_line), (1, 8))
        self.assertEqual(p.get("region").line, 2)
        dt = p.children("default_tags")[0]
        self.assertEqual((dt.line, dt.end_line), (3, 7))
        tags = dt.get("tags")
        self.assertEqual(tags.line, 4)
        self.assertEqual(tags.literal(), {"Project": "p"})
        self.assertEqual(p.children("missing"), [])
        self.assertIsNone(p.get("missing"))

    def test_terraform_backend(self):
        text = (
            'terraform {\n'
            '  backend "s3" {\n'
            '    encrypt      = true\n'
            '    use_lockfile = true\n'
            '  }\n'
            '  required_providers {\n'
            '    aws = { source = "hashicorp/aws", version = "~> 6.0" }\n'
            '  }\n'
            '}\n'
        )
        (t,) = hcl.parse(text)
        backend = t.children("backend")[0]
        self.assertEqual(backend.labels, ["s3"])
        self.assertIs(backend.get("encrypt").literal(), True)
        aws = t.children("required_providers")[0].get("aws")
        self.assertEqual(aws.literal(), {"source": "hashicorp/aws", "version": "~> 6.0"})

    def test_expressions_kept_raw(self):
        text = (
            'resource "a" "b" {\n'
            '  bucket = var.name # commento\n'
            '  count = 1\n'
            '  ratio = -0.5\n'
            '  x = true\n'
            '  l = ["a", "b"]\n'
            '  name = "${var.p}-site"\n'
            '  esc = "$${literal}"\n'
            '  cond = var.a ? "x" : "y"\n'
            '  call = merge(\n'
            '    var.tags,\n'
            '    { Name = "n" },\n'
            '  )\n'
            '  after = "ok"\n'
            '}\n'
        )
        (b,) = hcl.parse(text)
        self.assertIsNone(b.get("bucket").literal())
        self.assertEqual(b.get("bucket").raw, "var.name")
        self.assertEqual(b.get("count").literal(), 1)
        self.assertEqual(b.get("ratio").literal(), -0.5)
        self.assertIs(b.get("x").literal(), True)
        self.assertEqual(b.get("l").literal(), ["a", "b"])
        self.assertIsNone(b.get("name").literal())
        self.assertEqual(b.get("esc").literal(), "${literal}")
        self.assertIsNone(b.get("cond").literal())
        call = b.get("call")
        self.assertEqual(call.line, 10)
        self.assertTrue(call.raw.startswith("merge(") and call.raw.endswith(")"))
        self.assertIn('{ Name = "n" }', call.raw)
        self.assertIsNone(call.literal())
        self.assertEqual(b.get("after").literal(), "ok")
        self.assertEqual(b.get("after").line, 14)

    def test_entries_of_partial_object(self):
        text = (
            'provider "aws" {\n'
            '  default_tags {\n'
            '    tags = {\n'
            '      Project   = var.project\n'
            '      "Owner"   = "team"\n'
            '      ManagedBy : "kynfra",\n'
            '    }\n'
            '  }\n'
            '}\n'
        )
        tags = hcl.parse(text)[0].children("default_tags")[0].get("tags")
        self.assertIsNone(tags.literal())
        entries = tags.entries()
        self.assertEqual(list(entries), ["Project", "Owner", "ManagedBy"])
        self.assertEqual(entries["Project"].raw, "var.project")
        self.assertEqual(entries["Project"].line, 4)
        self.assertEqual(entries["ManagedBy"].literal(), "kynfra")
        self.assertIsNone(hcl.parse('x "y" { a = var.b }')[0].get("a").entries())

    def test_heredoc_and_braces_in_strings(self):
        text = (
            'resource "aws_s3_bucket_policy" "p" {\n'
            '  policy = <<-EOT\n'
            '    {"a": "#{}"}\n'
            '    EOT\n'
            '  acl = "private"\n'
            '  x = "a { # b // c"\n'
            '}\n'
        )
        (b,) = hcl.parse(text)
        self.assertEqual(sorted(b.attrs), ["acl", "policy", "x"])
        self.assertEqual(b.blocks, [])
        self.assertEqual(b.get("policy").literal(), '{"a": "#{}"}\n')
        self.assertEqual(b.get("acl").literal(), "private")
        self.assertEqual(b.get("acl").line, 5)
        self.assertEqual(b.get("x").literal(), "a { # b // c")

    def test_heredoc_with_interpolation_not_literal(self):
        text = 'locals {\n  p = <<EOT\n${var.x}\nEOT\n  q = 2\n}\n'
        (b,) = hcl.parse(text)
        self.assertIsNone(b.get("p").literal())
        self.assertEqual(b.get("q").literal(), 2)

    def test_comments_ignored(self):
        text = (
            'resource "aws_s3_bucket" "b" {\n'
            '  # acl = "public-read"\n'
            '  // acl = "public-read"\n'
            '  /* acl = "public-read"\n'
            '     resource "x" "y" { } */\n'
            '  bucket = "b" // fine\n'
            '}\n'
            '# resource "aws_s3_bucket" "hidden" {}\n'
        )
        blocks = hcl.parse(text)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(list(blocks[0].attrs), ["bucket"])
        self.assertEqual(blocks[0].get("bucket").raw, '"b"')
        stripped = hcl.strip_comments(text)
        self.assertEqual(len(stripped), len(text))
        self.assertEqual(stripped.count("\n"), text.count("\n"))
        self.assertNotIn("public-read", stripped)
        self.assertIn('"b"', stripped)

    def test_strip_comments_respects_strings_and_heredoc(self):
        text = 'a = "http://x # y"\nb = <<EOT\n# not a comment\nEOT\nc = "${d /* x */}"\n'
        self.assertEqual(hcl.strip_comments(text), text)

    def test_comment_does_not_hide_following_code(self):
        (b,) = hcl.parse('r "a" "b" {\n  /* c */ acl = "public-read"\n}\n')
        self.assertEqual(b.get("acl").literal(), "public-read")

    def test_tf_json_blocks(self):
        text = '{"resource": {"aws_s3_bucket": {"site": {"acl": "public-read"}}}}'
        (b,) = hcl.parse(text, "main.tf.json")
        self.assertEqual(b.type, "resource")
        self.assertEqual(b.labels, ["aws_s3_bucket", "site"])
        self.assertEqual(b.attrs["acl"].literal(), "public-read")
        self.assertEqual(b.address(), "aws_s3_bucket.site")

    def test_tf_json_nested_and_lines(self):
        text = (
            '{\n'
            '  "provider": {\n'
            '    "aws": [\n'
            '      {\n'
            '        "region": "${var.region}",\n'
            '        "default_tags": {"tags": {"Project": "p"}}\n'
            '      }\n'
            '    ]\n'
            '  },\n'
            '  "terraform": {"backend": {"s3": {"encrypt": true}}},\n'
            '  "locals": {"m": {"a": 1}}\n'
            '}\n'
        )
        blocks = hcl.parse(text, "x.tf.json")
        self.assertEqual([b.address() for b in blocks], ["provider.aws", "terraform", "locals"])
        p = blocks[0]
        self.assertEqual(p.line, 4)
        self.assertEqual(p.get("region").line, 5)
        self.assertIsNone(p.get("region").literal())
        self.assertEqual(p.get("region").raw, "var.region")
        self.assertEqual(p.get("default_tags").literal(), {"tags": {"Project": "p"}})
        self.assertEqual(p.children("default_tags")[0].get("tags").literal(), {"Project": "p"})
        self.assertEqual(p.children("default_tags")[0].get("tags").entries()["Project"].literal(), "p")
        backend = blocks[1].children("backend")[0]
        self.assertEqual(backend.labels, ["s3"])
        self.assertIs(backend.get("encrypt").literal(), True)
        self.assertEqual(blocks[2].get("m").literal(), {"a": 1})
        self.assertEqual(blocks[2].blocks, [])

    def test_tf_json_invalid_does_not_raise(self):
        self.assertEqual(hcl.parse('{"resource": ', "x.tf.json"), [])
        self.assertEqual(hcl.parse('[1, 2]', "x.tf.json"), [])

    def test_tfvars(self):
        vars_ = hcl.parse_tfvars('db_password = "s3cr3t"\n', "x.tfvars")
        self.assertEqual(vars_["db_password"].literal(), "s3cr3t")
        vars_ = hcl.parse_tfvars('{"db_password": "s3cr3t", "n": 2}', "x.tfvars.json")
        self.assertEqual(vars_["db_password"].literal(), "s3cr3t")
        self.assertEqual(vars_["n"].line, 1)
        (b,) = hcl.parse('env = "dev"\n', "dev.tfvars")
        self.assertEqual(b.type, "tfvars")
        self.assertEqual(b.get("env").literal(), "dev")

    def test_malformed_does_not_raise(self):
        text = (
            'resource "a" "ok" {\n  x = 1\n}\n'
            '}\n'
            'resource "a" "ok2" { y = "}" }\n'
            'resource "a" "broken" {\n  z = {\n'
        )
        blocks = hcl.parse(text)
        self.assertEqual([b.address() for b in blocks], ["a.ok", "a.ok2"])
        self.assertEqual(blocks[1].get("y").literal(), "}")
        for bad in ['"unterminated', "x = <<EOT\nno end", "{" * 5000, "a = " + "[" * 5000, "<<", "${"]:
            hcl.parse(bad)
            hcl.strip_comments(bad)
            hcl.parse_tfvars(bad, "x.tfvars")


if __name__ == "__main__":
    unittest.main()
