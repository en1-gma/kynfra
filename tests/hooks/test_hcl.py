"""Test del parser HCL minimale (plugins/kynfra/scripts/hcl.py)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "plugins" / "kynfra" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import hcl  # noqa: E402


class HclTest(unittest.TestCase):
    def parse_ok(self, text, filename="main.tf"):
        """parse() su un file valido: nessun problema segnalato da parse_problems()."""
        self.assertEqual(hcl.parse_problems(text, filename), [])
        return hcl.parse(text, filename)

    def test_resource_block(self):
        blocks = self.parse_ok('resource "aws_s3_bucket" "site" { bucket = "x" }\n')
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
            [b.address() for b in self.parse_ok(text)],
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
        (p,) = self.parse_ok(text)
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
        (t,) = self.parse_ok(text)
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
        (b,) = self.parse_ok(text)
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
        tags = self.parse_ok(text)[0].children("default_tags")[0].get("tags")
        self.assertIsNone(tags.literal())
        entries = tags.entries()
        self.assertEqual(list(entries), ["Project", "Owner", "ManagedBy"])
        self.assertEqual(entries["Project"].raw, "var.project")
        self.assertEqual(entries["Project"].line, 4)
        self.assertEqual(entries["ManagedBy"].literal(), "kynfra")
        self.assertIsNone(self.parse_ok('x "y" { a = var.b }')[0].get("a").entries())

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
        (b,) = self.parse_ok(text)
        self.assertEqual(sorted(b.attrs), ["acl", "policy", "x"])
        self.assertEqual(b.blocks, [])
        self.assertEqual(b.get("policy").literal(), '{"a": "#{}"}\n')
        self.assertEqual(b.get("acl").literal(), "private")
        self.assertEqual(b.get("acl").line, 5)
        self.assertEqual(b.get("x").literal(), "a { # b // c")

    def test_heredoc_with_interpolation_not_literal(self):
        text = 'locals {\n  p = <<EOT\n${var.x}\nEOT\n  q = 2\n}\n'
        (b,) = self.parse_ok(text)
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
        blocks = self.parse_ok(text)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(list(blocks[0].attrs), ["bucket"])
        self.assertEqual(blocks[0].get("bucket").raw, '"b"')
        stripped = hcl.strip_comments(text)
        self.assertEqual(len(stripped), len(text))
        self.assertEqual(stripped.count("\n"), text.count("\n"))
        self.assertNotIn("public-read", stripped)
        self.assertIn('"b"', stripped)

    def test_strip_comments_respects_strings_and_heredoc(self):
        text = 'a = "http://x # y"\nb = <<EOT\n# not a comment\nEOT\n'
        self.assertEqual(hcl.strip_comments(text), text)
        self.assertEqual(hcl.strip_comments('c = "${d /* x */}"'), 'c = "${d        }"')

    def test_comment_does_not_hide_following_code(self):
        (b,) = self.parse_ok('r "a" "b" {\n  /* c */ acl = "public-read"\n}\n')
        self.assertEqual(b.get("acl").literal(), "public-read")

    def test_tf_json_blocks(self):
        text = '{"resource": {"aws_s3_bucket": {"site": {"acl": "public-read"}}}}'
        (b,) = self.parse_ok(text, "main.tf.json")
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
        blocks = self.parse_ok(text, "x.tf.json")
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
        (b,) = self.parse_ok('env = "dev"\n', "dev.tfvars")
        self.assertEqual(hcl.parse_problems('{"db_password": "s3cr3t"}', "x.tfvars.json"), [])
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

    # --- Fix round 1 ------------------------------------------------------------------------------------------------

    def test_tf_json_arrays_at_label_levels(self):
        bucket = '{"pub": {"acl": "public-read"}}'
        for text in (
            '{"resource": [{"aws_s3_bucket": %s}]}' % bucket,
            '{"resource": {"aws_s3_bucket": [%s]}}' % bucket,
            '{"resource": {"aws_s3_bucket": {"pub": [{"acl": "public-read"}]}}}',
        ):
            (b,) = self.parse_ok(text, "main.tf.json")
            self.assertEqual(b.address(), "aws_s3_bucket.pub")
            self.assertEqual(b.get("acl").literal(), "public-read")

    def test_tf_json_deep_nesting_keeps_siblings(self):
        deep = '{"a": ' * 1200 + "1" + "}" * 1200
        text = (
            '{\n"locals": {"x": %s},\n'
            '"resource": {"aws_s3_bucket": {"pub": {"acl": "public-read"}}}\n}' % deep
        )
        blocks = hcl.parse(text, "main.tf.json")
        self.assertEqual([b.address() for b in blocks], ["locals", "aws_s3_bucket.pub"])
        self.assertEqual(blocks[1].get("acl").literal(), "public-read")
        self.assertIsNone(blocks[0].get("x").literal())
        problems = hcl.parse_problems(text, "main.tf.json")
        self.assertTrue(problems and all("profondità massima" in m for _, m in problems))

    def test_hcl_deep_nesting_keeps_siblings(self):
        text = "a {\n" * 300 + "}\n" * 300 + 'resource "aws_s3_bucket" "pub" {\n  acl = "public-read"\n}\n'
        blocks = hcl.parse(text)
        self.assertEqual(blocks[-1].address(), "aws_s3_bucket.pub")
        self.assertEqual(blocks[-1].get("acl").literal(), "public-read")
        self.assertTrue(any("profondità massima" in m for _, m in hcl.parse_problems(text)))

    def test_comment_inside_interpolation(self):
        text = (
            'resource "a" "b" {\n'
            '  name = "${var.a /* " */}"\n'
            '  x = "${var.a /* { */}"\n'
            '  y = "${var.a # " {\n}"\n'
            '}\n'
            'resource "aws_s3_bucket" "pub" { acl = "public-read" }\n'
        )
        blocks = self.parse_ok(text)
        self.assertEqual([b.address() for b in blocks], ["a.b", "aws_s3_bucket.pub"])
        self.assertEqual(blocks[0].get("name").raw, '"${var.a        }"')
        self.assertEqual(blocks[1].get("acl").literal(), "public-read")
        stripped = hcl.strip_comments(text)
        self.assertEqual(len(stripped), len(text))
        self.assertNotIn("/*", stripped)

    def test_parse_problems(self):
        cases = {
            "blocco non chiuso": ('resource "a" "b" {\n  x = 1\n', "main.tf"),
            "parentesi non chiusa": ('resource "a" "b" {\n  x = [1,\n}\n', "main.tf"),
            "graffa in eccesso": ('resource "a" "b" {}\n}\n', "main.tf"),
            "stringa non chiusa": ('resource "a" "b" {\n  x = "abc\n}\n', "main.tf"),
            "heredoc non chiuso": ('resource "a" "b" {\n  p = <<EOT\n{}\n}\n', "main.tf"),
            "commento non chiuso": ('resource "a" "b" {}\n/* x\n', "main.tf"),
            "elemento non riconosciuto": ('resource "a" "b"\n{\n}\n', "main.tf"),
            "JSON non valido": ('{"resource": ', "main.tf.json"),
            "JSON non oggetto": ("[1, 2]", "main.tf.json"),
            "tfvars.json non valido": ('{"a": 1,}', "x.tfvars.json"),
            "profondità JSON": ('{"locals": {"x": %s}}' % ("[" * 150 + "]" * 150), "main.tf.json"),
            "profondità HCL": ("a {\n" * 150 + "}\n" * 150, "main.tf"),
        }
        for name, (text, filename) in cases.items():
            with self.subTest(name):
                problems = hcl.parse_problems(text, filename)
                self.assertTrue(problems)
                for line, msg in problems:
                    self.assertIsInstance(line, int)
                    self.assertGreaterEqual(line, 1)
                    self.assertTrue(msg)
        self.assertEqual(hcl.parse_problems('resource "a" "b" {\n  x = 1\n', "main.tf")[0][0], 1)
        self.assertEqual(hcl.parse_problems("", "main.tf"), [])

    def test_only_tf_json_and_tfvars_json_are_json(self):
        text = '{"resource": {"aws_s3_bucket": {"pub": {"acl": "public-read"}}}}'
        self.assertEqual(hcl.parse(text, "main.json"), [])
        self.assertTrue(hcl.parse_problems(text, "main.json"))
        self.assertEqual(hcl.parse_tfvars('a = 1\n', "x.json")["a"].literal(), 1)


if __name__ == "__main__":
    unittest.main()
