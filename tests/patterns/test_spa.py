"""Test specifici del pattern spa: OAC e non OAI, certificato in us-east-1, nessuna risposta d'errore riscritta su
index.html, behavior /api/* solo con api_origin, zona condivisa solo con hosted_zone=create, WAF in prod."""
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_patterns as tp  # noqa: E402

generate = tp.generate


def tfvars(text: str) -> dict:
    return dict(re.findall(r'^(\w+)\s*=\s*"?([^"\n]*?)"?\s*$', text, re.M))


def block(text: str, header: str) -> str:
    """Corpo di un blocco di primo livello (chiuso da '}' a inizio riga)."""
    m = re.search(re.escape(header) + r" \{(.*?)\n\}", text, re.S)
    assert m, f"blocco assente: {header}"
    return m.group(1)


class SpaPatternTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="kynfra-spa-")
        cls.proj = Path(cls._tmp.name)
        cfg = tp.make_project(cls.proj)
        res = generate.generate(cls.proj, cfg, "aws", "spa", ["dev", "staging", "prod"],
                                {"domain_name": "app.example.com", "hosted_zone": "create"})
        assert res["created"]
        cls.other = Path(cls._tmp.name) / "existing"
        cls.other.mkdir()
        cfg2 = tp.make_project(cls.other)
        generate.generate(cls.other, cfg2, "aws", "spa", ["dev"],
                          {"domain_name": "app.example.com", "hosted_zone": "existing:Z0123456789ABC",
                           "api_origin": "backend"})

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def module(self, name: str) -> str:
        return (self.proj / "infra/modules/spa" / name).read_text(encoding="utf-8")

    def stack(self, env: str, name: str, proj: Path = None) -> str:
        return ((proj or self.proj) / "infra/envs" / env / "spa" / name).read_text(encoding="utf-8")

    def test_spa_uses_oac_not_oai(self):
        text = self.module("main.tf")
        self.assertNotIn("s3_origin_config", text)
        self.assertNotIn("aws_cloudfront_origin_access_identity", text)
        oac = block(text, 'resource "aws_cloudfront_origin_access_control" "site"')
        for pattern in (r'origin_access_control_origin_type\s*=\s*"s3"', r'signing_behavior\s*=\s*"always"',
                        r'signing_protocol\s*=\s*"sigv4"'):
            self.assertRegex(oac, pattern)
        dist = block(text, 'resource "aws_cloudfront_distribution" "this"')
        self.assertRegex(dist, r"domain_name\s*=\s*aws_s3_bucket\.site\.bucket_regional_domain_name")
        self.assertRegex(dist, r"origin_access_control_id\s*=\s*aws_cloudfront_origin_access_control\.site\.id")
        policy = block(text, 'resource "aws_s3_bucket_policy" "site"')
        self.assertIn('Service = "cloudfront.amazonaws.com"', policy)
        self.assertRegex(policy, r'"AWS:SourceArn"\s*=\s*aws_cloudfront_distribution\.this\.arn')
        self.assertRegex(policy, r'"aws:SecureTransport"\s*=\s*"false"')

    def test_spa_cert_in_us_east_1(self):
        text = self.module("main.tf")
        for header in ('resource "aws_acm_certificate" "this"', 'resource "aws_acm_certificate_validation" "this"',
                       'resource "aws_wafv2_web_acl" "this"', 'resource "aws_cloudwatch_log_delivery_source" "cdn"'):
            self.assertRegex(block(text, header), r"provider\s*=\s*aws\.us_east_1", header)
        self.assertRegex(block(text, 'resource "aws_acm_certificate" "this"'), r'validation_method\s*=\s*"DNS"')
        self.assertRegex(self.module("versions.tf"), r"configuration_aliases\s*=\s*\[aws\.us_east_1\]")
        providers = self.stack("prod", "providers.tf")
        alias = providers.split('alias               = "us_east_1"', 1)[1]
        self.assertRegex(alias, r'region\s*=\s*"us-east-1"')
        self.assertIn("allowed_account_ids = [var.account_id]", alias)
        self.assertIn('ManagedBy   = "kynfra"', alias)
        self.assertRegex(self.stack("prod", "main.tf"), r"aws\.us_east_1\s*=\s*aws\.us_east_1")
        viewer = block(text, 'resource "aws_cloudfront_distribution" "this"')
        self.assertRegex(viewer, r'minimum_protocol_version\s*=\s*"TLSv1\.2_2021"')
        self.assertRegex(viewer, r'ssl_support_method\s*=\s*"sni-only"')

    def test_spa_no_error_response_rewrite(self):
        text = self.module("main.tf")
        # nessun blocco custom_error_response (statico o dynamic): 403/404 dell'origin non diventano index.html
        found = re.findall(r'(?m)^\s*(?:dynamic\s+")?custom_error_response"?\s*\{', text)
        self.assertEqual(found, [])
        fn = block(text, 'resource "aws_cloudfront_function" "spa_routing"')
        self.assertRegex(fn, r'runtime\s*=\s*"cloudfront-js-2\.0"')
        self.assertIn("'/api/'", fn)
        self.assertIn("request.uri = '/index.html'", fn)
        self.assertRegex(text, r'event_type\s*=\s*"viewer-request"\s*\n\s*function_arn\s*=\s*'
                               r"aws_cloudfront_function\.spa_routing\.arn")

    def test_spa_api_behavior_optional(self):
        text = self.module("main.tf")
        # unico /api/*: dentro un dynamic acceso solo con api_domain_name non vuoto
        self.assertEqual(text.count('"/api/*"'), 1)
        self.assertRegex(text, r'dynamic "ordered_cache_behavior" \{\s*for_each = local\.api_enabled \? '
                               r'toset\(\["/api/\*"\]\) : toset\(\[\]\)')
        self.assertRegex(text, r'dynamic "origin" \{\s*for_each = local\.api_enabled \?')
        self.assertRegex(text, r'api_enabled\s*=\s*var\.api_domain_name != ""')
        self.assertRegex(self.module("variables.tf"), r'variable "api_domain_name" \{[^}]*default\s*=\s*""')
        # senza api_origin: tfvars vuoto, nessun remote state del backend, nessun dominio API al modulo
        self.assertEqual(tfvars(self.stack("dev", "terraform.tfvars"))["api_origin"], "")
        main = self.stack("dev", "main.tf")
        self.assertRegex(block(main, 'data "terraform_remote_state" "backend"'),
                         r"count\s*=\s*local\.api_backend \? 1 : 0")
        self.assertRegex(main, r'api_backend\s*=\s*var\.api_origin == "backend"')
        self.assertRegex(main, r'api_domain_name\s*=\s*local\.api_backend \? '
                               r'data\.terraform_remote_state\.backend\[0\]\.outputs\.api_domain_name : ""')
        self.assertIn('key    = "${var.project}/${var.environment}/backend.tfstate"', main)
        # con api_origin=backend: il valore arriva ai tfvars
        self.assertEqual(tfvars(self.stack("dev", "terraform.tfvars", self.other))["api_origin"], "backend")
        api = text.split('for_each = local.api_enabled ? toset(["/api/*"])', 1)[1].split("\n  }\n", 1)[0]
        for pattern in (r'viewer_protocol_policy\s*=\s*"https-only"',
                        r"cache_policy_id\s*=\s*data\.aws_cloudfront_cache_policy\.caching_disabled\.id",
                        r"origin_request_policy_id\s*=\s*data\.aws_cloudfront_origin_request_policy\."
                        r"all_viewer_except_host\.id"):
            self.assertRegex(api, pattern)
        self.assertRegex(text, r'origin_protocol_policy\s*=\s*"https-only"')
        self.assertRegex(text, r'origin_ssl_protocols\s*=\s*\["TLSv1\.2"\]')

    def test_spa_shared_dns_only_with_create(self):
        self.assertTrue((self.proj / "infra/envs/shared/dns/main.tf").is_file())
        self.assertFalse((self.other / "infra/envs/shared").exists())
        shared = tfvars((self.proj / "infra/envs/shared/dns/terraform.tfvars").read_text(encoding="utf-8"))
        self.assertEqual((shared["environment"], shared["domain_name"]), ("shared", "app.example.com"))
        backend = (self.proj / "infra/envs/shared/dns/backend.tf").read_text(encoding="utf-8")
        self.assertIn('key          = "acme/shared/dns.tfstate"', backend)
        main = self.stack("dev", "main.tf")
        self.assertIn('key    = "${var.project}/shared/dns.tfstate"', main)
        self.assertEqual(tfvars(self.stack("dev", "terraform.tfvars", self.other))["hosted_zone"],
                         "existing:Z0123456789ABC")

    def test_spa_waf_prod_only(self):
        self.assertEqual(tfvars(self.stack("prod", "terraform.tfvars"))["waf_enabled"], "true")
        self.assertEqual(tfvars(self.stack("dev", "terraform.tfvars"))["waf_enabled"], "false")
        self.assertEqual(tfvars(self.stack("staging", "terraform.tfvars"))["waf_enabled"], "false")
        text = self.module("main.tf")
        self.assertRegex(text, r"web_acl_id\s*=\s*var\.waf_enabled \? aws_wafv2_web_acl\.this\[0\]\.arn : null")
        waf = block(text, 'resource "aws_wafv2_web_acl" "this"')
        self.assertIn('scope       = "CLOUDFRONT"', waf)
        for group in ("AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet",
                      "AWSManagedRulesAmazonIpReputationList"):
            self.assertIn(f'"{group}"', waf)
        self.assertIn("rate_based_statement", waf)
        self.assertRegex(self.module("variables.tf"), r'var\.environment != "prod" \|\| var\.waf_enabled')

    def test_spa_headers_cache_and_logs(self):
        text = self.module("main.tf")
        headers = block(text, 'resource "aws_cloudfront_response_headers_policy" "security"')
        for pattern in (r"include_subdomains\s*=\s*true", r"preload\s*=\s*true",
                        r"content_security_policy\s*=\s*var\.content_security_policy", r'frame_option\s*=\s*"DENY"',
                        r"content_type_options \{", r"referrer_policy \{"):
            self.assertRegex(headers, pattern)
        self.assertRegex(text, r"hsts_max_age\s*=\s*63072000")
        self.assertRegex(self.module("variables.tf"), r"frame-ancestors 'none'")
        index = text.split('path_pattern               = "/index.html"', 1)[1].split("\n  }\n", 1)[0]
        self.assertIn("caching_disabled", index)
        self.assertRegex(block(text, 'resource "aws_cloudfront_cache_policy" "site"'), r"default_ttl\s*=\s*0")
        self.assertRegex(block(text, 'resource "aws_cloudwatch_log_delivery_source" "cdn"'),
                         r"resource_arn\s*=\s*aws_cloudfront_distribution\.this\.arn")
        for bucket in ("site", "logs"):
            self.assertRegex(block(text, f'resource "aws_s3_bucket_ownership_controls" "{bucket}"'),
                             r'object_ownership\s*=\s*"BucketOwnerEnforced"')

    def test_spa_outputs(self):
        for text in (self.stack("dev", "outputs.tf"), self.module("outputs.tf")):
            self.assertEqual(re.findall(r'^output "(\w+)"', text, re.M),
                             ["bucket_name", "distribution_id", "distribution_domain_name"])


if __name__ == "__main__":
    unittest.main()
