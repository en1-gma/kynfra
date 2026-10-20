"""Test specifici del pattern elb: listener 80 solo redirect a HTTPS, listener 443 con policy TLS 1.3 e certificato
ACM, ingress dalla prefix list gestita di CloudFront con allow_from=cloudfront, rete letta dallo stack network,
deletion protection e WAF in prod, NLB con listener TLS."""
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


class ElbPatternTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="kynfra-elb-")
        cls.proj = Path(cls._tmp.name)
        cfg = tp.make_project(cls.proj)
        generate.generate(cls.proj, cfg, "aws", "network", ["dev", "prod"], {})
        cls.results = {}
        for env, domain in (("prod", "api.example.com"), ("dev", "dev.api.example.com")):
            cls.results[env] = generate.generate(cls.proj, cfg, "aws", "elb", [env],
                                                 {"domain_name": domain, "hosted_zone": "create",
                                                  "zone_name": "example.com"})
            assert cls.results[env]["created"]
        cls.cf = cls.proj / "cloudfront"
        cls.cf.mkdir()
        cfg2 = tp.make_project(cls.cf)
        cls.cf_result = generate.generate(cls.cf, cfg2, "aws", "elb", ["dev"],
                                          {"domain_name": "origin.example.com",
                                           "hosted_zone": "existing:Z0123456789ABC", "allow_from": "cloudfront"})

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def module(self, name: str) -> str:
        return (self.proj / "infra/modules/elb" / name).read_text(encoding="utf-8")

    def stack(self, env: str, name: str, proj: Path = None) -> str:
        return ((proj or self.proj) / "infra/envs" / env / "elb" / name).read_text(encoding="utf-8")

    def test_elb_http_listener_redirects(self):
        text = self.module("main.tf")
        http = block(text, 'resource "aws_lb_listener" "http"')
        self.assertRegex(http, r'protocol\s*=\s*"HTTP"')
        self.assertRegex(http, r'port\s*=\s*80\b')
        self.assertRegex(http, r'type\s*=\s*"redirect"')
        redirect = http.split("redirect {", 1)[1]
        for pattern in (r'protocol\s*=\s*"HTTPS"', r'port\s*=\s*"443"', r'status_code\s*=\s*"HTTP_301"'):
            self.assertRegex(redirect, pattern)
        # su HTTP nessun forward e nessuna regola: solo redirect
        self.assertNotIn("forward", http)
        self.assertNotIn("target_group_arn", http)
        for rule in re.findall(r'resource "aws_lb_listener_rule" "\w+" \{(.*?)\n\}', text, re.S):
            self.assertNotRegex(rule, r"aws_lb_listener\.http\b(?!s)")
        https = block(text, 'resource "aws_lb_listener" "https"')
        self.assertRegex(https, r'protocol\s*=\s*"HTTPS"')
        self.assertRegex(https, r'ssl_policy\s*=\s*"ELBSecurityPolicy-TLS13-1-2-2021-06"')
        self.assertRegex(https, r"certificate_arn\s*=\s*aws_acm_certificate_validation\.this\.certificate_arn")
        self.assertRegex(https, r'type\s*=\s*"fixed-response"')
        self.assertRegex(https, r'status_code\s*=\s*"404"')
        tls = block(text, 'resource "aws_lb_listener" "tls"')
        self.assertRegex(tls, r'protocol\s*=\s*"TLS"')
        self.assertRegex(tls, r'ssl_policy\s*=\s*"ELBSecurityPolicy-TLS13-1-2-2021-06"')
        lb = block(text, 'resource "aws_lb" "this"')
        for pattern in (r"drop_invalid_header_fields\s*=\s*true", r"enable_deletion_protection\s*=\s*"
                        r"var\.deletion_protection", r"enabled\s*=\s*true"):
            self.assertRegex(lb, pattern)
        self.assertIn('"strictest"', lb)

    def test_elb_cloudfront_prefix_list(self):
        text = self.module("main.tf")
        pl = block(text, 'data "aws_ec2_managed_prefix_list" "cloudfront"')
        self.assertRegex(pl, r'name\s*=\s*"com\.amazonaws\.global\.cloudfront\.origin-facing"')
        self.assertRegex(pl, r"count\s*=\s*local\.from_cloudfront \? 1 : 0")
        rule = block(text, 'resource "aws_vpc_security_group_ingress_rule" "https_cloudfront"')
        self.assertRegex(rule, r"prefix_list_id\s*=\s*data\.aws_ec2_managed_prefix_list\.cloudfront\[0\]\.id")
        self.assertRegex(rule, r"from_port\s*=\s*443")
        self.assertRegex(rule, r"to_port\s*=\s*443")
        self.assertNotIn("cidr_ipv4", rule)
        # le regole dal mondo esistono solo con allow_from = internet, quella sulla 80 solo per l'ALB
        for name in ("https_ipv4", "http_ipv4"):
            world = block(text, f'resource "aws_vpc_security_group_ingress_rule" "{name}"')
            self.assertRegex(world, r"count\s*=\s*local\.from_internet")
            self.assertIn('"0.0.0.0/0"', world)
        self.assertRegex(block(text, 'resource "aws_vpc_security_group_ingress_rule" "http_ipv4"'),
                         r"count\s*=\s*local\.from_internet && local\.is_alb \? 1 : 0")
        self.assertRegex(text, r'from_cloudfront\s*=\s*!var\.internal && var\.allow_from == "cloudfront"')
        self.assertRegex(text, r'from_internet\s*=\s*!var\.internal && var\.allow_from == "internet"')
        # egress solo verso la VPC sulla porta dei target
        egress = block(text, 'resource "aws_vpc_security_group_egress_rule" "targets"')
        self.assertRegex(egress, r"cidr_ipv4\s*=\s*local\.vpc_cidr")
        self.assertRegex(text, r"vpc_cidr\s*=\s*data\.aws_vpc\.this\.cidr_block")
        self.assertRegex(egress, r"from_port\s*=\s*var\.target_port")
        self.assertEqual(tfvars(self.stack("dev", "terraform.tfvars", self.cf))["allow_from"], "cloudfront")
        self.assertEqual(tfvars(self.stack("dev", "terraform.tfvars"))["allow_from"], "internet")

    def test_elb_reads_network_state(self):
        main = self.stack("dev", "main.tf")
        net = block(main, 'data "terraform_remote_state" "network"')
        self.assertIn('key    = "${var.project}/${var.environment}/network.tfstate"', net)
        self.assertRegex(main, r"vpc_id\s*=\s*data\.terraform_remote_state\.network\.outputs\.vpc_id")
        self.assertRegex(main, r"var\.internal \? data\.terraform_remote_state\.network\.outputs\.private_subnet_ids"
                               r" : data\.terraform_remote_state\.network\.outputs\.public_subnet_ids")
        self.assertEqual(self.results["dev"]["missing_requires"], [])
        self.assertEqual(self.cf_result["missing_requires"], ["network"])

    def test_elb_prod_toggles(self):
        prod = tfvars(self.stack("prod", "terraform.tfvars"))
        dev = tfvars(self.stack("dev", "terraform.tfvars"))
        self.assertEqual((prod["deletion_protection"], prod["waf_enabled"]), ("true", "true"))
        self.assertEqual((dev["deletion_protection"], dev["waf_enabled"]), ("false", "false"))
        self.assertEqual(prod["type"], "alb")
        text = self.module("main.tf")
        assoc = block(text, 'resource "aws_wafv2_web_acl_association" "this"')
        self.assertRegex(assoc, r"count\s*=\s*var\.waf_enabled \? 1 : 0")
        self.assertRegex(block(text, 'resource "aws_wafv2_web_acl" "this"'), r'scope\s*=\s*"REGIONAL"')
        self.assertRegex(self.stack("prod", "main.tf"), r"deletion_protection\s*=\s*var\.deletion_protection")

    def test_elb_access_log_bucket_policy(self):
        text = self.module("main.tf")
        doc = block(text, 'data "aws_iam_policy_document" "logs"')
        self.assertIn('"logdelivery.elasticloadbalancing.amazonaws.com"', doc)
        self.assertIn('"delivery.logs.amazonaws.com"', doc)
        self.assertIn("data.aws_elb_service_account.this[0].arn", doc)
        self.assertRegex(doc, r'"aws:SecureTransport"')
        self.assertRegex(block(text, 'data "aws_elb_service_account" "this"'),
                         r"count\s*=\s*local\.legacy_elb_account \? 1 : 0")
        self.assertRegex(text, r"legacy_elb_account\s*=\s*contains\(var\.legacy_elb_regions, local\.region\)")
        self.assertIn('"eu-south-1"', block(self.module("variables.tf"), 'variable "legacy_elb_regions"'))
        sse = block(text, 'resource "aws_s3_bucket_server_side_encryption_configuration" "logs"')
        self.assertIn('"AES256"', sse)

    def test_elb_nlb_variant(self):
        with tempfile.TemporaryDirectory(prefix="kynfra-nlb-") as d:
            proj = Path(d)
            cfg = tp.make_project(proj)
            generate.generate(proj, cfg, "aws", "elb", ["prod"],
                              {"domain_name": "tcp.example.com", "hosted_zone": "existing:Z0123456789ABC",
                               "type": "nlb", "internal": "true", "waf_enabled": "false"})
            vals = tfvars((proj / "infra/envs/prod/elb/terraform.tfvars").read_text(encoding="utf-8"))
            self.assertEqual((vals["type"], vals["internal"], vals["waf_enabled"], vals["deletion_protection"]),
                             ("nlb", "true", "false", "true"))
            self.assertFalse((proj / "infra/envs/shared").exists())


if __name__ == "__main__":
    unittest.main()
