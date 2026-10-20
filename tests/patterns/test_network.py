"""Test specifici del pattern network: NAT per zona solo in prod, security group di default senza regole,
endpoint, flow log cifrati."""
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_patterns as tp  # noqa: E402

generate = tp.generate


def tfvars(text: str) -> dict:
    return dict(re.findall(r'^(\w+)\s*=\s*"?([^"\n]+?)"?\s*$', text, re.M))


class NetworkPatternTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="kynfra-network-")
        cls.proj = Path(cls._tmp.name)
        cfg = tp.make_project(cls.proj)
        res = generate.generate(cls.proj, cfg, "aws", "network", ["dev", "staging", "prod"], {})
        assert res["created"]

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def stack(self, env: str, name: str) -> str:
        return (self.proj / "infra" / "envs" / env / "network" / name).read_text(encoding="utf-8")

    def module(self, name: str) -> str:
        return (self.proj / "infra" / "modules" / "network" / name).read_text(encoding="utf-8")

    def test_network_prod_nat_per_az(self):
        prod = tfvars(self.stack("prod", "terraform.tfvars"))
        dev = tfvars(self.stack("dev", "terraform.tfvars"))
        self.assertEqual(prod["nat_per_az"], "true")
        self.assertEqual(prod["az_count"], "3")
        self.assertEqual(prod["flow_log_retention_days"], "365")
        self.assertEqual(dev["nat_per_az"], "false")
        self.assertEqual(dev["az_count"], "2")
        self.assertEqual(dev["flow_log_retention_days"], "90")

    def test_network_staging_non_prod_defaults(self):
        staging = tfvars(self.stack("staging", "terraform.tfvars"))
        self.assertEqual((staging["nat_per_az"], staging["az_count"], staging["flow_log_retention_days"]),
                         ("false", "2", "90"))

    def test_network_default_sg_no_rules(self):
        text = self.module("main.tf")
        m = re.search(r'resource "aws_default_security_group" "\w+" \{(.*?)\n\}', text, re.S)
        self.assertIsNotNone(m, "aws_default_security_group assente")
        self.assertNotRegex(m.group(1), r"\b(ingress|egress)\b")

    def test_network_endpoints_and_flow_logs(self):
        text = self.module("main.tf")
        for service in ("ecr.api", "ecr.dkr", "secretsmanager", "sts", "logs"):
            self.assertIn(f'"{service}"', text)
        for pattern in (r'vpc_endpoint_type\s*=\s*"Gateway"', r"private_dns_enabled\s*=\s*true",
                        r'traffic_type\s*=\s*"ALL"', r'log_destination_type\s*=\s*"cloud-watch-logs"',
                        r"enable_key_rotation\s*=\s*true", r"kms_key_id\s*=\s*aws_kms_key\.flow_logs\.arn",
                        r"aws:ResourceAccount", r"aws:SourceArn"):
            self.assertRegex(text, pattern)

    def test_network_isolated_has_no_internet_route(self):
        text = self.module("main.tf")
        routes = re.findall(r'resource "aws_route" "\w+" \{(.*?)\n\}', text, re.S)
        self.assertTrue(routes)
        for body in routes:
            self.assertNotIn("aws_route_table.isolated", body)
        self.assertRegex(text, r'resource "aws_route_table" "isolated"')

    def test_network_private_route_tables_use_distinct_nats(self):
        text = self.module("main.tf")
        self.assertRegex(text, r"nat_keys\s*=\s*var\.nat_per_az\s*\?\s*keys\(local\.az_index\)\s*:\s*\[\"0\"\]")
        self.assertRegex(text, r"nat_for_az\s*=\s*\{\s*for k in keys\(local\.az_index\) : k => var\.nat_per_az \? k : \"0\"\s*\}")
        self.assertRegex(text, r"nat_gateway_id\s*=\s*aws_nat_gateway\.this\[local\.nat_for_az\[each\.key\]\]\.id")

    def test_network_prod_retention_validation(self):
        text = self.module("variables.tf")
        self.assertRegex(text, r'var\.environment\s*!=\s*"prod"\s*\|\|\s*var\.flow_log_retention_days\s*>=\s*365')
        self.assertRegex(self.module("main.tf"), r"retention_in_days\s*=\s*var\.flow_log_retention_days")

    def test_network_outputs(self):
        text = self.stack("dev", "outputs.tf")
        names = re.findall(r'^output "(\w+)"', text, re.M)
        self.assertEqual(names, ["vpc_id", "public_subnet_ids", "private_subnet_ids", "isolated_subnet_ids",
                                 "vpc_endpoint_sg_id"])


if __name__ == "__main__":
    unittest.main()
