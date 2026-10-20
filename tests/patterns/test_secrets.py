"""Test specifici del pattern secrets: nessun valore nei file, policy per lettore, chiave KMS dedicata, recovery window
per ambiente, rotazione e replica solo su richiesta."""
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
    m = re.search(re.escape(header) + r" \{(.*?)\n\}", text, re.S)
    assert m, f"blocco assente: {header}"
    return m.group(1)


class SecretsPatternTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="kynfra-secrets-")
        cls.proj = Path(cls._tmp.name)
        cfg = tp.make_project(cls.proj)
        generate.generate(cls.proj, cfg, "aws", "secrets", ["dev", "staging", "prod"], {})
        cls.other = Path(cls._tmp.name) / "replica"
        cls.other.mkdir()
        cfg2 = tp.make_project(cls.other)
        generate.generate(cls.other, cfg2, "aws", "secrets", ["dev"], {"replica_region": "eu-west-1",
                                                                      "recovery_window_days": "14"})

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def module(self, name: str) -> str:
        return (self.proj / "infra/modules/secrets" / name).read_text(encoding="utf-8")

    def stack(self, env: str, name: str, proj: Path = None) -> str:
        return ((proj or self.proj) / "infra/envs" / env / "secrets" / name).read_text(encoding="utf-8")

    def test_secrets_no_values_in_files(self):
        files = [p for p in (self.proj / "infra").rglob("*") if p.is_file() and p.suffix in (".tf", ".tfvars")]
        self.assertTrue(files)
        for path in files:
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"secret_string(_wo)?\s*=", str(path))
            self.assertNotIn("aws_secretsmanager_secret_version", text, str(path))
        # il tfvars ha un segnaposto senza lettori e nessun valore
        self.assertRegex(self.stack("dev", "terraform.tfvars"), r"app-db = \{\s*description = \"[^\"]+\"\s*readers\s*=\s*\[\]")

    def test_secrets_policy_per_reader(self):
        text = self.module("main.tf")
        policy = block(text, 'resource "aws_secretsmanager_secret_policy" "this"')
        self.assertRegex(policy, r"for_each\s*=\s*var\.secrets")
        self.assertRegex(policy, r"secret_arn\s*=\s*aws_secretsmanager_secret\.this\[each\.key\]\.arn")
        self.assertRegex(policy, r"length\(each\.value\.readers\) == 0 \? \[\]")
        self.assertRegex(policy, r"Principal\s*=\s*\{ AWS = each\.value\.readers \}")
        self.assertRegex(policy, r'"secretsmanager:GetSecretValue"')
        self.assertRegex(policy, r'"aws:PrincipalAccount"\s*=\s*local\.account_id')
        self.assertRegex(policy, r'Effect\s*=\s*"Deny"')
        self.assertRegex(policy, r'"aws:SecureTransport"\s*=\s*"false"')
        # nessun Allow con principal "*"
        allow = re.split(r'Sid\s*=\s*"DenyOutsideAccount"', policy)[0]
        self.assertNotRegex(allow, r'Principal\s*=\s*\{\s*AWS\s*=\s*"\*"')
        self.assertRegex(self.module("variables.tf"), r"role/\.\+\$")

    def test_secrets_kms_dedicated(self):
        text = self.module("main.tf")
        key = block(text, 'resource "aws_kms_key" "secrets"')
        self.assertRegex(key, r"enable_key_rotation\s*=\s*true")
        self.assertRegex(key, r"policy\s*=\s*local\.key_policies\[data\.aws_region\.current\.region\]")
        text_policies = text.split("key_policies = {", 1)[1].split("\n}\n", 1)[0]
        self.assertRegex(text_policies, r'"kms:ViaService"\s*=\s*"secretsmanager\.\$\{region\}\.amazonaws\.com"')
        self.assertRegex(text_policies, r"Principal\s*=\s*\{ AWS = local\.account_root \}")
        secret = block(text, 'resource "aws_secretsmanager_secret" "this"')
        self.assertRegex(secret, r"kms_key_id\s*=\s*aws_kms_key\.secrets\.arn")
        self.assertRegex(secret, r'name\s*=\s*"\$\{var\.project\}/\$\{var\.environment\}/\$\{each\.key\}"')

    def test_secrets_recovery_window_per_env(self):
        self.assertEqual(tfvars(self.stack("prod", "terraform.tfvars"))["recovery_window_days"], "30")
        self.assertEqual(tfvars(self.stack("dev", "terraform.tfvars"))["recovery_window_days"], "7")
        self.assertEqual(tfvars(self.stack("staging", "terraform.tfvars"))["recovery_window_days"], "7")
        self.assertEqual(tfvars(self.stack("dev", "terraform.tfvars", self.other))["recovery_window_days"], "14")
        variables = self.module("variables.tf")
        self.assertRegex(variables, r'var\.environment != "prod" \|\| var\.recovery_window_days >= 30')
        self.assertRegex(variables, r'var\.environment != "prod" \|\| var\.rotation_days <= 30')
        self.assertRegex(self.module("main.tf"), r"recovery_window_in_days\s*=\s*var\.recovery_window_days")

    def test_secrets_rotation_and_replica_optional(self):
        text = self.module("main.tf")
        rotation = block(text, 'resource "aws_secretsmanager_secret_rotation" "this"')
        self.assertRegex(rotation, r"for_each\s*=\s*local\.rotated")
        self.assertRegex(rotation, r"automatically_after_days\s*=\s*var\.rotation_days")
        self.assertRegex(text, r"s\.rotation_lambda_arn != null")
        self.assertRegex(text, r'for_each = var\.replica_region != "" \? toset\(\[var\.replica_region\]\) : toset\(\[\]\)')
        self.assertEqual(tfvars(self.stack("dev", "terraform.tfvars"))["replica_region"], "")
        self.assertEqual(tfvars(self.stack("dev", "terraform.tfvars", self.other))["replica_region"], "eu-west-1")

    def test_secrets_readers_guards(self):
        # readers vuoti: statement Allow (e Principal) assenti, resta il solo deny; readers pieni: Principal = la lista
        text = self.module("main.tf")
        policy = block(text, 'resource "aws_secretsmanager_secret_policy" "this"')
        self.assertRegex(policy, r"length\(each\.value\.readers\) == 0 \? \[\]\s*:\s*\[")
        self.assertEqual(len(re.findall(r"each\.value\.readers", policy)), 3)  # guardia, Principal, precondition
        self.assertEqual(len(re.findall(r'Effect\s*=\s*"Allow"', policy)), 1)
        self.assertRegex(policy, r'"aws:PrincipalIsAWSService"\s*=\s*"false"')
        self.assertRegex(policy, r'split\(":", r\)\[4\] == local\.account_id')
        self.assertRegex(text, r"length\(local\.all_readers\) == 0 \? \[\]\s*:\s*\[")
        self.assertRegex(text, r'Principal\s*=\s*\{ AWS = local\.all_readers \}')
        # lo stack non legge lo stato di altri stack
        self.assertNotIn("terraform_remote_state", self.stack("dev", "main.tf"))

    def test_secrets_replica_key(self):
        text = self.module("main.tf")
        self.assertRegex(block(text, 'resource "aws_kms_key" "secrets"'), r"multi_region\s*=\s*true")
        rep = block(text, 'resource "aws_kms_replica_key" "secrets"')
        self.assertRegex(rep, r'count\s*=\s*var\.replica_region != "" \? 1 : 0')
        self.assertRegex(rep, r"provider\s*=\s*aws\.replica")
        self.assertRegex(rep, r"primary_key_arn\s*=\s*aws_kms_key\.secrets\.arn")
        self.assertRegex(rep, r"var\.replica_region != data\.aws_region\.current\.region")
        self.assertRegex(text, r"kms_key_id\s*=\s*aws_kms_replica_key\.secrets\[0\]\.arn")
        self.assertRegex(self.module("versions.tf"), r"configuration_aliases\s*=\s*\[aws\.replica\]")
        providers = self.stack("dev", "providers.tf")
        alias = providers.split('alias               = "replica"', 1)[1]
        self.assertRegex(alias, r'region\s*=\s*var\.replica_region != "" \? var\.replica_region : var\.region')
        self.assertIn("allowed_account_ids = [var.account_id]", alias)
        self.assertIn('ManagedBy   = "kynfra"', alias)
        self.assertRegex(self.stack("dev", "main.tf"), r"aws\.replica\s*=\s*aws\.replica")

    def test_secrets_stack_does_not_duplicate_validation(self):
        stack = self.stack("dev", "variables.tf")
        self.assertEqual(stack.count("validation {"), 2)  # account_id e replica_region != region
        self.assertNotIn("can(regex", stack.split('variable "secrets"', 1)[1])

    def test_secrets_outputs(self):
        for text in (self.stack("dev", "outputs.tf"), self.module("outputs.tf")):
            self.assertEqual(re.findall(r'^output "(\w+)"', text, re.M), ["secret_arns", "secret_names", "kms_key_arn"])


if __name__ == "__main__":
    unittest.main()
