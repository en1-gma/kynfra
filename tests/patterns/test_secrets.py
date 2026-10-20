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
        self.assertRegex(key, r'"kms:ViaService"\s*=\s*"secretsmanager\.\$\{data\.aws_region\.current\.region\}\.amazonaws\.com"')
        self.assertRegex(key, r"Principal\s*=\s*\{ AWS = local\.account_root \}")
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

    def test_secrets_outputs(self):
        for text in (self.stack("dev", "outputs.tf"), self.module("outputs.tf")):
            self.assertEqual(re.findall(r'^output "(\w+)"', text, re.M), ["secret_arns", "kms_key_arn"])


if __name__ == "__main__":
    unittest.main()
