"""Test specifici del pattern ecr: stack condiviso unico, lifecycle per ogni repository, repository immutabili cifrati,
policy di pull con deny fuori dall'account, lettura dello stato in un solo verso."""
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


class EcrPatternTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="kynfra-ecr-")
        cls.proj = Path(cls._tmp.name)
        cfg = tp.make_project(cls.proj)
        cls.result = generate.generate(cls.proj, cfg, "aws", "ecr", [], {
            "repositories": "api, worker", "pull_principals": "arn:aws:iam::123456789012:role/acme-eks-node",
            "keep_last": "10"})

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def module(self, name: str) -> str:
        return (self.proj / "infra/modules/ecr" / name).read_text(encoding="utf-8")

    def stack(self, name: str) -> str:
        return (self.proj / "infra/envs/shared/ecr" / name).read_text(encoding="utf-8")

    def test_ecr_shared_stack_location(self):
        # generato una sola volta, senza --env, solo in envs/shared/ecr con la chiave di stato condivisa
        stacks = sorted(p.relative_to(self.proj).as_posix() for p in (self.proj / "infra/envs").glob("*/*"))
        self.assertEqual(stacks, ["infra/envs/shared/ecr"])
        self.assertIn('key          = "acme/shared/ecr.tfstate"', self.stack("backend.tf"))
        self.assertEqual(tfvars(self.stack("terraform.tfvars"))["environment"], "shared")
        self.assertTrue(all("/envs/shared/ecr/" in f or "/modules/ecr/" in f for f in self.result["created"]))
        self.assertIn("allowed_account_ids = [var.account_id]", self.stack("providers.tf"))
        # un --env passato per errore non crea stack per ambiente
        with tempfile.TemporaryDirectory(prefix="kynfra-ecr-env-") as d:
            other = Path(d)
            cfg = tp.make_project(other)
            generate.generate(other, cfg, "aws", "ecr", ["dev", "prod"], {"repositories": "api"})
            self.assertEqual(sorted(p.name for p in (other / "infra/envs").iterdir()), ["shared"])

    def test_ecr_lifecycle_present_for_each_repo(self):
        text = self.module("main.tf")
        repo = block(text, 'resource "aws_ecr_repository" "this"')
        self.assertRegex(repo, r"for_each\s*=\s*toset\(var\.repositories\)")
        life = block(text, 'resource "aws_ecr_lifecycle_policy" "this"')
        self.assertRegex(life, r"for_each\s*=\s*aws_ecr_repository\.this")
        self.assertRegex(life, r"repository\s*=\s*aws_ecr_repository\.this\[each\.key\]\.name")
        self.assertRegex(life, r'tagStatus\s*=\s*"untagged"')
        self.assertRegex(life, r'countType\s*=\s*"sinceImagePushed"')
        self.assertRegex(life, r"countNumber\s*=\s*var\.untagged_expiry_days")
        self.assertRegex(life, r"countNumber\s*=\s*var\.keep_last")
        vars_ = tfvars(self.stack("terraform.tfvars"))
        self.assertEqual((vars_["untagged_expiry_days"], vars_["keep_last"]), ("7", "10"))
        self.assertEqual(vars_["repositories"], "api, worker")

    def test_ecr_repository_hardening(self):
        repo = block(self.module("main.tf"), 'resource "aws_ecr_repository" "this"')
        self.assertRegex(repo, r'image_tag_mutability\s*=\s*"IMMUTABLE"')
        self.assertRegex(repo, r"force_delete\s*=\s*false")
        self.assertRegex(repo, r"scan_on_push\s*=\s*true")
        self.assertRegex(repo, r'encryption_type\s*=\s*"KMS"')
        self.assertRegex(repo, r"kms_key\s*=\s*aws_kms_key\.ecr\.arn")
        self.assertRegex(block(self.module("main.tf"), 'resource "aws_kms_key" "ecr"'), r"enable_key_rotation\s*=\s*true")

    def test_ecr_pull_policy_and_perimeter(self):
        text = self.module("main.tf")
        policy = block(text, 'resource "aws_ecr_repository_policy" "this"')
        self.assertRegex(policy, r"length\(var\.pull_principals\) == 0 \? \[\]")
        self.assertRegex(policy, r"Principal\s*=\s*\{ AWS = var\.pull_principals \}")
        self.assertEqual(len(re.findall(r'Effect\s*=\s*"Allow"', policy)), 1)
        allow = policy.split("DenyOutsideAccount")[0]
        for action in ("GetDownloadUrlForLayer", "BatchGetImage", "BatchCheckLayerAvailability"):
            self.assertIn(f"ecr:{action}", allow)
        for push in ("PutImage", "InitiateLayerUpload", "UploadLayerPart", "CompleteLayerUpload"):
            self.assertNotIn(push, policy)
        self.assertNotRegex(allow, r'Principal\s*=\s*(\{\s*AWS\s*=\s*)?"\*"')
        self.assertRegex(policy, r'"aws:PrincipalAccount"\s*=\s*local\.account_id')
        self.assertRegex(policy, r'BoolIfExists\s*=\s*\{ "aws:PrincipalIsAWSService" = "false" \}')
        self.assertRegex(policy, r'split\(":", r\)\[4\] == local\.account_id')
        self.assertRegex(self.module("variables.tf"), r"role/\.\+\$")

    def test_ecr_repository_names_validated_once(self):
        self.assertRegex(self.module("variables.tf"), r"\^\[a-z0-9\]\+\(-\[a-z0-9\]\+\)\*\$")
        self.assertEqual(self.stack("variables.tf").count("validation {"), 1)  # solo account_id
        self.assertRegex(self.stack("main.tf"), r'compact\(\[for r in split\(",", var\.repositories\) : trimspace\(r\)\]\)')

    def test_ecr_one_way_no_remote_state(self):
        for f in ("main.tf", "variables.tf", "outputs.tf"):
            self.assertNotIn("terraform_remote_state", self.stack(f))
        self.assertNotIn("terraform_remote_state", self.module("main.tf"))

    def test_ecr_outputs(self):
        for text in (self.stack("outputs.tf"), self.module("outputs.tf")):
            self.assertEqual(re.findall(r'^output "(\w+)"', text, re.M),
                             ["repository_urls", "repository_arns", "kms_key_arn", "registry_id"])

    def test_ecr_repositories_required(self):
        with tempfile.TemporaryDirectory(prefix="kynfra-ecr-req-") as d:
            other = Path(d)
            cfg = tp.make_project(other)
            with self.assertRaises(generate.GenerateError):
                generate.generate(other, cfg, "aws", "ecr", [], {})


if __name__ == "__main__":
    unittest.main()
