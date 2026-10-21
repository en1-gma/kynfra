"""Test delle regole trasversali sul contenuto (rules_common.py) e di rules.check_content."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "plugins" / "kynfra" / "scripts"))

import rules  # noqa: E402

STACK = "envs/dev/spa/"

GOOD_BACKEND = '''terraform {
  backend "s3" {
    bucket       = "acme-tfstate"
    key          = "acme/dev/spa.tfstate"
    region       = "eu-south-1"
    encrypt      = true
    use_lockfile = true
  }
}
'''

GOOD_PROVIDER = '''provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]
  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
      Owner       = "platform"
      CostCenter  = local.cost_center
      ManagedBy   = "kynfra"
    }
  }
}
'''


def cfg_for(**raw):
    return rules.normalize_config({"infra_root": ".", **raw})


def run(rel, text, rule=None, cfg=None):
    out = rules.check_content(rel, text, cfg or cfg_for())
    return [f for f in out if rule is None or f.rule == rule]


class RemoteStateTest(unittest.TestCase):
    def test_remote_state_local_backend_in_stack(self):
        f = run(STACK + "backend.tf", 'terraform {\n  backend "local" {}\n}\n', "remote-state")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "block")
        self.assertEqual(f[0].line, 2)

    def test_remote_state_s3_without_encrypt(self):
        text = GOOD_BACKEND.replace("    encrypt      = true\n", "")
        f = run(STACK + "backend.tf", text, "remote-state")
        self.assertEqual(len(f), 1)
        self.assertIn("encrypt", f[0].message)

    def test_remote_state_s3_without_lockfile(self):
        text = GOOD_BACKEND.replace("use_lockfile = true", "use_lockfile = false")
        f = run(STACK + "backend.tf", text, "remote-state")
        self.assertEqual(len(f), 1)
        self.assertIn("use_lockfile", f[0].message)

    def test_remote_state_s3_complete(self):
        self.assertEqual(run(STACK + "backend.tf", GOOD_BACKEND, "remote-state"), [])

    def test_remote_state_local_in_bootstrap(self):
        self.assertEqual(run("bootstrap/backend.tf", 'terraform {\n  backend "local" {}\n}\n', "remote-state"), [])


class VersionPinningTest(unittest.TestCase):
    def tf(self, body):
        return run(STACK + "versions.tf", body, "version-pinning")

    def test_version_pinning_provider_without_version(self):
        f = self.tf('terraform {\n  required_providers {\n    aws = { source = "hashicorp/aws" }\n  }\n}\n')
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].line, 3)

    def test_version_pinning_open_range(self):
        f = self.tf('terraform {\n  required_providers {\n'
                    '    aws = { source = "hashicorp/aws", version = ">= 5.0" }\n  }\n}\n')
        self.assertEqual(len(f), 1)
        self.assertIn("~>", f[0].message)

    def test_version_pinning_pessimistic_ok(self):
        self.assertEqual(self.tf('terraform {\n  required_version = "~> 1.9"\n  required_providers {\n'
                                 '    aws = { source = "hashicorp/aws", version = "~> 6.0" }\n  }\n}\n'), [])

    def test_version_pinning_required_version_open(self):
        self.assertEqual(len(self.tf('terraform {\n  required_version = ">= 1.5"\n}\n')), 1)

    # moduli: dalla final review fix wave (C1) solo locali, regola `module-source` (version-pinning non li guarda più)
    def test_module_source_git_module_without_ref(self):
        f = run(STACK + "main.tf", 'module "x" {\n  source = "git::https://github.com/a/b.git"\n}\n',
                "module-source")
        self.assertEqual(len(f), 1)

    def test_module_source_git_module_with_branch_ref(self):
        f = run(STACK + "main.tf", 'module "x" {\n  source = "git::https://github.com/a/b.git?ref=main"\n}\n',
                "module-source")
        self.assertEqual(len(f), 1)

    def test_module_source_git_module_with_tag_ref_still_blocked(self):
        self.assertEqual(len(run(STACK + "main.tf",
                                 'module "x" {\n  source = "git::https://github.com/a/b.git?ref=v1.2.3"\n}\n',
                                 "module-source")), 1)

    def test_module_source_local_module(self):
        self.assertEqual(run(STACK + "main.tf", 'module "spa" {\n  source = "../../../modules/spa"\n}\n',
                             "module-source"), [])

    def test_module_source_registry_module_without_version(self):
        f = run(STACK + "main.tf", 'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n',
                "module-source")
        self.assertEqual(len(f), 1)

    def test_module_source_registry_module_with_version_still_blocked(self):
        for ver in ("~> 5.1", "5.1.2"):
            self.assertEqual(len(run(STACK + "main.tf",
                                     'module "vpc" {\n  source  = "terraform-aws-modules/vpc/aws"\n'
                                     f'  version = "{ver}"\n}}\n', "module-source")), 1)

    def test_version_pinning_ignores_modules(self):
        self.assertEqual(run(STACK + "main.tf", 'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n',
                             "version-pinning"), [])


class StaticCredentialsDataRefTest(unittest.TestCase):
    def test_static_credentials_kubernetes_data_token_ok(self):
        self.assertEqual(run(STACK + "providers.tf", 'provider "kubernetes" {\n'
                             '  token = data.aws_eks_cluster_auth.c.token\n}\n', "static-credentials"), [])

    def test_static_credentials_helm_data_token_ok(self):
        self.assertEqual(run(STACK + "providers.tf", 'provider "helm" {\n  kubernetes {\n'
                             '    token = data.aws_eks_cluster_auth.c.token\n  }\n}\n', "static-credentials"), [])

    def test_static_credentials_token_from_variable(self):
        f = run(STACK + "providers.tf", 'provider "kubernetes" {\n  token = var.t\n}\n', "static-credentials")
        self.assertEqual(len(f), 1)


class StaticCredentialsTest(unittest.TestCase):
    def test_static_credentials_literal_access_key(self):
        f = run(STACK + "providers.tf", 'provider "aws" {\n  access_key = "AKIAABCDEFGHIJKLMNOP"\n}\n',
                "static-credentials")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].line, 2)

    def test_static_credentials_secret_key_from_variable(self):
        f = run(STACK + "providers.tf", 'provider "aws" {\n  secret_key = var.k\n}\n', "static-credentials")
        self.assertEqual(len(f), 1)

    def test_static_credentials_profile_ok(self):
        self.assertEqual(run(STACK + "providers.tf", 'provider "aws" {\n  profile = "x"\n}\n',
                             "static-credentials"), [])

    def test_static_credentials_in_tfvars(self):
        f = run(STACK + "terraform.tfvars", 'aws_secret_access_key = "abcdEFGH1234abcdEFGH1234"\n',
                "static-credentials")
        self.assertEqual(len(f), 1)

    def test_static_credentials_variable_with_default(self):
        f = run(STACK + "variables.tf",
                'variable "access_key" {\n  type    = string\n  default = "AKIAABCDEFGHIJKLMNOP"\n}\n',
                "static-credentials")
        self.assertEqual(len(f), 1)


class SecretsTest(unittest.TestCase):
    def test_secrets_password_literal_in_tf(self):
        f = run(STACK + "main.tf", 'resource "aws_db_instance" "db" {\n  password = "Sup3rS3cret!"\n}\n',
                "secrets")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].line, 2)
        self.assertEqual(f[0].resource, "aws_db_instance.db")

    def test_secrets_secret_string_literal(self):
        f = run(STACK + "main.tf", 'resource "aws_secretsmanager_secret_version" "v" {\n'
                '  secret_id     = aws_secretsmanager_secret.s.id\n  secret_string = "x"\n}\n', "secrets")
        self.assertEqual(len(f), 1)

    def test_secrets_secret_string_wo_variable_ok(self):
        self.assertEqual(run(STACK + "main.tf", 'resource "aws_secretsmanager_secret_version" "v" {\n'
                             '  secret_id        = aws_secretsmanager_secret.s.id\n'
                             '  secret_string_wo = var.x\n  secret_string_wo_version = 1\n}\n', "secrets"), [])

    def test_secrets_sensitive_variable_without_sensitive(self):
        f = run(STACK + "variables.tf", 'variable "db_password" {}\n', "secrets")
        self.assertEqual(len(f), 1)
        self.assertIn("sensitive", f[0].message)

    def test_secrets_sensitive_variable_marked_ok(self):
        self.assertEqual(run(STACK + "variables.tf", 'variable "db_password" {\n  type      = string\n'
                             '  sensitive = true\n}\n', "secrets"), [])

    def test_secrets_in_auto_tfvars(self):
        f = run("envs/dev/backend/x.auto.tfvars", 'api_token = "abc123xyz"\n', "secrets")
        self.assertEqual(len(f), 1)

    def test_secrets_placeholder_ok(self):
        self.assertEqual(run(STACK + "terraform.tfvars", 'db_password = "changeme"\napi_token = "<token>"\n',
                             "secrets"), [])

    def test_secrets_reference_ok(self):
        self.assertEqual(run(STACK + "main.tf", 'resource "aws_db_instance" "db" {\n'
                             '  password = data.aws_ssm_parameter.p.value\n'
                             '  manage_master_user_password = true\n}\n', "secrets"), [])

    def test_secrets_comment_ignored(self):
        self.assertEqual(run(STACK + "main.tf", '# password = "Sup3rS3cret!"\nlocals {}\n', "secrets"), [])

    def test_secrets_inside_object(self):
        f = run(STACK + "main.tf", 'resource "aws_lambda_function" "f" {\n  environment {\n'
                '    variables = {\n      DB_PASSWORD = "Sup3rS3cret!"\n    }\n  }\n}\n', "secrets")
        self.assertEqual(len(f), 1)

    def test_secrets_connection_string(self):
        f = run(STACK + "main.tf", 'locals {\n  db_url = "postgres://app:Sup3rS3cret@db:5432/app"\n}\n',
                "secrets")
        self.assertEqual(len(f), 1)

    def test_secrets_token_validity_units_ok(self):
        self.assertEqual(run(STACK + "main.tf", 'resource "aws_cognito_user_pool_client" "c" {\n'
                             '  token_validity_units {\n    access_token = "minutes"\n  }\n}\n', "secrets"), [])

    def test_secrets_ssm_secure_string_literal(self):
        f = run(STACK + "main.tf", 'resource "aws_ssm_parameter" "p" {\n  name  = "/app/db"\n'
                '  type  = "SecureString"\n  value = "Sup3rS3cret!"\n}\n', "secrets")
        self.assertEqual([x.line for x in f], [4])

    def test_secrets_ssm_secure_string_wo_ok(self):
        self.assertEqual(run(STACK + "main.tf", 'resource "aws_ssm_parameter" "p" {\n  name  = "/app/db"\n'
                             '  type  = "SecureString"\n  value_wo = var.v\n  value_wo_version = 1\n}\n',
                             "secrets"), [])

    def test_secrets_tf_json(self):
        text = '{"resource": {"aws_db_instance": {"db": {"password": "Sup3rS3cret!"}}}}\n'
        f = run(STACK + "main.tf.json", text, "secrets")
        self.assertEqual(len(f), 1)

    def test_secrets_tfvars_json(self):
        f = run(STACK + "terraform.tfvars.json", '{\n  "client_secret": "abcDEF123456"\n}\n', "secrets")
        self.assertEqual(len(f), 1)


class RequiredTagsTest(unittest.TestCase):
    def test_required_tags_no_default_tags(self):
        f = run(STACK + "providers.tf", 'provider "aws" {\n  allowed_account_ids = [var.account_id]\n}\n',
                "required-tags")
        self.assertEqual(len(f), 1)

    def test_required_tags_missing_cost_center(self):
        text = GOOD_PROVIDER.replace("      CostCenter  = local.cost_center\n", "")
        f = run(STACK + "providers.tf", text, "required-tags")
        self.assertEqual(len(f), 1)
        self.assertIn("CostCenter", f[0].message)

    def test_required_tags_managed_by_wrong(self):
        f = run(STACK + "providers.tf", GOOD_PROVIDER.replace('"kynfra"', '"terraform"'), "required-tags")
        self.assertEqual(len(f), 1)
        self.assertIn("ManagedBy", f[0].message)

    def test_required_tags_all_present(self):
        self.assertEqual(run(STACK + "providers.tf", GOOD_PROVIDER, "required-tags"), [])

    def test_required_tags_not_literal_keys(self):
        text = ('provider "aws" {\n  allowed_account_ids = [var.account_id]\n'
                '  default_tags {\n    tags = local.tags\n  }\n}\n')
        self.assertEqual(len(run(STACK + "providers.tf", text, "required-tags")), 1)


class AccountGuardTest(unittest.TestCase):
    def test_account_guard_missing_in_stack(self):
        text = GOOD_PROVIDER.replace("  allowed_account_ids = [var.account_id]\n", "")
        f = run(STACK + "providers.tf", text, "account-guard")
        self.assertEqual(len(f), 1)

    def test_account_guard_present(self):
        self.assertEqual(run(STACK + "providers.tf", GOOD_PROVIDER, "account-guard"), [])

    def test_account_guard_module_ignored(self):
        self.assertEqual(run("modules/spa/main.tf", 'provider "aws" {}\n', "account-guard"), [])


class VariablesTypedTest(unittest.TestCase):
    def test_variables_typed_missing_both(self):
        f = run(STACK + "variables.tf", 'variable "x" {}\n', "variables-typed")
        self.assertEqual(len(f), 2)
        self.assertTrue(all(x.severity == "warn" for x in f))

    def test_variables_typed_ok(self):
        self.assertEqual(run(STACK + "variables.tf", 'variable "x" {\n  type        = string\n'
                             '  description = "Nome."\n}\n', "variables-typed"), [])


class ScannerSuppressionTest(unittest.TestCase):
    def test_scanner_suppression_comments(self):
        text = ('resource "aws_s3_bucket" "b" {\n  #checkov:skip=CKV_AWS_1\n  # trivy:ignore:AVD-AWS-0001\n'
                '  # tflint-ignore: x\n  bucket = "b"\n}\n')
        f = run(STACK + "main.tf", text, "scanner-suppression")
        self.assertEqual([x.line for x in f], [2, 3, 4])

    def test_scanner_suppression_clean(self):
        self.assertEqual(run(STACK + "main.tf", '# nota qualsiasi\nlocals {}\n', "scanner-suppression"), [])


class NoProvisionersTest(unittest.TestCase):
    def test_no_provisioners_local_exec(self):
        f = run(STACK + "main.tf", 'resource "terraform_data" "x" {\n  provisioner "local-exec" {\n'
                '    command = "echo hi"\n  }\n}\n', "no-provisioners")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].line, 2)

    def test_no_provisioners_clean(self):
        self.assertEqual(run(STACK + "main.tf", 'resource "terraform_data" "x" {}\n', "no-provisioners"), [])


class RegionPinningTest(unittest.TestCase):
    def test_region_pinning_literal_region_in_module(self):
        f = run("modules/spa/main.tf", 'resource "aws_x" "y" {\n  region = "eu-west-1"\n}\n', "region-pinning")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "warn")

    def test_region_pinning_account_id_in_module(self):
        f = run("modules/spa/main.tf", 'locals {\n  role = "arn:aws:iam::123456789012:role/x"\n}\n',
                "region-pinning")
        self.assertEqual(len(f), 1)

    def test_region_pinning_tfvars_ok(self):
        self.assertEqual(run(STACK + "terraform.tfvars", 'region = "eu-west-1"\naccount_id = "123456789012"\n',
                             "region-pinning"), [])

    def test_region_pinning_variable_in_module_ok(self):
        self.assertEqual(run("modules/spa/main.tf", 'resource "aws_x" "y" {\n  region = var.region\n}\n',
                             "region-pinning"), [])


class CheckContentTest(unittest.TestCase):
    def test_check_content_outside_infra_root(self):
        cfg = rules.normalize_config({"infra_root": "infra"})
        self.assertEqual(rules.check_content("src/backend.tf", 'terraform {\n  backend "local" {}\n}\n', cfg), [])

    def test_check_content_uses_infra_rel_and_project_path(self):
        cfg = rules.normalize_config({"infra_root": "infra"})
        f = rules.check_content("infra/envs/dev/spa/backend.tf", 'terraform {\n  backend "local" {}\n}\n', cfg)
        f = [x for x in f if x.rule == "remote-state"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].path, "infra/envs/dev/spa/backend.tf")

    def test_check_content_non_iac_ignored(self):
        self.assertEqual(run(STACK + "README.md", 'password = "Sup3rS3cret!"\n'), [])

    def test_hcl_syntax_fail_closed(self):
        f = run(STACK + "main.tf", 'resource "aws_db_instance" "db" {\n  password = "Sup3rS3cret!"\n')
        rules_hit = {x.rule for x in f}
        self.assertIn("hcl-syntax", rules_hit)
        self.assertTrue(all(x.severity == "block" for x in f if x.rule == "hcl-syntax"))

    def test_severity_from_config(self):
        cfg = cfg_for(rules={"no-provisioners": "warn", "variables-typed": "off"})
        text = ('variable "x" {}\nresource "terraform_data" "x" {\n  provisioner "local-exec" {\n'
                '    command = "echo"\n  }\n}\n')
        f = rules.check_content(STACK + "main.tf", text, cfg)
        self.assertEqual([x.severity for x in f if x.rule == "no-provisioners"], ["warn"])
        self.assertEqual([x for x in f if x.rule == "variables-typed"], [])

    def test_provider_rules_hook(self):
        def fake(irel, blocks, text, cfg):
            return [rules.Finding("s3-private", "block", irel, 1, "prova")]
        rules.PROVIDER_RULES["aws"] = [fake]
        try:
            f = run(STACK + "main.tf", "locals {}\n", "s3-private")
            self.assertEqual(len(f), 1)
            self.assertEqual(f[0].path, STACK + "main.tf")
            f = run(STACK + "main.tf", "locals {}\n", "s3-private", cfg_for(providers=["azure"]))
            self.assertEqual(f, [])
        finally:
            rules.PROVIDER_RULES.pop("aws", None)

    def test_good_stack_files_are_clean(self):
        versions = ('terraform {\n  required_version = "~> 1.9"\n  required_providers {\n'
                    '    aws = { source = "hashicorp/aws", version = "~> 6.0" }\n  }\n}\n')
        for name, text in (("backend.tf", GOOD_BACKEND), ("providers.tf", GOOD_PROVIDER),
                           ("versions.tf", versions)):
            self.assertEqual(run(STACK + name, text), [], name)


class NativeTest(unittest.TestCase):
    def test_native_secrets_yaml(self):
        text = 'Resources:\n  Db:\n    Properties:\n      MasterUserPassword: Sup3rS3cret!\n'
        f = run("native/db/template.yaml", text, "secrets")
        self.assertEqual([x.line for x in f], [4])

    def test_native_secrets_reference_ok(self):
        text = ('Resources:\n  Db:\n    Properties:\n'
                '      MasterUserPassword: "{{resolve:secretsmanager:db:SecretString:password}}"\n'
                '      Other: !Ref DbPassword\n')
        self.assertEqual(run("native/db/template.yaml", text, "secrets"), [])

    def test_native_secrets_quoted_value_not_reference(self):
        f = run("native/db/template.yaml", 'Props:\n  DbPassword: "!Sup3rS3cret"\n', "secrets")
        self.assertEqual(len(f), 1)

    def test_native_no_hcl_syntax(self):
        self.assertEqual(run("native/db/template.yaml", "a: [unclosed\n", "hcl-syntax"), [])

    def test_native_scanner_suppression(self):
        f = run("native/db/template.yaml", "# checkov:skip=CKV_AWS_16\nResources: {}\n", "scanner-suppression")
        self.assertEqual(len(f), 1)

    def test_native_params_cfn_yaml_bad(self):
        text = ('Parameters:\n  Env:\n    Description: ambiente\n  DbPassword:\n    Type: String\n'
                '    Default: abc\nResources: {}\n')
        f = run("native/db/template.yaml", text, "native-params")
        self.assertEqual(sorted(x.line for x in f), [2, 4, 4])

    def test_native_params_cfn_yaml_good(self):
        text = ('Parameters:\n  Env:\n    Type: String\n  DbPassword:\n    Type: String\n'
                '    NoEcho: true\nResources: {}\n')
        self.assertEqual(run("native/db/template.yaml", text, "native-params"), [])

    def test_native_params_cfn_json_bad(self):
        text = '{\n  "Parameters": {\n    "ApiToken": {\n      "Type": "String"\n    }\n  }\n}\n'
        f = run("native/api/template.json", text, "native-params")
        self.assertEqual([x.line for x in f], [3])

    def test_native_params_cfn_json_good(self):
        text = '{\n  "Parameters": {\n    "ApiToken": {\n      "Type": "String", "NoEcho": true\n    }\n  }\n}\n'
        self.assertEqual(run("native/api/template.json", text, "native-params"), [])

    def test_native_params_bicep_bad(self):
        text = "param location string\nparam adminPassword string = 'x'\n"
        f = run("native/vm/main.bicep", text, "native-params")
        self.assertEqual(sorted(x.line for x in f), [2, 2])

    def test_native_params_bicep_good(self):
        text = "param location string\n@secure()\nparam adminPassword string\n"
        self.assertEqual(run("native/vm/main.bicep", text, "native-params"), [])


if __name__ == "__main__":
    unittest.main()
