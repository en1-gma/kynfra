"""Test specifici del pattern eks: endpoint API privato di default (pubblico solo con CIDR espliciti), IMDSv2
obbligatorio con hop limit 1 sui nodi, accesso con access entries (nessun ConfigMap aws-auth), versioni dei chart
Helm dello stack kubernetes-addons bloccate su versions.json, Pod Identity per i ruoli dei pod, Karpenter con coda
di interruzione e ruolo del nodo, provider helm autenticato con il token di breve durata del data source."""
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_patterns as tp  # noqa: E402

generate = tp.generate
VERSIONS = json.loads((tp.PLUGIN / "templates/versions.json").read_text(encoding="utf-8"))
ADMIN = "arn:aws:iam::123456789012:role/acme-devops"


def tfvars(text: str) -> dict:
    return dict(re.findall(r'^(\w+)\s*=\s*"?([^"\n]*?)"?\s*$', text, re.M))


def blocks(text: str, header_re: str) -> list:
    """Corpi dei blocchi di primo livello che combaciano con header_re (chiusi da '}' a inizio riga)."""
    return re.findall(r"(?m)^" + header_re + r" \{(.*?)\n\}", text, re.S)


def block(text: str, header: str) -> str:
    found = blocks(text, re.escape(header))
    assert found, f"blocco assente: {header}"
    return found[0]


class EksPatternTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="kynfra-eks-")
        cls.proj = Path(cls._tmp.name)
        cfg = tp.make_project(cls.proj)
        generate.generate(cls.proj, cfg, "aws", "network", ["dev", "prod"], {})
        generate.generate(cls.proj, cfg, "aws", "ecr", [], {"repositories": "api"})
        cls.result = generate.generate(cls.proj, cfg, "aws", "eks", ["dev", "prod"], {"admin_principals": ADMIN})
        cls.pub = cls.proj / "public"
        cls.pub.mkdir()
        cfg2 = tp.make_project(cls.pub)
        cls.pub_result = generate.generate(cls.pub, cfg2, "aws", "eks", ["dev"],
                                           {"admin_principals": ADMIN, "public_endpoint_cidrs": "203.0.113.0/24"})

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def module(self, name: str, proj: Path = None) -> str:
        return ((proj or self.proj) / "infra/modules/eks" / name).read_text(encoding="utf-8")

    def stack(self, env: str, stack: str, name: str, proj: Path = None) -> str:
        return ((proj or self.proj) / "infra/envs" / env / stack / name).read_text(encoding="utf-8")

    def all_text(self, proj: Path = None) -> str:
        root = (proj or self.proj) / "infra"
        files = list((root / "modules/eks").rglob("*.tf")) + list(root.glob("envs/*/kubernetes*/*"))
        return "\n".join(p.read_text(encoding="utf-8") for p in sorted(files))

    def test_generates_two_stacks_per_env(self):
        self.assertEqual(self.result["missing_requires"], [])
        for env in ("dev", "prod"):
            for stack in ("kubernetes", "kubernetes-addons"):
                for f in ("backend.tf", "providers.tf", "versions.tf", "main.tf", "variables.tf", "outputs.tf",
                          "terraform.tfvars"):
                    self.assertTrue((self.proj / "infra/envs" / env / stack / f).is_file(), f"{env}/{stack}/{f}")
            self.assertIn(f'key          = "acme/{env}/kubernetes-addons.tfstate"',
                          self.stack(env, "kubernetes-addons", "backend.tf"))

    def test_eks_private_endpoint_default(self):
        cluster = block(self.module("main.tf"), 'resource "aws_eks_cluster" "this"')
        self.assertRegex(cluster, r"endpoint_private_access\s*=\s*true")
        self.assertRegex(cluster, r"endpoint_public_access\s*=\s*local\.public_endpoint")
        self.assertRegex(cluster, r"public_access_cidrs\s*=\s*local\.public_endpoint \? var\.public_endpoint_cidrs "
                                  r": null")
        self.assertRegex(self.module("main.tf"), r"public_endpoint\s*=\s*length\(var\.public_endpoint_cidrs\) > 0")
        # default: nessun CIDR → solo endpoint privato
        for env in ("dev", "prod"):
            self.assertEqual(tfvars(self.stack(env, "kubernetes", "terraform.tfvars"))["public_endpoint_cidrs"], "")
        self.assertEqual(tfvars(self.stack("dev", "kubernetes", "terraform.tfvars", self.pub))["public_endpoint_cidrs"],
                         "203.0.113.0/24")
        # il modulo rifiuta 0.0.0.0/0 e ::/0 e la variabile non ha default (niente lista vuota implicita)
        variables = self.module("variables.tf")
        var = block(variables, 'variable "public_endpoint_cidrs"')
        self.assertNotIn("default", var)
        self.assertIn('"0.0.0.0/0"', var)
        self.assertIn('"::/0"', var)

    def test_eks_cluster_hardening(self):
        text = self.module("main.tf")
        cluster = block(text, 'resource "aws_eks_cluster" "this"')
        self.assertRegex(cluster, r'enabled_cluster_log_types\s*=\s*\["api", "audit", "authenticator", '
                                  r'"controllerManager", "scheduler"\]')
        self.assertRegex(cluster, r'resources\s*=\s*\["secrets"\]')
        self.assertRegex(cluster, r"key_arn\s*=\s*aws_kms_key\.secrets\.arn")
        self.assertRegex(cluster, r"aws_cloudwatch_log_group\.cluster")  # depends_on: log group prima del cluster
        log_group = block(text, 'resource "aws_cloudwatch_log_group" "cluster"')
        self.assertRegex(log_group, r"retention_in_days\s*=\s*var\.log_retention_days")
        self.assertRegex(log_group, r"kms_key_id\s*=\s*aws_kms_key\.logs\.arn")
        self.assertRegex(text, r'log_group_name\s*=\s*"/aws/eks/\$\{local\.cluster_name\}/cluster"')
        for key in blocks(text, r'resource "aws_kms_key" "\w+"'):
            self.assertRegex(key, r"enable_key_rotation\s*=\s*true")

    def test_eks_imdsv2_required(self):
        text = self.module("main.tf")
        lt = block(text, 'resource "aws_launch_template" "nodes"')
        self.assertRegex(lt, r'http_tokens\s*=\s*"required"')
        self.assertRegex(lt, r"http_put_response_hop_limit\s*=\s*1\b")
        self.assertRegex(lt, r'volume_type\s*=\s*"gp3"')
        self.assertRegex(lt, r"encrypted\s*=\s*true")
        self.assertRegex(lt, r"kms_key_id\s*=\s*aws_kms_key\.ebs\.arn")
        ng = block(text, 'resource "aws_eks_node_group" "this"')
        self.assertRegex(ng, r"id\s*=\s*aws_launch_template\.nodes\[each\.key\]\.id")
        self.assertRegex(ng, r"subnet_ids\s*=\s*var\.subnet_ids")
        self.assertEqual(len(blocks(text, r'resource "aws_launch_template" "\w+"')), 1)
        # i nodi di Karpenter (EC2NodeClass, fuori dal kit) hanno lo stesso IMDSv2 nell'esempio del README
        readme = self.module("README.md")
        self.assertIn("httpTokens: required", readme)
        self.assertIn("httpPutResponseHopLimit: 1", readme)

    def test_eks_access_entries_not_aws_auth(self):
        everything = self.all_text()
        self.assertNotIn("aws-auth", everything)
        self.assertNotRegex(everything, r"kubernetes_config_map|mapRoles|mapUsers")
        text = self.module("main.tf")
        access = re.search(r"access_config \{(.*?)\n  \}", block(text, 'resource "aws_eks_cluster" "this"'), re.S)
        self.assertIsNotNone(access)
        self.assertRegex(access.group(1), r'authentication_mode\s*=\s*"API"')
        self.assertRegex(access.group(1), r"bootstrap_cluster_creator_admin_permissions\s*=\s*false")
        admins = block(text, 'resource "aws_eks_access_entry" "admins"')
        self.assertRegex(admins, r"for_each\s*=\s*toset\(var\.admin_principals\)")
        assoc = block(text, 'resource "aws_eks_access_policy_association" "admins"')
        self.assertIn("cluster-access-policy/AmazonEKSClusterAdminPolicy", assoc)
        self.assertRegex(assoc, r'type\s*=\s*"cluster"')
        karpenter = block(text, 'resource "aws_eks_access_entry" "karpenter_node"')
        self.assertRegex(karpenter, r'type\s*=\s*"EC2_LINUX"')
        self.assertEqual(tfvars(self.stack("dev", "kubernetes", "terraform.tfvars"))["admin_principals"], ADMIN)

    def test_addons_versions_pinned(self):
        addons = (self.proj / "infra/modules/eks/addons/main.tf").read_text(encoding="utf-8")
        releases = re.findall(r'(?m)^resource "helm_release" "(\w+)" \{(.*?)\n\}', addons, re.S)
        charts = {name: body for name, body in releases}
        expected = {
            "aws_load_balancer_controller": ("aws_load_balancer_controller_chart", "https://aws.github.io/eks-charts"),
            "karpenter_crd": ("karpenter_chart", "oci://public.ecr.aws/karpenter"),
            "karpenter": ("karpenter_chart", "oci://public.ecr.aws/karpenter"),
            "keda": ("keda_chart", "https://kedacore.github.io/charts"),
        }
        self.assertEqual(sorted(charts), sorted(expected))
        for name, body in charts.items():
            with self.subTest(release=name):
                key, repo = expected[name]
                self.assertRegex(body, rf'(?m)^\s*version\s*=\s*"{re.escape(VERSIONS[key]["version"])}"$')
                self.assertRegex(body, rf'repository\s*=\s*"{re.escape(repo)}"')
        self.assertRegex(charts["karpenter"], r"skip_crds\s*=\s*true")
        self.assertRegex(charts["karpenter"], r"helm_release\.karpenter_crd")
        # nessun helm_release fuori dal sottomodulo addons, nessun chart locale
        self.assertNotRegex(self.module("main.tf"), r'resource "helm_release"')
        self.assertNotRegex(addons, r'chart\s*=\s*"\.')

    def test_helm_provider_uses_data_source_token(self):
        providers = self.stack("dev", "kubernetes-addons", "providers.tf")
        helm = block(providers, 'provider "helm"')
        self.assertRegex(helm, r"host\s*=\s*data\.aws_eks_cluster\.this\.endpoint")
        self.assertRegex(helm, r"token\s*=\s*data\.aws_eks_cluster_auth\.this\.token")
        self.assertRegex(helm, r"cluster_ca_certificate\s*=\s*base64decode\(data\.aws_eks_cluster\.this\."
                               r"certificate_authority\[0\]\.data\)")
        self.assertNotIn("exec", helm)
        main = self.stack("dev", "kubernetes-addons", "main.tf")
        self.assertIn('key    = "${var.project}/${var.environment}/kubernetes.tfstate"', main)
        self.assertRegex(main, r"name\s*=\s*data\.terraform_remote_state\.kubernetes\.outputs\.cluster_name")
        versions = self.stack("dev", "kubernetes-addons", "versions.tf")
        major, minor = VERSIONS["helm_provider"]["version"].split(".")[:2]
        self.assertIn(f'version = "~> {major}.{minor}"', versions)

    def test_pod_identity_roles(self):
        text = self.module("main.tf")
        self.assertNotRegex(text, r"aws_iam_openid_connect_provider|AssumeRoleWithWebIdentity")
        pod_roles = re.search(r"pod_roles = \{(.*?)\n  \}", text, re.S).group(1)
        for sa in ("aws-load-balancer-controller", "karpenter", "keda-operator", "ebs-csi-controller-sa"):
            self.assertIn(f'"{sa}"', pod_roles)
        role = block(text, 'resource "aws_iam_role" "pod"')
        self.assertIn('"pods.eks.amazonaws.com"', role)
        self.assertIn('"aws:RequestTag/kubernetes-service-account"', role)
        self.assertIn('"aws:RequestTag/eks-cluster-arn"', role)
        self.assertIn('"aws:RequestTag/kubernetes-namespace"', role)
        assoc = block(text, 'resource "aws_eks_pod_identity_association" "this"')
        self.assertRegex(assoc, r"role_arn\s*=\s*aws_iam_role\.pod\[each\.key\]\.arn")
        ebs = block(text, 'resource "aws_eks_addon" "ebs_csi"')
        self.assertRegex(ebs, r'service_account\s*=\s*"ebs-csi-controller-sa"')
        # i ruoli si leggono solo da jsonencode/aws_iam_policy_document
        self.assertNotRegex(self.all_text(), r"\b(file|templatefile)\(")

    def test_managed_addons(self):
        text = self.module("main.tf")
        for addon in ("vpc-cni", "kube-proxy", "eks-pod-identity-agent", "coredns", "aws-ebs-csi-driver"):
            self.assertIn(f'"{addon}"', text)
        data = block(text, 'data "aws_eks_addon_version" "this"')
        self.assertRegex(data, r"kubernetes_version\s*=\s*aws_eks_cluster\.this\.version")
        self.assertRegex(data, r"most_recent\s*=\s*true")
        cluster = block(text, 'resource "aws_eks_cluster" "this"')
        self.assertRegex(cluster, r"bootstrap_self_managed_addons\s*=\s*false")

    def test_karpenter_resources(self):
        text = self.module("main.tf")
        queue = block(text, 'resource "aws_sqs_queue" "karpenter"')
        self.assertRegex(queue, r"sqs_managed_sse_enabled\s*=\s*true")
        rules = block(text, 'resource "aws_cloudwatch_event_rule" "karpenter"')
        self.assertIn("for_each", rules)
        for detail in ("EC2 Spot Instance Interruption Warning", "EC2 Instance Rebalance Recommendation",
                       "EC2 Instance State-change Notification", "AWS Health Event",
                       "EC2 Capacity Reservation Instance Interruption Warning"):
            self.assertIn(detail, text)
        policy = block(text, 'resource "aws_iam_role_policy" "karpenter"')
        self.assertIn('"aws:ResourceTag/kubernetes.io/cluster/${local.cluster_name}"', policy)
        passrole = re.search(r'Sid\s*=\s*"AllowPassingInstanceRole"(.*?)\n      \}', policy, re.S).group(1)
        self.assertRegex(passrole, r"Resource\s*=\s*aws_iam_role\.karpenter_node\.arn")
        outputs = self.stack("dev", "kubernetes", "outputs.tf")
        for out in ("cluster_name", "cluster_endpoint", "cluster_ca", "node_security_group_id",
                    "cluster_security_group_id", "karpenter_queue_name", "karpenter_node_role_name"):
            self.assertRegex(outputs, rf'output "{out}"')

    def test_skill(self):
        skill = tp.PLUGIN / "skills/create-eks-infra-aws"
        text = (skill / "SKILL.md").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?s)^---\nname: create-eks-infra-aws\ndescription: \S")
        self.assertIn("generate.py --pattern eks --provider aws", text)
        self.assertIn("arch_check.py . --external", text)
        yaml = (skill / "agents/openai.yaml").read_text(encoding="utf-8")
        self.assertIn("$create-eks-infra-aws", yaml)
        self.assertIn('brand_color: "#F97316"', yaml)

    def test_prod_defaults(self):
        dev = tfvars(self.stack("dev", "kubernetes", "terraform.tfvars"))
        prod = tfvars(self.stack("prod", "kubernetes", "terraform.tfvars"))
        self.assertEqual(dev["deletion_protection"], "false")
        self.assertEqual(prod["deletion_protection"], "true")
        self.assertEqual(prod["log_retention_days"], "365")
        self.assertEqual(dev["kubernetes_version"], prod["kubernetes_version"])
        self.assertRegex(dev["kubernetes_version"], r"^1\.\d+$")


if __name__ == "__main__":
    unittest.main()
