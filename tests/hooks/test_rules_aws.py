"""Test delle regole AWS (rules_aws.py): regole per file (check_content) e regole d'insieme (check_project)."""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "plugins" / "kynfra" / "scripts"))

import rules  # noqa: E402
import rules_aws  # noqa: E402

MOD = "modules/spa/"
DEV = "envs/dev/spa/"
PROD = "envs/prod/spa/"


def cfg_for(**raw):
    return rules.normalize_config({"infra_root": ".", "project": "acme", "providers": ["aws"], **raw})


def run(rel, text, rule, cfg=None):
    return [f for f in rules.check_content(rel, text, cfg or cfg_for()) if f.rule == rule]


def project(files, rule, **kw):
    with tempfile.TemporaryDirectory() as d:
        for rel, text in files.items():
            p = Path(d) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        return [f for f in rules.check_project(Path(d), cfg_for(**kw)) if f.rule == rule]


class Base(unittest.TestCase):
    def one(self, findings, line, rule=None, contains=None):
        self.assertEqual(len(findings), 1, [f.format() for f in findings])
        f = findings[0]
        self.assertEqual(f.severity, "block")
        self.assertEqual(f.line, line)
        if rule:
            self.assertEqual(f.rule, rule)
        if contains:
            self.assertIn(contains, f.message)
        return f


# ---------------------------------------------------------------- s3-private

BUCKET = 'resource "aws_s3_bucket" "site" {\n  bucket = var.bucket_name\n}\n'
PAB = '''resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.site.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
'''
SSE = '''resource "aws_s3_bucket_server_side_encryption_configuration" "site" {
  bucket = aws_s3_bucket.site.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
'''
VERSIONING = '''resource "aws_s3_bucket_versioning" "site" {
  bucket = aws_s3_bucket.site.id
  versioning_configuration {
    status = "Enabled"
  }
}
'''
TLS_POLICY = '''resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id
  policy = data.aws_iam_policy_document.site.json
}

data "aws_iam_policy_document" "site" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.site.arn, "${aws_s3_bucket.site.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}
'''


def s3_module(**override):
    parts = {"main.tf": BUCKET, "pab.tf": PAB, "sse.tf": SSE, "versioning.tf": VERSIONING, "policy.tf": TLS_POLICY}
    parts.update(override)
    return {MOD + k: v for k, v in parts.items() if v is not None}


class S3PrivateTest(Base):
    def test_s3_private_good(self):
        self.assertEqual(project(s3_module(), "s3-private"), [])

    def test_s3_private_bad_without_public_access_block(self):
        f = self.one(project(s3_module(**{"pab.tf": None}), "s3-private"), 1, contains="public_access_block")
        self.assertEqual(f.path, MOD + "main.tf")
        self.assertEqual(f.resource, "aws_s3_bucket.site")

    def test_s3_private_bad_public_access_block_flag_false(self):
        text = PAB.replace("restrict_public_buckets = true", "restrict_public_buckets = false")
        self.one(run(MOD + "pab.tf", text, "s3-private"), 6, contains="restrict_public_buckets")
        missing = PAB.replace("  ignore_public_acls      = true\n", "")
        self.one(run(MOD + "pab.tf", missing, "s3-private"), 1, contains="ignore_public_acls")

    def test_s3_private_bad_companion_on_other_bucket(self):
        other = PAB.replace("aws_s3_bucket.site.id", "aws_s3_bucket.logs.id")
        self.one(project(s3_module(**{"pab.tf": other}), "s3-private"), 1, contains="public_access_block")

    def test_s3_private_bad_public_acl(self):
        text = 'resource "aws_s3_bucket_acl" "site" {\n  bucket = aws_s3_bucket.site.id\n  acl    = "public-read"\n}\n'
        self.one(run(MOD + "acl.tf", text, "s3-private"), 3, contains="public-read")

    def test_s3_private_bad_without_encryption(self):
        self.one(project(s3_module(**{"sse.tf": None}), "s3-private"), 1, contains="cifratura")

    def test_s3_private_bad_without_tls_policy(self):
        policy = TLS_POLICY.replace('values   = ["false"]', 'values   = ["true"]')
        self.one(project(s3_module(**{"policy.tf": policy}), "s3-private"), 1, contains="aws:SecureTransport")

    def test_s3_private_bad_without_versioning(self):
        self.one(project(s3_module(**{"versioning.tf": None}), "s3-private"), 1, contains="versioning")

    def test_s3_private_good_tls_policy_jsonencode(self):
        policy = '''resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.site.arn, "${aws_s3_bucket.site.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}
'''
        self.assertEqual(project(s3_module(**{"policy.tf": policy}), "s3-private"), [])

    def test_s3_private_good_for_each_companions(self):
        files = {MOD + "main.tf": 'resource "aws_s3_bucket" "b" {\n  for_each = var.buckets\n  bucket = each.key\n}\n'}
        for name, text in (("pab", PAB), ("sse", SSE), ("ver", VERSIONING)):
            files[MOD + name + ".tf"] = text.replace("aws_s3_bucket.site.id", "each.value.id").replace(
                '" "site" {\n', '" "site" {\n  for_each = aws_s3_bucket.b\n', 1)
        files[MOD + "policy.tf"] = TLS_POLICY.replace("aws_s3_bucket.site.id", "aws_s3_bucket.b[each.key].id")
        self.assertEqual(project(files, "s3-private"), [])


# ---------------------------------------------------------------- cloudfront-https

DIST = '''resource "aws_cloudfront_distribution" "site" {
  enabled    = true
  web_acl_id = var.waf_enabled ? aws_wafv2_web_acl.site[0].arn : null

  origin {
    domain_name              = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id                = "s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.site.id
  }

  default_cache_behavior {
    target_origin_id           = "s3"
    viewer_protocol_policy     = "redirect-to-https"
    response_headers_policy_id = aws_cloudfront_response_headers_policy.site.id
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
  }

  logging_config {
    bucket = aws_s3_bucket.logs.bucket_domain_name
  }

  viewer_certificate {
    acm_certificate_arn      = var.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}
'''

WAF_VAR = 'variable "waf_enabled" {\n  type        = bool\n  description = "WAF"\n  default     = false\n}\n'
STACK_MAIN = 'module "spa" {\n  source      = "../../../modules/spa"\n  waf_enabled = var.waf_enabled\n}\n'


class CloudFrontTest(Base):
    def cf(self, text, rel=MOD + "cdn.tf"):
        return run(rel, text, "cloudfront-https")

    def test_cloudfront_https_good(self):
        self.assertEqual(self.cf(DIST), [])
        self.assertEqual(project({MOD + "cdn.tf": DIST}, "cloudfront-https"), [])

    def test_cloudfront_https_bad_allow_all(self):
        self.one(self.cf(DIST.replace('"redirect-to-https"', '"allow-all"')), 13, contains="redirect-to-https")

    def test_cloudfront_https_bad_tls_v1(self):
        self.one(self.cf(DIST.replace('"TLSv1.2_2021"', '"TLSv1"')), 26, contains="TLSv1.2_2021")

    def test_cloudfront_https_bad_oai(self):
        text = DIST.replace("    origin_access_control_id = aws_cloudfront_origin_access_control.site.id\n",
                            "    s3_origin_config {\n"
                            "      origin_access_identity = aws_cloudfront_origin_access_identity.o.path\n    }\n")
        self.one(self.cf(text), 8, contains="origin_access_control_id")

    def test_cloudfront_https_bad_without_response_headers_policy(self):
        text = DIST.replace("    response_headers_policy_id = aws_cloudfront_response_headers_policy.site.id\n", "")
        self.one(self.cf(text), 11, contains="response_headers_policy_id")

    def test_cloudfront_https_bad_without_logging(self):
        text = DIST.replace("  logging_config {\n    bucket = aws_s3_bucket.logs.bucket_domain_name\n  }\n", "")
        self.one(project({MOD + "cdn.tf": text}, "cloudfront-https"), 1, contains="log")

    def test_cloudfront_https_good_logging_v2(self):
        text = DIST.replace("  logging_config {\n    bucket = aws_s3_bucket.logs.bucket_domain_name\n  }\n", "")
        v2 = '''resource "aws_cloudwatch_log_delivery_source" "cf" {
  name         = "cf"
  log_type     = "ACCESS_LOGS"
  resource_arn = aws_cloudfront_distribution.site.arn
}

resource "aws_cloudwatch_log_delivery" "cf" {
  delivery_source_name     = aws_cloudwatch_log_delivery_source.cf.name
  delivery_destination_arn = aws_cloudwatch_log_delivery_destination.cf.arn
}
'''
        self.assertEqual(project({MOD + "cdn.tf": text, MOD + "logs.tf": v2}, "cloudfront-https"), [])

    def test_cloudfront_https_bad_waf_false_in_prod_tfvars(self):
        files = {MOD + "cdn.tf": DIST, MOD + "variables.tf": WAF_VAR,
                 PROD + "main.tf": STACK_MAIN, PROD + "variables.tf": WAF_VAR,
                 PROD + "terraform.tfvars": 'environment = "prod"\nwaf_enabled = false\n'}
        f = self.one(project(files, "cloudfront-https"), 2, contains="waf_enabled")
        self.assertEqual(f.path, PROD + "terraform.tfvars")

    def test_cloudfront_https_bad_waf_absent_in_prod_tfvars(self):
        files = {MOD + "cdn.tf": DIST, MOD + "variables.tf": WAF_VAR,
                 PROD + "main.tf": STACK_MAIN, PROD + "variables.tf": WAF_VAR,
                 PROD + "terraform.tfvars": 'environment = "prod"\n'}
        f = self.one(project(files, "cloudfront-https"), 0, contains="waf_enabled")
        self.assertEqual(f.path, PROD + "terraform.tfvars")

    def test_cloudfront_https_good_waf_true_in_prod_tfvars(self):
        files = {MOD + "cdn.tf": DIST, MOD + "variables.tf": WAF_VAR,
                 PROD + "main.tf": STACK_MAIN, PROD + "variables.tf": WAF_VAR,
                 PROD + "terraform.tfvars": 'waf_enabled = true\n'}
        self.assertEqual(project(files, "cloudfront-https"), [])

    def test_cloudfront_https_bad_web_acl_absent_in_module(self):
        text = DIST.replace("  web_acl_id = var.waf_enabled ? aws_wafv2_web_acl.site[0].arn : null\n", "")
        self.one(self.cf(text), 1, contains="waf_enabled")

    def test_cloudfront_https_bad_web_acl_absent_in_prod_stack(self):
        text = DIST.replace("  web_acl_id = var.waf_enabled ? aws_wafv2_web_acl.site[0].arn : null\n", "")
        self.one(self.cf(text, PROD + "cdn.tf"), 1, contains="WAF")

    def test_prod_only_rules_skip_dev(self):
        text = DIST.replace("  web_acl_id = var.waf_enabled ? aws_wafv2_web_acl.site[0].arn : null\n", "")
        self.assertEqual(self.cf(text, DEV + "cdn.tf"), [])
        files = {MOD + "cdn.tf": DIST, MOD + "variables.tf": WAF_VAR,
                 DEV + "main.tf": STACK_MAIN, DEV + "variables.tf": WAF_VAR,
                 DEV + "terraform.tfvars": 'environment = "dev"\n'}
        self.assertEqual(project(files, "cloudfront-https"), [])


# ---------------------------------------------------------------- lb-https

ALB = '''resource "aws_lb" "this" {
  name                       = var.name
  load_balancer_type         = "application"
  drop_invalid_header_fields = true
  enable_deletion_protection = var.deletion_protection

  access_logs {
    bucket  = var.logs_bucket
    enabled = true
  }
}
'''
HTTP_LISTENER = '''resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
'''
HTTPS_LISTENER = '''resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}
'''
ELB_MOD = "modules/elb/"


class LbHttpsTest(Base):
    def lb(self, text, rel=ELB_MOD + "lb.tf"):
        return run(rel, text, "lb-https")

    def test_lb_https_good(self):
        self.assertEqual(self.lb(ALB + HTTP_LISTENER + HTTPS_LISTENER), [])
        self.assertEqual(self.lb(HTTPS_LISTENER.replace("TLS13-1-2-2021-06", "TLS13-1-2-Res-2021-06")), [])

    def test_lb_https_bad_http_forward(self):
        text = HTTP_LISTENER.replace('    type = "redirect"\n    redirect {\n      port        = "443"\n'
                                     '      protocol    = "HTTPS"\n      status_code = "HTTP_301"\n    }\n',
                                     '    type             = "forward"\n'
                                     '    target_group_arn = aws_lb_target_group.this.arn\n')
        self.one(self.lb(text), 6, contains="redirect")

    def test_lb_https_bad_http_redirect_to_http(self):
        self.one(self.lb(HTTP_LISTENER.replace('"HTTPS"', '"HTTP"')), 6, contains="redirect")

    def test_lb_https_bad_old_ssl_policy(self):
        self.one(self.lb(HTTPS_LISTENER.replace("ELBSecurityPolicy-TLS13-1-2-2021-06", "ELBSecurityPolicy-2016-08")),
                 5, contains="ELBSecurityPolicy-TLS13-1-2-2021-06")

    def test_lb_https_bad_ssl_policy_absent(self):
        text = HTTPS_LISTENER.replace('  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"\n', "")
        self.one(self.lb(text), 1, contains="ssl_policy")

    def test_lb_https_bad_nlb_tls_old_policy(self):
        text = HTTPS_LISTENER.replace('"HTTPS"', '"TLS"').replace("TLS13-1-2-2021-06", "TLS-1-2-2017-01")
        self.one(self.lb(text), 5)

    def test_lb_https_bad_drop_invalid_header_fields(self):
        self.one(self.lb(ALB.replace("drop_invalid_header_fields = true", "drop_invalid_header_fields = false")), 4,
                 contains="drop_invalid_header_fields")

    def test_lb_https_bad_access_logs_disabled(self):
        self.one(self.lb(ALB.replace("enabled = true", "enabled = false")), 7, contains="access_logs")

    def test_lb_https_bad_access_logs_absent(self):
        text = ALB.replace("  access_logs {\n    bucket  = var.logs_bucket\n    enabled = true\n  }\n", "")
        self.one(self.lb(text), 1, contains="access_logs")

    def test_lb_https_bad_deletion_protection_false_in_prod_stack(self):
        text = ALB.replace("var.deletion_protection", "false")
        self.one(self.lb(text, "envs/prod/elb/lb.tf"), 5, contains="enable_deletion_protection")

    def test_lb_https_good_deletion_protection_false_in_dev_stack(self):
        self.assertEqual(self.lb(ALB.replace("var.deletion_protection", "false"), "envs/dev/elb/lb.tf"), [])

    def test_lb_https_bad_deletion_protection_false_in_prod_tfvars(self):
        var = 'variable "deletion_protection" {\n  type        = bool\n  description = "x"\n  default     = false\n}\n'
        files = {ELB_MOD + "lb.tf": ALB, ELB_MOD + "variables.tf": var,
                 "envs/prod/elb/main.tf": 'module "elb" {\n  source              = "../../../modules/elb"\n'
                                          '  deletion_protection = var.deletion_protection\n}\n',
                 "envs/prod/elb/variables.tf": var,
                 "envs/prod/elb/terraform.tfvars": 'deletion_protection = false\n'}
        f = self.one(project(files, "lb-https"), 1, contains="deletion_protection")
        self.assertEqual(f.path, "envs/prod/elb/terraform.tfvars")
        files["envs/prod/elb/terraform.tfvars"] = 'deletion_protection = true\n'
        self.assertEqual(project(files, "lb-https"), [])

    def test_lb_https_bad_listener_rule_forwarding_on_http(self):
        rule = '''resource "aws_lb_listener_rule" "api" {
  listener_arn = aws_lb_listener.http.arn
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
  condition {
    path_pattern {
      values = ["/api/*"]
    }
  }
}
'''
        files = {ELB_MOD + "lb.tf": ALB + HTTP_LISTENER + HTTPS_LISTENER, ELB_MOD + "rules.tf": rule}
        self.one(project(files, "lb-https"), 1, contains="HTTP")
        files[ELB_MOD + "rules.tf"] = rule.replace("aws_lb_listener.http.arn", "aws_lb_listener.https.arn")
        self.assertEqual(project(files, "lb-https"), [])


# ---------------------------------------------------------------- sg-open

class SgOpenTest(Base):
    def sg(self, text):
        return run(MOD + "sg.tf", text, "sg-open")

    def inline(self, port_from, port_to, cidr='"0.0.0.0/0"', protocol='"tcp"'):
        return (f'resource "aws_security_group" "web" {{\n  name = "web"\n  ingress {{\n'
                f'    from_port   = {port_from}\n    to_port     = {port_to}\n    protocol    = {protocol}\n'
                f'    cidr_blocks = [{cidr}]\n  }}\n}}\n')

    def test_sg_open_bad_ssh_from_world(self):
        self.one(self.sg(self.inline(22, 22)), 3, contains="22")

    def test_sg_open_bad_range_including_db_port(self):
        self.one(self.sg(self.inline(3000, 6000)), 3, contains="5432")

    def test_sg_open_bad_ipv6_rdp(self):
        text = ('resource "aws_security_group" "web" {\n  ingress {\n    from_port        = 3389\n'
                '    to_port          = 3389\n    protocol         = "tcp"\n    ipv6_cidr_blocks = ["::/0"]\n'
                '  }\n}\n')
        self.one(self.sg(text), 2, contains="::/0")

    def test_sg_open_bad_other_port_from_world(self):
        self.one(self.sg(self.inline(8080, 8080)), 3, contains="80/443")

    def test_sg_open_bad_all_protocols(self):
        self.one(self.sg(self.inline(0, 0, protocol='"-1"')), 3)

    def test_sg_open_bad_security_group_rule(self):
        text = ('resource "aws_security_group_rule" "ssh" {\n  type              = "ingress"\n  from_port         = 22\n'
                '  to_port           = 22\n  protocol          = "tcp"\n  cidr_blocks       = ["0.0.0.0/0"]\n'
                '  security_group_id = aws_security_group.web.id\n}\n')
        self.one(self.sg(text), 1)

    def test_sg_open_bad_vpc_ingress_rule_all_ports(self):
        text = ('resource "aws_vpc_security_group_ingress_rule" "all" {\n'
                '  security_group_id = aws_security_group.web.id\n  cidr_ipv4         = "0.0.0.0/0"\n'
                '  ip_protocol       = "-1"\n}\n')
        self.one(self.sg(text), 1)

    def test_sg_open_bad_cidr_from_local(self):
        text = 'locals {\n  world = "0.0.0.0/0"\n}\n' + self.inline(22, 22, cidr="local.world")
        self.one(self.sg(text), 6)

    def test_sg_open_good_https_from_world(self):
        self.assertEqual(self.sg(self.inline(443, 443)), [])
        text = ('resource "aws_vpc_security_group_ingress_rule" "https" {\n'
                '  security_group_id = aws_security_group.web.id\n  cidr_ipv6         = "::/0"\n'
                '  ip_protocol       = "tcp"\n  from_port         = 443\n  to_port           = 443\n}\n')
        self.assertEqual(self.sg(text), [])

    def test_sg_open_good_any_port_from_source_sg(self):
        text = ('resource "aws_vpc_security_group_ingress_rule" "db" {\n'
                '  security_group_id            = aws_security_group.db.id\n'
                '  referenced_security_group_id = aws_security_group.app.id\n'
                '  ip_protocol                  = "tcp"\n  from_port                    = 5432\n'
                '  to_port                      = 5432\n}\n')
        self.assertEqual(self.sg(text), [])
        text = ('resource "aws_security_group" "db" {\n  ingress {\n    from_port       = 0\n    to_port         = 65535\n'
                '    protocol        = "tcp"\n    security_groups = [aws_security_group.app.id]\n  }\n}\n')
        self.assertEqual(self.sg(text), [])

    def test_sg_open_good_egress_rule(self):
        text = ('resource "aws_security_group_rule" "out" {\n  type        = "egress"\n  from_port   = 0\n'
                '  to_port     = 0\n  protocol    = "-1"\n  cidr_blocks = ["0.0.0.0/0"]\n'
                '  security_group_id = aws_security_group.web.id\n}\n')
        self.assertEqual(self.sg(text), [])


# ---------------------------------------------------------------- iam-least-privilege

class IamTest(Base):
    def iam(self, text):
        return run(MOD + "iam.tf", text, "iam-least-privilege")

    def test_iam_least_privilege_bad_jsonencode_star(self):
        text = '''resource "aws_iam_policy" "p" {
  name = "p"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
    ]
  })
}
'''
        self.one(self.iam(text), 6, contains="Action")

    def test_iam_least_privilege_bad_heredoc_star(self):
        text = '''resource "aws_iam_role_policy" "p" {
  role   = aws_iam_role.r.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["${var.x}", "*"]}]
}
EOF
}
'''
        self.one(self.iam(text), 3, contains="Action")

    def test_iam_least_privilege_bad_policy_document_star(self):
        text = ('data "aws_iam_policy_document" "d" {\n  statement {\n    actions   = ["*"]\n'
                '    resources = ["*"]\n  }\n}\n')
        self.one(self.iam(text), 2, contains="Action")

    def test_iam_least_privilege_bad_admin_attachment(self):
        text = ('resource "aws_iam_role_policy_attachment" "a" {\n  role       = aws_iam_role.r.name\n'
                '  policy_arn = "arn:${data.aws_partition.p.partition}:iam::aws:policy/AdministratorAccess"\n}\n')
        self.one(self.iam(text), 3, contains="AdministratorAccess")

    def test_iam_least_privilege_bad_power_user(self):
        text = ('resource "aws_iam_role" "r" {\n  assume_role_policy = data.aws_iam_policy_document.t.json\n'
                '  managed_policy_arns = ["arn:aws:iam::aws:policy/PowerUserAccess"]\n}\n')
        self.one(self.iam(text), 3, contains="PowerUserAccess")

    def test_iam_least_privilege_bad_passrole_star(self):
        text = ('data "aws_iam_policy_document" "d" {\n  statement {\n    actions   = ["iam:PassRole"]\n'
                '    resources = ["*"]\n  }\n}\n')
        self.one(self.iam(text), 2, contains="iam:PassRole")

    def test_iam_least_privilege_bad_principal_star_without_condition(self):
        text = '''resource "aws_iam_role" "r" {
  name = "r"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRole"
    }]
  })
}
'''
        self.one(self.iam(text), 5, contains="Principal")

    def test_iam_least_privilege_bad_policy_from_file(self):
        text = 'resource "aws_iam_policy" "p" {\n  policy = file("${path.module}/policy.json")\n}\n'
        self.one(self.iam(text), 2, contains="jsonencode")

    def test_iam_least_privilege_bad_doc_in_local(self):
        text = ('locals {\n  doc = { Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] }\n}\n'
                'resource "aws_iam_policy" "p" {\n  policy = jsonencode(local.doc)\n}\n')
        self.one(self.iam(text), 2)

    def test_iam_least_privilege_bad_tf_json(self):
        text = ('{"resource": {"aws_iam_policy": {"p": {"policy": '
                '"${jsonencode({Statement = [{Effect = \\"Allow\\", Action = \\"*\\", Resource = \\"*\\"}]})}"}}}}')
        self.assertEqual(len(run(MOD + "iam.tf.json", text, "iam-least-privilege")), 1)

    def test_iam_least_privilege_bad_principal_star_non_restricting_condition(self):
        text = ('resource "aws_s3_bucket_policy" "p" {\n  policy = jsonencode({ Statement = [{ Effect = "Allow", '
                'Principal = "*", Action = "s3:GetObject", Resource = "x", '
                'Condition = { Bool = { "aws:SecureTransport" = "true" } } }] })\n}\n')
        self.one(self.iam(text), 2, contains="Principal")

    def test_iam_least_privilege_good(self):
        text = '''resource "aws_iam_policy" "p" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "${aws_s3_bucket.b.arn}/*"
    }, {
      Effect   = "Allow"
      Action   = "iam:PassRole"
      Resource = aws_iam_role.task.arn
    }]
  })
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [var.org_id]
    }
  }
}
'''
        self.assertEqual(self.iam(text), [])


# ---------------------------------------------------------------- kms-rotation, logs-retention

class KmsLogsTest(Base):
    def test_kms_rotation_bad(self):
        self.one(run(MOD + "kms.tf", 'resource "aws_kms_key" "k" {\n  description = "k"\n}\n', "kms-rotation"), 1,
                 contains="enable_key_rotation")
        self.one(run(MOD + "kms.tf", 'resource "aws_kms_key" "k" {\n  enable_key_rotation = false\n}\n',
                     "kms-rotation"), 2)

    def test_kms_rotation_good(self):
        self.assertEqual(run(MOD + "kms.tf", 'resource "aws_kms_key" "k" {\n  enable_key_rotation = true\n}\n',
                             "kms-rotation"), [])

    LG = 'resource "aws_cloudwatch_log_group" "l" {\n  name              = "/x"\n{body}}}\n'

    def lg(self, body, rel=MOD + "logs.tf"):
        return run(rel, self.LG.replace("{body}", body).replace("}}", "}"), "logs-retention")

    def test_logs_retention_bad_without_retention(self):
        self.one(self.lg("  kms_key_id = var.kms_key_arn\n"), 1, contains="retention_in_days")

    def test_logs_retention_bad_without_kms_in_prod(self):
        self.one(self.lg("  retention_in_days = 90\n", "envs/prod/net/logs.tf"), 1, contains="kms_key_id")

    def test_logs_retention_good(self):
        self.assertEqual(self.lg("  retention_in_days = 90\n  kms_key_id = aws_kms_key.logs.arn\n",
                                 "envs/prod/net/logs.tf"), [])
        self.assertEqual(self.lg("  retention_in_days = 90\n", "envs/dev/net/logs.tf"), [])
        self.assertEqual(self.lg("  retention_in_days = var.retention\n  kms_key_id = var.kms_key_arn\n"), [])


# ---------------------------------------------------------------- eks-hardening

EKS = '''resource "aws_eks_cluster" "this" {
  name     = var.name
  role_arn = aws_iam_role.cluster.arn

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.eks.arn
    }
  }
}

resource "aws_launch_template" "nodes" {
  name_prefix = "nodes"
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}
'''


class EksTest(Base):
    def eks(self, text):
        return run("modules/eks/eks.tf", text, "eks-hardening")

    def test_eks_hardening_good(self):
        self.assertEqual(self.eks(EKS), [])
        text = EKS.replace("endpoint_public_access  = false",
                           'endpoint_public_access  = true\n    public_access_cidrs     = ["203.0.113.0/24"]')
        self.assertEqual(self.eks(text), [])

    def test_eks_hardening_bad_public_without_cidrs(self):
        self.one(self.eks(EKS.replace("endpoint_public_access  = false", "endpoint_public_access  = true")), 7,
                 contains="public_access_cidrs")

    def test_eks_hardening_bad_public_world_cidr(self):
        text = EKS.replace("endpoint_public_access  = false",
                           'endpoint_public_access  = true\n    public_access_cidrs     = ["0.0.0.0/0"]')
        self.one(self.eks(text), 7)

    def test_eks_hardening_bad_without_secrets_encryption(self):
        text = EKS.replace('  encryption_config {\n    resources = ["secrets"]\n    provider {\n'
                           '      key_arn = aws_kms_key.eks.arn\n    }\n  }\n', "")
        self.one(self.eks(text), 1, contains="encryption_config")

    def test_eks_hardening_bad_empty_log_types(self):
        text = EKS.replace('["api", "audit", "authenticator", "controllerManager", "scheduler"]', "[]")
        self.one(self.eks(text), 5, contains="enabled_cluster_log_types")

    def test_eks_hardening_bad_launch_template_without_imdsv2(self):
        self.one(self.eks(EKS.replace('"required"', '"optional"')), 25, contains="http_tokens")


# ---------------------------------------------------------------- ecr-hardening

ECR = '''resource "aws_ecr_repository" "app" {
  name                 = var.name
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}
'''
LIFECYCLE = ('resource "aws_ecr_lifecycle_policy" "app" {\n  repository = aws_ecr_repository.app.name\n'
             '  policy     = jsonencode({ rules = [] })\n}\n')
ECR_MOD = "modules/ecr/"


class EcrTest(Base):
    def test_ecr_hardening_good(self):
        self.assertEqual(project({ECR_MOD + "ecr.tf": ECR + LIFECYCLE}, "ecr-hardening"), [])

    def test_ecr_hardening_bad_mutable(self):
        self.one(run(ECR_MOD + "ecr.tf", ECR.replace('"IMMUTABLE"', '"MUTABLE"'), "ecr-hardening"), 3,
                 contains="IMMUTABLE")

    def test_ecr_hardening_bad_scan_disabled(self):
        files = {ECR_MOD + "ecr.tf": ECR.replace("scan_on_push = true", "scan_on_push = false") + LIFECYCLE}
        self.one(project(files, "ecr-hardening"), 1, contains="scan_on_push")

    def test_ecr_hardening_good_enhanced_scanning(self):
        enhanced = ('resource "aws_ecr_registry_scanning_configuration" "s" {\n  scan_type = "ENHANCED"\n'
                    '  rule {\n    scan_frequency = "CONTINUOUS_SCAN"\n    repository_filter {\n'
                    '      filter      = "*"\n      filter_type = "WILDCARD"\n    }\n  }\n}\n')
        files = {ECR_MOD + "ecr.tf": ECR.replace("scan_on_push = true", "scan_on_push = false") + LIFECYCLE,
                 ECR_MOD + "scan.tf": enhanced}
        self.assertEqual(project(files, "ecr-hardening"), [])

    def test_ecr_hardening_bad_without_lifecycle(self):
        self.one(project({ECR_MOD + "ecr.tf": ECR}, "ecr-hardening"), 1, contains="aws_ecr_lifecycle_policy")


# ---------------------------------------------------------------- api-hardening

REST = '''resource "aws_api_gateway_rest_api" "api" {
  name = "api"
}

resource "aws_api_gateway_resource" "health" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "health"
}

resource "aws_api_gateway_method" "health" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.health.id
  http_method   = "GET"
  authorization = "NONE"
}
'''
STAGE = '''resource "aws_api_gateway_stage" "live" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.d.id
  stage_name    = "live"
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format          = jsonencode({ requestId = "$context.requestId" })
  }
}

resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  stage_name  = aws_api_gateway_stage.live.stage_name
  method_path = "*/*"
  settings {
    throttling_rate_limit  = 100
    throttling_burst_limit = 50
  }
}
'''
API_MOD = "modules/backend/"


class ApiTest(Base):
    def test_api_hardening_bad_method_without_authorizer(self):
        f = self.one(project({API_MOD + "api.tf": REST}, "api-hardening"), 15, contains="GET /health")
        self.assertEqual(f.resource, "aws_api_gateway_method.health")

    def test_api_hardening_good_public_route(self):
        self.assertEqual(project({API_MOD + "api.tf": REST}, "api-hardening", public_routes=["GET /health"]), [])

    def test_api_hardening_good_authorizer(self):
        text = REST.replace('authorization = "NONE"', 'authorization = "COGNITO_USER_POOLS"')
        self.assertEqual(project({API_MOD + "api.tf": text}, "api-hardening"), [])

    def test_api_hardening_bad_http_api_route(self):
        text = ('resource "aws_apigatewayv2_route" "r" {\n  api_id    = aws_apigatewayv2_api.a.id\n'
                '  route_key = "POST /v1/orders"\n}\n')
        self.one(run(API_MOD + "api.tf", text, "api-hardening"), 1, contains="POST /v1/orders")
        ok = text.replace('"POST /v1/orders"\n', '"POST /v1/orders"\n  authorization_type = "JWT"\n')
        self.assertEqual(run(API_MOD + "api.tf", ok, "api-hardening"), [])

    def test_api_hardening_bad_stage_without_access_log(self):
        text = STAGE.replace('  access_log_settings {\n    destination_arn = aws_cloudwatch_log_group.api.arn\n'
                             '    format          = jsonencode({ requestId = "$context.requestId" })\n  }\n', "")
        self.one(run(API_MOD + "stage.tf", text, "api-hardening"), 1, contains="access_log_settings")

    def test_api_hardening_bad_stage_without_throttling(self):
        text = STAGE[:STAGE.index('resource "aws_api_gateway_method_settings"')]
        self.one(project({API_MOD + "stage.tf": text}, "api-hardening"), 1, contains="throttling")

    def test_api_hardening_good_stage(self):
        self.assertEqual(project({API_MOD + "stage.tf": STAGE}, "api-hardening"), [])


# ---------------------------------------------------------------- lambda-hardening

LAMBDA = '''resource "aws_lambda_function" "fn" {
  function_name = local.function_name
  role          = aws_iam_role.fn.arn
  timeout       = 10

  environment {
    variables = {
      DB_SECRET_ARN = aws_secretsmanager_secret.db.arn
      LOG_LEVEL     = "info"
    }
  }

  tracing_config {
    mode = "Active"
  }
}

resource "aws_cloudwatch_log_group" "fn" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 30
}
'''


class LambdaTest(Base):
    def test_lambda_hardening_good(self):
        self.assertEqual(project({API_MOD + "fn.tf": LAMBDA}, "lambda-hardening"), [])

    def test_lambda_hardening_bad_sensitive_env_literal(self):
        text = LAMBDA.replace('LOG_LEVEL     = "info"', 'API_TOKEN     = "abc123def456"')
        self.one(run(API_MOD + "fn.tf", text, "lambda-hardening"), 9, contains="API_TOKEN")

    def test_lambda_hardening_bad_without_tracing(self):
        text = LAMBDA.replace('  tracing_config {\n    mode = "Active"\n  }\n', "")
        self.one(run(API_MOD + "fn.tf", text, "lambda-hardening"), 1, contains="tracing_config")

    def test_lambda_hardening_bad_tracing_passthrough(self):
        self.one(run(API_MOD + "fn.tf", LAMBDA.replace('"Active"', '"PassThrough"'), "lambda-hardening"), 13)

    def test_lambda_hardening_bad_without_log_group(self):
        text = LAMBDA[:LAMBDA.index('resource "aws_cloudwatch_log_group"')]
        self.one(project({API_MOD + "fn.tf": text}, "lambda-hardening"), 1, contains="log group")

    def test_lambda_hardening_bad_log_group_of_other_function(self):
        text = LAMBDA.replace("/aws/lambda/${local.function_name}", "/aws/lambda/${local.other}")
        self.one(project({API_MOD + "fn.tf": text}, "lambda-hardening"), 1, contains="log group")


# ---------------------------------------------------------------- fix round 1: aggiramenti

NO_WAF = "  web_acl_id = var.waf_enabled ? aws_wafv2_web_acl.site[0].arn : null\n"
DYN = '''locals {
  rules = {
    ssh = { port = 22, cidrs = ["0.0.0.0/0"] }
  }
}

resource "aws_security_group" "s" {
  dynamic "ingress" {
    for_each = local.rules
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = ingress.value.cidrs
    }
  }
}
'''
SG_VAR = ('resource "aws_security_group_rule" "s" {\n  type        = "ingress"\n  from_port   = 22\n'
          '  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = var.cidrs\n}\n')


def cidrs_var(default=None):
    body = f'  default     = {default}\n' if default else ""
    return 'variable "cidrs" {\n  type        = list(string)\n  description = "x"\n' + body + '}\n'


def project_all(files, cfg=None):
    with tempfile.TemporaryDirectory() as d:
        for rel, text in files.items():
            p = Path(d) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        return rules.check_project(Path(d), cfg or cfg_for())


class BypassRound1Test(Base):
    def test_toggle_local_null_in_module_and_prod_stack(self):
        text = 'locals {\n  none = null\n}\n' + DIST.replace(NO_WAF, "  web_acl_id = local.none\n")
        for rel in (MOD + "cdn.tf", PROD + "cdn.tf"):
            self.one(run(rel, text, "cloudfront-https"), 6, contains="WAF")

    def test_toggle_constant_conditional_in_module(self):
        text = DIST.replace(NO_WAF, "  web_acl_id = true ? null : null\n")
        self.one(run(MOD + "cdn.tf", text, "cloudfront-https"), 3, contains="waf_enabled")

    def test_toggle_unverifiable_expression_in_prod_stack(self):
        text = DIST.replace(NO_WAF, "  web_acl_id = 1 == 2 ? aws_wafv2_web_acl.site[0].arn : null\n")
        self.one(run(PROD + "cdn.tf", text, "cloudfront-https"), 3)
        ok = DIST.replace(NO_WAF, "  web_acl_id = aws_wafv2_web_acl.site.arn\n")
        self.assertEqual(run(PROD + "cdn.tf", ok, "cloudfront-https"), [])

    def test_toggle_module_argument_expressions_in_prod(self):
        for expr in ("1 == 2", "!true", "local.off"):
            main = ('locals {\n  off = false\n}\nmodule "spa" {\n  source      = "../../../modules/spa"\n'
                    f'  waf_enabled = {expr}\n}}\n')
            files = {MOD + "cdn.tf": DIST, MOD + "variables.tf": WAF_VAR, PROD + "main.tf": main}
            f = self.one(project(files, "cloudfront-https"), 6, contains="waf_enabled")
            self.assertEqual(f.path, PROD + "main.tf")
        main = 'module "spa" {\n  source      = "../../../modules/spa"\n  waf_enabled = true\n}\n'
        self.assertEqual(project({MOD + "cdn.tf": DIST, MOD + "variables.tf": WAF_VAR, PROD + "main.tf": main},
                                 "cloudfront-https"), [])

    def test_sg_open_default_security_group(self):
        text = ('resource "aws_default_security_group" "d" {\n  vpc_id = var.vpc_id\n  ingress {\n'
                '    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n'
                '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
        self.one(run(MOD + "sg.tf", text, "sg-open"), 3, contains="22")

    def test_sg_open_dynamic_for_each_local(self):
        self.one(run(MOD + "sg.tf", DYN, "sg-open"), 10, contains="22")
        self.assertEqual(run(MOD + "sg.tf", DYN.replace("port = 22", "port = 443"), "sg-open"), [])

    def test_sg_open_variable_default_world(self):
        files = {MOD + "sg.tf": SG_VAR, MOD + "variables.tf": cidrs_var('["0.0.0.0/0"]')}
        f = self.one(project(files, "sg-open"), 1, contains="22")
        self.assertEqual(f.path, MOD + "sg.tf")

    def test_sg_open_tfvars_value_world(self):
        files = {"envs/dev/net/sg.tf": SG_VAR, "envs/dev/net/variables.tf": cidrs_var(),
                 "envs/dev/net/terraform.tfvars": 'cidrs = ["0.0.0.0/0"]\n'}
        self.one(project(files, "sg-open"), 1)

    def test_sg_open_variable_without_value_not_verifiable(self):
        self.assertEqual(project({MOD + "sg.tf": SG_VAR, MOD + "variables.tf": cidrs_var()}, "sg-open"), [])

    def test_eks_public_cidrs_variable_default_world(self):
        text = EKS.replace("endpoint_public_access  = false",
                           "endpoint_public_access  = true\n    public_access_cidrs     = var.cidrs")
        self.assertEqual(run("modules/eks/eks.tf", text, "eks-hardening"), [])
        files = {"modules/eks/eks.tf": text, "modules/eks/variables.tf": cidrs_var('["0.0.0.0/0"]')}
        self.one(project(files, "eks-hardening"), 7, contains="public_access_cidrs")

    def test_prod_toggle_findings_carry_toggle_rule(self):
        var = 'variable "deletion_protection" {\n  type        = bool\n  description = "x"\n  default     = false\n}\n'
        files = {ELB_MOD + "lb.tf": ALB, ELB_MOD + "variables.tf": var,
                 "envs/prod/elb/main.tf": 'module "elb" {\n  source              = "../../../modules/elb"\n'
                                          '  deletion_protection = var.deletion_protection\n}\n',
                 "envs/prod/elb/variables.tf": var}
        toggle_rules = rules_aws.prod_toggles.rules
        out = [f for f in project_all(files) if f.path.startswith("envs/prod/") and f.rule in toggle_rules]
        self.assertEqual([f.rule for f in out], ["lb-https"])

    def test_prod_toggles_internal_error_one_finding_per_rule(self):
        orig = rules_aws._stack_var

        def boom(*a, **k):
            raise RuntimeError("x")
        rules_aws._stack_var = boom
        try:
            out = [f for f in project_all({PROD + "cdn.tf": DIST}) if "errore interno" in f.message]
        finally:
            rules_aws._stack_var = orig
        self.assertEqual(sorted(f.rule for f in out), ["cloudfront-https", "lb-https", "logs-retention"])
        self.assertTrue(all(f.severity == "block" for f in out))


class BypassRound2Test(Base):
    def test_prod_stack_toggle_through_local_var_without_value(self):
        text = ('locals {\n  w = var.web_acl_arn\n}\n'
                + DIST.replace(NO_WAF, "  web_acl_id = local.w\n"))
        var = 'variable "web_acl_arn" {\n  type        = string\n  description = "x"\n  default     = null\n}\n'
        f = self.one(project({PROD + "cdn.tf": text, PROD + "variables.tf": var}, "cloudfront-https"), 0,
                     contains="web_acl_arn")
        self.assertEqual(f.path, PROD + "terraform.tfvars")

    def test_module_toggle_shapes_rejected(self):
        for expr in ("var.waf_enabled ? null : null", "true ? null : aws_wafv2_web_acl.this.arn",
                     "false ? aws_wafv2_web_acl.this.arn : null",
                     "var.waf_enabled && false ? aws_wafv2_web_acl.this[0].arn : null",
                     "try(null, aws_wafv2_web_acl.this.arn)"):
            text = DIST.replace(NO_WAF, f"  web_acl_id = {expr}\n")
            self.one(run(MOD + "cdn.tf", text, "cloudfront-https"), 3, contains="waf_enabled")

    def test_module_toggle_shapes_accepted(self):
        for expr in ("var.web_acl_arn", "var.waf_enabled ? aws_wafv2_web_acl.this[0].arn : null",
                     "aws_wafv2_web_acl.this[*].arn", "local.acl"):
            text = 'locals {\n  acl = aws_wafv2_web_acl.this.arn\n}\n' + DIST.replace(NO_WAF, f"  web_acl_id = {expr}\n")
            self.assertEqual(run(MOD + "cdn.tf", text, "cloudfront-https"), [], expr)
        self.assertEqual(run(ELB_MOD + "lb.tf", ALB.replace("var.deletion_protection", "true"), "lb-https"), [])

    def test_prod_stack_boolean_toggle_resource_ref_rejected(self):
        text = ALB.replace("var.deletion_protection", "aws_ssm_parameter.p.insecure_value")
        self.one(run("envs/prod/elb/lb.tf", text, "lb-https"), 5, contains="deletion protection")

    def sg(self, dyn_for_each, cidr, local='{\n    ssh = { port = 22, cidr = "0.0.0.0/0", cidrs = ["0.0.0.0/0"] }\n  }'):
        return (f'locals {{\n  rules = {local}\n}}\n\nresource "aws_security_group" "s" {{\n  dynamic "ingress" {{\n'
                f'    for_each = {dyn_for_each}\n    content {{\n      from_port   = ingress.value.port\n'
                f'      to_port     = ingress.value.port\n      protocol    = "tcp"\n      cidr_blocks = {cidr}\n'
                '    }\n  }\n}\n')

    def test_sg_dynamic_iterator_inside_list_and_lookup(self):
        for cidr in ("[ingress.value.cidr]", 'lookup(ingress.value, "cidrs", [])', 'ingress.value["cidrs"]'):
            self.one(run(MOD + "sg.tf", self.sg("local.rules", cidr), "sg-open"), 10, contains="22")

    def test_sg_dynamic_identity_for_expression(self):
        text = self.sg("{ for k, v in local.rules : k => v }", "ingress.value.cidrs")
        self.one(run(MOD + "sg.tf", text, "sg-open"), 10, contains="22")

    def test_sg_dynamic_unresolvable_for_each_fails_closed(self):
        text = self.sg("{ for k, v in local.rules : k => v if v.port > 0 }", "ingress.value.cidrs")
        self.one(run(MOD + "sg.tf", text, "sg-open"), 8, contains="for_each")
        self.one(run(MOD + "sg.tf", self.sg("var.rules", "[ingress.value.cidr]"), "sg-open"), 8, contains="for_each")
        self.assertEqual(run(MOD + "sg.tf", self.sg("var.rules", '["10.0.0.0/8"]'), "sg-open"), [])

    def test_var_values_dedup_by_rule(self):
        text = ('resource "aws_security_group_rule" "s" {\n  type        = "ingress"\n  from_port   = var.port\n'
                '  to_port     = var.port\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n')
        var = 'variable "port" {\n  type        = number\n  description = "x"\n  default     = 22\n}\n'
        self.assertEqual(len(project({MOD + "sg.tf": text, MOD + "variables.tf": var}, "sg-open")), 1)


class RegistrationTest(unittest.TestCase):
    def test_rules_registered_for_aws(self):
        self.assertIs(rules.PROVIDER_RULES["aws"], rules_aws.AWS_RULES)
        self.assertTrue(rules_aws.AWS_PROJECT_RULES)

    def test_is_prod(self):
        cfg = cfg_for()
        self.assertTrue(rules_aws.is_prod("envs/prod/spa/main.tf", cfg))
        self.assertFalse(rules_aws.is_prod("envs/dev/spa/main.tf", cfg))
        self.assertFalse(rules_aws.is_prod("modules/spa/main.tf", cfg))

    def test_no_aws_rules_without_aws_provider(self):
        cfg = cfg_for(providers=["azure"])
        out = rules.check_content(MOD + "kms.tf", 'resource "aws_kms_key" "k" {}\n', cfg)
        self.assertEqual([f for f in out if f.rule == "kms-rotation"], [])


if __name__ == "__main__":
    unittest.main()
