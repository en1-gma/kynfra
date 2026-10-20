data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

# CIDR della VPC dello stack network: sorgente degli ingress con internal = true e destinazione dell'egress.
data "aws_vpc" "this" {
  id = var.vpc_id
}

# Indirizzi di CloudFront verso gli origin (prefix list gestita da AWS), solo con allow_from = "cloudfront".
data "aws_ec2_managed_prefix_list" "cloudfront" {
  count = local.from_cloudfront ? 1 : 0

  name = "com.amazonaws.global.cloudfront.origin-facing"
}

# Account del servizio ELB della regione: serve solo nelle regioni aperte prima di ap-southeast-3 (dicembre 2021),
# dove i log di accesso dell'ALB si concedono all'account; nelle regioni successive basta il service principal.
data "aws_elb_service_account" "this" {
  count = local.legacy_elb_account ? 1 : 0
}

locals {
  name       = "${var.project}-${var.environment}"
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  is_alb          = var.type == "alb"
  lb_type         = local.is_alb ? "application" : "network"
  dualstack       = var.ip_address_type == "dualstack"
  from_internet   = !var.internal && var.allow_from == "internet"
  from_cloudfront = !var.internal && var.allow_from == "cloudfront"
  vpc_cidr        = data.aws_vpc.this.cidr_block

  legacy_elb_account = contains(var.legacy_elb_regions, local.region)

  log_prefix          = var.type
  log_objects         = "${aws_s3_bucket.logs.arn}/${local.log_prefix}/AWSLogs/${local.account_id}/*"
  log_expiration_days = 365
  log_retention_days  = 365
  noncurrent_days     = 30
  multipart_days      = 7

  waf_log_group     = "aws-waf-logs-${local.name}-lb"
  waf_log_group_arn = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:${local.waf_log_group}"
  account_root      = "arn:${local.partition}:iam::${local.account_id}:root"
}

# ---------------------------------------------------------------- bucket degli access log

resource "aws_s3_bucket" "logs" {
  bucket = "${local.name}-lb-logs-${local.account_id}"
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# SSE-S3: è l'unica cifratura di default ammessa dagli access log dell'ALB.
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = local.log_expiration_days
    }

    noncurrent_version_expiration {
      noncurrent_days = local.noncurrent_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = local.multipart_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.logs]
}

# Solo HTTPS; scrittura dei log solo sotto <tipo>/AWSLogs/<account>/: ALB tramite il service principal di ELB (e
# l'account ELB della regione dove serve), NLB tramite la consegna dei log di CloudWatch (delivery.logs).
data "aws_iam_policy_document" "logs" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]

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

  dynamic "statement" {
    for_each = local.is_alb ? toset(["alb"]) : toset([])

    content {
      sid       = "AlbLogDelivery"
      actions   = ["s3:PutObject"]
      resources = [local.log_objects]

      principals {
        type        = "Service"
        identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
      }
    }
  }

  dynamic "statement" {
    for_each = local.is_alb && local.legacy_elb_account ? toset(["alb-legacy"]) : toset([])

    content {
      sid       = "AlbLogDeliveryRegionalAccount"
      actions   = ["s3:PutObject"]
      resources = [local.log_objects]

      principals {
        type        = "AWS"
        identifiers = [data.aws_elb_service_account.this[0].arn]
      }
    }
  }

  dynamic "statement" {
    for_each = local.is_alb ? toset([]) : toset(["nlb"])

    content {
      sid       = "NlbLogDeliveryWrite"
      actions   = ["s3:PutObject"]
      resources = [local.log_objects]

      principals {
        type        = "Service"
        identifiers = ["delivery.logs.amazonaws.com"]
      }

      condition {
        test     = "StringEquals"
        variable = "s3:x-amz-acl"
        values   = ["bucket-owner-full-control"]
      }

      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [local.account_id]
      }

      condition {
        test     = "ArnLike"
        variable = "aws:SourceArn"
        values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:*"]
      }
    }
  }

  dynamic "statement" {
    for_each = local.is_alb ? toset([]) : toset(["nlb"])

    content {
      sid       = "NlbLogDeliveryAclCheck"
      actions   = ["s3:GetBucketAcl"]
      resources = [aws_s3_bucket.logs.arn]

      principals {
        type        = "Service"
        identifiers = ["delivery.logs.amazonaws.com"]
      }

      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [local.account_id]
      }

      condition {
        test     = "ArnLike"
        variable = "aws:SourceArn"
        values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:*"]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs.json

  depends_on = [aws_s3_bucket_public_access_block.logs]
}

# ---------------------------------------------------------------- certificato ACM (regionale) e DNS

resource "aws_acm_certificate" "this" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = {
    for o in aws_acm_certificate.this.domain_validation_options : o.domain_name => {
      name   = o.resource_record_name
      type   = o.resource_record_type
      record = o.resource_record_value
    }
  }

  zone_id         = var.zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 60
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "this" {
  certificate_arn         = aws_acm_certificate.this.arn
  validation_record_fqdns = [for r in aws_route53_record.validation : r.fqdn]
}

# A sempre; AAAA solo con ip_address_type = "dualstack" (subnet con IPv6).
resource "aws_route53_record" "alias" {
  for_each = toset(local.dualstack ? ["A", "AAAA"] : ["A"])

  zone_id = var.zone_id
  name    = var.domain_name
  type    = each.key

  alias {
    name                   = aws_lb.this.dns_name
    zone_id                = aws_lb.this.zone_id
    evaluate_target_health = true
  }
}

# ---------------------------------------------------------------- security group

resource "aws_security_group" "lb" {
  name        = "${local.name}-lb"
  description = "Load balancer ${local.name}: 443 (e 80 per il redirect) dai client ammessi, uscita verso i target"
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "https_ipv4" {
  count = local.from_internet ? 1 : 0

  security_group_id = aws_security_group.lb.id
  description       = "HTTPS dal mondo (IPv4)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "https_ipv6" {
  count = local.from_internet && local.dualstack ? 1 : 0

  security_group_id = aws_security_group.lb.id
  description       = "HTTPS dal mondo (IPv6)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv6         = "::/0"
}

# Porta 80 solo per il redirect a HTTPS dell'ALB (l'NLB non ha listener sulla 80).
resource "aws_vpc_security_group_ingress_rule" "http_ipv4" {
  count = local.from_internet && local.is_alb ? 1 : 0

  security_group_id = aws_security_group.lb.id
  description       = "HTTP dal mondo (IPv4), solo redirect a HTTPS"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "http_ipv6" {
  count = local.from_internet && local.is_alb && local.dualstack ? 1 : 0

  security_group_id = aws_security_group.lb.id
  description       = "HTTP dal mondo (IPv6), solo redirect a HTTPS"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv6         = "::/0"
}

# Con allow_from = "cloudfront" solo HTTPS dagli indirizzi di CloudFront verso gli origin.
resource "aws_vpc_security_group_ingress_rule" "https_cloudfront" {
  count = local.from_cloudfront ? 1 : 0

  security_group_id = aws_security_group.lb.id
  description       = "HTTPS solo da CloudFront (prefix list origin-facing)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = data.aws_ec2_managed_prefix_list.cloudfront[0].id
}

# Load balancer interno: client nella VPC.
resource "aws_vpc_security_group_ingress_rule" "https_vpc" {
  count = var.internal ? 1 : 0

  security_group_id = aws_security_group.lb.id
  description       = "HTTPS dalla VPC"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = local.vpc_cidr
}

resource "aws_vpc_security_group_ingress_rule" "http_vpc" {
  count = var.internal && local.is_alb ? 1 : 0

  security_group_id = aws_security_group.lb.id
  description       = "HTTP dalla VPC, solo redirect a HTTPS"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = local.vpc_cidr
}

# Uscita solo verso la VPC sulla porta dei target (traffico e health check).
resource "aws_vpc_security_group_egress_rule" "targets" {
  security_group_id = aws_security_group.lb.id
  description       = "Verso i target nella VPC"
  ip_protocol       = "tcp"
  from_port         = var.target_port
  to_port           = var.target_port
  cidr_ipv4         = local.vpc_cidr
}

# ---------------------------------------------------------------- load balancer

resource "aws_lb" "this" {
  name               = "${local.name}-${var.type}"
  load_balancer_type = local.lb_type
  internal           = var.internal
  ip_address_type    = var.ip_address_type
  subnets            = var.subnet_ids
  security_groups    = [aws_security_group.lb.id]

  # solo ALB (il provider li ignora sull'NLB)
  drop_invalid_header_fields = true
  desync_mitigation_mode     = local.is_alb ? "strictest" : null

  # solo NLB: l'ALB bilancia sempre tra le zone
  enable_cross_zone_load_balancing = local.is_alb ? null : true

  enable_deletion_protection = var.deletion_protection

  access_logs {
    bucket  = aws_s3_bucket.logs.id
    prefix  = local.log_prefix
    enabled = true
  }

  depends_on = [aws_s3_bucket_policy.logs]
}

# Gruppo di destinazione di default: target IP (pod con AWS Load Balancer Controller/TargetGroupBinding, task ECS).
# Il nome contiene tipo e porta: cambiandoli il gruppo nuovo nasce prima che il vecchio sia rimosso dal listener.
resource "aws_lb_target_group" "this" {
  name                 = "${local.name}-${var.type}-${var.target_port}"
  vpc_id               = var.vpc_id
  target_type          = "ip"
  port                 = var.target_port
  protocol             = local.is_alb ? "HTTP" : "TCP"
  deregistration_delay = 30

  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "traffic-port"
    path                = var.health_path
    matcher             = "200-399"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ALB: 80 fa solo redirect a 443.
resource "aws_lb_listener" "http" {
  count = local.is_alb ? 1 : 0

  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      protocol    = "HTTPS"
      port        = "443"
      status_code = "HTTP_301"
    }
  }
}

# ALB: 443 con TLS 1.3/1.2; le richieste con un Host diverso da domain_name (scanner, accesso per IP o per il nome
# *.elb.amazonaws.com) ricevono 404, quelle per domain_name vanno al gruppo di default con la regola "app".
resource "aws_lb_listener" "https" {
  count = local.is_alb ? 1 : 0

  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.this.certificate_arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Not Found"
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener_rule" "app" {
  count = local.is_alb ? 1 : 0

  listener_arn = aws_lb_listener.https[0].arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }

  condition {
    host_header {
      values = [var.domain_name]
    }
  }
}

# NLB: 443 TLS terminato sul load balancer, inoltro TCP ai target.
resource "aws_lb_listener" "tls" {
  count = local.is_alb ? 0 : 1

  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "TLS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.this.certificate_arn
  alpn_policy       = "HTTP2Preferred"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

# ---------------------------------------------------------------- WAF (regionale, solo ALB)

resource "aws_wafv2_web_acl" "this" {
  count = var.waf_enabled ? 1 : 0

  name        = "${local.name}-lb"
  description = "WAF del load balancer ${local.name}: managed rule set AWS e rate limit per IP"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "aws-common"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-lb-aws-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-known-bad-inputs"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-lb-aws-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-ip-reputation"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-lb-aws-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-limit-ip"
    priority = 40

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-lb-rate-limit-ip"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-lb"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "this" {
  count = var.waf_enabled ? 1 : 0

  resource_arn = aws_lb.this.arn
  web_acl_arn  = aws_wafv2_web_acl.this[0].arn
}

resource "aws_kms_key" "waf_logs" {
  count = var.waf_enabled ? 1 : 0

  description             = "Cifratura dei log WAF del load balancer ${local.name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = local.account_root }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudWatchLogsEncryption"
        Effect    = "Allow"
        Principal = { Service = "logs.${local.region}.amazonaws.com" }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
        Condition = {
          ArnLike = { "kms:EncryptionContext:aws:logs:arn" = local.waf_log_group_arn }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "waf_logs" {
  count = var.waf_enabled ? 1 : 0

  name          = "alias/${local.name}-lb-waf-logs"
  target_key_id = aws_kms_key.waf_logs[0].key_id
}

resource "aws_cloudwatch_log_group" "waf" {
  count = var.waf_enabled ? 1 : 0

  name              = local.waf_log_group
  retention_in_days = local.log_retention_days
  kms_key_id        = aws_kms_key.waf_logs[0].arn
}

# Policy dedicata: evita che WAF aggiorni la policy condivisa AWSWAF-LOGS dell'account (limite di dimensione).
resource "aws_cloudwatch_log_resource_policy" "waf" {
  count = var.waf_enabled ? 1 : 0

  policy_name = "${local.name}-lb-waf-logs"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "WafLogDelivery"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource  = "${aws_cloudwatch_log_group.waf[0].arn}:*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
          ArnLike      = { "aws:SourceArn" = "arn:${local.partition}:logs:${local.region}:${local.account_id}:*" }
        }
      }
    ]
  })
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  count = var.waf_enabled ? 1 : 0

  resource_arn            = aws_wafv2_web_acl.this[0].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

  depends_on = [aws_cloudwatch_log_resource_policy.waf]
}
