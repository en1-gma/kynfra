data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "aws_region" "query_logs" {
  provider = aws.us_east_1
}

locals {
  name           = "${var.project}-${var.environment}"
  zone_name      = var.zone_name != "" ? var.zone_name : var.domain_name
  account_id     = data.aws_caller_identity.current.account_id
  partition      = data.aws_partition.current.partition
  logs_region    = data.aws_region.query_logs.region
  query_log_name = "/aws/route53/${local.zone_name}"
  query_log_arn  = "arn:${local.partition}:logs:${local.logs_region}:${local.account_id}:log-group:${local.query_log_name}"
  retention_days = 365
}

# Zona pubblica condivisa dagli ambienti: ogni stack envs/<env>/spa vi scrive i propri record.
resource "aws_route53_zone" "this" {
  name    = local.zone_name
  comment = "Zona pubblica di ${local.name} (kynfra)"
}

resource "aws_kms_key" "query_logs" {
  provider = aws.us_east_1

  description             = "Cifratura dei log delle query DNS di ${local.zone_name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudWatchLogsEncryption"
        Effect    = "Allow"
        Principal = { Service = "logs.${local.logs_region}.amazonaws.com" }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
        Condition = {
          ArnLike = { "kms:EncryptionContext:aws:logs:arn" = local.query_log_arn }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "query_logs" {
  provider = aws.us_east_1

  name          = "alias/${local.name}-dns-query-logs"
  target_key_id = aws_kms_key.query_logs.key_id
}

resource "aws_cloudwatch_log_group" "query_logs" {
  provider = aws.us_east_1

  name              = local.query_log_name
  retention_in_days = local.retention_days
  kms_key_id        = aws_kms_key.query_logs.arn
}

resource "aws_cloudwatch_log_resource_policy" "query_logs" {
  provider = aws.us_east_1

  policy_name = "${local.name}-dns-query-logs"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "Route53QueryLogs"
        Effect    = "Allow"
        Principal = { Service = "route53.amazonaws.com" }
        Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource  = "${aws_cloudwatch_log_group.query_logs.arn}:*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
          ArnLike      = { "aws:SourceArn" = aws_route53_zone.this.arn }
        }
      }
    ]
  })
}

resource "aws_route53_query_log" "this" {
  zone_id                  = aws_route53_zone.this.zone_id
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.query_logs.arn

  depends_on = [aws_cloudwatch_log_resource_policy.query_logs]
}
