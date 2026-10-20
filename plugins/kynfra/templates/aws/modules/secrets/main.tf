data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  name         = "${var.project}-${var.environment}"
  account_id   = data.aws_caller_identity.current.account_id
  account_root = "arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"
  all_readers  = distinct(flatten([for s in var.secrets : s.readers]))
  rotated      = { for name, s in var.secrets : name => s if s.rotation_lambda_arn != null }
}

# ---------------------------------------------------------------- chiave KMS dedicata

resource "aws_kms_key" "secrets" {
  description             = "Cifratura dei segreti di ${local.name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid       = "AccountAdministration"
          Effect    = "Allow"
          Principal = { AWS = local.account_root }
          Action    = "kms:*"
          Resource  = "*"
        }
      ],
      length(local.all_readers) == 0 ? [] : [
        {
          Sid       = "ReadersDecryptViaSecretsManager"
          Effect    = "Allow"
          Principal = { AWS = local.all_readers }
          Action    = ["kms:Decrypt", "kms:DescribeKey"]
          Resource  = "*"
          Condition = {
            StringEquals = {
              "kms:ViaService"    = "secretsmanager.${data.aws_region.current.region}.amazonaws.com"
              "kms:CallerAccount" = local.account_id
            }
          }
        }
      ]
    )
  })
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${local.name}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# ---------------------------------------------------------------- segreti (solo contenitori, nessun valore)

resource "aws_secretsmanager_secret" "this" {
  for_each = var.secrets

  name                    = "${var.project}/${var.environment}/${each.key}"
  description             = each.value.description
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = var.recovery_window_days

  dynamic "replica" {
    for_each = var.replica_region != "" ? toset([var.replica_region]) : toset([])

    content {
      region = replica.value
    }
  }
}

resource "aws_secretsmanager_secret_policy" "this" {
  for_each = var.secrets

  secret_arn          = aws_secretsmanager_secret.this[each.key].arn
  block_public_policy = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      length(each.value.readers) == 0 ? [] : [
        {
          Sid       = "AllowReaders"
          Effect    = "Allow"
          Principal = { AWS = each.value.readers }
          Action    = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
          Resource  = "*"
        }
      ],
      [
        {
          Sid       = "DenyOutsideAccount"
          Effect    = "Deny"
          Principal = { AWS = "*" }
          Action    = "secretsmanager:*"
          Resource  = "*"
          Condition = {
            StringNotEquals = { "aws:PrincipalAccount" = local.account_id }
          }
        },
        {
          Sid       = "DenyInsecureTransport"
          Effect    = "Deny"
          Principal = { AWS = "*" }
          Action    = "secretsmanager:*"
          Resource  = "*"
          Condition = {
            Bool = { "aws:SecureTransport" = "false" }
          }
        }
      ]
    )
  })
}

# ---------------------------------------------------------------- rotazione (solo con rotation_lambda_arn)

resource "aws_secretsmanager_secret_rotation" "this" {
  for_each = local.rotated

  secret_id           = aws_secretsmanager_secret.this[each.key].id
  rotation_lambda_arn = each.value.rotation_lambda_arn

  rotation_rules {
    automatically_after_days = var.rotation_days
  }
}
