data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  name         = "${var.project}-${var.environment}"
  account_id   = data.aws_caller_identity.current.account_id
  account_root = "arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"
  all_readers  = distinct(flatten([for s in var.secrets : s.readers]))
  rotated      = { for name, s in var.secrets : name => s if s.rotation_lambda_arn != null }

  # Una policy per regione della chiave (primaria e replica): ViaService è legato alla regione.
  key_policies = {
    for region in compact([data.aws_region.current.region, var.replica_region]) : region => jsonencode({
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
                "kms:ViaService"    = "secretsmanager.${region}.amazonaws.com"
                "kms:CallerAccount" = local.account_id
              }
            }
          }
        ]
      )
    })
  }
}

# ---------------------------------------------------------------- chiave KMS dedicata

# Multi-regione: la replica dei segreti (replica_region) usa una replica della stessa chiave nella regione di destinazione.
resource "aws_kms_key" "secrets" {
  description             = "Cifratura dei segreti di ${local.name}"
  enable_key_rotation     = true
  multi_region            = true
  deletion_window_in_days = 30

  policy = local.key_policies[data.aws_region.current.region]
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${local.name}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

resource "aws_kms_replica_key" "secrets" {
  count    = var.replica_region != "" ? 1 : 0
  provider = aws.replica

  description             = "Replica della chiave dei segreti di ${local.name}"
  primary_key_arn         = aws_kms_key.secrets.arn
  deletion_window_in_days = 30
  policy                  = local.key_policies[var.replica_region]

  lifecycle {
    precondition {
      condition     = var.replica_region != data.aws_region.current.region
      error_message = "replica_region deve essere diversa dalla regione dello stack."
    }
  }
}

resource "aws_kms_alias" "secrets_replica" {
  count    = var.replica_region != "" ? 1 : 0
  provider = aws.replica

  name          = "alias/${local.name}-secrets"
  target_key_id = aws_kms_replica_key.secrets[0].key_id
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
      region     = replica.value
      kms_key_id = aws_kms_replica_key.secrets[0].arn
    }
  }
}

resource "aws_secretsmanager_secret_policy" "this" {
  for_each = var.secrets

  secret_arn          = aws_secretsmanager_secret.this[each.key].arn
  block_public_policy = true

  lifecycle {
    precondition {
      condition     = alltrue([for r in each.value.readers : split(":", r)[4] == local.account_id])
      error_message = "Ogni reader deve essere un ruolo di questo account (${local.account_id})."
    }
  }

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
            Bool            = { "aws:PrincipalIsAWSService" = "false" }
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
