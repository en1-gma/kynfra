data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  name         = "${var.project}-${var.environment}"
  account_id   = data.aws_caller_identity.current.account_id
  account_root = "arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"
}

# ---------------------------------------------------------------- chiave KMS dedicata

resource "aws_kms_key" "ecr" {
  description             = "Cifratura dei repository ECR di ${var.project}"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  # ECR usa la chiave con grant a nome del chiamante: basta l'amministrazione dell'account, nessun principal in più.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = local.account_root }
        Action    = "kms:*"
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "ecr" {
  name          = "alias/${local.name}-ecr"
  target_key_id = aws_kms_key.ecr.key_id
}

# ---------------------------------------------------------------- repository

resource "aws_ecr_repository" "this" {
  for_each = toset(var.repositories)

  name                 = "${var.project}/${each.key}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  for_each = aws_ecr_repository.this

  repository = aws_ecr_repository.this[each.key].name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Scadenza delle immagini non taggate dopo ${var.untagged_expiry_days} giorni"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = var.untagged_expiry_days
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Conserva le ultime ${var.keep_last} immagini taggate"
        selection = {
          tagStatus      = "tagged"
          tagPatternList = ["*"]
          countType      = "imageCountMoreThan"
          countNumber    = var.keep_last
        }
        action = { type = "expire" }
      }
    ]
  })
}

# Pull solo per i ruoli indicati; il push non è concesso dalla policy (i ruoli di CI usano policy identity). Il deny
# esclude i principal fuori dall'account, salvo i servizi AWS (replica, scansione) e i principal anonimi senza chiave.
resource "aws_ecr_repository_policy" "this" {
  for_each = aws_ecr_repository.this

  repository = aws_ecr_repository.this[each.key].name

  lifecycle {
    precondition {
      condition     = alltrue([for r in var.pull_principals : split(":", r)[4] == local.account_id])
      error_message = "Ogni principal deve essere un ruolo di questo account (${local.account_id})."
    }
  }

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      length(var.pull_principals) == 0 ? [] : [
        {
          Sid       = "AllowPull"
          Effect    = "Allow"
          Principal = { AWS = var.pull_principals }
          Action = [
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage",
            "ecr:BatchCheckLayerAvailability"
          ]
        }
      ],
      [
        {
          Sid       = "DenyOutsideAccount"
          Effect    = "Deny"
          Principal = { AWS = "*" }
          Action    = "ecr:*"
          Condition = {
            StringNotEquals = { "aws:PrincipalAccount" = local.account_id }
            BoolIfExists    = { "aws:PrincipalIsAWSService" = "false" }
          }
        }
      ]
    )
  })
}
