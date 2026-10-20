output "repository_urls" {
  description = "URL dei repository, per nome."
  value       = { for name, r in aws_ecr_repository.this : name => r.repository_url }
}

output "repository_arns" {
  description = "ARN dei repository, per nome."
  value       = { for name, r in aws_ecr_repository.this : name => r.arn }
}

output "kms_key_arn" {
  description = "ARN della chiave KMS dedicata ai repository."
  value       = aws_kms_key.ecr.arn
}

output "registry_id" {
  description = "ID del registry (l'ID dell'account)."
  value       = local.account_id
}
