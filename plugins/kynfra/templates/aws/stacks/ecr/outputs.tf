output "repository_urls" {
  description = "URL dei repository, per nome."
  value       = module.ecr.repository_urls
}

output "repository_arns" {
  description = "ARN dei repository, per nome."
  value       = module.ecr.repository_arns
}

output "kms_key_arn" {
  description = "ARN della chiave KMS dedicata ai repository."
  value       = module.ecr.kms_key_arn
}

output "registry_id" {
  description = "ID del registry (l'ID dell'account)."
  value       = module.ecr.registry_id
}
