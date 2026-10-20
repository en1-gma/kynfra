output "secret_arns" {
  description = "ARN dei segreti, per nome (mai i valori)."
  value       = module.secrets.secret_arns
}

output "secret_names" {
  description = "Nome completo dei segreti in Secrets Manager (<progetto>/<env>/<nome>), per nome."
  value       = module.secrets.secret_names
}

output "kms_key_arn" {
  description = "ARN della chiave KMS dedicata ai segreti."
  value       = module.secrets.kms_key_arn
}
