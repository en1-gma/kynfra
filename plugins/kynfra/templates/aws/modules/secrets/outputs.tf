output "secret_arns" {
  description = "ARN dei segreti, per nome (mai i valori)."
  value       = { for name, s in aws_secretsmanager_secret.this : name => s.arn }
}

output "kms_key_arn" {
  description = "ARN della chiave KMS dedicata ai segreti."
  value       = aws_kms_key.secrets.arn
}
