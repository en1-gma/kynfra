output "state_bucket" {
  description = "Nome del bucket dello stato: bucket del backend s3 degli stack."
  value       = aws_s3_bucket.state.bucket
}

output "state_bucket_arn" {
  description = "ARN del bucket dello stato."
  value       = aws_s3_bucket.state.arn
}

output "state_kms_key_arn" {
  description = "ARN della chiave KMS che cifra lo stato (kms_key_id del backend s3, se serve)."
  value       = aws_kms_key.state.arn
}

output "region" {
  description = "Regione del bucket dello stato."
  value       = var.region
}
