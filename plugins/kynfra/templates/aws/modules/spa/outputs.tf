output "bucket_name" {
  description = "Nome del bucket S3 privato con i file della SPA (destinazione del deploy del frontend)."
  value       = aws_s3_bucket.site.id
}

output "distribution_id" {
  description = "ID della distribuzione CloudFront (per le invalidazioni dopo il deploy)."
  value       = aws_cloudfront_distribution.this.id
}

output "distribution_domain_name" {
  description = "Dominio *.cloudfront.net della distribuzione."
  value       = aws_cloudfront_distribution.this.domain_name
}
