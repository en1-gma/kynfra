output "bucket_name" {
  description = "Nome del bucket S3 privato della SPA (destinazione del deploy del frontend)."
  value       = module.spa.bucket_name
}

output "distribution_id" {
  description = "ID della distribuzione CloudFront (invalidazioni dopo il deploy)."
  value       = module.spa.distribution_id
}

output "distribution_domain_name" {
  description = "Dominio *.cloudfront.net della distribuzione."
  value       = module.spa.distribution_domain_name
}
