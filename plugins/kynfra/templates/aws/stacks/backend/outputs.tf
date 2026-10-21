output "api_domain_name" {
  description = "Dominio execute-api dello stage: lo legge lo stack spa (api_origin = backend) come origin di /api/*."
  value       = module.backend.api_domain_name
}

output "api_origin_path" {
  description = "Origin path per lo stack spa: vuoto (stage api, il behavior /api/* inoltra il percorso così com'è)."
  value       = module.backend.api_origin_path
}

output "api_id" {
  description = "ID della REST API."
  value       = module.backend.api_id
}

output "stage_name" {
  description = "Nome dello stage."
  value       = module.backend.stage_name
}

output "base_path" {
  description = "Percorso base delle risorse (da servers[0].url dello schema)."
  value       = module.backend.base_path
}

output "invoke_url" {
  description = "URL di invocazione dello stage."
  value       = module.backend.invoke_url
}

output "lambda_function_names" {
  description = "Nome delle Lambda, per handler."
  value       = module.backend.lambda_function_names
}

output "artifacts_bucket" {
  description = "Bucket degli zip delle Lambda."
  value       = module.backend.artifacts_bucket
}

output "artifact_keys" {
  description = "Chiave S3 attesa per lo zip di ogni Lambda."
  value       = module.backend.artifact_keys
}

output "kms_key_arn" {
  description = "Chiave KMS del backend."
  value       = module.backend.kms_key_arn
}

output "queue_urls" {
  description = "URL della coda di ogni job."
  value       = module.backend.queue_urls
}

output "dlq_urls" {
  description = "URL della dead-letter queue di ogni job."
  value       = module.backend.dlq_urls
}

output "pod_role_arns" {
  description = "Ruolo Pod Identity di ogni microservizio e job."
  value       = module.backend.pod_role_arns
}

output "service_accounts" {
  description = "Service account Kubernetes di ogni ruolo Pod Identity."
  value       = module.backend.service_accounts
}

output "vpc_link_id" {
  description = "ID del VPC link verso l'NLB interno dei microservizi."
  value       = module.backend.vpc_link_id
}

output "ms_target_group_arns" {
  description = "Target group di ogni microservizio (TargetGroupBinding)."
  value       = module.backend.ms_target_group_arns
}

output "db_proxy_endpoint" {
  description = "Endpoint di RDS Proxy."
  value       = module.backend.db_proxy_endpoint
}

output "db_proxy_security_group_id" {
  description = "Security group del proxy da ammettere nel security group del database."
  value       = module.backend.db_proxy_security_group_id
}

output "workload_repository_urls" {
  description = "Repository ECR (stack envs/shared/ecr) di ogni microservizio (<contesto>-<nome>) e job; null se il repository non esiste."
  value       = local.has_workloads ? { for w in local.workloads : w => lookup(data.terraform_remote_state.ecr[0].outputs.repository_urls, w, null) } : {}
}
