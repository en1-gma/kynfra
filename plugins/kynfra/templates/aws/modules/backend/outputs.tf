output "api_id" {
  description = "ID della REST API."
  value       = aws_api_gateway_rest_api.this.id
}

output "stage_name" {
  description = "Nome dello stage (api)."
  value       = aws_api_gateway_stage.this.stage_name
}

output "api_domain_name" {
  description = "Dominio execute-api dello stage (<id>.execute-api.<regione>.amazonaws.com): origin /api/* dello stack spa."
  value       = split("/", aws_api_gateway_stage.this.invoke_url)[2]
}

output "api_origin_path" {
  description = "Origin path per lo stack spa: vuoto, perché lo stage si chiama api e il behavior /api/* inoltra /api/<base>/... così com'è."
  value       = ""
}

output "base_path" {
  description = "Percorso base delle risorse (percorso di servers[0].url dello schema, es. /v1; vuoto se assente)."
  value       = local.base_path
}

output "invoke_url" {
  description = "URL di invocazione dello stage."
  value       = aws_api_gateway_stage.this.invoke_url
}

output "lambda_function_names" {
  description = "Nome delle Lambda, per handler (più \"authorizer\" con authorizer = lambda)."
  value       = { for k, f in aws_lambda_function.this : k => f.function_name }
}

output "lambda_role_arns" {
  description = "Ruolo IAM di ogni Lambda, per handler."
  value       = { for k, r in aws_iam_role.lambda : k => r.arn }
}

output "artifacts_bucket" {
  description = "Bucket degli zip delle Lambda (privato, versionato, SSE-KMS): la CI carica qui i pacchetti."
  value       = aws_s3_bucket.artifacts.id
}

output "artifact_keys" {
  description = "Chiave S3 attesa per lo zip di ogni Lambda, per handler."
  value       = { for k, f in aws_lambda_function.this : k => f.s3_key }
}

output "kms_key_arn" {
  description = "Chiave KMS del backend (log, code, variabili delle Lambda, artefatti): la CI ne ha bisogno per caricare gli zip."
  value       = aws_kms_key.this.arn
}

output "queue_urls" {
  description = "URL della coda di ogni job."
  value       = { for k, q in aws_sqs_queue.job : k => q.url }
}

output "queue_arns" {
  description = "ARN della coda di ogni job."
  value       = { for k, q in aws_sqs_queue.job : k => q.arn }
}

output "dlq_urls" {
  description = "URL della dead-letter queue di ogni job."
  value       = { for k, q in aws_sqs_queue.dlq : k => q.url }
}

output "pod_role_arns" {
  description = "Ruolo Pod Identity di ogni microservizio e job (chiave handler o jobs/<nome>)."
  value       = { for k, r in aws_iam_role.pod : k => r.arn }
}

output "service_accounts" {
  description = "Service account Kubernetes associato a ogni ruolo Pod Identity (namespace kubernetes_namespace)."
  value       = { for k, p in local.pods : k => p.service_account }
}

output "vpc_link_id" {
  description = "ID del VPC link verso l'NLB interno dei microservizi (null senza microservizi)."
  value       = local.has_ms ? aws_api_gateway_vpc_link.ms[0].id : null
}

output "ms_target_group_arns" {
  description = "Target group IP di ogni microservizio: TargetGroupBinding dell'AWS Load Balancer Controller."
  value       = { for k, tg in aws_lb_target_group.ms : k => tg.arn }
}

output "ms_listener_ports" {
  description = "Porta del listener dell'NLB di ogni microservizio."
  value       = local.ms_ports
}

output "ms_nlb_security_group_id" {
  description = "Security group dell'NLB interno (null senza microservizi)."
  value       = local.has_ms ? aws_security_group.nlb[0].id : null
}

output "db_proxy_endpoint" {
  description = "Endpoint di RDS Proxy (null senza schemas/db)."
  value       = var.has_db ? aws_db_proxy.this[0].endpoint : null
}

output "db_proxy_security_group_id" {
  description = "Security group del proxy: ammettilo nel security group del database sulla sua porta (null senza schemas/db)."
  value       = var.has_db ? aws_security_group.proxy[0].id : null
}
