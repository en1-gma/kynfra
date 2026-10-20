output "lb_arn" {
  description = "ARN del load balancer."
  value       = module.elb.lb_arn
}

output "lb_dns_name" {
  description = "Nome DNS del load balancer (*.elb.amazonaws.com)."
  value       = module.elb.lb_dns_name
}

output "lb_zone_id" {
  description = "Hosted zone del load balancer, per altri record alias."
  value       = module.elb.lb_zone_id
}

output "https_listener_arn" {
  description = "ARN del listener 443 (HTTPS per l'ALB, TLS per l'NLB)."
  value       = module.elb.https_listener_arn
}

output "target_group_arn" {
  description = "ARN del gruppo di destinazione di default (target IP): lo usano TargetGroupBinding su EKS o il servizio ECS."
  value       = module.elb.target_group_arn
}

output "security_group_id" {
  description = "ID del security group del load balancer: da ammettere nel security group dei target sulla porta target_port."
  value       = module.elb.security_group_id
}
