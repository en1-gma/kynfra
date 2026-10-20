output "lb_arn" {
  description = "ARN del load balancer."
  value       = aws_lb.this.arn
}

output "lb_dns_name" {
  description = "Nome DNS del load balancer (*.elb.amazonaws.com)."
  value       = aws_lb.this.dns_name
}

output "lb_zone_id" {
  description = "Hosted zone del load balancer, per altri record alias."
  value       = aws_lb.this.zone_id
}

output "https_listener_arn" {
  description = "ARN del listener 443 (HTTPS per l'ALB, TLS per l'NLB): qui si aggiungono regole e certificati."
  value       = local.is_alb ? aws_lb_listener.https[0].arn : aws_lb_listener.tls[0].arn
}

output "target_group_arn" {
  description = "ARN del gruppo di destinazione di default (target IP) in cui registrare i pod o i task."
  value       = aws_lb_target_group.this.arn
}

output "security_group_id" {
  description = "ID del security group del load balancer: sorgente da ammettere nel security group dei target sulla porta target_port."
  value       = aws_security_group.lb.id
}
