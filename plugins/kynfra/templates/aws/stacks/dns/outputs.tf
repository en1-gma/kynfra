output "zone_id" {
  description = "ID della hosted zone pubblica (letto dagli stack envs/<env>/spa con hosted_zone = \"create\")."
  value       = aws_route53_zone.this.zone_id
}

output "name_servers" {
  description = "Name server della zona: delegali dal registrar o dalla zona padre."
  value       = aws_route53_zone.this.name_servers
}
