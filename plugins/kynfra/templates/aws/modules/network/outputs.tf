output "vpc_id" {
  description = "ID della VPC."
  value       = aws_vpc.this.id
}

output "public_subnet_ids" {
  description = "ID delle subnet pubbliche, una per zona."
  value       = [for k in sort(keys(aws_subnet.public)) : aws_subnet.public[k].id]
}

output "private_subnet_ids" {
  description = "ID delle subnet private (workload), una per zona."
  value       = [for k in sort(keys(aws_subnet.private)) : aws_subnet.private[k].id]
}

output "isolated_subnet_ids" {
  description = "ID delle subnet isolate (dati, senza uscita verso internet), una per zona."
  value       = [for k in sort(keys(aws_subnet.isolated)) : aws_subnet.isolated[k].id]
}

output "vpc_endpoint_sg_id" {
  description = "ID del security group degli endpoint VPC di tipo interface (443 dal CIDR della VPC)."
  value       = aws_security_group.endpoints.id
}
