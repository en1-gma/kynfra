output "vpc_id" {
  description = "ID della VPC."
  value       = module.network.vpc_id
}

output "public_subnet_ids" {
  description = "ID delle subnet pubbliche, una per zona."
  value       = module.network.public_subnet_ids
}

output "private_subnet_ids" {
  description = "ID delle subnet private (workload), una per zona."
  value       = module.network.private_subnet_ids
}

output "isolated_subnet_ids" {
  description = "ID delle subnet isolate (dati), una per zona."
  value       = module.network.isolated_subnet_ids
}

output "vpc_endpoint_sg_id" {
  description = "ID del security group degli endpoint VPC interface."
  value       = module.network.vpc_endpoint_sg_id
}
