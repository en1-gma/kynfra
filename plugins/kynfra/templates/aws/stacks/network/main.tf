module "network" {
  source = "../../../modules/network"

  project                 = var.project
  environment             = var.environment
  vpc_cidr                = var.vpc_cidr
  availability_zones      = var.availability_zones
  az_count                = var.az_count
  nat_per_az              = var.nat_per_az
  flow_log_retention_days = var.flow_log_retention_days
}
