# VPC e subnet private dallo stack network dello stesso ambiente (lo stack network non legge mai questo stack).
data "terraform_remote_state" "network" {
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "${var.project}/${var.environment}/network.tfstate"
    region = var.region
  }
}

# Le liste arrivano come stringhe separate da virgola (il generatore passa solo stringhe); le validazioni stanno nel
# modulo. Altri node group: aggiungi voci alla mappa node_groups.
module "eks" {
  source = "../../../modules/eks"

  project               = var.project
  environment           = var.environment
  kubernetes_version    = var.kubernetes_version
  vpc_id                = data.terraform_remote_state.network.outputs.vpc_id
  subnet_ids            = data.terraform_remote_state.network.outputs.private_subnet_ids
  public_endpoint_cidrs = compact([for c in split(",", var.public_endpoint_cidrs) : trimspace(c)])
  admin_principals      = compact([for a in split(",", var.admin_principals) : trimspace(a)])
  log_retention_days    = var.log_retention_days
  deletion_protection   = var.deletion_protection

  node_groups = {
    system = {
      instance_types = compact([for t in split(",", var.node_instance_types) : trimspace(t)])
      min_size       = var.node_min_size
      max_size       = var.node_max_size
      desired_size   = var.node_desired_size
    }
  }
}
