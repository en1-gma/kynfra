locals {
  # hosted_zone = "create": zona dello stack envs/shared/dns; "existing:<zone_id>": zona già esistente
  create_zone = var.hosted_zone == "create"
  zone_id     = local.create_zone ? data.terraform_remote_state.dns[0].outputs.zone_id : trimprefix(var.hosted_zone, "existing:")
}

# VPC e subnet dallo stack network dello stesso ambiente (lo stack network non legge mai questo stack).
data "terraform_remote_state" "network" {
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "${var.project}/${var.environment}/network.tfstate"
    region = var.region
  }
}

data "terraform_remote_state" "dns" {
  count = local.create_zone ? 1 : 0

  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "${var.project}/shared/dns.tfstate"
    region = var.region
  }
}

# Zona effettiva (creata in envs/shared/dns o esistente): al plan domain_name deve stare nella zona pubblica.
data "aws_route53_zone" "this" {
  zone_id = local.zone_id

  lifecycle {
    postcondition {
      condition     = !self.private_zone
      error_message = "La hosted zone indicata è privata: la validazione DNS del certificato ACM richiede una zona pubblica."
    }

    postcondition {
      condition     = var.domain_name == trimsuffix(self.name, ".") || endswith(var.domain_name, ".${trimsuffix(self.name, ".")}")
      error_message = "domain_name non appartiene alla hosted zone: usa il nome della zona o un suo sottodominio (o un'altra zona in hosted_zone)."
    }
  }
}

module "elb" {
  source = "../../../modules/elb"

  project             = var.project
  environment         = var.environment
  type                = var.type
  internal            = var.internal
  vpc_id              = data.terraform_remote_state.network.outputs.vpc_id
  subnet_ids          = var.internal ? data.terraform_remote_state.network.outputs.private_subnet_ids : data.terraform_remote_state.network.outputs.public_subnet_ids
  allow_from          = var.allow_from
  domain_name         = var.domain_name
  zone_id             = data.aws_route53_zone.this.zone_id
  target_port         = var.target_port
  health_path         = var.health_path
  deletion_protection = var.deletion_protection
  waf_enabled         = var.waf_enabled
}
