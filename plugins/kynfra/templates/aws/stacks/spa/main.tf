locals {
  # hosted_zone = "create": zona dello stack envs/shared/dns; "existing:<zone_id>": zona già esistente
  create_zone = var.hosted_zone == "create"
  zone_id     = local.create_zone ? data.terraform_remote_state.dns[0].outputs.zone_id : trimprefix(var.hosted_zone, "existing:")
  api_backend = var.api_origin == "backend"
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
      error_message = "La hosted zone indicata è privata: CloudFront e la validazione ACM richiedono una zona pubblica."
    }

    postcondition {
      condition     = var.domain_name == trimsuffix(self.name, ".") || endswith(var.domain_name, ".${trimsuffix(self.name, ".")}")
      error_message = "domain_name non appartiene alla hosted zone: usa il nome della zona o un suo sottodominio (o un'altra zona in hosted_zone)."
    }
  }
}

# Solo con api_origin = "backend": dominio e stage dell'API Gateway dallo stack backend dello stesso ambiente.
data "terraform_remote_state" "backend" {
  count = local.api_backend ? 1 : 0

  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "${var.project}/${var.environment}/backend.tfstate"
    region = var.region
  }
}

module "spa" {
  source = "../../../modules/spa"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  project         = var.project
  environment     = var.environment
  domain_name     = var.domain_name
  zone_id         = data.aws_route53_zone.this.zone_id
  waf_enabled     = var.waf_enabled
  api_domain_name = local.api_backend ? data.terraform_remote_state.backend[0].outputs.api_domain_name : ""
  api_origin_path = local.api_backend ? data.terraform_remote_state.backend[0].outputs.api_origin_path : ""
}
