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
  zone_id         = local.zone_id
  waf_enabled     = var.waf_enabled
  api_domain_name = local.api_backend ? data.terraform_remote_state.backend[0].outputs.api_domain_name : ""
  api_origin_path = local.api_backend ? data.terraform_remote_state.backend[0].outputs.api_origin_path : ""
}
