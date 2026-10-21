locals {
  # microservizi e job girano su EKS: servono gli stack kubernetes ed ecr dello stesso ambiente
  has_workloads = length([for k, h in var.handlers : k if h.kind == "ms"]) > 0 || length(var.jobs) > 0
  workloads     = concat([for k, h in var.handlers : replace(k, "/ms/", "-") if h.kind == "ms"], keys(var.jobs))
}

# Letture a senso unico (gli altri stack non leggono mai questo stack, salvo spa per api_domain_name).
data "terraform_remote_state" "network" {
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "${var.project}/${var.environment}/network.tfstate"
    region = var.region
  }
}

data "terraform_remote_state" "secrets" {
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "${var.project}/${var.environment}/secrets.tfstate"
    region = var.region
  }
}

data "terraform_remote_state" "kubernetes" {
  count = local.has_workloads ? 1 : 0

  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "${var.project}/${var.environment}/kubernetes.tfstate"
    region = var.region
  }
}

data "terraform_remote_state" "ecr" {
  count = local.has_workloads ? 1 : 0

  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "${var.project}/shared/ecr.tfstate"
    region = var.region
  }
}

# handlers, routes, public_routes e jobs arrivano da handlers.auto.tfvars e jobs.auto.tfvars, rigenerati da
# /kynfra:create-backend-infra-aws a partire dal progetto kybes (non modificarli a mano).
module "backend" {
  source = "../../../modules/backend"

  project      = var.project
  environment  = var.environment
  openapi_file = "${path.root}/${var.kybes_root}/${var.openapi_path}"
  handlers     = var.handlers
  routes       = var.routes
  jobs         = var.jobs

  public_routes      = var.public_routes
  vpc_id             = data.terraform_remote_state.network.outputs.vpc_id
  private_subnet_ids = data.terraform_remote_state.network.outputs.private_subnet_ids

  secret_arns         = data.terraform_remote_state.secrets.outputs.secret_arns
  secrets_kms_key_arn = data.terraform_remote_state.secrets.outputs.kms_key_arn
  context_secrets     = var.context_secrets

  authorizer            = var.authorizer
  cognito_user_pool_arn = var.cognito_user_pool_arn
  oidc_issuer           = var.oidc_issuer
  oidc_audience         = var.oidc_audience

  artifact_keys    = var.artifact_keys
  artifact_sha256s = var.artifact_sha256s

  log_retention_days         = var.log_retention_days
  throttling_rate_limit      = var.throttling_rate_limit
  throttling_burst_limit     = var.throttling_burst_limit
  waf_enabled                = var.waf_enabled
  deletion_protection        = var.deletion_protection
  manage_api_gateway_account = var.manage_api_gateway_account

  eks_cluster_name           = local.has_workloads ? data.terraform_remote_state.kubernetes[0].outputs.cluster_name : ""
  eks_node_security_group_id = local.has_workloads ? data.terraform_remote_state.kubernetes[0].outputs.node_security_group_id : ""
  kubernetes_namespace       = var.kubernetes_namespace

  has_db                 = var.has_db
  db_instance_identifier = var.db_instance_identifier
  db_engine_family       = var.db_engine_family
}
