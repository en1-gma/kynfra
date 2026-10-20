module "secrets" {
  source = "../../../modules/secrets"

  project              = var.project
  environment          = var.environment
  secrets              = var.secrets
  recovery_window_days = var.recovery_window_days
  replica_region       = var.replica_region
  rotation_days        = var.rotation_days
}
