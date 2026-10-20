# Le liste arrivano come stringhe separate da virgola (il generatore passa solo stringhe); le validazioni stanno nel modulo.
module "ecr" {
  source = "../../../modules/ecr"

  project              = var.project
  environment          = var.environment
  repositories         = compact([for r in split(",", var.repositories) : trimspace(r)])
  pull_principals      = compact([for r in split(",", var.pull_principals) : trimspace(r)])
  untagged_expiry_days = var.untagged_expiry_days
  keep_last            = var.keep_last
}
