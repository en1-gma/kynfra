provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
      Owner       = var.owner
      CostCenter  = var.cost_center
      ManagedBy   = "kynfra"
    }
  }
}

# Regione di replica dei segreti e della chiave KMS; senza replica_region resta la regione dello stack (nessuna risorsa).
provider "aws" {
  alias               = "replica"
  region              = var.replica_region != "" ? var.replica_region : var.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
      Owner       = var.owner
      CostCenter  = var.cost_center
      ManagedBy   = "kynfra"
    }
  }
}
