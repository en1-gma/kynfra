# Cluster dallo stack kubernetes dello stesso ambiente (lo stack kubernetes non legge mai questo stack).
data "terraform_remote_state" "kubernetes" {
  backend = "s3"
  config = {
    bucket = var.state_bucket
    key    = "${var.project}/${var.environment}/kubernetes.tfstate"
    region = var.region
  }
}

# Endpoint e CA per il provider helm; il token è di breve durata (circa 15 minuti), firmato con le credenziali di chi
# esegue Terraform, che deve avere un'access entry di amministratore (admin_principals dello stack kubernetes).
data "aws_eks_cluster" "this" {
  name = data.terraform_remote_state.kubernetes.outputs.cluster_name
}

data "aws_eks_cluster_auth" "this" {
  name = data.terraform_remote_state.kubernetes.outputs.cluster_name
}

module "addons" {
  source = "../../../modules/eks/addons"

  cluster_name         = data.aws_eks_cluster.this.name
  region               = var.region
  vpc_id               = data.aws_eks_cluster.this.vpc_config[0].vpc_id
  karpenter_queue_name = data.terraform_remote_state.kubernetes.outputs.karpenter_queue_name
}
