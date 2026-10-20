output "cluster_name" {
  description = "Nome del cluster EKS (lo legge lo stack kubernetes-addons)."
  value       = module.eks.cluster_name
}

output "cluster_arn" {
  description = "ARN del cluster EKS."
  value       = module.eks.cluster_arn
}

output "cluster_endpoint" {
  description = "Endpoint dell'API server."
  value       = module.eks.cluster_endpoint
}

output "cluster_ca" {
  description = "Certificato della CA del cluster, in base64."
  value       = module.eks.cluster_ca
}

output "cluster_security_group_id" {
  description = "Security group del cluster (control plane e nodi): per l'endpoint privato da VPN o bastion ammetti qui la 443."
  value       = module.eks.cluster_security_group_id
}

output "node_security_group_id" {
  description = "Security group aggiuntivo dei nodi: ammetti qui la porta dei pod dal security group del load balancer."
  value       = module.eks.node_security_group_id
}

output "node_subnet_ids" {
  description = "Subnet private dei nodi (subnetSelectorTerms dell'EC2NodeClass)."
  value       = module.eks.node_subnet_ids
}

output "node_kms_key_arn" {
  description = "Chiave KMS dei volumi EBS dei nodi (EC2NodeClass e StorageClass)."
  value       = module.eks.node_kms_key_arn
}

output "karpenter_queue_name" {
  description = "Coda SQS degli eventi di interruzione di Karpenter."
  value       = module.eks.karpenter_queue_name
}

output "karpenter_node_role_name" {
  description = "Ruolo IAM dei nodi di Karpenter (spec.role dell'EC2NodeClass)."
  value       = module.eks.karpenter_node_role_name
}

output "pod_role_arns" {
  description = "ARN dei ruoli Pod Identity dei componenti di sistema."
  value       = module.eks.pod_role_arns
}
