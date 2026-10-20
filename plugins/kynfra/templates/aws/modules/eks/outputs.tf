output "cluster_name" {
  description = "Nome del cluster EKS."
  value       = aws_eks_cluster.this.name
}

output "cluster_arn" {
  description = "ARN del cluster EKS."
  value       = aws_eks_cluster.this.arn
}

output "cluster_endpoint" {
  description = "Endpoint dell'API server (privato; pubblico solo con public_endpoint_cidrs)."
  value       = aws_eks_cluster.this.endpoint
}

output "cluster_ca" {
  description = "Certificato della CA del cluster, in base64."
  value       = aws_eks_cluster.this.certificate_authority[0].data
}

output "cluster_security_group_id" {
  description = "Security group creato da EKS per il traffico tra control plane e nodi (anche sui nodi): per raggiungere l'endpoint privato da una VPN o da un bastion ammetti qui la porta 443."
  value       = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
}

output "node_security_group_id" {
  description = "Security group aggiuntivo dei nodi (node group e, nell'EC2NodeClass, Karpenter): ammetti qui la porta dei pod dal security group del load balancer."
  value       = aws_security_group.node.id
}

output "node_subnet_ids" {
  description = "Subnet private dei nodi, da usare in subnetSelectorTerms dell'EC2NodeClass di Karpenter."
  value       = var.subnet_ids
}

output "node_kms_key_arn" {
  description = "ARN della chiave KMS dei volumi EBS dei nodi, da usare in blockDeviceMappings dell'EC2NodeClass e nelle StorageClass dell'EBS CSI."
  value       = aws_kms_key.ebs.arn
}

output "karpenter_queue_name" {
  description = "Coda SQS degli eventi di interruzione (settings.interruptionQueue del chart karpenter)."
  value       = aws_sqs_queue.karpenter.name
}

output "karpenter_node_role_name" {
  description = "Ruolo IAM dei nodi creati da Karpenter (spec.role dell'EC2NodeClass)."
  value       = aws_iam_role.karpenter_node.name
}

output "pod_role_arns" {
  description = "ARN dei ruoli Pod Identity dei componenti di sistema (lb-controller, karpenter, keda, ebs-csi)."
  value       = { for k, r in aws_iam_role.pod : k => r.arn }
}
