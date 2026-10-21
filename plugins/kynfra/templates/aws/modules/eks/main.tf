data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  name         = "${var.project}-${var.environment}"
  cluster_name = local.name
  account_id   = data.aws_caller_identity.current.account_id
  partition    = data.aws_partition.current.partition
  region       = data.aws_region.current.region
  account_root = "arn:${local.partition}:iam::${local.account_id}:root"
  dns_suffix   = data.aws_partition.current.dns_suffix
  cluster_arn  = "arn:${local.partition}:eks:${local.region}:${local.account_id}:cluster/${local.cluster_name}"

  # endpoint pubblico solo con CIDR espliciti (validati: mai 0.0.0.0/0); altrimenti solo l'endpoint privato
  public_endpoint = length(var.public_endpoint_cidrs) > 0

  log_group_name = "/aws/eks/${local.cluster_name}/cluster"
  log_group_arn  = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:${local.log_group_name}"

  # policy gestite dei nodi (node group e Karpenter): kubelet e Pod Identity Agent, VPC CNI, pull da ECR
  node_policies = toset(["AmazonEKSWorkerNodePolicy", "AmazonEKS_CNI_Policy", "AmazonEC2ContainerRegistryPullOnly"])

  # add-on gestiti: rete e Pod Identity Agent prima dei nodi (bootstrap_self_managed_addons = false), CoreDNS e
  # EBS CSI dopo, perché i loro pod hanno bisogno di nodi pronti
  addons_before_nodes = toset(["vpc-cni", "kube-proxy", "eks-pod-identity-agent"])
  addons              = toset(["vpc-cni", "kube-proxy", "eks-pod-identity-agent", "coredns", "aws-ebs-csi-driver"])

  # ruoli dei pod con EKS Pod Identity: namespace e service account dei chart di kubernetes-addons e dell'add-on EBS CSI
  pod_roles = {
    lb-controller = { namespace = "kube-system", service_account = "aws-load-balancer-controller" }
    karpenter     = { namespace = "kube-system", service_account = "karpenter" }
    keda          = { namespace = "keda", service_account = "keda-operator" }
    ebs-csi       = { namespace = "kube-system", service_account = "ebs-csi-controller-sa" }
  }

  # eventi EC2 e AWS Health che Karpenter legge dalla coda di interruzione
  karpenter_events = {
    health    = { source = "aws.health", detail_type = "AWS Health Event" }
    spot      = { source = "aws.ec2", detail_type = "EC2 Spot Instance Interruption Warning" }
    rebalance = { source = "aws.ec2", detail_type = "EC2 Instance Rebalance Recommendation" }
    state     = { source = "aws.ec2", detail_type = "EC2 Instance State-change Notification" }
    capacity  = { source = "aws.ec2", detail_type = "EC2 Capacity Reservation Instance Interruption Warning" }
  }

  ec2_arn = "arn:${local.partition}:ec2:${local.region}"
}

# ---------------------------------------------------------------- chiavi KMS

# Secret di Kubernetes (cifratura a envelope): il ruolo del cluster usa la chiave con la sua policy IAM.
resource "aws_kms_key" "secrets" {
  description             = "Cifratura dei Secret del cluster EKS ${local.cluster_name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = local.account_root }
        Action    = "kms:*"
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${local.name}-eks-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# Log del control plane: CloudWatch Logs usa la chiave solo per il log group del cluster.
resource "aws_kms_key" "logs" {
  description             = "Cifratura dei log del control plane EKS ${local.cluster_name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = local.account_root }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudWatchLogsEncryption"
        Effect    = "Allow"
        Principal = { Service = "logs.${local.region}.amazonaws.com" }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = local.log_group_arn
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${local.name}-eks-logs"
  target_key_id = aws_kms_key.logs.key_id
}

# Dischi dei nodi (node group, Karpenter) e volumi dell'EBS CSI: come la chiave aws/ebs, la usa ogni principal
# dell'account solo tramite EC2 (anche i ruoli collegati ai servizi di Auto Scaling e dei node group, che non si
# possono nominare prima che esistano).
resource "aws_kms_key" "ebs" {
  description             = "Cifratura dei volumi EBS dei nodi del cluster EKS ${local.cluster_name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = local.account_root }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "EbsThroughEc2InThisAccount"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = local.account_id
            "kms:ViaService"    = "ec2.${local.region}.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/${local.name}-eks-ebs"
  target_key_id = aws_kms_key.ebs.key_id
}

# ---------------------------------------------------------------- log del control plane

# Creato prima del cluster, altrimenti EKS lo crea senza retention né cifratura.
resource "aws_cloudwatch_log_group" "cluster" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn
}

# ---------------------------------------------------------------- cluster

resource "aws_iam_role" "cluster" {
  name = "${local.name}-eks-cluster"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "eks.amazonaws.com" }
        Action    = ["sts:AssumeRole", "sts:TagSession"]
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy" "cluster_kms" {
  name = "${local.name}-eks-secrets-kms"
  role = aws_iam_role.cluster.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SecretsEnvelopeEncryption"
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:ListGrants", "kms:DescribeKey"]
        Resource = aws_kms_key.secrets.arn
      }
    ]
  })
}

resource "aws_eks_cluster" "this" {
  name                          = local.cluster_name
  role_arn                      = aws_iam_role.cluster.arn
  version                       = var.kubernetes_version
  bootstrap_self_managed_addons = false
  deletion_protection           = var.deletion_protection

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = local.public_endpoint
    public_access_cidrs     = local.public_endpoint ? var.public_endpoint_cidrs : null
  }

  encryption_config {
    resources = ["secrets"]

    provider {
      key_arn = aws_kms_key.secrets.arn
    }
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  # STANDARD: alla fine dello standard support EKS aggiorna il control plane invece di passare all'extended
  # support (a pagamento); EXTENDED si sceglie consapevolmente con la variabile.
  upgrade_policy {
    support_type = var.support_type
  }

  depends_on = [
    aws_cloudwatch_log_group.cluster,
    aws_iam_role_policy_attachment.cluster,
    aws_iam_role_policy.cluster_kms,
  ]
}

# ---------------------------------------------------------------- accesso al cluster (access entries, authentication_mode = "API")

resource "aws_eks_access_entry" "admins" {
  for_each = toset(var.admin_principals)

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.key
  type          = "STANDARD"

  lifecycle {
    precondition {
      condition     = split(":", each.key)[4] == local.account_id
      error_message = "Ogni principal di admin_principals deve essere di questo account (${local.account_id})."
    }
  }
}

resource "aws_eks_access_policy_association" "admins" {
  for_each = aws_eks_access_entry.admins

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value.principal_arn
  policy_arn    = "arn:${local.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }
}

# ---------------------------------------------------------------- nodi di sistema (node group gestiti)

resource "aws_iam_role" "node" {
  name = "${local.name}-eks-node"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.${local.dns_suffix}" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "node" {
  for_each = local.node_policies

  role       = aws_iam_role.node.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/${each.key}"
}

# Security group dei nodi in aggiunta a quello del cluster (creato da EKS, traffico tra control plane e nodi): qui
# si ammettono le porte dei pod dal security group del load balancer (stack elb). Nessuna regola di default.
resource "aws_security_group" "node" {
  name        = "${local.name}-eks-node"
  description = "Nodi del cluster ${local.cluster_name}: ingress dei workload (es. dal load balancer)"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${local.name}-eks-node"
  }
}

resource "aws_launch_template" "nodes" {
  for_each = var.node_groups

  name_prefix            = "${local.name}-${each.key}-"
  update_default_version = true
  vpc_security_group_ids = [aws_eks_cluster.this.vpc_config[0].cluster_security_group_id, aws_security_group.node.id]

  # IMDSv2 obbligatorio; hop limit 1: i pod (fuori dalla rete dell'host) non raggiungono le credenziali del nodo
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = each.value.disk_size
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = aws_kms_key.ebs.arn
      delete_on_termination = true
    }
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "${local.name}-${each.key}"
    }
  }

  tag_specifications {
    resource_type = "volume"

    tags = {
      Name = "${local.name}-${each.key}"
    }
  }
}

resource "aws_eks_node_group" "this" {
  for_each = var.node_groups

  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${local.name}-${each.key}"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.subnet_ids
  ami_type        = each.value.ami_type
  capacity_type   = "ON_DEMAND"
  instance_types  = each.value.instance_types

  scaling_config {
    min_size     = each.value.min_size
    max_size     = each.value.max_size
    desired_size = each.value.desired_size
  }

  update_config {
    max_unavailable = 1
  }

  launch_template {
    id      = aws_launch_template.nodes[each.key].id
    version = aws_launch_template.nodes[each.key].latest_version
  }

  labels = {
    "node-group" = each.key
  }

  lifecycle {
    # desired_size cambia con gli scale-in/out: Terraform fissa solo min e max
    ignore_changes = [scaling_config[0].desired_size]
  }

  depends_on = [
    aws_iam_role_policy_attachment.node,
    aws_eks_addon.before_nodes,
  ]
}

# ---------------------------------------------------------------- add-on gestiti

# Versione più recente compatibile con la versione del cluster, salvo quelle fissate in addon_versions.
data "aws_eks_addon_version" "this" {
  for_each = local.addons

  addon_name         = each.key
  kubernetes_version = aws_eks_cluster.this.version
  most_recent        = true
}

resource "aws_eks_addon" "before_nodes" {
  for_each = local.addons_before_nodes

  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = each.key
  addon_version               = lookup(var.addon_versions, each.key, data.aws_eks_addon_version.this[each.key].version)
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
}

resource "aws_eks_addon" "coredns" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "coredns"
  addon_version               = lookup(var.addon_versions, "coredns", data.aws_eks_addon_version.this["coredns"].version)
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  depends_on = [aws_eks_node_group.this]
}

resource "aws_eks_addon" "ebs_csi" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "aws-ebs-csi-driver"
  addon_version               = lookup(var.addon_versions, "aws-ebs-csi-driver", data.aws_eks_addon_version.this["aws-ebs-csi-driver"].version)
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  pod_identity_association {
    role_arn        = aws_iam_role.pod["ebs-csi"].arn
    service_account = "ebs-csi-controller-sa"
  }

  depends_on = [aws_eks_node_group.this, aws_iam_role_policy_attachment.ebs_csi]
}

# ---------------------------------------------------------------- ruoli dei pod (EKS Pod Identity)

# Trust del servizio Pod Identity limitata a cluster (ARN, quindi anche all'account), namespace e service account
# con i session tag che Pod Identity aggiunge: non disattivare i session tag nelle associazioni.
resource "aws_iam_role" "pod" {
  for_each = local.pod_roles

  name = "${local.name}-eks-${each.key}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEksAuthToAssumeRoleForPodIdentity"
        Effect    = "Allow"
        Principal = { Service = "pods.eks.amazonaws.com" }
        Action    = ["sts:AssumeRole", "sts:TagSession"]
        Condition = {
          StringEquals = {
            "aws:RequestTag/eks-cluster-arn"            = local.cluster_arn
            "aws:RequestTag/kubernetes-namespace"       = each.value.namespace
            "aws:RequestTag/kubernetes-service-account" = each.value.service_account
          }
        }
      }
    ]
  })
}

# L'associazione dell'EBS CSI la crea l'add-on (pod_identity_association): qui le altre.
resource "aws_eks_pod_identity_association" "this" {
  for_each = { for k, v in local.pod_roles : k => v if k != "ebs-csi" }

  cluster_name    = aws_eks_cluster.this.name
  namespace       = each.value.namespace
  service_account = each.value.service_account
  role_arn        = aws_iam_role.pod[each.key].arn
}

resource "aws_iam_role_policy_attachment" "ebs_csi" {
  role       = aws_iam_role.pod["ebs-csi"].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEBSCSIDriverPolicyV2"
}

# KEDA: lettura degli attributi (lunghezza) delle code SQS del progetto per lo scaler aws-sqs-queue.
resource "aws_iam_role_policy" "keda" {
  name = "${local.name}-eks-keda"
  role = aws_iam_role.pod["keda"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadProjectQueueAttributes"
        Effect   = "Allow"
        Action   = ["sqs:GetQueueAttributes"]
        Resource = "arn:${local.partition}:sqs:${local.region}:${local.account_id}:${local.name}-*"
      }
    ]
  })
}

# ---------------------------------------------------------------- Karpenter

# Ruolo dei nodi creati da Karpenter (EC2NodeClass.spec.role): le stesse policy dei nodi gestiti.
resource "aws_iam_role" "karpenter_node" {
  name = "${local.name}-karpenter-node"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.${local.dns_suffix}" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "karpenter_node" {
  for_each = local.node_policies

  role       = aws_iam_role.karpenter_node.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/${each.key}"
}

# I nodi di Karpenter entrano nel cluster con un'access entry EC2_LINUX (i node group gestiti hanno la propria).
resource "aws_eks_access_entry" "karpenter_node" {
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = aws_iam_role.karpenter_node.arn
  type          = "EC2_LINUX"
}

# Coda degli eventi di interruzione (spot, rebalance, manutenzioni): messaggi effimeri, SSE gestita da SQS.
resource "aws_sqs_queue" "karpenter" {
  name                      = local.cluster_name
  message_retention_seconds = 300
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue_policy" "karpenter" {
  queue_url = aws_sqs_queue.karpenter.id

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "EC2InterruptionPolicy"
    Statement = [
      {
        Sid       = "EventBridgeWrite"
        Effect    = "Allow"
        Principal = { Service = ["events.amazonaws.com", "sqs.amazonaws.com"] }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.karpenter.arn
      },
      {
        Sid       = "DenyHTTP"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.karpenter.arn
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_event_rule" "karpenter" {
  for_each = local.karpenter_events

  name        = "${local.name}-karpenter-${each.key}"
  description = "Karpenter ${local.cluster_name}: ${each.value.detail_type}"

  event_pattern = jsonencode({
    source      = [each.value.source]
    detail-type = [each.value.detail_type]
  })
}

resource "aws_cloudwatch_event_target" "karpenter" {
  for_each = local.karpenter_events

  rule      = aws_cloudwatch_event_rule.karpenter[each.key].name
  target_id = "KarpenterInterruptionQueueTarget"
  arn       = aws_sqs_queue.karpenter.arn
}

# Controller di Karpenter: policy ufficiale (cloudformation.yaml di karpenter.sh per la v1.15), limitata dai tag del
# cluster, al ruolo dei nodi (PassRole), alla coda di interruzione e alla regione.
resource "aws_iam_role_policy" "karpenter" {
  name = "${local.name}-eks-karpenter"
  role = aws_iam_role.pod["karpenter"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowScopedEC2InstanceAccessActions"
        Effect = "Allow"
        Resource = [
          "${local.ec2_arn}::image/*",
          "${local.ec2_arn}::snapshot/*",
          "${local.ec2_arn}:*:security-group/*",
          "${local.ec2_arn}:*:subnet/*",
          "${local.ec2_arn}:*:capacity-reservation/*",
          "${local.ec2_arn}:*:placement-group/*"
        ]
        Action = ["ec2:RunInstances", "ec2:CreateFleet"]
      },
      {
        Sid      = "AllowScopedEC2LaunchTemplateAccessActions"
        Effect   = "Allow"
        Resource = "${local.ec2_arn}:*:launch-template/*"
        Action   = ["ec2:RunInstances", "ec2:CreateFleet"]
        Condition = {
          StringEquals = { "aws:ResourceTag/kubernetes.io/cluster/${local.cluster_name}" = "owned" }
          StringLike   = { "aws:ResourceTag/karpenter.sh/nodepool" = "*" }
        }
      },
      {
        Sid    = "AllowScopedEC2InstanceActionsWithTags"
        Effect = "Allow"
        Resource = [
          "${local.ec2_arn}:*:fleet/*",
          "${local.ec2_arn}:*:instance/*",
          "${local.ec2_arn}:*:volume/*",
          "${local.ec2_arn}:*:network-interface/*",
          "${local.ec2_arn}:*:launch-template/*",
          "${local.ec2_arn}:*:spot-instances-request/*"
        ]
        Action = ["ec2:RunInstances", "ec2:CreateFleet", "ec2:CreateLaunchTemplate"]
        Condition = {
          StringEquals = {
            "aws:RequestTag/kubernetes.io/cluster/${local.cluster_name}" = "owned"
            "aws:RequestTag/eks:eks-cluster-name"                        = local.cluster_name
          }
          StringLike = { "aws:RequestTag/karpenter.sh/nodepool" = "*" }
        }
      },
      {
        Sid    = "AllowScopedResourceCreationTagging"
        Effect = "Allow"
        Resource = [
          "${local.ec2_arn}:*:fleet/*",
          "${local.ec2_arn}:*:instance/*",
          "${local.ec2_arn}:*:volume/*",
          "${local.ec2_arn}:*:network-interface/*",
          "${local.ec2_arn}:*:launch-template/*",
          "${local.ec2_arn}:*:spot-instances-request/*"
        ]
        Action = "ec2:CreateTags"
        Condition = {
          StringEquals = {
            "aws:RequestTag/kubernetes.io/cluster/${local.cluster_name}" = "owned"
            "aws:RequestTag/eks:eks-cluster-name"                        = local.cluster_name
            "ec2:CreateAction"                                           = ["RunInstances", "CreateFleet", "CreateLaunchTemplate"]
          }
          StringLike = { "aws:RequestTag/karpenter.sh/nodepool" = "*" }
        }
      },
      {
        Sid      = "AllowScopedResourceTagging"
        Effect   = "Allow"
        Resource = "${local.ec2_arn}:*:instance/*"
        Action   = "ec2:CreateTags"
        Condition = {
          StringEquals                = { "aws:ResourceTag/kubernetes.io/cluster/${local.cluster_name}" = "owned" }
          StringLike                  = { "aws:ResourceTag/karpenter.sh/nodepool" = "*" }
          StringEqualsIfExists        = { "aws:RequestTag/eks:eks-cluster-name" = local.cluster_name }
          "ForAllValues:StringEquals" = { "aws:TagKeys" = ["eks:eks-cluster-name", "karpenter.sh/nodeclaim", "Name"] }
        }
      },
      {
        Sid      = "AllowScopedDeletion"
        Effect   = "Allow"
        Resource = ["${local.ec2_arn}:*:instance/*", "${local.ec2_arn}:*:launch-template/*"]
        Action   = ["ec2:TerminateInstances", "ec2:RebootInstances", "ec2:DeleteLaunchTemplate"]
        Condition = {
          StringEquals = { "aws:ResourceTag/kubernetes.io/cluster/${local.cluster_name}" = "owned" }
          StringLike   = { "aws:ResourceTag/karpenter.sh/nodepool" = "*" }
        }
      },
      {
        Sid      = "AllowPassingInstanceRole"
        Effect   = "Allow"
        Resource = aws_iam_role.karpenter_node.arn
        Action   = "iam:PassRole"
        Condition = {
          StringEquals = { "iam:PassedToService" = ["ec2.amazonaws.com", "ec2.amazonaws.com.cn"] }
        }
      },
      {
        Sid      = "AllowScopedInstanceProfileCreationActions"
        Effect   = "Allow"
        Resource = "arn:${local.partition}:iam::${local.account_id}:instance-profile/*"
        Action   = ["iam:CreateInstanceProfile"]
        Condition = {
          StringEquals = {
            "aws:RequestTag/kubernetes.io/cluster/${local.cluster_name}" = "owned"
            "aws:RequestTag/eks:eks-cluster-name"                        = local.cluster_name
            "aws:RequestTag/topology.kubernetes.io/region"               = local.region
          }
          StringLike = { "aws:RequestTag/karpenter.k8s.aws/ec2nodeclass" = "*" }
        }
      },
      {
        Sid      = "AllowScopedInstanceProfileTagActions"
        Effect   = "Allow"
        Resource = "arn:${local.partition}:iam::${local.account_id}:instance-profile/*"
        Action   = ["iam:TagInstanceProfile"]
        Condition = {
          StringEquals = {
            "aws:ResourceTag/kubernetes.io/cluster/${local.cluster_name}" = "owned"
            "aws:ResourceTag/topology.kubernetes.io/region"               = local.region
            "aws:RequestTag/kubernetes.io/cluster/${local.cluster_name}"  = "owned"
            "aws:RequestTag/eks:eks-cluster-name"                         = local.cluster_name
            "aws:RequestTag/topology.kubernetes.io/region"                = local.region
          }
          StringLike = {
            "aws:ResourceTag/karpenter.k8s.aws/ec2nodeclass" = "*"
            "aws:RequestTag/karpenter.k8s.aws/ec2nodeclass"  = "*"
          }
        }
      },
      {
        Sid      = "AllowScopedInstanceProfileActions"
        Effect   = "Allow"
        Resource = "arn:${local.partition}:iam::${local.account_id}:instance-profile/*"
        Action   = ["iam:AddRoleToInstanceProfile", "iam:RemoveRoleFromInstanceProfile", "iam:DeleteInstanceProfile"]
        Condition = {
          StringEquals = {
            "aws:ResourceTag/kubernetes.io/cluster/${local.cluster_name}" = "owned"
            "aws:ResourceTag/topology.kubernetes.io/region"               = local.region
          }
          StringLike = { "aws:ResourceTag/karpenter.k8s.aws/ec2nodeclass" = "*" }
        }
      },
      {
        Sid      = "AllowAPIServerEndpointDiscovery"
        Effect   = "Allow"
        Resource = aws_eks_cluster.this.arn
        Action   = "eks:DescribeCluster"
      },
      {
        Sid      = "AllowInterruptionQueueActions"
        Effect   = "Allow"
        Resource = aws_sqs_queue.karpenter.arn
        Action   = ["sqs:DeleteMessage", "sqs:GetQueueUrl", "sqs:ReceiveMessage"]
      },
      {
        Sid      = "AllowZonalShiftStatusReadOnly"
        Effect   = "Allow"
        Resource = "*"
        Action   = ["arc-zonal-shift:GetManagedResource"]
        Condition = {
          StringEquals = { "arc-zonal-shift:ResourceIdentifier" = aws_eks_cluster.this.arn }
        }
      },
      {
        Sid      = "AllowRegionalReadActions"
        Effect   = "Allow"
        Resource = "*"
        Action = [
          "ec2:DescribeCapacityReservations",
          "ec2:DescribeImages",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeInstanceTypeOfferings",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribePlacementGroups",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSpotPriceHistory",
          "ec2:DescribeSubnets"
        ]
        Condition = {
          StringEquals = { "aws:RequestedRegion" = local.region }
        }
      },
      {
        Sid      = "AllowSSMReadActions"
        Effect   = "Allow"
        Resource = "arn:${local.partition}:ssm:${local.region}::parameter/aws/service/*"
        Action   = "ssm:GetParameter"
      },
      {
        Sid      = "AllowPricingReadActions"
        Effect   = "Allow"
        Resource = "*"
        Action   = "pricing:GetProducts"
      },
      {
        Sid      = "AllowUnscopedInstanceProfileListAction"
        Effect   = "Allow"
        Resource = "*"
        Action   = "iam:ListInstanceProfiles"
      },
      {
        Sid      = "AllowInstanceProfileReadActions"
        Effect   = "Allow"
        Resource = "arn:${local.partition}:iam::${local.account_id}:instance-profile/*"
        Action   = "iam:GetInstanceProfile"
      }
    ]
  })
}
