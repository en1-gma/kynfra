# Componenti di piattaforma installati con Helm, versioni bloccate su templates/versions.json del kit (per
# aggiornarle: generate.py --upgrade). I ruoli IAM arrivano da EKS Pod Identity (associazioni dello stack
# kubernetes sui service account indicati qui): nessuna annotazione IRSA, nessuna credenziale nei values.
# NodePool ed EC2NodeClass di Karpenter non stanno qui: li gestiscono i workload (vedi README del modulo eks).

resource "helm_release" "aws_load_balancer_controller" {
  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  version    = "{{ aws_load_balancer_controller_chart_version }}"
  namespace  = "kube-system"

  values = [yamlencode({
    clusterName  = var.cluster_name
    region       = var.region
    vpcId        = var.vpc_id
    replicaCount = var.controller_replicas
    serviceAccount = {
      create = true
      name   = "aws-load-balancer-controller"
    }
  })]
}

# CRD di Karpenter in un chart dedicato: Helm non aggiorna le CRD della cartella crds/ del chart principale.
resource "helm_release" "karpenter_crd" {
  name       = "karpenter-crd"
  repository = "oci://public.ecr.aws/karpenter"
  chart      = "karpenter-crd"
  version    = "{{ karpenter_chart_version }}"
  namespace  = "kube-system"
}

resource "helm_release" "karpenter" {
  name       = "karpenter"
  repository = "oci://public.ecr.aws/karpenter"
  chart      = "karpenter"
  version    = "{{ karpenter_chart_version }}"
  namespace  = "kube-system"
  skip_crds  = true

  values = [yamlencode({
    replicas = var.controller_replicas
    serviceAccount = {
      create = true
      name   = "karpenter"
    }
    settings = {
      clusterName       = var.cluster_name
      interruptionQueue = var.karpenter_queue_name
    }
    controller = {
      env = [{ name = "AWS_REGION", value = var.region }]
    }
  })]

  # i webhook dell'AWS Load Balancer Controller intercettano i Service: prima lui, pronto
  depends_on = [helm_release.karpenter_crd, helm_release.aws_load_balancer_controller]
}

resource "helm_release" "keda" {
  name             = "keda"
  repository       = "https://kedacore.github.io/charts"
  chart            = "keda"
  version          = "{{ keda_chart_version }}"
  namespace        = "keda"
  create_namespace = true

  values = [yamlencode({
    operator = {
      replicaCount = var.controller_replicas
    }
    serviceAccount = {
      operator = {
        create = true
        name   = "keda-operator"
      }
    }
  })]

  depends_on = [helm_release.aws_load_balancer_controller]
}
