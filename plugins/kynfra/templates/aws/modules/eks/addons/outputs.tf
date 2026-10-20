output "releases" {
  description = "Release Helm installate (nome => versione del chart)."
  value = {
    (helm_release.aws_load_balancer_controller.name) = helm_release.aws_load_balancer_controller.version
    (helm_release.karpenter_crd.name)                = helm_release.karpenter_crd.version
    (helm_release.karpenter.name)                    = helm_release.karpenter.version
    (helm_release.keda.name)                         = helm_release.keda.version
  }
}
