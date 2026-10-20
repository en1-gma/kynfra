output "releases" {
  description = "Release Helm installate (nome => versione del chart)."
  value       = module.addons.releases
}
