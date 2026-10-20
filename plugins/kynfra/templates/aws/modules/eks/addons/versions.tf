terraform {
  required_version = "{{ tf_version_constraint }}"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "{{ helm_provider_constraint }}"
    }
  }
}
