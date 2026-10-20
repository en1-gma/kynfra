terraform {
  required_version = "{{ tf_version_constraint }}"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "{{ aws_provider_constraint }}"
    }
  }

  # Unico root module con backend locale: crea il bucket che ospita lo stato di tutti gli altri.
  backend "local" {
    path = "terraform.tfstate"
  }
}
