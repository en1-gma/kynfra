terraform {
  required_version = "{{ tf_version_constraint }}"

  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "{{ aws_provider_constraint }}"
      configuration_aliases = [aws.us_east_1]
    }
  }
}
