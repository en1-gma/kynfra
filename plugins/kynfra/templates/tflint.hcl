config {
  call_module_type = "local"
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

plugin "aws" {
  enabled = true
  version = "__RULESET_AWS_VERSION__"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}
