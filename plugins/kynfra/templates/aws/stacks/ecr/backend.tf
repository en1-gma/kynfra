terraform {
  backend "s3" {
    bucket       = "{{ state_bucket }}"
    key          = "{{ state_key }}"
    region       = "{{ region }}"
    encrypt      = true
    use_lockfile = true
  }
}
