variable "project" {
  type        = string
  description = "Nome del progetto (kebab-case): prefisso dei nomi delle risorse."
}

variable "environment" {
  type        = string
  description = "Nome dell'ambiente di questo stack."
}

variable "region" {
  type        = string
  description = "Regione AWS dello stack."
}

variable "account_id" {
  type        = string
  description = "ID dell'account AWS (12 cifre): il provider rifiuta ogni altro account."

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id deve avere 12 cifre."
  }
}

variable "owner" {
  type        = string
  description = "Valore del tag Owner."
}

variable "cost_center" {
  type        = string
  description = "Valore del tag CostCenter."
}

variable "state_bucket" {
  type        = string
  description = "Bucket dello stato Terraform (lo stesso del backend): da qui si leggono gli stack network e dns."
}

variable "type" {
  type        = string
  description = "Tipo di load balancer: alb oppure nlb (validato dal modulo)."
}

variable "internal" {
  type        = bool
  description = "true: load balancer interno nelle subnet private; false: pubblico nelle subnet pubbliche."
}

variable "allow_from" {
  type        = string
  description = "Client di un load balancer pubblico: internet oppure cloudfront (validato dal modulo)."
}

variable "domain_name" {
  type        = string
  description = "Dominio del load balancer (es. api.example.com)."
}

variable "hosted_zone" {
  type        = string
  description = "Zona Route53: \"create\" usa la zona creata dallo stack envs/shared/dns, \"existing:<zone_id>\" una zona esistente."

  validation {
    condition     = var.hosted_zone == "create" || can(regex("^existing:Z[A-Z0-9]+$", var.hosted_zone))
    error_message = "hosted_zone deve essere \"create\" oppure \"existing:<zone_id>\" (es. existing:Z0123456789ABCDEFGHIJ)."
  }
}

variable "target_port" {
  type        = number
  description = "Porta dei target del gruppo di default."
}

variable "health_path" {
  type        = string
  description = "Percorso HTTP dell'health check dei target."
}

variable "deletion_protection" {
  type        = bool
  description = "true impedisce la cancellazione del load balancer: obbligatoria in prod."
}

variable "waf_enabled" {
  type        = bool
  description = "true associa all'ALB un web ACL WAF regionale: obbligatorio in prod per l'ALB."
}
