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
  description = "Bucket dello stato Terraform (lo stesso del backend): da qui si leggono gli stack dns e backend."
}

variable "domain_name" {
  type        = string
  description = "Dominio pubblico della SPA (es. app.example.com)."
}

variable "hosted_zone" {
  type        = string
  description = "Zona Route53: \"create\" usa la zona creata dallo stack envs/shared/dns, \"existing:<zone_id>\" una zona esistente."

  validation {
    condition     = var.hosted_zone == "create" || can(regex("^existing:Z[A-Z0-9]+$", var.hosted_zone))
    error_message = "hosted_zone deve essere \"create\" oppure \"existing:<zone_id>\" (es. existing:Z0123456789ABCDEFGHIJ)."
  }
}

variable "api_origin" {
  type        = string
  description = "\"backend\" aggiunge il behavior /api/* verso l'API Gateway dello stack backend dello stesso ambiente; vuoto = nessuna API."

  validation {
    condition     = contains(["", "backend"], var.api_origin)
    error_message = "api_origin deve essere vuoto oppure \"backend\"."
  }
}

variable "waf_enabled" {
  type        = bool
  description = "true associa alla distribuzione un web ACL WAF: obbligatorio in prod."
}
