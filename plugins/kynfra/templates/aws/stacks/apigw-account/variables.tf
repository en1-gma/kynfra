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

