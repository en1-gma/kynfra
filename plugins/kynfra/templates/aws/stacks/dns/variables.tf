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

variable "domain_name" {
  type        = string
  description = "Dominio della SPA del comando che ha generato questo stack: deve stare nella zona; se zone_name è vuoto diventa anche il nome della zona."
}

variable "zone_name" {
  type        = string
  description = "Nome della hosted zone pubblica da creare, di solito il dominio radice (es. example.com); vuoto = domain_name. I domini delle SPA di tutti gli ambienti devono essere questo nome o suoi sottodomini."
  default     = ""

  validation {
    condition     = var.zone_name == "" || var.domain_name == var.zone_name || endswith(var.domain_name, ".${var.zone_name}")
    error_message = "domain_name deve essere zone_name o un suo sottodominio."
  }
}
