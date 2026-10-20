variable "project" {
  type        = string
  description = "Nome del progetto (kebab-case): prefisso dei nomi delle risorse."

  validation {
    condition     = can(regex("^[a-z0-9]+(-[a-z0-9]+)*$", var.project)) && length(var.project) <= 42
    error_message = "project deve essere kebab-case (minuscole, cifre e trattini) e al massimo di 42 caratteri: il nome del bucket <project>-tfstate-<account_id> non supera 63."
  }
}

variable "region" {
  type        = string
  description = "Regione AWS del bucket dello stato."

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", var.region))
    error_message = "region deve essere una regione AWS (es. eu-south-1)."
  }
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

variable "noncurrent_version_retention_days" {
  type        = number
  description = "Giorni di conservazione delle versioni non correnti dei file di stato."
  default     = 90

  validation {
    condition     = var.noncurrent_version_retention_days >= 30
    error_message = "Conserva le versioni non correnti dello stato per almeno 30 giorni."
  }
}
