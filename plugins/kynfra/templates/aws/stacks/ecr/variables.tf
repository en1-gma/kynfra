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

variable "repositories" {
  type        = string
  description = "Nomi dei repository separati da virgola (kebab-case, es. api,worker); in ECR diventano <progetto>/<nome>. Validato dal modulo."
}

variable "pull_principals" {
  type        = string
  description = "ARN di ruoli IAM dell'account autorizzati al pull, separati da virgola; vuoto = nessuna concessione nella policy. Validato dal modulo."
  default     = ""
}

variable "untagged_expiry_days" {
  type        = number
  description = "Giorni dopo i quali scadono le immagini non taggate. Validato dal modulo."
  default     = 7
}

variable "keep_last" {
  type        = number
  description = "Numero di immagini taggate più recenti da conservare per repository. Validato dal modulo."
  default     = 30
}
