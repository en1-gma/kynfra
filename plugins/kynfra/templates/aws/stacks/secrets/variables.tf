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

variable "secrets" {
  type = map(object({
    description         = string
    readers             = list(string)
    rotation_lambda_arn = optional(string)
  }))
  description = "Segreti da creare (solo i contenitori, mai i valori): nome => descrizione, ruoli IAM lettori facoltativi (readers) e Lambda di rotazione facoltativa. Le validazioni stanno nel modulo."
}

variable "recovery_window_days" {
  type        = number
  description = "Giorni di recupero di un segreto cancellato (7-30; in prod 30). Validato dal modulo."
}

variable "replica_region" {
  type        = string
  description = "Regione di replica dei segreti (vuoto = nessuna replica); diversa da region."
  default     = ""

  validation {
    condition     = var.replica_region == "" || var.replica_region != var.region
    error_message = "replica_region deve essere diversa dalla regione dello stack."
  }
}

variable "rotation_days" {
  type        = number
  description = "Giorni tra due rotazioni automatiche (in prod al massimo 30). Validato dal modulo."
  default     = 30
}
