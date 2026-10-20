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
  description = "Segreti da creare (solo i contenitori, mai i valori): nome => descrizione, ARN dei ruoli IAM dell'account che possono leggerlo (readers) e, per la rotazione automatica, ARN della Lambda di rotazione."

  validation {
    condition     = alltrue([for name, s in var.secrets : can(regex("^[a-z0-9][a-z0-9-]*$", name))])
    error_message = "I nomi dei segreti usano solo minuscole, cifre e trattini."
  }

  validation {
    condition     = alltrue([for name, s in var.secrets : alltrue([for r in s.readers : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$", r))])])
    error_message = "Ogni reader è l'ARN di un ruolo IAM (arn:aws:iam::<account>:role/<nome>)."
  }

  validation {
    condition     = alltrue([for name, s in var.secrets : s.rotation_lambda_arn == null || can(regex("^arn:aws[a-z-]*:lambda:[a-z0-9-]+:[0-9]{12}:function:.+$", s.rotation_lambda_arn))])
    error_message = "rotation_lambda_arn è l'ARN di una funzione Lambda."
  }
}

variable "recovery_window_days" {
  type        = number
  description = "Giorni di recupero di un segreto cancellato (7-30; 0, cancellazione immediata, non è ammesso)."

  validation {
    condition     = var.recovery_window_days >= 7 && var.recovery_window_days <= 30
    error_message = "recovery_window_days deve essere tra 7 e 30."
  }

  validation {
    condition     = var.environment != "prod" || var.recovery_window_days >= 30
    error_message = "In prod la recovery window è di 30 giorni."
  }
}

variable "replica_region" {
  type        = string
  description = "Regione di replica dei segreti (vuoto = nessuna replica); in quella regione si usa la chiave gestita aws/secretsmanager."
  default     = ""

  validation {
    condition     = var.replica_region == "" || can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", var.replica_region))
    error_message = "replica_region deve essere vuoto o il nome di una regione AWS."
  }
}

variable "rotation_days" {
  type        = number
  description = "Giorni tra due rotazioni automatiche, per i segreti con rotation_lambda_arn."
  default     = 30

  validation {
    condition     = var.rotation_days >= 1 && var.rotation_days <= 365
    error_message = "rotation_days deve essere tra 1 e 365."
  }

  validation {
    condition     = var.environment != "prod" || var.rotation_days <= 30
    error_message = "In prod la rotazione avviene almeno ogni 30 giorni."
  }
}
