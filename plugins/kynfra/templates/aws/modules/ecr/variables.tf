variable "project" {
  type        = string
  description = "Nome del progetto (kebab-case): prefisso dei nomi delle risorse e dei repository."
}

variable "environment" {
  type        = string
  description = "Nome dell'ambiente dello stack (shared per lo stack condiviso): prefisso dei nomi delle risorse."
}

variable "repositories" {
  type        = list(string)
  description = "Nomi dei repository (kebab-case); in ECR diventano <progetto>/<nome>."

  validation {
    condition     = length(var.repositories) > 0 && length(distinct(var.repositories)) == length(var.repositories)
    error_message = "Serve almeno un repository e i nomi non si ripetono."
  }

  validation {
    condition     = alltrue([for r in var.repositories : can(regex("^[a-z0-9]+(-[a-z0-9]+)*$", r)) && length(r) <= 64])
    error_message = "I nomi dei repository sono in kebab-case (minuscole, cifre, trattini singoli), al massimo 64 caratteri."
  }
}

variable "pull_principals" {
  type        = list(string)
  description = "ARN di ruoli IAM di questo account autorizzati al pull nella repository policy (nodi EKS, Lambda, ...); vuoto = nessuna concessione nella policy (restano le policy identity dei ruoli)."
  default     = []

  validation {
    condition     = alltrue([for r in var.pull_principals : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$", r))])
    error_message = "Ogni principal è l'ARN di un ruolo IAM (arn:aws:iam::<account>:role/<nome>)."
  }
}

variable "untagged_expiry_days" {
  type        = number
  description = "Giorni dopo i quali scadono le immagini non taggate."
  default     = 7

  validation {
    condition     = var.untagged_expiry_days >= 1 && var.untagged_expiry_days <= 365
    error_message = "untagged_expiry_days deve essere tra 1 e 365."
  }
}

variable "keep_last" {
  type        = number
  description = "Numero di immagini taggate più recenti da conservare per repository."
  default     = 30

  validation {
    condition     = var.keep_last >= 1 && var.keep_last <= 1000
    error_message = "keep_last deve essere tra 1 e 1000."
  }
}
