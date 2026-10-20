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

variable "vpc_cidr" {
  type        = string
  description = "CIDR della VPC (da /16 a /20)."
}

variable "az_count" {
  type        = number
  description = "Numero di zone di disponibilità (2 o 3)."
}

variable "availability_zones" {
  type        = list(string)
  description = "Nomi delle zone da usare (vuoto = le prime az_count zone disponibili)."
  default     = []
}

variable "nat_per_az" {
  type        = bool
  description = "true crea un NAT gateway per zona (produzione), false ne crea uno solo."
}

variable "flow_log_retention_days" {
  type        = number
  description = "Giorni di conservazione dei flow log su CloudWatch Logs."
}
