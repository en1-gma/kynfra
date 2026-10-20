variable "project" {
  type        = string
  description = "Nome del progetto (kebab-case): prefisso dei nomi delle risorse."
}

variable "environment" {
  type        = string
  description = "Nome dell'ambiente (dev, staging, prod): prefisso dei nomi delle risorse."
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR della VPC: da /16 a /20, viene suddiviso in subnet pubbliche, private e isolate (da /20 a /24, quattro bit in più del prefisso)."

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0)) && can(regex("/(1[6-9]|20)$", var.vpc_cidr))
    error_message = "vpc_cidr deve essere un CIDR IPv4 valido con prefisso tra /16 e /20."
  }
}

variable "az_count" {
  type        = number
  description = "Numero di zone di disponibilità (2 o 3)."

  validation {
    condition     = contains([2, 3], var.az_count)
    error_message = "az_count deve essere 2 o 3."
  }
}

variable "availability_zones" {
  type        = list(string)
  description = "Nomi delle zone da usare (vuoto = le prime az_count zone disponibili della regione). Fissarli evita che un'indisponibilità o una nuova zona spostino le subnet."
  default     = []

  validation {
    condition     = length(var.availability_zones) == 0 || length(var.availability_zones) == var.az_count
    error_message = "availability_zones deve essere vuoto oppure avere esattamente az_count elementi."
  }
}

variable "nat_per_az" {
  type        = bool
  description = "true crea un NAT gateway per zona (produzione), false ne crea uno solo."
}

variable "flow_log_retention_days" {
  type        = number
  description = "Giorni di conservazione dei flow log su CloudWatch Logs."

  validation {
    condition     = var.environment != "prod" || var.flow_log_retention_days >= 365
    error_message = "In prod i flow log si conservano per almeno 365 giorni."
  }

  validation {
    condition     = contains([30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.flow_log_retention_days)
    error_message = "flow_log_retention_days deve essere un valore di retention ammesso da CloudWatch Logs (diverso da 0)."
  }
}
