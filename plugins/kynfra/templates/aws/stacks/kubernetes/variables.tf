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
  description = "Bucket dello stato Terraform (lo stesso del backend): da qui si legge lo stack network."
}

variable "kubernetes_version" {
  type        = string
  description = "Versione minore di Kubernetes del cluster (validata dal modulo)."
}

variable "public_endpoint_cidrs" {
  type        = string
  description = "CIDR dell'endpoint pubblico dell'API server separati da virgola; vuoto = solo endpoint privato (validati dal modulo: mai 0.0.0.0/0)."
}

variable "admin_principals" {
  type        = string
  description = "ARN di ruoli o utenti IAM amministratori del cluster (access entries), separati da virgola."
}

variable "node_instance_types" {
  type        = string
  description = "Tipi di istanza del node group di sistema separati da virgola (es. m6i.large,m5.large)."
}

variable "node_min_size" {
  type        = number
  description = "Nodi minimi del node group di sistema."
}

variable "node_max_size" {
  type        = number
  description = "Nodi massimi del node group di sistema."
}

variable "node_desired_size" {
  type        = number
  description = "Nodi iniziali del node group di sistema (poi gestiti dagli scale-in/out)."
}

variable "log_retention_days" {
  type        = number
  description = "Retention in giorni dei log del control plane (almeno 365 in prod)."
}

variable "deletion_protection" {
  type        = bool
  description = "true impedisce la cancellazione del cluster: obbligatoria in prod."
}
