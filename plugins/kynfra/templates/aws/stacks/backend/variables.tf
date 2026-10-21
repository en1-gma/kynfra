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
  description = "Bucket dello stato Terraform (lo stesso del backend): da qui si leggono gli stack network, secrets, kubernetes ed ecr."
}

variable "kybes_root" {
  type        = string
  description = "Radice del progetto kybes relativa a questo stack (kybes.root della config di kynfra)."
}

variable "openapi_path" {
  type        = string
  description = "Schema OpenAPI relativo alla radice kybes (es. schemas/openapi.yaml)."
}

variable "has_db" {
  type        = bool
  description = "true se il progetto kybes ha schemas/db (rigenerato dal comando)."
}

variable "handlers" {
  type = map(object({
    kind    = string
    runtime = optional(string)
    handler = optional(string)
  }))
  description = "Handler kybes (handlers.auto.tfvars, generato)."
}

variable "routes" {
  type        = map(string)
  description = "Mappatura \"METODO percorso\" => handler (handlers.auto.tfvars, generato)."
}

variable "public_routes" {
  type        = list(string)
  description = "Operazioni pubbliche approvate in public_routes della config di kynfra (handlers.auto.tfvars, generato)."
  default     = []
}

variable "jobs" {
  type = map(object({
    trigger  = string
    schedule = optional(string)
  }))
  description = "Job kybes (jobs.auto.tfvars, generato)."
  default     = {}
}

variable "authorizer" {
  type        = string
  description = "Authorizer delle operazioni non pubbliche: lambda (JWT OIDC) oppure cognito (validato dal modulo)."
}

variable "cognito_user_pool_arn" {
  type        = string
  description = "ARN della user pool Cognito (solo con authorizer = cognito)."
}

variable "oidc_issuer" {
  type        = string
  description = "Issuer OIDC dei token (authorizer = lambda)."
}

variable "oidc_audience" {
  type        = string
  description = "Audience attesa nei token (authorizer = lambda)."
}

variable "artifact_keys" {
  type        = map(string)
  description = "Chiave S3 dello zip di ogni Lambda, per handler: la passa la CI (-var o file *.auto.tfvars suo); vuota = <contesto>/<nome>.zip."
  default     = {}
}

variable "artifact_sha256s" {
  type        = map(string)
  description = "SHA-256 in base64 dello zip di ogni Lambda, per handler: la passa la CI a ogni build."
  default     = {}
}

variable "log_retention_days" {
  type        = number
  description = "Retention dei log in giorni (almeno 365 in prod)."
}

variable "throttling_rate_limit" {
  type        = number
  description = "Richieste al secondo ammesse in media sullo stage."
}

variable "throttling_burst_limit" {
  type        = number
  description = "Picco di richieste ammesso sullo stage."
}

variable "waf_enabled" {
  type        = bool
  description = "true associa allo stage un web ACL WAF regionale: obbligatorio in prod."
}

variable "deletion_protection" {
  type        = bool
  description = "Deletion protection dell'NLB interno dei microservizi: obbligatoria in prod."
}

variable "kubernetes_namespace" {
  type        = string
  description = "Namespace dei service account di microservizi e job."
}

variable "db_instance_identifier" {
  type        = string
  description = "Istanza RDS esistente dietro RDS Proxy (con schemas/db), con iam_database_authentication_enabled = true e l'utente db_iam_user per l'autenticazione IAM."
}

variable "db_engine_family" {
  type        = string
  description = "Famiglia del motore di RDS Proxy: POSTGRESQL o MYSQL (anche MariaDB)."
}

variable "context_secrets" {
  type        = map(list(string))
  description = "Segreti dello stack secrets leggibili per contesto kybes o per job."
}
