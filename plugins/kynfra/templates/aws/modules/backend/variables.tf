variable "project" {
  type        = string
  description = "Nome del progetto (kebab-case): prefisso dei nomi delle risorse."

  validation {
    # il nome più lungo con limite stretto è quello dei target group dell'NLB, <project>-<env>-<hash 8>: 32 caratteri
    condition     = length("${var.project}-${var.environment}") <= 23
    error_message = "project e environment sono troppo lunghi: <project>-<env> supera i 23 caratteri (i target group dell'NLB, <project>-<env>-<hash>, ne ammettono al massimo 32)."
  }
}

variable "environment" {
  type        = string
  description = "Nome dell'ambiente (dev, staging, prod, …)."
}

variable "openapi_file" {
  type        = string
  description = "Percorso dello schema OpenAPI di kybes (schemas/openapi.yaml), letto con yamldecode(file(...)): unica fonte delle operazioni."
}

variable "handlers" {
  type = map(object({
    kind    = string
    runtime = optional(string)
    handler = optional(string)
  }))
  description = "Handler del progetto kybes da handlers.auto.tfvars: \"<contesto>/functions/<nome>\" (Lambda) o \"<contesto>/ms/<nome>\" (microservizio su EKS)."

  validation {
    condition     = alltrue([for k, h in var.handlers : contains(["function", "ms"], h.kind)])
    error_message = "kind di ogni handler deve essere function oppure ms."
  }

  validation {
    condition     = alltrue([for k, h in var.handlers : h.kind != "function" || (try(length(h.runtime), 0) > 0 && try(length(h.handler), 0) > 0)])
    error_message = "Ogni function ha bisogno di runtime e handler: kynfra li deduce da package.json (engines.node, main) o pyproject.toml (requires-python, handler.py/app.py); completa il manifest della function e rigenera."
  }

  validation {
    condition     = alltrue([for k, h in var.handlers : can(regex("^[a-z0-9][a-z0-9-]*/(functions|ms)/[a-z0-9][a-z0-9-]*$", k))])
    error_message = "Le chiavi di handlers sono \"<contesto>/functions/<nome>\" o \"<contesto>/ms/<nome>\" in kebab-case."
  }
}

variable "routes" {
  type        = map(string)
  description = "Mappatura generata \"METODO percorso\" => chiave di handlers (handlers.auto.tfvars). Un'operazione assente ricade sul suo x-kybes-handler."
}

variable "public_routes" {
  type        = list(string)
  description = "Operazioni pubbliche approvate (\"METODO percorso\"): solo quelle con security: [] nello schema E in public_routes della config di kynfra restano senza authorizer."
  default     = []
}

variable "jobs" {
  type = map(object({
    trigger  = string
    schedule = optional(string)
  }))
  description = "Job del progetto kybes da jobs.auto.tfvars: trigger sqs (coda) o schedule (EventBridge Scheduler che scrive nella coda)."
  default     = {}

  validation {
    condition     = alltrue([for k, j in var.jobs : j.trigger == "sqs" || (j.trigger == "schedule" && can(regex("^(cron|rate)\\(.+\\)$", j.schedule)))])
    error_message = "trigger deve essere sqs oppure schedule con schedule = \"cron(...)\" o \"rate(...)\"."
  }

  validation {
    condition     = alltrue([for k, j in var.jobs : can(regex("^[a-z0-9][a-z0-9-]*$", k))])
    error_message = "I nomi dei job sono in kebab-case."
  }
}

variable "vpc_id" {
  type        = string
  description = "ID della VPC (stack network)."
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Subnet private (stack network): Lambda con accesso al DB, RDS Proxy e NLB interno dei microservizi."

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "Servono almeno due subnet private in zone di disponibilità diverse."
  }
}

variable "secret_arns" {
  type        = map(string)
  description = "ARN dei segreti dello stack secrets, per nome (output secret_arns)."
  default     = {}
}

variable "secrets_kms_key_arn" {
  type        = string
  description = "Chiave KMS dei segreti (output kms_key_arn dello stack secrets)."
  default     = ""
}

variable "context_secrets" {
  type        = map(list(string))
  description = "Segreti leggibili per contesto kybes (functions e microservizi del contesto) o per nome di job: {\"ordini\" = [\"db\"]}. I nomi sono quelli dello stack secrets."
  default     = {}

  validation {
    condition     = alltrue(flatten([for k, names in var.context_secrets : [for n in names : contains(keys(var.secret_arns), n)]]))
    error_message = "context_secrets cita un segreto che non esiste nello stack secrets (output secret_arns): crealo prima nello stack secrets."
  }
}

variable "authorizer" {
  type        = string
  description = "Authorizer delle operazioni non pubbliche: lambda (TOKEN, Lambda che valida il JWT OIDC) oppure cognito (COGNITO_USER_POOLS). API Gateway REST non ha un authorizer JWT nativo."

  validation {
    condition     = contains(["lambda", "cognito"], var.authorizer)
    error_message = "authorizer deve essere lambda oppure cognito."
  }
}

variable "cognito_user_pool_arn" {
  type        = string
  description = "ARN della user pool Cognito (solo con authorizer = cognito)."
  default     = ""

  validation {
    condition     = var.authorizer != "cognito" || can(regex("^arn:[a-z-]+:cognito-idp:[a-z0-9-]+:[0-9]{12}:userpool/.+$", var.cognito_user_pool_arn))
    error_message = "Con authorizer = cognito serve cognito_user_pool_arn (arn:aws:cognito-idp:<regione>:<account>:userpool/<id>)."
  }
}

variable "oidc_issuer" {
  type        = string
  description = "Issuer OIDC dei token (claim iss), passato alla Lambda authorizer."
  default     = ""

  validation {
    condition     = var.authorizer != "lambda" || can(regex("^https://[^\\s]+$", var.oidc_issuer))
    error_message = "Con authorizer = lambda serve oidc_issuer, un URL https (es. https://login.example.com)."
  }
}

variable "oidc_audience" {
  type        = string
  description = "Audience attesa nei token (claim aud), passata alla Lambda authorizer."
  default     = ""

  validation {
    condition     = var.authorizer != "lambda" || length(var.oidc_audience) > 0
    error_message = "Con authorizer = lambda serve oidc_audience (claim aud atteso nei token)."
  }
}

variable "authorizer_runtime" {
  type        = string
  description = "Runtime della Lambda authorizer (codice fuori dal kit, pacchetto authorizer nel bucket degli artefatti)."
  default     = "nodejs22.x"
}

variable "authorizer_handler" {
  type        = string
  description = "Handler della Lambda authorizer."
  default     = "index.handler"
}

variable "artifact_keys" {
  type        = map(string)
  description = "Chiave S3 dello zip di ogni Lambda nel bucket degli artefatti, per handler (e \"authorizer\"); default <contesto>/<nome>.zip e authorizer/authorizer.zip. La compila la CI."
  default     = {}
}

variable "artifact_sha256s" {
  type        = map(string)
  description = "SHA-256 in base64 dello zip di ogni Lambda (source_code_hash), per handler: la CI lo passa a ogni build così Terraform aggiorna il codice."
  default     = {}
}

variable "lambda_memory_size" {
  type        = number
  description = "Memoria delle Lambda in MB."
  default     = 256
}

variable "log_retention_days" {
  type        = number
  description = "Retention dei log (Lambda, access log, execution log, WAF) in giorni: almeno 365 in prod."

  validation {
    condition     = contains([30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days deve essere un valore ammesso da CloudWatch Logs (30, 60, 90, 120, 150, 180, 365, …)."
  }

  validation {
    condition     = var.environment != "prod" || var.log_retention_days >= 365
    error_message = "In prod log_retention_days deve essere almeno 365."
  }
}

variable "throttling_rate_limit" {
  type        = number
  description = "Richieste al secondo ammesse in media sullo stage (throttling)."

  validation {
    condition     = var.throttling_rate_limit > 0
    error_message = "throttling_rate_limit deve essere maggiore di 0."
  }
}

variable "throttling_burst_limit" {
  type        = number
  description = "Picco di richieste ammesso sullo stage (throttling)."

  validation {
    condition     = var.throttling_burst_limit > 0
    error_message = "throttling_burst_limit deve essere maggiore di 0."
  }
}

variable "waf_enabled" {
  type        = bool
  description = "true associa allo stage un web ACL WAF regionale: obbligatorio in prod."

  validation {
    condition     = var.environment != "prod" || var.waf_enabled
    error_message = "In prod il WAF è obbligatorio: waf_enabled = true."
  }
}

variable "waf_rate_limit" {
  type        = number
  description = "Richieste per IP in 5 minuti oltre le quali il WAF blocca."
  default     = 2000
}

variable "deletion_protection" {
  type        = bool
  description = "Deletion protection dell'NLB interno dei microservizi: obbligatoria in prod."

  validation {
    condition     = var.environment != "prod" || var.deletion_protection
    error_message = "In prod deletion_protection deve essere true."
  }
}

variable "eks_cluster_name" {
  type        = string
  description = "Cluster EKS (stack kubernetes) delle associazioni Pod Identity di microservizi e job; vuoto senza ms né job."
  default     = ""
}

variable "eks_node_security_group_id" {
  type        = string
  description = "Security group dei nodi EKS (stack kubernetes): riceve dall'NLB la porta ms_target_port."
  default     = ""
}

variable "kubernetes_namespace" {
  type        = string
  description = "Namespace Kubernetes dei service account di microservizi e job (Pod Identity)."
  default     = "default"
}

variable "ms_target_port" {
  type        = number
  description = "Porta dei pod dei microservizi (target IP dell'NLB)."
  default     = 8080
}

variable "ms_health_path" {
  type        = string
  description = "Percorso HTTP dell'health check dei pod dei microservizi."
  default     = "/healthz"
}

variable "ms_listener_ports" {
  type        = map(number)
  description = "Porta del listener dell'NLB per microservizio; default 10001, 10002, … in ordine alfabetico delle chiavi."
  default     = {}
}

variable "job_visibility_timeout_seconds" {
  type        = number
  description = "Visibility timeout delle code dei job: almeno la durata massima di un'elaborazione."
  default     = 900
}

variable "has_db" {
  type        = bool
  description = "true se il progetto kybes ha schemas/db: RDS Proxy, Lambda nella VPC con accesso IAM al proxy."
}

variable "db_instance_identifier" {
  type        = string
  description = "Istanza RDS esistente (fuori dalla v1) dietro il proxy, con manage_master_user_password = true: il proxy usa il suo segreto gestito da RDS."
  default     = ""

  validation {
    condition     = !var.has_db || length(var.db_instance_identifier) > 0
    error_message = "Il progetto ha schemas/db: indica db_instance_identifier (istanza RDS con il segreto gestito da RDS) nei tfvars dello stack."
  }
}

variable "db_engine_family" {
  type        = string
  description = "Famiglia del motore del proxy: POSTGRESQL, MYSQL o SQLSERVER."
  default     = "POSTGRESQL"

  validation {
    condition     = contains(["POSTGRESQL", "MYSQL", "SQLSERVER"], var.db_engine_family)
    error_message = "db_engine_family deve essere POSTGRESQL, MYSQL o SQLSERVER."
  }
}

variable "db_iam_user" {
  type        = string
  description = "Utente del database con cui le Lambda si collegano al proxy con autenticazione IAM (rds-db:connect)."
  default     = "app"
}
