variable "project" {
  type        = string
  description = "Nome del progetto (kebab-case): prefisso dei nomi delle risorse."

  validation {
    # il nome più lungo è quello del target group, <project>-<env>-<tipo>-<porta>: limite di 32 caratteri
    condition     = length("${var.project}-${var.environment}") <= 21
    error_message = "project e environment sono troppo lunghi: <project>-<env> supera i 21 caratteri (i nomi di load balancer e target group, <project>-<env>-alb-<porta>, ne ammettono al massimo 32)."
  }
}

variable "environment" {
  type        = string
  description = "Nome dell'ambiente (dev, staging, prod): prefisso dei nomi delle risorse."
}

variable "type" {
  type        = string
  description = "Tipo di load balancer: alb (Application, HTTP/HTTPS, WAF) o nlb (Network, TLS terminato sul load balancer, inoltro TCP)."
  default     = "alb"

  validation {
    condition     = contains(["alb", "nlb"], var.type)
    error_message = "type deve essere alb oppure nlb."
  }
}

variable "internal" {
  type        = bool
  description = "true crea un load balancer interno nelle subnet private, raggiungibile solo dalla VPC; false uno pubblico nelle subnet pubbliche."
  default     = false
}

variable "vpc_id" {
  type        = string
  description = "ID della VPC (output vpc_id dello stack network)."
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnet del load balancer, almeno due in zone diverse: pubbliche se internal = false, private se internal = true."

  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "Servono almeno due subnet in zone di disponibilità diverse."
  }
}

variable "allow_from" {
  type        = string
  description = "Chi raggiunge un load balancer pubblico: internet (443 e 80 dal mondo) o cloudfront (solo 443 dalla prefix list gestita com.amazonaws.global.cloudfront.origin-facing). Con internal = true i client sono la VPC."
  default     = "internet"

  validation {
    condition     = contains(["internet", "cloudfront"], var.allow_from)
    error_message = "allow_from deve essere internet oppure cloudfront."
  }

  validation {
    condition     = !(var.internal && var.allow_from == "cloudfront")
    error_message = "allow_from = cloudfront richiede internal = false: CloudFront raggiunge solo origin pubblici tramite la prefix list (per un ALB interno usa le VPC origin di CloudFront, fuori dal pattern)."
  }
}

variable "domain_name" {
  type        = string
  description = "Dominio del load balancer (es. api.example.com): certificato ACM, regola host dell'ALB e record alias."

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.domain_name))
    error_message = "domain_name deve essere un nome DNS in minuscolo senza punto finale (es. api.example.com)."
  }
}

variable "zone_id" {
  type        = string
  description = "ID della hosted zone Route53 pubblica che contiene domain_name (record di validazione ACM e alias)."

  validation {
    condition     = can(regex("^Z[A-Z0-9]+$", var.zone_id))
    error_message = "zone_id deve essere l'ID di una hosted zone Route53 (es. Z0123456789ABCDEFGHIJ)."
  }
}

variable "ip_address_type" {
  type        = string
  description = "ipv4 oppure dualstack (richiede subnet con IPv6, che il pattern network non crea): con dualstack si aggiungono il record AAAA e gli ingress IPv6."
  default     = "ipv4"

  validation {
    condition     = contains(["ipv4", "dualstack"], var.ip_address_type)
    error_message = "ip_address_type deve essere ipv4 oppure dualstack."
  }
}

variable "target_port" {
  type        = number
  description = "Porta dei target del gruppo di default (traffico e health check)."
  default     = 8080

  validation {
    condition     = var.target_port >= 1 && var.target_port <= 65535 && floor(var.target_port) == var.target_port
    error_message = "target_port deve essere un intero tra 1 e 65535."
  }
}

variable "health_path" {
  type        = string
  description = "Percorso HTTP dell'health check dei target (risposte 200-399 = sano)."
  default     = "/healthz"

  validation {
    condition     = can(regex("^/[A-Za-z0-9._~/-]*$", var.health_path))
    error_message = "health_path deve iniziare con / (es. /healthz)."
  }
}

variable "deletion_protection" {
  type        = bool
  description = "true impedisce la cancellazione del load balancer dall'API (va disattivata prima di un destroy): obbligatoria in prod."

  validation {
    condition     = var.environment != "prod" || var.deletion_protection
    error_message = "In prod la deletion protection è obbligatoria: deletion_protection = true."
  }
}

variable "waf_enabled" {
  type        = bool
  description = "true associa all'ALB un web ACL WAF regionale (managed rule set e rate limit) con log cifrati: obbligatorio in prod per l'ALB; l'NLB non supporta WAF."

  validation {
    condition     = var.environment != "prod" || var.waf_enabled || var.type == "nlb"
    error_message = "In prod il WAF dell'ALB è obbligatorio: waf_enabled = true."
  }

  validation {
    condition     = !(var.waf_enabled && var.type == "nlb")
    error_message = "WAF non disponibile per l'NLB: con type = nlb imposta waf_enabled = false."
  }
}

variable "waf_rate_limit" {
  type        = number
  description = "Richieste per IP in 5 minuti oltre le quali il WAF blocca il client (da 100 a 2000000000)."
  default     = 2000

  validation {
    condition     = var.waf_rate_limit >= 100 && var.waf_rate_limit <= 2000000000
    error_message = "waf_rate_limit deve essere tra 100 e 2000000000."
  }
}

variable "legacy_elb_regions" {
  type        = list(string)
  description = "Regioni aperte prima di ap-southeast-3 (dicembre 2021), dove gli access log dell'ALB si concedono anche all'account ELB della regione (data aws_elb_service_account); nelle altre basta il service principal logdelivery.elasticloadbalancing.amazonaws.com. Elenco chiuso: le regioni nuove non vanno aggiunte."
  default = [
    "af-south-1", "ap-east-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ap-southeast-1",
    "ap-southeast-2", "ca-central-1", "cn-north-1", "cn-northwest-1", "eu-central-1", "eu-north-1", "eu-south-1",
    "eu-west-1", "eu-west-2", "eu-west-3", "me-south-1", "sa-east-1", "us-east-1", "us-east-2", "us-gov-east-1",
    "us-gov-west-1", "us-west-1", "us-west-2",
  ]
}
