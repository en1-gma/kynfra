variable "project" {
  type        = string
  description = "Nome del progetto (kebab-case): prefisso dei nomi delle risorse."
}

variable "environment" {
  type        = string
  description = "Nome dell'ambiente (dev, staging, prod): prefisso dei nomi delle risorse."
}

variable "domain_name" {
  type        = string
  description = "Dominio pubblico della SPA (es. app.example.com): alias della distribuzione, certificato ACM e record A/AAAA."

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.domain_name))
    error_message = "domain_name deve essere un nome DNS in minuscolo senza punto finale (es. app.example.com)."
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

variable "waf_enabled" {
  type        = bool
  description = "true associa alla distribuzione un web ACL WAF (managed rule set e rate limit) con log cifrati: obbligatorio in prod."

  validation {
    condition     = var.environment != "prod" || var.waf_enabled
    error_message = "In prod il WAF è obbligatorio: waf_enabled = true."
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

variable "api_domain_name" {
  type        = string
  description = "Dominio dell'origin API (es. <id>.execute-api.<regione>.amazonaws.com): se non vuoto aggiunge il behavior /api/* verso di esso, senza cache e solo HTTPS."
  default     = ""
}

variable "api_origin_path" {
  type        = string
  description = "Prefisso aggiunto alle richieste verso l'origin API (es. /v1 per lo stage di API Gateway); vuoto se l'API ha un dominio personalizzato."
  default     = ""

  validation {
    condition     = var.api_origin_path == "" || can(regex("^/[A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)*$", var.api_origin_path))
    error_message = "api_origin_path deve essere vuoto o iniziare con / senza / finale (es. /v1)."
  }
}

variable "content_security_policy" {
  type        = string
  description = "Valore dell'header Content-Security-Policy restituito da CloudFront. Il default è rigoroso: aggiungi solo le sorgenti che l'app usa davvero (es. connect-src verso l'API o l'identity provider)."
  default     = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests"
}

variable "price_class" {
  type        = string
  description = "Price class della distribuzione: PriceClass_100 (Europa e Nord America), PriceClass_200 o PriceClass_All."
  default     = "PriceClass_100"

  validation {
    condition     = contains(["PriceClass_100", "PriceClass_200", "PriceClass_All"], var.price_class)
    error_message = "price_class deve essere PriceClass_100, PriceClass_200 o PriceClass_All."
  }
}
