variable "cluster_name" {
  type        = string
  description = "Nome del cluster EKS (output cluster_name dello stack kubernetes)."
}

variable "region" {
  type        = string
  description = "Regione del cluster: i pod non raggiungono IMDS (hop limit 1), quindi i controller la ricevono esplicita."
}

variable "vpc_id" {
  type        = string
  description = "ID della VPC del cluster, per l'AWS Load Balancer Controller (senza IMDS non la scopre da solo)."
}

variable "karpenter_queue_name" {
  type        = string
  description = "Coda SQS degli eventi di interruzione (output karpenter_queue_name dello stack kubernetes)."
}

variable "controller_replicas" {
  type        = number
  description = "Repliche dei controller (AWS Load Balancer Controller, Karpenter, operatore KEDA): 2 per l'alta disponibilità."
  default     = 2

  validation {
    condition     = var.controller_replicas >= 1 && floor(var.controller_replicas) == var.controller_replicas
    error_message = "controller_replicas deve essere un intero >= 1."
  }
}
