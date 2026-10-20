variable "project" {
  type        = string
  description = "Nome del progetto (kebab-case): prefisso dei nomi delle risorse."

  validation {
    # il nome più lungo è quello delle regole EventBridge, <project>-<env>-karpenter-rebalance: limite di 64 caratteri
    condition     = length("${var.project}-${var.environment}") <= 40
    error_message = "project e environment sono troppo lunghi: <project>-<env> supera i 40 caratteri (nomi di ruoli IAM e regole EventBridge ne ammettono al massimo 64)."
  }
}

variable "environment" {
  type        = string
  description = "Nome dell'ambiente (dev, staging, prod): prefisso dei nomi delle risorse."
}

variable "kubernetes_version" {
  type        = string
  description = "Versione minore di Kubernetes del cluster (es. 1.36): deve essere supportata da EKS e dai chart dello stack kubernetes-addons; gli aggiornamenti sono di una versione minore alla volta."

  validation {
    condition     = can(regex("^1\\.[0-9]{2}$", var.kubernetes_version))
    error_message = "kubernetes_version deve avere la forma 1.<minore> (es. 1.36)."
  }
}

variable "vpc_id" {
  type        = string
  description = "ID della VPC (output vpc_id dello stack network)."
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnet private del control plane e dei nodi (output private_subnet_ids dello stack network), almeno due in zone diverse."

  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "Servono almeno due subnet private in zone di disponibilità diverse."
  }
}

variable "public_endpoint_cidrs" {
  type        = list(string)
  description = "CIDR ammessi sull'endpoint pubblico dell'API server; lista vuota = solo endpoint privato (raggiungibile dalla VPC). Mai 0.0.0.0/0 né ::/0."

  validation {
    condition     = alltrue([for c in var.public_endpoint_cidrs : can(cidrhost(c, 0)) && !contains(["0.0.0.0/0", "::/0"], c)])
    error_message = "public_endpoint_cidrs accetta solo CIDR validi ed espliciti (es. 203.0.113.0/24): 0.0.0.0/0 e ::/0 non sono ammessi."
  }
}

variable "admin_principals" {
  type        = list(string)
  description = "ARN di ruoli o utenti IAM di questo account con access entry e AmazonEKSClusterAdminPolicy sul cluster: tra questi c'è l'identità che applica lo stack kubernetes-addons."

  validation {
    condition     = length(var.admin_principals) > 0 && alltrue([for a in var.admin_principals : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:(role|user)/.+$", a))])
    error_message = "admin_principals deve contenere almeno un ARN di ruolo o utente IAM (es. arn:aws:iam::123456789012:role/devops)."
  }
}

variable "node_groups" {
  type = map(object({
    instance_types = list(string)
    min_size       = number
    max_size       = number
    desired_size   = number
    ami_type       = optional(string, "AL2023_x86_64_STANDARD")
    disk_size      = optional(number, 50)
  }))
  description = "Node group gestiti (nome => tipi di istanza, dimensioni, AMI e disco in GiB): ospitano i componenti di sistema e il controller di Karpenter, che crea i nodi dei workload."

  validation {
    condition     = length(var.node_groups) > 0 && alltrue([for k, g in var.node_groups : can(regex("^[a-z][a-z0-9-]{0,15}$", k)) && length(g.instance_types) > 0 && g.min_size >= 1 && g.min_size <= g.desired_size && g.desired_size <= g.max_size])
    error_message = "Ogni node group ha un nome kebab-case di al massimo 16 caratteri, almeno un tipo di istanza e 1 <= min_size <= desired_size <= max_size."
  }
}

variable "log_retention_days" {
  type        = number
  description = "Retention in giorni dei log del control plane (/aws/eks/<cluster>/cluster): almeno 365 in prod."

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days deve essere un valore ammesso da CloudWatch Logs (es. 30, 90, 365)."
  }

  validation {
    condition     = var.environment != "prod" || var.log_retention_days >= 365
    error_message = "In prod i log del control plane si conservano almeno 365 giorni."
  }
}

variable "deletion_protection" {
  type        = bool
  description = "true impedisce la cancellazione del cluster dall'API (va disattivata prima di un destroy): obbligatoria in prod."

  validation {
    condition     = var.environment != "prod" || var.deletion_protection
    error_message = "In prod la deletion protection del cluster è obbligatoria: deletion_protection = true."
  }
}

variable "addon_versions" {
  type        = map(string)
  description = "Versioni fissate degli add-on gestiti (nome => versione, es. { coredns = \"v1.14.7-eksbuild.10\" }); un add-on assente usa la versione più recente compatibile con kubernetes_version."
  default     = {}

  validation {
    condition     = alltrue([for k in keys(var.addon_versions) : contains(["vpc-cni", "kube-proxy", "eks-pod-identity-agent", "coredns", "aws-ebs-csi-driver"], k)])
    error_message = "addon_versions accetta solo vpc-cni, kube-proxy, eks-pod-identity-agent, coredns e aws-ebs-csi-driver."
  }
}
