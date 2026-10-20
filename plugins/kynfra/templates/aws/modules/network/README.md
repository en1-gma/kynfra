# Modulo `network`

VPC su 2 o 3 zone di disponibilità con tre livelli di subnet (prefisso della VPC + 4 bit, da /20 a /24) calcolate con `cidrsubnet`:

| Livello | Uscita | Uso |
|---|---|---|
| pubbliche | internet gateway | load balancer, NAT gateway |
| private | NAT gateway | workload (EKS, Lambda in VPC) |
| isolate | nessuna | dati (database, cache) |

- NAT: uno per zona con `nat_per_az = true` (produzione), uno solo altrimenti.
- Endpoint VPC: gateway S3 (rotte private e isolate); interface `ecr.api`, `ecr.dkr`, `secretsmanager`, `sts`, `logs` nelle subnet private con un security group dedicato che accetta 443 solo dal CIDR della VPC.
- Flow log (`ALL`) su CloudWatch Logs, cifrati con una chiave KMS dedicata (rotazione attiva) e con retention configurabile.
- Il security group di default non ha regole. L'endpoint S3 ammette solo i bucket dell'account (e il bucket dei layer ECR). Con `availability_zones` si fissano le zone invece di prendere le prime disponibili; in prod la retention dei flow log è almeno 365 giorni (validazione).

Output: `vpc_id`, `public_subnet_ids`, `private_subnet_ids`, `isolated_subnet_ids`, `vpc_endpoint_sg_id`. Gli altri stack li leggono con `terraform_remote_state`.
