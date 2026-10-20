# Modulo `network`

VPC su 2 o 3 zone di disponibilità con tre livelli di subnet /20 calcolate con `cidrsubnet`:

| Livello | Uscita | Uso |
|---|---|---|
| pubbliche | internet gateway | load balancer, NAT gateway |
| private | NAT gateway | workload (EKS, Lambda in VPC) |
| isolate | nessuna | dati (database, cache) |

- NAT: uno per zona con `nat_per_az = true` (produzione), uno solo altrimenti.
- Endpoint VPC: gateway S3 (rotte private e isolate); interface `ecr.api`, `ecr.dkr`, `secretsmanager`, `sts`, `logs` nelle subnet private con un security group dedicato che accetta 443 solo dal CIDR della VPC.
- Flow log (`ALL`) su CloudWatch Logs, cifrati con una chiave KMS dedicata (rotazione attiva) e con retention configurabile.
- Il security group di default non ha regole.

Output: `vpc_id`, `public_subnet_ids`, `private_subnet_ids`, `isolated_subnet_ids`, `vpc_endpoint_sg_id`. Gli altri stack li leggono con `terraform_remote_state`.
