# Roadmap

| Area | Stato |
|---|---|
| Regole, hook e stop gate per Terraform/OpenTofu su AWS, in Claude Code e Codex | disponibile (preview) |
| Sette pattern AWS (rete, SPA, backend kybes, ELB, EKS, ECR, segreti) più il bootstrap dello stato | disponibile |
| `tools.py`: download approvato e tracciato degli strumenti esterni | disponibile |
| Pipeline CI/CD: GitHub Actions con OIDC verso AWS, `plan` sulle PR, `apply` con approvazione per `prod`; poi Azure DevOps e GitLab | pianificato |
| **Gestore degli account** `/kynfra:manage-accounts-aws` (più account AWS, vedi sotto) | pianificato |
| Azure: stessi pattern (Storage + Front Door, APIM + Functions, Application Gateway, AKS, ACR, Key Vault, VNet) | pianificato |
| Vercel (provider Terraform + `vercel.json`), poi GCP e Cloudflare | pianificato |
| Stima dei costi (Infracost), rilevamento del drift, policy as code aggiuntive (OPA/Conftest) | pianificato |
| Verifica delle firme GPG degli strumenti scaricati (oggi solo checksum SHA256 su HTTPS) | in valutazione |
| Checksum delle singole dipendenze di Checkov (oggi fissata solo la wheel principale) | in valutazione |

## Gestore degli account

Oggi un solo account per tutti gli ambienti ([account](account.md)). Il comando `/kynfra:manage-accounts-aws` aggiungerà account alla config, genererà un `bootstrap/` per account, configurerà i provider con `assume_role` verso un ruolo per account e renderà cross-account le dipendenze (pull ECR, delega DNS, lettura dello stato). Il codice della v1 è già predisposto: nessun ID nei moduli, `account_id` sempre passato, `allowed_account_ids` in ogni stack.

## Fuori dalla v1, da non dimenticare

Elementi lasciati fuori di proposito e documentati nei pattern; chi li incontra deve saperlo.

- **Il database**: il pattern `backend` mette RDS Proxy davanti a un'istanza **esistente** (`db_instance_identifier`); creare l'istanza è fuori dalla v1, così come la regola sul security group del database verso il proxy (passo manuale).
- **NodePool ed EC2NodeClass di Karpenter**: sono risorse dei workload (kybes); il modulo `eks` ne documenta un esempio conforme ma non li applica.
- **Manifest e chart applicativi** su Kubernetes: compito di kybes. kynfra installa solo i componenti di sistema (AWS Load Balancer Controller, Karpenter, KEDA).
- **Codice delle Lambda e dell'authorizer**: la build li carica nel bucket degli artefatti; Terraform riferisce chiave e hash, non costruisce il codice.
- **Backend dell'API con altri engine**: RDS Proxy con `IAM_AUTH` non supporta SQL Server; supportati PostgreSQL e MySQL/MariaDB.
- **Endpoint S3 della rete**: la policy ammette solo i bucket dello stesso account e il bucket dei layer ECR, quindi i repository di pacchetti AWS (es. Amazon Linux) non sono raggiungibili dalle subnet private tramite l'endpoint.
- **Replica del bucket dello stato** e log di accesso S3 del bucket dello stato: scelte del DevOps (baseline motivata).
- **OIDC provider per IRSA**: non creato; i pod usano solo EKS Pod Identity.
- **Più progetti nello stesso account**: i singleton per account (ruolo CloudWatch di API Gateway) vanno applicati una volta sola.
- **Proposta per kybes** (fuori da questo progetto): far scrivere `x-kybes-handler` al suo architect, così la mappatura endpoint → handler non dipende dalla convenzione `/v1/<contesto>/…`.
