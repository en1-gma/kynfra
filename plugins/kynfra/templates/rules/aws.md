---
paths:
  - "__PATH_PREFIX__**/*.tf"
  - "__PATH_PREFIX__**/*.tfvars"
  - "__PATH_PREFIX__**/*.tf.json"
---

# Regole AWS (kynfra)

- Provider `aws` con `default_tags` (`Project`, `Environment`, `Owner`, `CostCenter`, `ManagedBy = "kynfra"`) e `allowed_account_ids` negli stack; regione e `account_id` da variabili, mai nei moduli.
- S3: public access block completo, nessuna ACL pubblica, cifratura, policy TLS only, versioning su bucket di stato e di contenuto.
- CloudFront: solo HTTPS, TLS minimo `TLSv1.2_2021`, OAC (non OAI), response headers policy, log, WAF in prod.
- Load balancer: HTTP solo come redirect, policy TLS moderna, `drop_invalid_header_fields`, access log, deletion protection in prod.
- Security group: niente `0.0.0.0/0` o `::/0` su porte diverse da 80/443; mai su 22, 3389 e porte di database.
- IAM a privilegi minimi: niente `Action = "*"` con `Resource = "*"`, niente `AdministratorAccess`/`PowerUserAccess`, `iam:PassRole` mai su `*`, trust policy senza principal `*` privo di condizioni.
- KMS con `enable_key_rotation = true`; log group con `retention_in_days` (e KMS in prod).
- EKS: endpoint pubblico solo con CIDR espliciti, cifratura dei Secret, log del control plane, IMDSv2 obbligatorio. ECR: tag immutabili, scansione attiva, lifecycle policy. API: authorizer su ogni route, throttling e access log. Lambda: tracing e log group con retention.
