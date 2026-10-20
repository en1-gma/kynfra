---
paths:
  - "__PATH_PREFIX__**/*.tf"
  - "__PATH_PREFIX__**/*.tfvars"
  - "__PATH_PREFIX__**/*.tf.json"
---

# Regole di sicurezza (kynfra)

- Nessuna credenziale statica (`access_key`, `secret_key`, token) nei provider, nei `tfvars` o nelle variabili con default: profilo, SSO o OIDC.
- Nessun segreto in chiaro in `.tf`, `.tfvars`, `native/`. I segreti sono contenitori (`aws_secretsmanager_secret`); il valore lo inserisce il DevOps fuori da Terraform, oppure lo genera AWS (`manage_master_user_password`). Dove serve passarli, argomenti write-only (`*_wo`).
- Variabili riservate (password, token, chiavi) con `sensitive = true`; `secret_string` mai con letterale.
- Niente `local-exec`/`remote-exec`.
- Niente soppressioni inline (`checkov:skip`, `trivy:ignore`, `tflint-ignore`). Le eccezioni sono voci di `.kynfra/config.json` (`rule`, `path`, `resource`, `reason`, `expires`) scritte solo dall'utente.
- Strumenti esterni solo con `tools.py install <strumento>`, uno alla volta e con approvazione dell'utente; checksum SHA256 verificato, binari in `.kynfra/bin/`.
- L'agente non esegue mai `apply`, `destroy`, `import`, `taint`, `plan`, `force-unlock` né CLI cloud mutanti (`aws`, `az`, `gcloud`, `vercel`, `kubectl`, `helm` oltre le sole letture).
